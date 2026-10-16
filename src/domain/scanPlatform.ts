import { createHash, randomUUID } from "node:crypto";
import { readJson, writeJson, safePath, withRootLock as withLock } from "../core/storage.js";
import { withExecution } from "../core/execution.js";
import { join } from "node:path";
import { AssetStore, type AssetNode } from "./graphs.js";

/** Native scan platform (ScopeSentry functional equivalent, fully in-process,
 *  zero external service / zero credentials). Deterministic orchestration
 *  shell over the existing domain modules:
 *
 *  - project: a named target set persisted in projects.json
 *  - task: an ordered module sequence bound to a project; each task writes
 *    its findings into the shared retest store and every discovered asset
 *    into the shared AssetStore with a taskTag for provenance
 *  - module pipeline maps 1:1 to existing domain modules (subdomains,
 *    ports, fingerprint, paths, spider, nuclei-lite, web probes)
 *  - two-phase best practice is a first-class field: a task may declare
 *    sourceTask — its targets are resolved from the AssetStore by that
 *    task's tag once the source task is done
 *
 *  Everything is local JSON state; no nodes, no templates marketplace, no
 *  auth — single-process, checkpoint-resumable per module. */

// ---------------- store models ----------------

export interface ProjectRecord {
  readonly id: string;
  readonly name: string;
  readonly targets: string[];
  readonly createdAt: string;
}

export type TaskStatus = "pending" | "running" | "done" | "failed";

export interface TaskRecord {
  readonly id: string;
  readonly projectId: string;
  readonly name: string;
  /** Ordered module names — the "template", inlined. */
  readonly modules: string[];
  /** Literal targets; ignored when sourceTask is set. */
  readonly targets: string[];
  /** Resolve targets from the AssetStore by this task's tag (two-phase). */
  readonly sourceTask?: string;
  readonly sourceTasks?: string[];
  runId?: string;
  lease?: {owner:string;runId:string;pid:number;heartbeatAt:string;expiresAt:string};
  checkpoint?: {targets:string[];inputHash?:string;completed:Record<string,{module:string;target:string;status:"ok"|"fail"|"skip";detail:string}>};
  status: TaskStatus;
  readonly createdAt: string;
  startedAt?: string;
  finishedAt?: string;
  /** Per-module outcome, appended in execution order. */
  stageLog: { module: string; status: "ok" | "fail" | "skip"; detail: string }[];
}

interface PlatformStore {
  version?: number;
  projects: Record<string, ProjectRecord>;
  tasks: Record<string, TaskRecord>;
}

const STORE = "scan_platform.json";

const load = (root:string):Promise<PlatformStore> => readJson(root,STORE,()=>({projects:{},tasks:{},version:0}),value=>{
  const st=value as PlatformStore;
  return !!st && !!st.projects && !!st.tasks && typeof st.projects==="object" && !Array.isArray(st.projects) && typeof st.tasks==="object" && !Array.isArray(st.tasks) &&
    (st.version===undefined || Number.isSafeInteger(st.version) && st.version>=0) &&
    Object.entries(st.projects).every(([id,p])=>p?.id===id && typeof p.name==="string" && Array.isArray(p.targets) && p.targets.every(t=>typeof t==="string")) &&
    Object.entries(st.tasks).every(([id,t])=>t?.id===id && !!st.projects[t.projectId] && Array.isArray(t.targets) && Array.isArray(t.modules) &&
      t.modules.every(m=>MODULES.includes(m as ModuleName)) && ["pending","running","done","failed"].includes(t.status) && Array.isArray(t.stageLog) &&
      (!t.lease || typeof t.lease.owner==="string" && Number.isFinite(Date.parse(t.lease.expiresAt)) && Number.isFinite(Date.parse(t.lease.heartbeatAt))) &&
      (!t.checkpoint || Array.isArray(t.checkpoint.targets) && !!t.checkpoint.completed && typeof t.checkpoint.completed==="object"));
});
const persist = async (root:string,st:PlatformStore):Promise<void> => {
  st.version=(st.version??0)+1;await writeJson(root,STORE,st);
};

// ---------------- module registry ----------------

export const MODULES = [
  "subdomain_scan",      // subdomains.ts: CT + brute + takeover hints
  "port_scan",           // portScan.ts: top-ports + service banner
  "fingerprint",         // fingerprint.ts: WAF/CDN/methods/cookies
  "dir_scan",            // pathProbe.ts: sensitive path dictionary
  "web_crawler",         // spider.ts: MPA link walk
  "nuclei_lite",         // nucleiLite.ts: exposed-panel templates
  "web_probes",          // cors + smuggle + jwt + domSinks probe family
] as const;
export type ModuleName = (typeof MODULES)[number];

const PROXY_TIMEOUT_DEFAULTS = { timeoutMs: 15000 };

interface ModuleCtx {
  readonly root: string;
  readonly proxy?: string;
  readonly cookie?: string;
  readonly timeoutMs?: number;
}

/** Run one module against one target. Returns a short detail line and the
 *  assets to upsert (taskTag applied by the caller). */
const runModule = async (mod: ModuleName, target: string, ctx: ModuleCtx): Promise<{ detail: string; assets: { type: string; value: string; parent?: string; meta?: Record<string, unknown> }[] }> => {
  const { timeoutMs = PROXY_TIMEOUT_DEFAULTS.timeoutMs, proxy, cookie } = ctx;
  const assets: { type: string; value: string; parent?: string; meta?: Record<string, unknown> }[] = [];
  const isDomain = !/^https?:\/\//.test(target);

  if (mod === "subdomain_scan") {
    if (!isDomain) return { detail: "skip: not a domain target", assets };
    const { discoverSubdomains } = await import("./subdomains.js");
    const r = await discoverSubdomains({ domain: target, outputRoot: ctx.root, proxy });
    for (const h of r.total) assets.push({ type: "subdomain", value: h, parent: r.domain, meta: { source: "subdomain_scan" } });
    assets.push({ type: "root_domain", value: r.domain });
    return { detail: `${r.total.length} subdomains (crt.sh=${r.crtSh.length} brute=${r.bruteFound.length})`, assets };
  }

  if (mod === "port_scan") {
    const host = isDomain ? target : new URL(target).hostname;
    const { scanPorts } = await import("./portScan.js");
    const r = await scanPorts({ host, outputRoot: ctx.root, timeoutMs });
    for (const p of r.open) {
      assets.push({ type: "service", value: `${host}:${p.port}`, parent: host, meta: { port: p.port, service: p.service } });
    }
    return { detail: `${r.open.length} open ports on ${host}`, assets };
  }

  if (mod === "fingerprint") {
    if (isDomain) return { detail: "skip: fingerprint needs a URL", assets };
    const { fingerprint } = await import("./fingerprint.js");
    const r = await fingerprint({ baseUrl: target, outputRoot: ctx.root, proxy, cookie, timeoutMs });
    assets.push({ type: "service", value: new URL(target).origin, meta: { waf: r.waf, methods: r.methods.allowed } });
    return { detail: `waf=${r.waf.join(",") || "none"} methods=${r.methods.allowed.length}`, assets };
  }

  if (mod === "dir_scan") {
    if (isDomain) return { detail: "skip: dir_scan needs a URL", assets };
    const { probePaths } = await import("./pathProbe.js");
    const r = await probePaths({ baseUrl: target, outputRoot: ctx.root, proxy, cookie, timeoutMs });
    const origin = new URL(target).origin;
    for (const hit of r.found) {
      // Full URL, not a bare path: '/.git/config' key-collides across every
      // target in the store; anchor to the scanned origin with a parent link.
      const cleanPath = hit.path.split("  [")[0]!.trim(); // strip inline flags
      assets.push({ type: "endpoint", value: `${origin}${cleanPath.startsWith("/") ? cleanPath : `/${cleanPath}`}`, parent: origin, meta: { status: hit.status, bytes: hit.bytes, signature: hit.signature } });
    }
    return { detail: `${r.found.length} sensitive paths`, assets };
  }

  if (mod === "web_crawler") {
    if (isDomain) return { detail: "skip: web_crawler needs a URL", assets };
    const { spiderMpa } = await import("../application/spider.js");
    const r = await spiderMpa({ baseUrl: target, outputRoot: ctx.root, proxy, cookie });
    void r;
    return { detail: `${r.crawled} pages / ${r.forms} forms / ${r.inlineApiUrls} inline apis`, assets };
  }

  if (mod === "nuclei_lite") {
    if (isDomain) return { detail: "skip: nuclei_lite needs a URL", assets };
    const { runNucleiLite } = await import("./nucleiLite.js");
    const r = await runNucleiLite({ baseUrl: target, outputRoot: ctx.root, proxy, timeoutMs });
    return { detail: `${r.matched.length} template matches`, assets };
  }

  // web_probes
  if (isDomain) return { detail: "skip: web_probes needs a URL", assets };
  const { probeCors } = await import("./cors.js");
  const { probeSmuggle } = await import("./smuggle.js");
  const cors = await probeCors({ baseUrl: target, outputRoot: ctx.root, proxy, cookie, timeoutMs });
  const smuggle = await probeSmuggle({ baseUrl: target, outputRoot: ctx.root, proxy, timeoutMs });
  const corsIssues = cors.results.filter((x) => x.verdict !== "none" && x.verdict !== "static");
  return { detail: `cors=${corsIssues.length} smuggle=${smuggle.differentials.length}`, assets };
};

// ---------------- platform operations ----------------

const nextId = (prefix: string, st: PlatformStore): string => {
  let n = Object.keys(st.projects).length + Object.keys(st.tasks).length + 1;
  let id = `${prefix}${n}`;
  while ((prefix === "p" ? st.projects : st.tasks)[id] !== undefined) { n += 1; id = `${prefix}${n}`; }
  return id;
};

export const createProject = async (root: string, input: { name: string; targets: string[] }): Promise<ProjectRecord> =>
  withLock<ProjectRecord>(root, async () => {
  if (input.targets.length === 0) throw new Error("project needs at least one target");
  const st = await load(root);
  const dup = Object.values(st.projects).find((p) => p.name === input.name);
  if (dup) throw new Error(`project name already exists: ${input.name}`);
  const rec: ProjectRecord = { id: nextId("p", st), name: input.name, targets: [...new Set(input.targets)], createdAt: new Date().toISOString() };
  st.projects[rec.id] = rec;
  await persist(root, st);
  return rec;
  });

export const createTask = async (root: string, input: {
  projectId: string; name: string; modules: string[]; targets?: string[]; sourceTask?: string; sourceTasks?: string[];
}): Promise<TaskRecord> =>
  withLock<TaskRecord>(root, async () => {
  const st = await load(root);
  const project = st.projects[input.projectId];
  if (!project) throw new Error(`unknown project: ${input.projectId}`);
  const bad = input.modules.filter((m) => !MODULES.includes(m as ModuleName));
  if (bad.length > 0) throw new Error(`unknown modules: ${bad.join(",")} (valid: ${MODULES.join(",")})`);
  if (input.modules.length === 0) throw new Error("task needs at least one module");
  const sourceTasks=[...new Set([...(input.sourceTasks??[]),...(input.sourceTask?[input.sourceTask]:[])])];
  for(const id of sourceTasks){
    const src=st.tasks[id]; if(!src)throw new Error(`unknown sourceTask: ${id}`);
    if(src.projectId!==input.projectId)throw new Error("sourceTask must belong to the same project");
  }
  const targets = sourceTasks.length ? [] : [...new Set(input.targets ?? project.targets)];
  if (!sourceTasks.length && targets.length === 0) throw new Error("task needs targets or sourceTask");
  const rec: TaskRecord = {
    id: nextId("t", st), projectId: input.projectId, name: input.name,
    modules: [...input.modules], targets, sourceTask: input.sourceTask, sourceTasks: sourceTasks.length ? sourceTasks : undefined,
    status: "pending", createdAt: new Date().toISOString(), stageLog: [],
  };
  st.tasks[rec.id] = rec;
  await persist(root, st);
  return rec;
  });

/** Resolve a task's effective targets: literal, or from the source task's
 *  assets in the shared AssetStore (two-phase chaining). */
const resolveTargets = async (root: string, task: TaskRecord, st: PlatformStore): Promise<string[]> => {
  if(task.checkpoint)return [...task.checkpoint.targets];
  const sources=task.sourceTasks??(task.sourceTask?[task.sourceTask]:[]);
  if(!sources.length)return [...task.targets];
  for(const id of sources){const src=st.tasks[id];if(!src)throw new Error(`unknown sourceTask: ${id}`);if(src.status!=="done")throw new Error(`sourceTask ${id} is ${src.status}, must be done`);}
  const store=new AssetStore(root);await store.load();const tags=new Set(sources.map(id=>`task:${id}`));
  return [...new Set(store.all().filter(a=>a.type==="subdomain" && [...(a.taskTags??[]),...(a.taskTag?[a.taskTag]:[])].some(tag=>tags.has(tag))).map(a=>a.value))];
};

/** Short claim/checkpoint transactions fence long-running workers by lease token. */
export const runTask = async (root:string,input:{
  taskId:string;proxy?:string;cookie?:string;timeoutMs?:number;runId?:string;leaseMs?:number;signal?:AbortSignal;
  onCheckpoint?:(task:TaskRecord)=>Promise<void>|void;
}):Promise<TaskRecord> => {
  const leaseMs=Math.max(1000,input.leaseMs??30000);
  if(!Number.isFinite(leaseMs)||leaseMs>3600000)throw new Error("invalid lease duration");
  const owner=randomUUID();
  const refresh=(task:TaskRecord):void=>{const now=Date.now();task.lease={owner,runId:task.runId!,pid:process.pid,heartbeatAt:new Date(now).toISOString(),expiresAt:new Date(now+leaseMs).toISOString()};};
  const claimed=await withLock(root,async()=>{
    const st=await load(root),task=st.tasks[input.taskId];
    if(!task)throw new Error(`unknown task: ${input.taskId}`);
    if(task.status==="done")return task;
    if(task.status==="running" && task.lease && Date.parse(task.lease.expiresAt)>Date.now())throw new Error("task already running");
    const targets=await resolveTargets(root,task,st);
    const inputHash=createHash("sha256").update(JSON.stringify({modules:task.modules,targets,sourceTasks:task.sourceTasks??(task.sourceTask?[task.sourceTask]:[]),
      credentialHash:createHash("sha256").update(input.cookie??"").digest("hex"),proxyHash:createHash("sha256").update(input.proxy??"").digest("hex")})).digest("hex");
    if(task.checkpoint?.inputHash && task.checkpoint.inputHash!==inputHash)throw new Error("checkpoint input changed; use a new task");
    if(task.runId && input.runId && task.runId!==input.runId)throw new Error("task runId mismatch");
    task.checkpoint??={targets:[...targets],inputHash,completed:{}};
    task.checkpoint.inputHash??=inputHash;
    task.runId??=input.runId??randomUUID();
    task.startedAt??=new Date().toISOString();delete task.finishedAt;
    if(!targets.length){task.status="failed";delete task.lease;task.finishedAt=new Date().toISOString();task.stageLog=[{module:"_resolve",status:"fail",detail:"no targets resolved (empty sourceTask result?)"}];}
    else {task.status="running";refresh(task);}
    await persist(root,st);return task;
  });
  if(claimed.status!=="running")return claimed;
  const runId=claimed.runId!,targets=claimed.checkpoint!.targets;
  const own=(st:PlatformStore):TaskRecord=>{
    const task=st.tasks[input.taskId];
    if(!task || task.status!=="running" || task.runId!==runId || task.lease?.owner!==owner)throw Object.assign(new Error("task lease lost"),{code:"lease_lost"});
    return task;
  };
  const abort=new AbortController();const signal=input.signal?AbortSignal.any([input.signal,abort.signal]):abort.signal;
  let heartbeatError:unknown;let pending=Promise.resolve();
  const heartbeat=setInterval(()=>{
    pending=pending.then(()=>withLock(root,async()=>{const st=await load(root),task=own(st);refresh(task);await persist(root,st);})).catch(error=>{heartbeatError=error;abort.abort(error);});
  },Math.max(250,Math.floor(leaseMs/3)));
  heartbeat.unref();
  const assertActive=():void=>{if(heartbeatError)throw heartbeatError;if(signal.aborted)throw Object.assign(new Error("task cancelled"),{code:"cancelled"});};
  const summarize=(task:TaskRecord):void=>{
    task.stageLog=task.modules.flatMap((module,index)=>{
      const rows=Object.entries(task.checkpoint!.completed).filter(([key])=>key.startsWith(`${index}:`)).map(([,row])=>row);
      if(rows.length!==targets.length)return [];
      const ok=rows.filter(x=>x.status==="ok").length,fail=rows.filter(x=>x.status==="fail").length,skip=rows.filter(x=>x.status==="skip").length;
      return [{module,status:fail===0?"ok" as const:ok+skip>0?"skip" as const:"fail" as const,detail:`ok=${ok} fail=${fail} skip=${skip} | ${rows.slice(0,3).map(x=>`${x.target}: ${x.detail}`).join(" ; ").slice(0,200)}`}];
    });
  };
  try {
    for(let mi=0;mi<claimed.modules.length;mi++)for(let ti=0;ti<targets.length;ti++){
      assertActive();const key=`${mi}:${ti}`,module=claimed.modules[mi]!,target=targets[ti]!;
      const latest=await withLock(root,async()=>own(await load(root)));
      if(latest.checkpoint!.completed[key])continue;
      const artifactRoot=await safePath(root,`tasks/${input.taskId}/${createHash("sha256").update(runId).digest("hex")}/targets/${createHash("sha256").update(target).digest("hex")}/${mi}-${module}`);
      let result:Awaited<ReturnType<typeof runModule>>={detail:"",assets:[]};let status:"ok"|"fail"|"skip"="ok";
      try {
        result=await withExecution({tool:`scan_platform:${module}`,runId,ledgerRoot:root,signal},()=>runModule(module as ModuleName,target,{root:artifactRoot,proxy:input.proxy,cookie:input.cookie,timeoutMs:input.timeoutMs}));
        if(result.detail.startsWith("skip:"))status="skip";
      }catch(error){assertActive();status="fail";result={detail:String((error as Error).message??error).slice(0,200),assets:[]};}
      assertActive();
      const snapshot=await withLock(root,async()=>{
        const st=await load(root),task=own(st),assets=new AssetStore(root);await assets.load();
        for(const asset of result.assets)assets.upsert({type:asset.type as never,value:asset.value,parent:asset.parent,taskTag:`task:${task.id}`,meta:asset.meta});
        if(result.assets.length)await assets.save();
        task.checkpoint!.completed[key]={module,target,status,detail:result.detail};summarize(task);refresh(task);await persist(root,st);return task;
      });
      await input.onCheckpoint?.(structuredClone(snapshot));
    }
    clearInterval(heartbeat);await pending;assertActive();
    return await withLock(root,async()=>{
      const st=await load(root),task=own(st);summarize(task);
      task.status=task.stageLog.every(x=>x.status==="fail")?"failed":"done";task.finishedAt=new Date().toISOString();delete task.lease;
      await persist(root,st);return task;
    });
  } catch(error) {
    clearInterval(heartbeat);await pending;
    // Never overwrite a successor's ownership or swallow a failed terminal commit.
    await withLock(root,async()=>{
      const st=await load(root),task=st.tasks[input.taskId];if(task?.lease?.owner!==owner)return;
      task.status="failed";task.finishedAt=new Date().toISOString();delete task.lease;
      task.stageLog.push({module:"_runner",status:"fail",detail:String((error as Error).message??error).slice(0,200)});await persist(root,st);
    });
    throw error;
  } finally {clearInterval(heartbeat);}
};

// ---------------- local retrieval (ScopeSentry list/count parity) ----------------

export interface AssetQuery {
  type?: string;
  taskTag?: string;
  valuePrefix?: string;
  valueRegex?: string;
}

export const listAssets = async (root: string, q: AssetQuery, page = 1, pageSize = 50): Promise<{ total: number; page: number; items: AssetNode[] }> => {
  const store = new AssetStore(root);
  await store.load();
  let items = store.all();
  if (q.type) items = items.filter((a) => a.type === q.type);
  if (q.taskTag) items = items.filter((a) => a.taskTag === q.taskTag || a.taskTags?.includes(q.taskTag!));
  if (q.valuePrefix) items = items.filter((a) => a.value.toLowerCase().startsWith(q.valuePrefix!.toLowerCase()));
  if (q.valueRegex) {
    // Caller-supplied pattern: cap length and compile defensively — an
    // unbounded catastrophic-backtracking regex turns this into a CPU DoS.
    if (q.valueRegex.length > 256) throw new Error("valueRegex too long (max 256 chars)");
    let re: RegExp;
    try { re = new RegExp(q.valueRegex, "i"); } catch (err) { throw new Error(`invalid valueRegex: ${(err as Error).message}`); }
    items = items.filter((a) => re.test(a.value));
  }
  items = items.sort((a, b) => a.firstSeen.localeCompare(b.firstSeen));
  const total = items.length;
  const start = (page - 1) * pageSize;
  return { total, page, items: items.slice(start, start + pageSize) };
};

export const countAssets = async (root: string, q: AssetQuery): Promise<{ total: number }> => {
  const r = await listAssets(root, q, 1, 1);
  return { total: r.total };
};

export const getTask = async (root: string, taskId: string): Promise<TaskRecord | null> => {
  const st = await load(root);
  return st.tasks[taskId] ?? null;
};

export const listTasks = async (root: string, projectId?: string): Promise<TaskRecord[]> => {
  const st = await load(root);
  const all = Object.values(st.tasks).sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  return projectId ? all.filter((t) => t.projectId === projectId) : all;
};

export const listProjects = async (root: string): Promise<ProjectRecord[]> => {
  const st = await load(root);
  return Object.values(st.projects).sort((a, b) => a.createdAt.localeCompare(b.createdAt));
};
