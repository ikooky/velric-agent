import { readFile, writeFile, mkdir, rename } from "node:fs/promises";
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
  status: TaskStatus;
  readonly createdAt: string;
  startedAt?: string;
  finishedAt?: string;
  /** Per-module outcome, appended in execution order. */
  stageLog: { module: string; status: "ok" | "fail" | "skip"; detail: string }[];
}

interface PlatformStore {
  projects: Record<string, ProjectRecord>;
  tasks: Record<string, TaskRecord>;
}

const STORE = "scan_platform.json";

/** Per-root in-process mutex: every store mutation (create/run) serializes
 *  through a promise chain — concurrent runTask on different tasks can no
 *  longer interleave load→mutate→persist cycles and lose updates. */
const locks = new Map<string, Promise<unknown>>();
async function withLock<T>(root: string, fn: () => Promise<T>): Promise<T> {
  const prev = locks.get(root) ?? Promise.resolve();
  const run = prev.then(fn, fn);
  locks.set(root, run.catch(() => {}));
  return run;
}

const load = async (root: string): Promise<PlatformStore> => {
  try { return JSON.parse(await readFile(join(root, STORE), "utf8")) as PlatformStore; }
  catch { return { projects: {}, tasks: {} }; }
};

const persist = async (root: string, st: PlatformStore): Promise<void> => {
  await mkdir(root, { recursive: true });
  const tmp = join(root, STORE + ".tmp");
  await writeFile(tmp, JSON.stringify(st, null, 2));
  await rename(tmp, join(root, STORE));
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
    for (const hit of r.found) assets.push({ type: "endpoint", value: hit.path, meta: { status: hit.status, bytes: hit.bytes, signature: hit.signature } });
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
  projectId: string; name: string; modules: string[]; targets?: string[]; sourceTask?: string;
}): Promise<TaskRecord> =>
  withLock<TaskRecord>(root, async () => {
  const st = await load(root);
  const project = st.projects[input.projectId];
  if (!project) throw new Error(`unknown project: ${input.projectId}`);
  const bad = input.modules.filter((m) => !MODULES.includes(m as ModuleName));
  if (bad.length > 0) throw new Error(`unknown modules: ${bad.join(",")} (valid: ${MODULES.join(",")})`);
  if (input.modules.length === 0) throw new Error("task needs at least one module");
  if (input.sourceTask) {
    const src = st.tasks[input.sourceTask];
    if (!src) throw new Error(`unknown sourceTask: ${input.sourceTask}`);
  }
  const targets = input.sourceTask ? [] : [...new Set(input.targets ?? project.targets)];
  if (!input.sourceTask && targets.length === 0) throw new Error("task needs targets or sourceTask");
  const rec: TaskRecord = {
    id: nextId("t", st), projectId: input.projectId, name: input.name,
    modules: input.modules, targets, sourceTask: input.sourceTask,
    status: "pending", createdAt: new Date().toISOString(), stageLog: [],
  };
  st.tasks[rec.id] = rec;
  await persist(root, st);
  return rec;
  });

/** Resolve a task's effective targets: literal, or from the source task's
 *  assets in the shared AssetStore (two-phase chaining). */
const resolveTargets = async (root: string, task: TaskRecord, st: PlatformStore): Promise<string[]> => {
  if (!task.sourceTask) return task.targets;
  const src = st.tasks[task.sourceTask];
  if (!src) throw new Error(`unknown sourceTask: ${task.sourceTask}`);
  if (src.status !== "done") throw new Error(`sourceTask ${task.sourceTask} is ${src.status}, must be done`);
  const store = new AssetStore(root);
  await store.load();
  const tag = `task:${task.sourceTask}`;
  return store.all().filter((a) => a.taskTag === tag && a.type === "subdomain").map((a) => a.value);
};

/** Execute a task: modules in order, assets upserted with the task tag,
 *  per-module stage log, status transitions. Deterministic — same inputs,
 *  same module calls; network variance is captured in stageLog detail. */
export const runTask = async (root: string, input: { taskId: string; proxy?: string; cookie?: string; timeoutMs?: number }): Promise<TaskRecord> =>
  withLock<TaskRecord>(root, async () => {
  const st = await load(root);
  const task = st.tasks[input.taskId];
  if (!task) throw new Error(`unknown task: ${input.taskId}`);
  if (task.status === "running") throw new Error("task already running");
  if (task.status === "done") return task; // idempotent re-run

  const targets = await resolveTargets(root, task, st);
  if (targets.length === 0) {
    task.status = "failed";
    task.stageLog.push({ module: "_resolve", status: "fail", detail: "no targets resolved (empty sourceTask result?)" });
    await persist(root, st);
    return task;
  }

  task.status = "running";
  task.startedAt = new Date().toISOString();
  task.stageLog = [];
  await persist(root, st);

  const store = new AssetStore(root);
  await store.load();
  const ctx: ModuleCtx = { root, proxy: input.proxy, cookie: input.cookie, timeoutMs: input.timeoutMs };
  const tag = `task:${task.id}`;
  let failed = 0;

  for (const mod of task.modules) {
    let ok = 0, fail = 0, skip = 0;
    const details: string[] = [];
    for (const target of targets) {
      try {
        const r = await runModule(mod as ModuleName, target, ctx);
        if (r.detail.startsWith("skip:")) { skip += 1; details.push(`${target}: skip`); continue; }
        for (const a of r.assets) {
          store.upsert({ type: a.type as never, value: a.value, parent: a.parent, taskTag: tag, meta: a.meta });
        }
        ok += 1;
        details.push(`${target}: ${r.detail}`);
      } catch (e) {
        fail += 1;
        details.push(`${target}: ${String((e as Error).message ?? e).slice(0, 100)}`);
      }
    }
    if (fail > 0 && ok === 0 && skip === 0) failed += 1;
    task.stageLog.push({ module: mod, status: fail === 0 ? "ok" : ok + skip > 0 ? "skip" : "fail", detail: `ok=${ok} fail=${fail} skip=${skip} | ${details.slice(0, 3).join(" ; ").slice(0, 200)}` });
    await store.save();
    await persist(root, st);
  }

  task.status = failed === task.modules.length ? "failed" : "done";
  task.finishedAt = new Date().toISOString();
  await persist(root, st);
  return task;
  });

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
  if (q.taskTag) items = items.filter((a) => a.taskTag === q.taskTag);
  if (q.valuePrefix) items = items.filter((a) => a.value.toLowerCase().startsWith(q.valuePrefix!.toLowerCase()));
  if (q.valueRegex) { const re = new RegExp(q.valueRegex, "i"); items = items.filter((a) => re.test(a.value)); }
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
