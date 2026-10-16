import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, rm, readFile, writeFile, mkdir, symlink } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { huntBegin, huntRecord, appendLedger, readLedger } from "../src/application/huntDriver.js";
import { loadGraph, saveGraph } from "../src/application/graph.js";
import { saveEvidence } from "../src/application/evidence.js";
import { EvidenceStore, AssetStore, ExplorationGraph } from "../src/domain/graphs.js";
import { bindEvidence, getBindings, reorderBindings, exportBindings } from "../src/domain/evidenceBinding.js";
import { compactGraph, expandDigest, touchLive, digestHash } from "../src/domain/coldGraph.js";
import { registerFinding, runRetest, listRetests } from "../src/domain/retest.js";
import { MockAgent, getGlobalDispatcher, setGlobalDispatcher } from "undici";
import { withExecution, recordReceipt } from "../src/core/execution.js";
import { fetchUrl } from "../src/adapters/http.js";
import { createProject, createTask, runTask, getTask, listAssets } from "../src/domain/scanPlatform.js";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
const exec = promisify(execFile);
const child = (code:string):Promise<{stdout:string;stderr:string}> => exec(process.execPath,["--input-type=module","--eval",`
  import { registerHooks } from "node:module";
  import { readFileSync, existsSync } from "node:fs";
  import ts from "typescript";
  registerHooks({
    resolve(specifier,context,next) {
      if (specifier.endsWith(".js") && context.parentURL?.includes("/src/")) {
        const candidate=new URL(specifier.replace(/\\.js$/, ".ts"),context.parentURL);
        if(existsSync(candidate))return next(candidate.href,context);
      }
      return next(specifier,context);
    },
    load(url,context,next) {
      if(url.endsWith(".ts"))return {format:"module",shortCircuit:true,source:ts.transpileModule(readFileSync(new URL(url),"utf8"),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText};
      return next(url,context);
    }
  });
  ${code.replace(/import \{([^}]+)\} from "([^"]+)";/g,'const {$1}=await import("$2");')}
`],{cwd:process.cwd(),timeout:30000});
const roots: string[] = [];
const root = async () => { const p = await mkdtemp(join(process.env.TMPDIR ?? tmpdir(), "velric-state-")); roots.push(p); return p; };
afterEach(async () => { await Promise.all(roots.splice(0).map(p => rm(p, {recursive:true,force:true}))); });
describe("evidence integrity", () => {
  it("G04 rejects malformed addresses, altered bytes and index length mismatch", async () => {
    const p = await root(); const store = new EvidenceStore(p); await store.load();
    const b = await store.put(Buffer.from("proof")); await store.save();
    await expect(store.get("../outside")).rejects.toMatchObject({code:"invalid_hash"});
    await writeFile(join(p,"blobs",b.hash.slice(0,2),b.hash+".bin"),"tampered");
    await expect(store.get(b.hash)).rejects.toMatchObject({code:"evidence_integrity"});
    await writeFile(join(p,"blobs",b.hash.slice(0,2),b.hash+".bin"),"proof");
    const index = JSON.parse(await readFile(join(p,"evidence_index.json"),"utf8"));
    index[b.hash].bytes += 1; await writeFile(join(p,"evidence_index.json"),JSON.stringify(index));
    await store.load(); await expect(store.get(b.hash)).rejects.toMatchObject({code:"evidence_integrity"});
  });
  it("G04 rejects symlink blobs and G01 preserves corrupt indexes", async () => {
    const p = await root(); const outside = await root();
    await mkdir(join(p,"blobs")); await symlink(outside,join(p,"blobs","ab"));
    const store = new EvidenceStore(p); await store.load();
    await expect(store.get("ab"+"0".repeat(62))).rejects.toMatchObject({code:"path_escape"});
    await writeFile(join(p,"evidence_index.json"),"{broken");
    await expect(store.load()).rejects.toMatchObject({code:"corrupt_state"});
    expect(await readFile(join(p,"evidence_index.json"),"utf8")).toBe("{broken");
  });
});
describe("manifest and binding transactions", () => {
  it("G01 retains concurrent manifests and fails closed on corrupt JSON", async () => {
    const p = await root();
    await Promise.all(Array.from({length:8},(_,i)=>saveEvidence({outputRoot:p,items:[{source:`s${i}`,content:`proof${i}`}]})));
    expect(JSON.parse(await readFile(join(p,"manifest.json"),"utf8")).blobs).toHaveLength(8);
    await writeFile(join(p,"manifest.json"),"{bad");
    await expect(saveEvidence({outputRoot:p,items:[{source:"new",content:"new"}]})).rejects.toMatchObject({code:"corrupt_state"});
    expect(await readFile(join(p,"manifest.json"),"utf8")).toBe("{bad");
  });
  it("G01 checks binding CAS in the commit lock and rejects repeated permutation IDs", async () => {
    const p = await root(); const s = new EvidenceStore(p); await s.load();
    const a = await s.put(Buffer.from("a")), b = await s.put(Buffer.from("b")); await s.save();
    const results = await Promise.allSettled([a,b].map(x=>bindEvidence({root:p,findingId:"f",expectedVersion:0,refs:[{hash:x.hash,role:"proof"}]})));
    expect(results.filter(x=>x.status==="fulfilled")).toHaveLength(1);
    expect((await getBindings(p,"f"))?.version).toBe(1);
    const x = await bindEvidence({root:p,findingId:"f",expectedVersion:1,refs:[{hash:a.hash,role:"proof"},{hash:b.hash,role:"supporting"}]});
    await expect(reorderBindings({root:p,findingId:"f",expectedVersion:2,order:[x.bindings[0]!.id,x.bindings[0]!.id]})).rejects.toThrow(/permutation/);
    await writeFile(join(p,"blobs",a.hash.slice(0,2),a.hash+".bin"),"changed");
    await expect(exportBindings({root:p,findingId:"f",zipPath:join(p,"out.zip")})).rejects.toMatchObject({code:"evidence_integrity"});
  });
});
describe("hunt identities and trust", () => {
  it("G01 rejects structurally corrupt embedded budgets and invalid graph identities", async () => {
    const p=await root();await huntBegin({outputRoot:p,goal:"a"});
    const file=join(p,"graph.json"),before=JSON.parse(await readFile(file,"utf8"));
    await writeFile(file,JSON.stringify({...before,huntBudget:{...before.huntBudget,cost:-1}}));
    await expect(huntRecord({outputRoot:p,goals:[{summary:"must not reset"}]})).rejects.toMatchObject({code:"corrupt_state"});
    await writeFile(file,JSON.stringify({...before,intents:[{id:1,summary:"bad",state:"invented",parentIds:[],yields:[]}]}));
    await expect(loadGraph(p)).rejects.toMatchObject({code:"corrupt_state"});
  });
  it("G06 never reuses finding IDs or an old runId on reset", async () => {
    const p=await root();const first=await huntBegin({outputRoot:p,goal:"a"});
    const old=await huntRecord({outputRoot:p,intents:[{summary:"first"}]});
    await huntBegin({outputRoot:p,goal:"b"});const next=await huntRecord({outputRoot:p,intents:[{summary:"second"}]});
    expect(next.graph.intents[0]!.id).toBeGreaterThan(old.graph.intents[0]!.id);
    await expect(huntBegin({outputRoot:p,goal:"c",runId:next.graph.runId,reset:true})).rejects.toThrow(/runId/);
  });
  it("G02 refuses implicit summary transitions and unknown intent IDs", async () => {
    const p = await root(); await huntBegin({outputRoot:p,goal:"a"});
    const one = await huntRecord({outputRoot:p,intents:[{summary:"scan",state:"running"}]});
    const id = one.graph.intents[0]!.id;
    await huntRecord({outputRoot:p,intents:[{summary:"scan",state:"done"}]});
    expect((await loadGraph(p)).intents[0]!.state).toBe("running");
    await huntRecord({outputRoot:p,intentId:id,intentState:"done"});
    expect((await loadGraph(p)).intents[0]!.state).toBe("done");
    await huntRecord({outputRoot:p,intentId:987,intentSummary:"unrelated",intentState:"running"});
    expect((await loadGraph(p)).intents).toHaveLength(1);
  });
  it("G02 reserves budgets before mutation and resets goal/run identity", async () => {
    const p = await root(); const a = await huntBegin({outputRoot:p,goal:"a",maxRounds:1,maxCost:2});
    await expect(huntRecord({outputRoot:p,round:0,costDelta:-1})).rejects.toThrow();
    await huntRecord({outputRoot:p,costDelta:2,goals:[{summary:"first"}]});
    const before = await readFile(join(p,"graph.json"),"utf8");
    const rejected=await huntRecord({outputRoot:p,goals:[{summary:"must not commit"}]});
    expect(rejected.budgetExceeded).toContain("maxRounds"); expect(await readFile(join(p,"graph.json"),"utf8")).toBe(before);
    const b = await huntBegin({outputRoot:p,goal:"b"}); expect(b.runId).not.toBe(a.runId); expect(b.budget.rounds).toBe(0);
    await expect(huntRecord({outputRoot:p,runId:a.runId})).rejects.toThrow(/runId/);
    const c = await huntBegin({outputRoot:p,goal:"b",reset:true}); expect(c.runId).not.toBe(b.runId);
  });
  it("G03 cannot upgrade caller-created URLs into proof receipts", async () => {
    const p = await root(); const {runId} = await huntBegin({outputRoot:p,goal:"trust"});
    const id="forged"; await appendLedger(p,[{id,runId,tool:"local",url:"https://proof.invalid/item?id=1",method:"GET",status:200,principal:"anonymous",complete:true,requestHash:"a".repeat(64),responseHash:"b".repeat(64),at:new Date().toISOString()}]);
    expect(await readLedger(p)).toEqual([]);
    const result = await huntRecord({outputRoot:p,facts:[{summary:"seen",evidence:"https://proof.invalid/item?id=1",observationIds:[id]}]});
    expect(result.accepted).toBe(0);
  });
  it("G03 binds trusted transport proof to exact query and principal/hash tuple", async () => {
    const p=await root(); const {runId}=await huntBegin({outputRoot:p,goal:"trust"});
    const mock=new MockAgent(); mock.disableNetConnect(); const old=getGlobalDispatcher(); setGlobalDispatcher(mock);
    try {
      mock.get("https://proof.invalid").intercept({path:"/item?id=1",method:"GET"}).reply(200,"private-object");
      const response=await withExecution({tool:"http_probe",runId,ledgerRoot:p},()=>fetchUrl("https://proof.invalid/item?id=1"));
      const [receipt]=await readLedger(p); expect(receipt!.id).toBe(response.receiptId);
      const proof={kind:"private_marker",observationIds:[receipt!.id!],principal:receipt!.principal!,requestHash:receipt!.requestHash!,responseHash:receipt!.responseHash!,claim:"private object read",expectedPolicy:"deny anonymous",objectOwner:"owner-a"};
      const bad=await huntRecord({outputRoot:p,findings:[{name:"bad",poc:"https://proof.invalid/item?id=2",observationIds:proof.observationIds,proof}]}); expect(bad.accepted).toBe(0);
      const wrong=await huntRecord({outputRoot:p,findings:[{name:"wrong",poc:receipt!.url,observationIds:proof.observationIds,proof:{...proof,principal:"different"}}]}); expect(wrong.accepted).toBe(0);
      const good=await huntRecord({outputRoot:p,findings:[{name:"private",poc:receipt!.url,observationIds:proof.observationIds,proof}]});
      expect(good.accepted).toBe(1); const f=good.graph.findings[0]!;
      expect(f.evidenceHashes?.length).toBeGreaterThan(0);
      const s=new EvidenceStore(p); expect(await s.get(f.evidenceHashes![0]!)).not.toBeNull();
    } finally {setGlobalDispatcher(old); await mock.close();}
  });
});
describe("retest truth and links", () => {
  it("G05 evaluates markers beyond the display snippet and binds the complete response", async () => {
    const p=await root(); const mock=new MockAgent(); mock.disableNetConnect(); const old=getGlobalDispatcher(); setGlobalDispatcher(mock);
    try {
      await registerFinding({root:p,id:"f",name:"test",severity:"high",poc:{method:"GET",url:"https://retest.invalid/item"},predicates:{fixedStatuses:[200],vulnerableBodyAny:["PRIVATE"]}});
      mock.get("https://retest.invalid").intercept({path:"/item"}).reply(200,"x".repeat(2100)+"PRIVATE");
      const r=await runRetest({root:p,findingId:"f"}); expect(r.verdict).toBe("reproduced"); expect(r.observed.bodySnippet.length).toBeLessThanOrEqual(400);
      const bindings=await getBindings(p,"f"); expect(bindings!.bindings.some(b=>b.role==="verification")).toBe(true);
      const store=new EvidenceStore(p); expect((await store.get(bindings!.bindings[0]!.hash))!.toString()).toContain("PRIVATE");
    } finally {setGlobalDispatcher(old); await mock.close();}
  });
  it("G05 rejects empty or illegal predicates before I/O", async () => {
    const p=await root();
    for (const predicates of [{},{fixedStatuses:[0]},{fixedBodyAny:[""]},{vulnerableBodyAny:["   "]},{fixedStatuses:[200.5]}]) {
      await expect(registerFinding({root:p,id:"f",name:"test",severity:"low",poc:{method:"GET",url:"https://retest.invalid/item"},predicates})).rejects.toThrow(/predicate/i);
    }
  });
  it("G05 treats a bounded truncation or unexpected redirect as inconclusive", async () => {
    const p=await root(); const mock=new MockAgent(); mock.disableNetConnect(); const old=getGlobalDispatcher(); setGlobalDispatcher(mock);
    try {
      await registerFinding({root:p,id:"f",name:"test",severity:"high",poc:{method:"GET",url:"https://retest.invalid/item"},predicates:{fixedStatuses:[200,302],vulnerableBodyAny:["PRIVATE"]}});
      mock.get("https://retest.invalid").intercept({path:"/item"}).reply(200,"x".repeat(100));
      const truncated=await runRetest({root:p,findingId:"f",maxBytes:8} as never); expect(truncated.verdict).toBe("inconclusive");
      mock.get("https://retest.invalid").intercept({path:"/item"}).reply(302,"",{headers:{location:"/login"}});
      expect((await runRetest({root:p,findingId:"f"})).verdict).toBe("inconclusive");
    } finally {setGlobalDispatcher(old); await mock.close();}
  });
  it("G01 appends concurrent retests without losing history", async () => {
    const p=await root(); const mock=new MockAgent(); mock.disableNetConnect(); const old=getGlobalDispatcher(); setGlobalDispatcher(mock);
    try {
      await registerFinding({root:p,id:"f",name:"test",severity:"high",poc:{method:"GET",url:"https://retest.invalid/item"},predicates:{fixedStatuses:[403]}});
      mock.get("https://retest.invalid").intercept({path:"/item"}).reply(403,"denied").times(4);
      const rs=await Promise.all(Array.from({length:4},()=>runRetest({root:p,findingId:"f"}))); expect(new Set(rs.map(r=>r.id)).size).toBe(4);
      expect((await listRetests(p)).findings[0]!.retests).toBe(4);
    } finally {setGlobalDispatcher(old); await mock.close();}
  });
});
describe("graph CAS and cold topology", () => {
  it("G01 rejects stale asset/exploration snapshots and preserves corrupt graph files", async () => {
    const p=await root(); const a=new AssetStore(p),b=new AssetStore(p); await a.load();await b.load();
    a.upsert({type:"subdomain",value:"a.invalid",taskTag:"task:1"}); b.upsert({type:"subdomain",value:"b.invalid",taskTag:"task:2"});
    await a.save();await expect(b.save()).rejects.toMatchObject({code:"version_conflict"});
    await b.load(); b.upsert({type:"subdomain",value:"a.invalid",taskTag:"task:2"}); await b.save();
    expect(b.all()[0]).toMatchObject({taskTag:"task:1",taskTags:["task:1","task:2"]});
    const x=new ExplorationGraph(p),y=new ExplorationGraph(p);await x.load();await y.load();x.addNode("intent","a");y.addNode("intent","b");
    await x.save();await expect(y.save()).rejects.toMatchObject({code:"version_conflict"});
    await writeFile(join(p,"asset_graph.json"),"{bad");await expect(a.load()).rejects.toMatchObject({code:"corrupt_state"});
    expect(await readFile(join(p,"asset_graph.json"),"utf8")).toBe("{bad");
  });
  it("G09 lets unchanged nodes become cold and warms payload/version changes", async () => {
    const p=await root(),g=new ExplorationGraph(p);const n=g.addNode("intent","same",{value:1});
    const stamps=new Map();touchLive(g,stamps,0);touchLive(g,stamps,1);touchLive(g,stamps,2);touchLive(g,stamps,3);
    expect(stamps.get(n.id).lastTouched).toBe(0);
    n.payload={value:2};touchLive(g,stamps,4);expect(stamps.get(n.id).lastTouched).toBe(4);
    expect(compactGraph(g,stamps,4).folded).toEqual([]);
    expect(digestHash([{...n,payload:{value:1}}])).not.toBe(digestHash([n]));
  });
  it("G09 reconnects live edges/anchors and restores exact payload topology after reload", async () => {
    const p=await root(),g=new ExplorationGraph(p);const parent=g.addNode("goal","root"),a=g.addNode("intent","a",{nested:{value:1}}),b=g.addNode("fact","b");
    g.addEdge(parent.id,"spawns",a.id);g.addEdge(a.id,"yields",b.id);g.anchor(b.id,"endpoint:https://cold.invalid/a");
    const before=JSON.parse(JSON.stringify({nodes:[...g["nodes"].values()],edges:g.edgesSnapshot(),anchors:g["anchors"]}));
    const stamps=new Map();touchLive(g,stamps,0);const folded=compactGraph(g,stamps,4);expect(folded.folded).toEqual(expect.arrayContaining([a.id,b.id]));
    const digest=folded.digests[0]!;expect(g.edgesSnapshot()).toContainEqual({from:parent.id,rel:"spawns",to:digest});
    expect(g.assetsOf(parent.id)).toContain("endpoint:https://cold.invalid/a");
    before.nodes.find((n:any)=>n.id===parent.id).touchVersion += 1; // the explicit traversal warms the surviving parent
    expect(g.edgesSnapshot().every(e=>g["nodes"].has(e.from)&&g["nodes"].has(e.to))).toBe(true);
    await g.save();const restored=new ExplorationGraph(p);await restored.load();expandDigest(restored,digest,stamps,5);await restored.save();
    expect([...restored["nodes"].values()].sort((x,y)=>x.id.localeCompare(y.id))).toEqual(before.nodes.sort((x:any,y:any)=>x.id.localeCompare(y.id)));
    expect(restored.edgesSnapshot()).toEqual(before.edges);expect(restored["anchors"]).toEqual(before.anchors);
  });
});
describe("task ownership and recovery", () => {
  it("G02 checkpoints every target without holding the root lock across callbacks", async () => {
    const p=await root(),project=await createProject(p,{name:"owner",targets:["a.invalid","b.invalid"]});
    const task=await createTask(p,{projectId:project.id,name:"owner",modules:["fingerprint"]});
    const checkpoints:string[]=[];
    const result=await runTask(p,{taskId:task.id,leaseMs:100,onCheckpoint:async (snapshot:any)=>{
      const disk=await getTask(p,task.id);expect(disk!.status).toBe("running");
      expect(Date.parse((disk as any).lease.expiresAt)).toBeGreaterThan(Date.now());
      checkpoints.push(...Object.keys(snapshot.checkpoint.completed).filter(k=>!checkpoints.includes(k)));
      await createProject(p,{name:`during-${checkpoints.length}`,targets:["local.invalid"]});
    }} as never);
    expect(result.status).toBe("done");expect(checkpoints).toEqual(["0:0","0:1"]);
  });
  it("G02 recovers an expired lease without re-running checkpointed targets", async () => {
    const p=await root(),project=await createProject(p,{name:"recover",targets:["a.invalid","b.invalid"]});
    const t=await createTask(p,{projectId:project.id,name:"recover",modules:["fingerprint"]});
    const file=join(p,"scan_platform.json"),st=JSON.parse(await readFile(file,"utf8"));
    st.tasks[t.id].status="running";
    st.tasks[t.id].lease={owner:"dead",runId:"old-run",pid:process.pid,heartbeatAt:new Date(0).toISOString(),expiresAt:new Date(0).toISOString()};
    st.tasks[t.id].checkpoint={targets:["a.invalid","b.invalid"],completed:{"0:0":{module:"fingerprint",target:"a.invalid",status:"skip",detail:"checkpoint only once"}}};
    await writeFile(file,JSON.stringify(st));
    const r=await runTask(p,{taskId:t.id});expect(r.status).toBe("done");expect(r.stageLog).toHaveLength(1);
    expect(JSON.stringify(r)).toContain("checkpoint only once");expect((r as any).checkpoint.completed["0:1"]).toBeDefined();
    expect((r as any).lease).toBeUndefined();
  });
  it("G01 fails closed on corrupt platform state", async () => {
    const p=await root();await writeFile(join(p,"scan_platform.json"),"{bad");
    await expect(createProject(p,{name:"no reset",targets:["a.invalid"]})).rejects.toMatchObject({code:"corrupt_state"});
    expect(await readFile(join(p,"scan_platform.json"),"utf8")).toBe("{bad");
  });
  it("G06 keeps immutable resolved source targets and multi-task asset provenance", async () => {
    const p=await root(),project=await createProject(p,{name:"source",targets:["seed.invalid"]});
    const first=await createTask(p,{projectId:project.id,name:"first",modules:["fingerprint"]});await runTask(p,{taskId:first.id});
    const assets=new AssetStore(p);await assets.load();assets.upsert({type:"subdomain",value:"a.invalid",taskTag:`task:${first.id}`});await assets.save();
    const next=await createTask(p,{projectId:project.id,name:"next",modules:["fingerprint"],sourceTask:first.id});await runTask(p,{taskId:next.id});
    await assets.load();assets.upsert({type:"subdomain",value:"a.invalid",taskTag:"task:another"});await assets.save();
    expect((await listAssets(p,{taskTag:`task:${first.id}`})).items.some(a=>a.value==="a.invalid")).toBe(true);
    expect((await getTask(p,next.id) as any).checkpoint.targets).toEqual(["a.invalid"]);
  });
});
describe("native state transactions", () => {
  it("G01 serializes successful mutations across independent processes", async () => {
    const p=await root();await huntBegin({outputRoot:p,goal:"multi-process"});
    await Promise.all(Array.from({length:3},(_,i)=>child(`
      import {huntRecord} from "./src/application/huntDriver.ts";
      import {saveEvidence} from "./src/application/evidence.ts";
      await huntRecord({outputRoot:${JSON.stringify(p)},goals:[{summary:"child-${i}"}]});
      await saveEvidence({outputRoot:${JSON.stringify(p)},items:[{source:"child-${i}",content:"bytes-${i}"}]});
    `)));
    expect((await loadGraph(p)).goals).toHaveLength(3);
    expect(JSON.parse(await readFile(join(p,"manifest.json"),"utf8")).blobs).toHaveLength(3);
  },30000);
  it("G01 fences two independent binding CAS writers at the same version", async () => {
    const p=await root(),s=new EvidenceStore(p);const blob=await s.put(Buffer.from("same"));
    const results=await Promise.all(Array.from({length:2},()=>child(`
      import {bindEvidence} from "./src/domain/evidenceBinding.ts";
      try {await bindEvidence({root:${JSON.stringify(p)},findingId:"f",expectedVersion:0,refs:[{hash:"${blob.hash}",role:"proof"}]});console.log("committed");}
      catch(e){if(e.code!=="version_conflict")throw e;console.log("version_conflict");}
    `)));
    expect(results.map(r=>r.stdout.trim()).sort()).toEqual(["committed","version_conflict"]);
    expect((await getBindings(p,"f"))?.version).toBe(1);
  },30000);
  it("retains every successful concurrent hunt mutation", async () => {
    const p = await root(); await huntBegin({outputRoot:p,goal:"goal"});
    const rs = await Promise.all(Array.from({length:12}, (_,i) => huntRecord({outputRoot:p, goals:[{summary:`goal ${i}`}]})));
    expect(rs.every(r => r.accepted === 1)).toBe(true);
    const g = await loadGraph(p); expect(g.goals).toHaveLength(12); expect(new Set(g.goals.map(x=>x.id)).size).toBe(12);
  });
});
