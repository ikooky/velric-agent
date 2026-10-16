/**
 * Host-driven hunt engine — no LLM client inside. The host agent IS the
 * planner/worker: velric-agent provides the state graph, the toolset, the
 * observation ledger (system digests of what tools actually saw), and the
 * anti-hallucination gates. Zero api keys, zero LLM config.
 *
 * Loop (driven by the host):
 *   hunt_begin(goal, outputRoot)        → graph + driver playbook
 *   <host calls any recon tools with observationLedgerRoot set>
 *   hunt_record(intents/facts/findings) → gated write-back into the graph
 *   hunt_overview()                     → situation for the host's next decision
 */
import { randomUUID } from "node:crypto";
import { readJson, writeJson, withRootLock, putBlob } from "../core/storage.js";
import { join } from "node:path";
import { EvidenceStore } from "../domain/graphs.js";
import { bindEvidence } from "../domain/evidenceBinding.js";
import {
  loadGraph, saveGraph, graphOverview,
  type Graph, type Intent,
} from "./graph.js";

export interface HuntBeginInput {
  readonly goal: string;
  readonly outputRoot: string;
  readonly reset?: boolean;
  readonly runId?: string;
  /** Budget caps (HackingBuddyGPT-style run limits). The hunt HARD-STOPS when
   *  any cap is exceeded; hunt_record refuses to advance and returns the
   *  exceeded limit. All optional — no caps means unbounded (legacy). */
  readonly maxRounds?: number;
  /** cost budget in currency units (host's accounting, e.g. USD). */
  readonly maxCost?: number;
  /** wall-clock budget in minutes. */
  readonly maxDurationMin?: number;
}

/** Persisted hunt state beyond the graph: round counter + budget bookkeeping. */
interface HuntBudget {
  readonly runId?: string;
  readonly startedAt: string;
  rounds: number;
  cost: number;
  readonly caps?: { maxRounds?: number; maxCost?: number; maxDurationMin?: number };
}

const BUDGET_FILE = "hunt_budget.json";

export const budgetPath = (root: string): string => join(root, BUDGET_FILE);

const loadBudget = async (root: string): Promise<HuntBudget> => {
  const graph = await loadGraph(root);
  if (graph.huntBudget) return graph.huntBudget;
  return readJson(root, BUDGET_FILE, () => ({startedAt:new Date().toISOString(),rounds:0,cost:0}), v => {
    const b=v as HuntBudget; return !!b && Number.isInteger(b.rounds) && b.rounds>=0 && Number.isFinite(b.cost) && b.cost>=0 && Number.isFinite(Date.parse(b.startedAt));
  });
};

/** Check the caps; returns the exceeded limit name, or null when within budget. */
export const budgetExceeded = (b: HuntBudget): string | null => {
  const caps = b.caps;
  if (!caps) return null;
  if (caps.maxRounds != null && b.rounds > caps.maxRounds) return `maxRounds(${caps.maxRounds})`;
  if (caps.maxCost != null && b.cost > caps.maxCost) return `maxCost(${caps.maxCost})`;
  if (caps.maxDurationMin != null) {
    const elapsedMin = (Date.now() - new Date(b.startedAt).getTime()) / 60000;
    if (elapsedMin > caps.maxDurationMin) return `maxDurationMin(${caps.maxDurationMin})`;
  }
  return null;
};

export interface HuntRecordInput {
  readonly outputRoot: string;
  readonly runId?: string;
  readonly expectedVersion?: number;
  readonly intentState?: Intent["state"];
  readonly intentId?: number;
  readonly intentSummary?: string;
  readonly goals?: { summary: string; vulnclass?: string }[];
  readonly intents?: { id?: number; summary?: string; state?: string }[];
  readonly facts?: { summary?: string; detail?: string; evidence?: string; confidence?: string; observationIds?: string[] }[];
  readonly findings?: { name?: string; vulnclass?: string; severity?: string; summary?: string; poc?: string; observationIds?: string[]; proofKind?: string; outcome?: string; proof?: {kind:string; observationIds:string[]; principal:string; requestHash:string; responseHash:string; claim?:string; expectedPolicy?:string; objectOwner?:string} }[];
  readonly assets?: { type?: string; key?: string; props?: Record<string, unknown> }[];
  readonly goalsMet?: { id: number; reason?: string }[];
  /** host-declared round increment (one hunt_record per round convention). */
  readonly round?: number;
  /** host-declared cost delta for this round (its own LLM accounting). */
  readonly costDelta?: number;
}

/** Ledger entry — system-written record of what a tool ACTUALLY observed. */
export interface LedgerEntry {
  readonly id?: string;
  readonly runId?: string;
  readonly tool: string;
  readonly url: string;
  readonly status: number | null;
  readonly at: string;
  readonly method?: string;
  readonly requestHash?: string | null;
  readonly responseHash?: string | null;
  readonly principal?: string;
  readonly complete?: boolean;
}
const LEDGER_FILE = "observation_ledger.json";
export const ledgerPath = (root: string): string => join(root, LEDGER_FILE);
export const readLedger = (root: string): Promise<LedgerEntry[]> => readJson(root, LEDGER_FILE, () => [], value =>
  Array.isArray(value) && value.every(e=>e && typeof e.tool === "string" && typeof e.url === "string" &&
    (e.status===null || (Number.isInteger(e.status) && e.status>=0 && e.status<=599)) && typeof e.at === "string") &&
  new Set(value.filter(e=>e.id).map(e=>e.id)).size === value.filter(e=>e.id).length);
/** Compatibility imports are hints, kept outside the transport-only observation ledger. */
export const appendLedger = (root: string, entries: LedgerEntry[]): Promise<void> => withRootLock(root, async () => {
  const receipts=await readLedger(root);
  const hints=await readJson<LedgerEntry[]>(root,"observation_hints.json",()=>[],Array.isArray);
  for(const entry of entries){
    const exists=entry.id?receipts.find(x=>x.id===entry.id):undefined;
    if(exists){if(JSON.stringify(exists)!==JSON.stringify(entry))throw new Error("immutable observation conflict");continue;}
    hints.push({...entry,id:undefined,runId:undefined,complete:false,requestHash:null,responseHash:null});
  }
  await writeJson(root,"observation_hints.json",hints);
});

/** Driver playbook handed to the host at hunt_begin. */
export const DRIVER_PLAYBOOK = `# 自主侦察驱动手册(宿主 agent 执行)

你现在是这套系统的 planner+worker 大脑。velric-agent 提供:状态图(graph.json)、侦察工具、观察台账(observation_ledger.json,系统记录工具真实请求过的 URL+状态码)、防幻觉写回闸门。

## 目标分解(开局先做)
从任务目标中识别**最终可交付/可核验的结果**,不是攻击步骤。拆分原则:
- 用户描述的最终目标只有一个 → 输出一个;多个相互独立的交付物 → 分别列出
- 能对应明确漏洞类的标注 vulnclass;信息收集/业务逻辑类留空
- **禁止列为子目标**:信息收集/侦察/端点扫描、漏洞分析验证过程、攻击步骤、结果验证步骤
- 同时抽取操作约束(deny=禁止操作/allow=允许范围),约束必须自包含写死具体目标值,把指代词替换成具体值;只登记明确写出的约束,严禁臆造;拿不准用 deny(更保守)
- 用 hunt_record(goals:[...]) 登记分解结果

## 每轮循环
1. hunt_overview(outputRoot) 读态势
2. **规划决策**:
   - **硬底线(最高优先)**:目标未达成且没有任何 open/running 意图时,必须产出至少一个推进意图;产出 0 意图要有正当理由(已覆盖/等依赖)
   - **判目标(核心)**:对已被发现/事实证明的目标标 met。量化验收核对(严禁提前盖章):目标含量化条件必须核对实测值,未达标禁止标 met,改派意图补差
   - 换措辞重复生成已存在的意图=严重错误
   - recent_done 里 done=已覆盖不重派,仅材料性新机理(新入口/新参数/明显不同构造)才重开;exhausted/blocked=看进度决定继续/重派/换打法
   - 否定/存疑观察采信前先看 evidence:evidence 扎实且手段已穷尽才视为封住;evidence 缺失或只探一次的按未探明处理,同一否定方向至多复核一次
   - **深度优先于覆盖度**:发现高价值入口优先往深打穿
   - **路线多样**:现有意图挤同一路线而存在本质不同的未覆盖方向,优先补分歧方向;理想 2-3 条机理不同路线并存
   - **串行利用链分步派**:强依赖链只派"前置已满足"的那步
3. 调侦察工具执行意图(带 observationLedgerRoot=outputRoot,系统自动记账)
4. hunt_record 写回结论

## 执行纪律(worker 红线)
- 只做领到的一条意图;瞥见意图外的深挖线索,在 fact summary 里点一句交回规划视角
- **初次受阻(404/被过滤/无回显)≠此路不通**:换 UA/方法/参数/路径变体,把本意图所有绕过手段走完再判死路
- 边发现边写回:新资产→assets;直接看到→facts(observed);推断→facts(inferred);确认漏洞→findings
- 观察分 observed(直接看到)/inferred(推断);证伪与证实同等有价值
- 不重复记录已有结论;嫌疑不硬记 finding

## 写回闸门(hunt_record 自动执行)
- evidence/poc 里引用的每个 http(s) URL 必须在台账里(工具真实请求过),否则整条丢弃
- observed 事实必须引用台账记录;inferred 免检但必须标 confidence=inferred
- **确认漏洞必须真实触发过且可复现**;版本号匹配、"看起来可注入"严禁当 finding

## 收尾
所有目标 met 或收益递减时:hunt_record(goalsMet)→ gen_report + save_evidence 交付`;

export const huntBegin = async (input: HuntBeginInput) => withRootLock(input.outputRoot, async () => {
  const root = input.outputRoot;
  const old = await loadGraph(root);
  const fresh = input.reset === true || old.goal === "" || old.goal !== input.goal;
  let g: Graph = fresh ? {goal:input.goal,constraints:[],goals:[],intents:[],facts:[],findings:[],assets:[],nextId:old.nextId,version:old.version,runId:input.runId ?? randomUUID()} : old;
  if(input.runId!==undefined && !input.runId.trim())throw new Error("invalid runId");
  if(fresh && old.runId && input.runId===old.runId)throw new Error("reset requires a new runId");
  if (!fresh && input.runId && input.runId !== g.runId) throw new Error("runId mismatch; reset required");
  if (!g.runId) g.runId=randomUUID();
  let budget: HuntBudget = fresh ? {runId:g.runId,startedAt:new Date().toISOString(),rounds:0,cost:0} : await loadBudget(root);
  const caps = {maxRounds:input.maxRounds,maxCost:input.maxCost,maxDurationMin:input.maxDurationMin};
  for (const [key,value] of Object.entries(caps)) if (value != null && (!Number.isFinite(value) || value < 0 || (key === "maxRounds" && !Number.isInteger(value)))) throw new Error("invalid budget cap");
  if (Object.values(caps).some(v => v != null)) budget={...budget,caps:{...budget.caps,...Object.fromEntries(Object.entries(caps).filter(([,v])=>v!=null))}};
  g.huntBudget=budget;
  await saveGraph(root,g);
  return {outputRoot:root,goal:input.goal,runId:g.runId,version:g.version,driverPlaybook:DRIVER_PLAYBOOK,next:"hunt_overview then hunt_record; cite observationIds and verified proof metadata",budget:{rounds:budget.rounds,cost:budget.cost,caps:budget.caps}};
});

export const huntRecord = async (input: HuntRecordInput): Promise<{ graph: Graph; accepted: number; dropped: number; dropReasons: string[]; budgetExceeded?: string }> => withRootLock(input.outputRoot, async () => {
  const root = input.outputRoot;
  const g = await loadGraph(root);
  if (input.runId && input.runId !== g.runId) throw new Error("runId mismatch");
  if (input.expectedVersion != null && input.expectedVersion !== (g.version ?? 0)) throw Object.assign(new Error("graph version conflict"),{code:"version_conflict"});
  const round = input.round ?? 1, cost = input.costDelta ?? 0;
  if (!Number.isInteger(round) || round <= 0 || !Number.isFinite(cost) || cost < 0) throw new Error("invalid nonnegative budget consumption");
  const budget = await loadBudget(root);
  const nextBudget = {...budget,rounds:budget.rounds+round,cost:budget.cost+cost};
  const exceeded = budgetExceeded(nextBudget);
  if (exceeded) return {graph:g,accepted:0,dropped:0,dropReasons:[`budget exceeded: ${exceeded}`],budgetExceeded:exceeded};
  const ledger = await readLedger(root);
  const validReceipts = ledger.filter(e => e.id && e.runId === g.runId && e.complete === true && e.method && e.principal && e.status != null && Number.isInteger(e.status) && e.status >= 100 && e.status <= 599 && /^[a-f0-9]{64}$/.test(e.requestHash ?? "") && /^[a-f0-9]{64}$/.test(e.responseHash ?? ""));
  const citedUrls = (txt:string):string[] => [...String(txt).matchAll(/https?:\/\/[^\s"'\]]+/g)].map(m=>m[0]!.replace(/[.,;)]+$/, ""));
  const receiptsFor = (ids?:string[]):LedgerEntry[] => ids?.length ? validReceipts.filter(e=>ids.includes(e.id!)) : [];
  const referencesOk = (ids:string[]|undefined,txt:string):boolean => {
    const receipts=receiptsFor(ids);
    return !!ids?.length && receipts.length === new Set(ids).size && citedUrls(txt).every(u=>receipts.some(e=>e.url===u));
  };
  const urlOk = (txt:string):boolean => citedUrls(txt).every(u=>validReceipts.some(e=>e.url===u));

  let accepted = 0;
  let dropped = 0;
  const dropReasons: string[] = [];
  const drop = (why: string): void => {
    dropped++;
    if (dropReasons.length < 10) dropReasons.push(why);
  };

  // goals: create (host decomposition) then apply met marks
  for (const ng of input.goals ?? []) {
    const summary = String(ng.summary ?? "").trim().slice(0, 300);
    if (!summary || g.goals.some((x) => x.summary === summary)) continue;
    g.goals.push({ id: g.nextId++, summary, vulnclass: String(ng.vulnclass ?? ""), met: false });
    accepted++;
  }
  for (const m of input.goalsMet ?? []) {
    const goal = g.goals.find((x) => x.id === m.id);
    if (goal && !goal.met) {
      // Symmetric anti-hallucination gate: a met-reason citing URLs must
      // cite LEDGERED URLs, same as facts/findings (a bare "done, checked
      // manually" reason with fabricated URLs is dropped).
      const rtxt = m.reason ?? "";
      // citedUrls([]) passes every() vacuously — require at least one
      // ledger-verified citation, symmetric with the findings gate.
      if (citedUrls(rtxt).length === 0) { drop(`goal#${m.id} met-reason cites no URL — cannot verify against ledger`); continue; }
      if (!urlOk(rtxt)) { drop(`goal#${m.id} met-reason url not in ledger`); continue; }
      goal.met = true;
      goal.metReason = rtxt.slice(0, 300);
      accepted++; // count only real open→met transitions
    }
    // unknown id or already met: not accepted — no inflation
  }

  const states = new Set(["open","running","done","blocked","exhausted"]);
  const transition = (intent: Intent, state: string): void => {
    if (!states.has(state)) { drop("invalid intent state"); return; }
    if (intent.state === state) return;
    if (intent.state === "done") { drop("completed intent requires a new intent ID"); return; }
    intent.state=state as Intent["state"]; accepted++;
  };
  for (const ni of input.intents ?? []) {
    const summary = String(ni.summary ?? "").trim().slice(0,300);
    if (ni.id != null) {
      const intent=g.intents.find(i=>i.id===ni.id);
      if (!intent) { drop("unknown intent id"); continue; }
      if (ni.state) transition(intent,ni.state);
      if (summary && summary!==intent.summary) { intent.summary=summary; accepted++; }
      continue;
    }
    if (!summary || g.intents.some(i=>i.summary===summary)) continue;
    if (ni.state && !states.has(ni.state)) { drop("invalid intent state"); continue; }
    g.intents.push({id:g.nextId++,summary,state:(ni.state??"open") as Intent["state"],parentIds:[],yields:[]}); accepted++;
  }
  let currentIntent: Intent | null = null;
  if (input.intentId != null) {
    currentIntent=g.intents.find(i=>i.id===input.intentId)??null;
    if (!currentIntent) drop("unknown intent id");
    else {
      if (input.intentState) transition(currentIntent,input.intentState);
      if (input.intentSummary?.trim()) currentIntent.summary=input.intentSummary.trim().slice(0,300);
    }
  }

  // assets: no gate (they are pointers, not claims) — but key must be sane
  for (const a of input.assets ?? []) {
    if (!a.type || !a.key) { drop("asset missing type/key"); continue; }
    g.assets.push({ type: String(a.type), key: String(a.key), props: a.props });
    accepted++;
  }

  // facts: double gate (URL + digest)
  for (const f of input.facts ?? []) {
    if (!f.summary) { drop("fact missing summary"); continue; }
    const conf = f.confidence === "inferred" ? "inferred" : "observed";
    const txt = `${f.summary} ${f.evidence ?? ""} ${f.detail ?? ""}`;
    if (!urlOk(txt)) { drop(`fact#? url not in ledger: ${citedUrls(txt)[0] ?? "(none)"}`); continue; }
    if (conf === "observed" && !referencesOk(f.observationIds, txt)) {
      drop(`fact#? observed but no ledger citation`);
      continue;
    }
    const id = g.nextId++;
    g.facts.push({
      id,
      intentId: currentIntent?.id ?? null,
      summary: String(f.summary).slice(0, 300),
      detail: f.detail,
      evidence: f.evidence,
      confidence: conf,
      observationIds: f.observationIds,
    });
    currentIntent?.yields.push(id);
    accepted++;
  }

  // findings: urlOk gate only (severity ranked by host; poc must cite real URLs).
  // A finding citing ZERO URLs passes every() vacuously — that is a hole:
  // require at least one cited, ledger-verified URL per finding.
  for (const f of input.findings ?? []) {
    if (!f.name) { drop("finding missing name"); continue; }
    const txt = `${f.summary ?? ""} ${f.poc ?? ""}`;
    if (citedUrls(txt).length === 0) { drop(`finding '${String(f.name).slice(0, 40)}' cites no URL — cannot verify against ledger`); continue; }
    if (!urlOk(txt)) { drop(`finding '${String(f.name).slice(0, 40)}' url not in ledger`); continue; }
    // Findings are the STRONGEST claims — they get the same digest check as
    // facts: a cited URL requested with any random status must not vouch
    // for "RCE at /api/x" unless the claimed status matches the ledger.
    const proof=f.proof;
    if (!referencesOk(f.observationIds,txt) || !proof || !referencesOk(proof.observationIds,txt) || !proof.claim?.trim() || !proof.kind?.trim() || !proof.expectedPolicy?.trim() || !proof.objectOwner?.trim() || proof.observationIds.some(id=>!f.observationIds?.includes(id)) || !receiptsFor(proof.observationIds).some(e=>e.principal===proof.principal && e.requestHash===proof.requestHash && e.responseHash===proof.responseHash)) {
      drop(`finding '${f.name}' missing receipt-bound policy proof`); continue;
    }
    const store = new EvidenceStore(root);
    const evidence = await store.put(Buffer.from(JSON.stringify({proof,receipts:receiptsFor(proof.observationIds)},null,2)), "finding-proof");
    const id = g.nextId++;
    g.findings.push({
      id,
      intentId: currentIntent?.id ?? null,
      name: String(f.name).slice(0, 200),
      vulnclass: String(f.vulnclass ?? ""),
      severity: (["low", "medium", "high", "critical"].includes(String(f.severity)) ? f.severity : "low") as "low",
      summary: String(f.summary ?? "").slice(0, 1000),
      poc: String(f.poc ?? "").slice(0, 4000),
      observationIds:f.observationIds, proofKind:proof.kind, proof:{...proof}, outcome:"confirmed", validated:true, evidenceVersion:0, evidenceHashes:[evidence.hash],
    });
    currentIntent?.yields.push(id);
    accepted++;
  }

  g.huntBudget=nextBudget;
  await saveGraph(root,g);
  for (const finding of g.findings.filter(f=>f.evidenceVersion===0 && f.evidenceHashes?.length)) {
    await bindEvidence({root,findingId:String(finding.id),expectedVersion:0,refs:finding.evidenceHashes!.map(hash=>({hash,role:"proof" as const}))});
  }
  return {graph:await loadGraph(root),accepted,dropped,dropReasons};
});

export const huntOverview = async (
  root: string,
): Promise<{ overview: string; goalsMet: number; goalsTotal: number; ledgerEntries: number }> => {
  const g = await loadGraph(root);
  const ledger = await readLedger(root);
  return {
    overview: graphOverview(g),
    goalsMet: g.goals.filter((x) => x.met).length,
    goalsTotal: g.goals.length,
    ledgerEntries: ledger.length,
  };
};

/** Persist the observation ledger as a content-addressed evidence blob so
 *  every hunt's claims are traceable to verifiable request receipts. */
export const exportLedgerEvidence = async (root: string): Promise<{ hash: string; bytes: number } | null> => {
  const ledger = await readLedger(root);
  if (ledger.length === 0) return null;
  const blob=await putBlob(root,Buffer.from(JSON.stringify(ledger,null,2)));
  return {hash:blob.hash,bytes:blob.bytes};
};
