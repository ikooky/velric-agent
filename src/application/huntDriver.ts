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
import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import {
  loadGraph, saveGraph, graphOverview,
  type Graph, type Intent,
} from "./graph.js";

export interface HuntBeginInput {
  readonly goal: string;
  readonly outputRoot: string;
}

export interface HuntRecordInput {
  readonly outputRoot: string;
  readonly intentId?: number;
  readonly intentSummary?: string;
  readonly goals?: { summary: string; vulnclass?: string }[];
  readonly intents?: { summary: string; state?: string }[];
  readonly facts?: { summary?: string; detail?: string; evidence?: string; confidence?: string }[];
  readonly findings?: { name?: string; vulnclass?: string; severity?: string; summary?: string; poc?: string }[];
  readonly assets?: { type?: string; key?: string; props?: Record<string, unknown> }[];
  readonly goalsMet?: { id: number; reason?: string }[];
}

/** Ledger entry — system-written record of what a tool ACTUALLY observed. */
export interface LedgerEntry {
  readonly tool: string;
  readonly url: string;
  readonly status: number | null;
  readonly at: string;
}

const LEDGER_FILE = "observation_ledger.json";

export const ledgerPath = (root: string): string => join(root, LEDGER_FILE);

// Per-root append queue: read-modify-write must not interleave across
// concurrent MCP tool calls sharing one ledger root.
const ledgerQueues = new Map<string, Promise<unknown>>();
const serialized = <T>(root: string, fn: () => Promise<T>): Promise<T> => {
  const prev = ledgerQueues.get(root) ?? Promise.resolve();
  const next = prev.then(fn, fn);
  ledgerQueues.set(root, next.catch(() => {}));
  return next;
};

/** Append what a tool truly requested/observed. Called by the MCP server for
 * every tool execution (never by the host). */
export const appendLedger = (root: string, entries: LedgerEntry[]): Promise<void> =>
  serialized(root, async () => {
    await mkdir(root, { recursive: true });
    const prev = await readLedger(root);
    // Upsert by URL: a statusless older entry upgrades when a later observation
    // carries a status; a URL never duplicates in the ledger.
    const byUrl = new Map<string, LedgerEntry>();
    for (const e of [...prev, ...entries]) {
      const prior = byUrl.get(e.url);
      if (!prior) byUrl.set(e.url, e);
      else if (prior.status == null && e.status != null) byUrl.set(e.url, { ...prior, status: e.status });
    }
    const next = [...byUrl.values()];
    const { writeFile, rename } = await import("node:fs/promises");
    // Atomic publish: concurrent appenders never expose a torn ledger.
    const tmp = ledgerPath(root) + ".tmp";
    await writeFile(tmp, JSON.stringify(next, null, 2));
    await rename(tmp, ledgerPath(root));
  });

export const readLedger = async (root: string): Promise<LedgerEntry[]> => {
  try {
    return JSON.parse(await readFile(ledgerPath(root), "utf8")) as LedgerEntry[];
  } catch {
    return [];
  }
};

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

export const huntBegin = async (input: HuntBeginInput): Promise<{ outputRoot: string; goal: string; driverPlaybook: string; next: string }> => {
  const root = input.outputRoot;
  await mkdir(root, { recursive: true });
  let g = await loadGraph(root);
  if (g.goal === "" || g.goal !== input.goal) {
    g = { goal: input.goal, constraints: [], goals: [], intents: [], facts: [], findings: [], assets: [], nextId: 1 };
  }
  // goals stay host-managed: the host decomposes via hunt_record(intents...)
  await saveGraph(root, g);
  return {
    outputRoot: root,
    goal: input.goal,
    driverPlaybook: DRIVER_PLAYBOOK,
    next: "调 hunt_overview 读态势;用 hunt_record 派 goals/intents;侦察工具带 observationLedgerRoot",
  };
};

const norm = (u: string): string => {
  try {
    const x = new URL(u);
    return `${x.origin}${x.pathname}`;
  } catch {
    return u.replace(/[?#].*$/, "");
  }
};

export const huntRecord = async (input: HuntRecordInput): Promise<{ graph: Graph; accepted: number; dropped: number; dropReasons: string[] }> => {
  const root = input.outputRoot;
  const g = await loadGraph(root);
  const ledger = await readLedger(root);
  const requested = new Set(ledger.map((e) => norm(e.url)));
  const statusByUrl = new Map<string, Set<number>>();
  for (const e of ledger) {
    const k = norm(e.url);
    if (!statusByUrl.has(k)) statusByUrl.set(k, new Set());
    if (e.status !== null) statusByUrl.get(k)!.add(e.status);
  }

  const citedUrls = (txt: string): string[] =>
    [...String(txt).matchAll(/https?:\/\/[^\s"'\]]+/g)].map((m) => m[0]!.replace(/[.,;)]+$/, ""));
  const urlOk = (txt: string): boolean =>
    citedUrls(txt).every((u) => requested.has(norm(u)));

  const digestOk = (evidence: string, summary: string): boolean => {
    const txt = `${evidence} ${summary}`;
    // EVERY cited URL must satisfy its own status check — a stray earlier
    // ledger entry must not vouch for a citation it doesn't cover.
    const cited = citedUrls(txt);
    if (cited.length === 0) return false;
    for (const cu of cited) {
      const statuses = statusByUrl.get(norm(cu)) ?? statusByUrl.get(cu);
      if (!statuses) {
        // not ledgered verbatim — allow same-origin relative-path match.
        // The ledger's site-root entry ("/") matches EVERYTHING, so it is
        // excluded from the fallback: only non-root paths may vouch.
        let matched = false;
        for (const [k, st] of statusByUrl) {
          try {
            const u = new URL(k);
            if (u.pathname === "/" || u.pathname === "") continue; // root vouches for nothing
            const stArr = [...st];
            if (cu.includes(u.pathname) || (new URL(cu, "http://l.invalid").pathname === u.pathname)) { matched = stArr.length === 0 || stArr.some((sv) => txt.includes(String(sv))); break; }
          } catch { /* malformed */ }
        }
        if (!matched) return false;
        continue;
      }
      const known = [...statuses].filter((sv): sv is number => typeof sv === "number");
      if (known.length > 0 && !known.some((sv) => txt.includes(String(sv)))) return false;
    }
    return true;
  };

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
      goal.met = true;
      goal.metReason = m.reason?.slice(0, 300);
      accepted++; // count only real open→met transitions
    }
    // unknown id or already met: not accepted — no inflation
  }

  // intents (create; optionally set state)
  for (const ni of input.intents ?? []) {
    const summary = String(ni.summary ?? "").trim().slice(0, 300);
    if (!summary) continue;
    if (g.intents.some((i) => i.summary === summary)) continue;
    g.intents.push({
      id: g.nextId++,
      summary,
      state: ni.state === "running" || ni.state === "done" || ni.state === "blocked" || ni.state === "exhausted" ? ni.state : "open",
      parentIds: [],
      yields: [],
    });
    accepted++;
  }

  // optional: mark one intent's state alongside the record
  if (typeof input.intentId === "number" && typeof input.intentSummary === "string") {
    const intent = g.intents.find((i) => i.id === input.intentId);
    if (intent) intent.summary = input.intentSummary.slice(0, 300);
  }

  let currentIntent: Intent | null = null;
  if (typeof input.intentId === "number") {
    currentIntent = g.intents.find((i) => i.id === input.intentId) ?? null;
    if (!currentIntent && input.intentSummary) {
      currentIntent = { id: g.nextId++, summary: input.intentSummary.slice(0, 300), state: "running", parentIds: [], yields: [] };
      g.intents.push(currentIntent);
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
    if (conf === "observed" && !digestOk(f.evidence ?? "", f.summary)) {
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
    const id = g.nextId++;
    g.findings.push({
      id,
      intentId: currentIntent?.id ?? null,
      name: String(f.name).slice(0, 200),
      vulnclass: String(f.vulnclass ?? ""),
      severity: (["low", "medium", "high", "critical"].includes(String(f.severity)) ? f.severity : "low") as "low",
      summary: String(f.summary ?? "").slice(0, 1000),
      poc: String(f.poc ?? "").slice(0, 4000),
    });
    currentIntent?.yields.push(id);
    accepted++;
  }

  await saveGraph(root, g);
  return { graph: g, accepted, dropped, dropReasons };
};

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
  const { createHash } = await import("node:crypto");
  const { mkdir, writeFile } = await import("node:fs/promises");
  const { join } = await import("node:path");
  const body = JSON.stringify(ledger, null, 2);
  const hash = createHash("sha256").update(body).digest("hex");
  const dir = join(root, "blobs", hash.slice(0, 2));
  await mkdir(dir, { recursive: true });
  const path = join(dir, `${hash}.json`);
  await writeFile(path, body);
  return { hash, bytes: Buffer.byteLength(body) };
};
