/** File-backed exploration graph. */
import { readJson, writeJson, withRootLock } from "../core/storage.js";

export interface Goal {
  readonly id: number;
  summary: string;
  vulnclass: string;
  met: boolean;
  metReason?: string;
}

export interface Constraint {
  readonly type: "allow" | "deny";
  readonly rule: string;
}

export interface Fact {
  readonly id: number;
  readonly intentId: number | null;
  summary: string;
  detail?: string;
  evidence?: string;
  confidence: "observed" | "inferred";
  observationIds?: string[];
}

export interface Finding {
  readonly id: number;
  readonly intentId: number | null;
  name: string;
  vulnclass: string;
  severity: "low" | "medium" | "high" | "critical";
  summary: string;
  poc: string;
  /** Disposition lifecycle: pending → fixed (via retest), regression flips back. */
  disposition?: "pending" | "fixed";
  /** Evidence blob hashes bound to this finding (save_evidence outputs). */
  evidenceHashes?: string[];
  /** Bump on evidence changes — reports must read the current version. */
  evidenceVersion?: number;
  observationIds?: string[];
  proofKind?: string;
  outcome?: string;
  validated?: boolean;
  proof?: Record<string, unknown>;
}

export interface Intent {
  readonly id: number;
  summary: string;
  state: "open" | "running" | "done" | "exhausted" | "blocked";
  parentIds: number[];
  yields: number[]; // fact/finding ids
  error?: string;
}

export interface AssetRec {
  readonly type: string;
  readonly key: string;
  readonly props?: Record<string, unknown>;
}

export interface Graph {
  version?: number;
  runId?: string;
  huntBudget?: { runId?: string; startedAt: string; rounds: number; cost: number; caps?: {maxRounds?:number;maxCost?:number;maxDurationMin?:number} };
  goal: string;
  constraints: Constraint[];
  goals: Goal[];
  intents: Intent[];
  facts: Fact[];
  findings: Finding[];
  assets: AssetRec[];
  nextId: number;
}

const emptyGraph = (goal: string): Graph => ({
  goal,
  constraints: [],
  goals: [],
  intents: [],
  facts: [],
  findings: [],
  assets: [],
  nextId: 1,
});

const natural=(value:unknown):boolean=>Number.isSafeInteger(value) && Number(value)>=0;
const strings=(value:unknown):boolean=>Array.isArray(value) && value.every(x=>typeof x==="string");
const validGraph=(value:unknown):boolean=>{
  const g=value as Graph;
  if(!g || typeof g.goal!=="string" || !natural(g.nextId) || g.nextId<1 ||
    ![g.goals,g.intents,g.facts,g.findings,g.assets,g.constraints].every(Array.isArray) ||
    g.version!==undefined && !natural(g.version) || g.runId!==undefined && (typeof g.runId!=="string" || !g.runId.trim()))return false;
  const records=[...g.goals,...g.intents,...g.facts,...g.findings];
  if(!records.every(x=>x && natural(x.id) && x.id>0) || new Set(records.map(x=>x.id)).size!==records.length)return false;
  if(!g.goals.every(x=>typeof x.summary==="string" && typeof x.vulnclass==="string" && typeof x.met==="boolean") ||
    !g.intents.every(x=>typeof x.summary==="string" && ["open","running","done","blocked","exhausted"].includes(x.state) &&
      Array.isArray(x.parentIds) && x.parentIds.every(n=>natural(n) && n>0) && Array.isArray(x.yields) && x.yields.every(n=>natural(n) && n>0)) ||
    !g.facts.every(x=>typeof x.summary==="string" && ["observed","inferred"].includes(x.confidence) && (x.intentId===null || natural(x.intentId)) && (x.observationIds===undefined || strings(x.observationIds))) ||
    !g.findings.every(x=>typeof x.name==="string" && typeof x.summary==="string" && typeof x.poc==="string" && ["low","medium","high","critical"].includes(x.severity) &&
      (x.evidenceVersion===undefined || natural(x.evidenceVersion)) && (x.evidenceHashes===undefined || Array.isArray(x.evidenceHashes) && x.evidenceHashes.every(h=>/^[a-f0-9]{64}$/.test(h)))) ||
    !g.constraints.every(x=>x && ["allow","deny"].includes(x.type) && typeof x.rule==="string") ||
    !g.assets.every(x=>x && typeof x.type==="string" && typeof x.key==="string"))return false;
  const b=g.huntBudget;
  if(b && (!natural(b.rounds) || !Number.isFinite(b.cost) || b.cost<0 || !Number.isFinite(Date.parse(b.startedAt)) || b.runId!==undefined && b.runId!==g.runId ||
    b.caps && Object.entries(b.caps).some(([key,v])=>!["maxRounds","maxCost","maxDurationMin"].includes(key) || v!==undefined && (!Number.isFinite(v) || v<0 || key==="maxRounds" && !natural(v)))))return false;
  return true;
};
export const loadGraph = (root:string):Promise<Graph> => readJson(root,"graph.json",()=>emptyGraph(""),validGraph);

/** Detached snapshots must not overwrite a newer successful mutation. */
export const saveGraph = async (root: string, g: Graph): Promise<void> => withRootLock(root, async () => {
  const disk = await loadGraph(root);
  if ((disk.version ?? 0) !== (g.version ?? 0)) throw Object.assign(new Error("graph version conflict"), {code:"version_conflict"});
  const next={...g,nextId:Math.max(g.nextId,...[...g.goals,...g.intents,...g.facts,...g.findings].map(x=>x.id+1),1),version:(disk.version??0)+1};
  if(!validGraph(next))throw Object.assign(new Error("invalid graph state"),{code:"corrupt_state"});
  await writeJson(root,"graph.json",next);g.nextId=next.nextId;g.version=next.version;
});

/** The situational overview handed to the planner each round (graph_overview). */
export const graphOverview = (g: Graph): string => {
  const open = g.intents.filter((i) => i.state === "open");
  const running = g.intents.filter((i) => i.state === "running");
  const terminal = g.intents.filter((i) => i.state === "done" || i.state === "exhausted" || i.state === "blocked");
  const recentDone = terminal.slice(-8);
  const olderDoneCount = Math.max(0, terminal.length - recentDone.length);
  const facts = g.facts.slice(-15);
  const findings = g.findings;
  const lines = [
    `task goal: ${g.goal}`,
    `constraints: ${g.constraints.map((c) => `${c.type}:${c.rule}`).join(" | ") || "(none)"}`,
    `goals: ${g.goals.map((x) => `#${x.id}[${x.met ? "met" : "open"}] ${x.summary}`).join("\n  ") || "(none decomposed)"}`,
    `assets(${g.assets.length}): ${[...new Set(g.assets.map((a) => a.type))].map((t) => `${t}=${g.assets.filter((a) => a.type === t).length}`).join(", ")}`,
    `open_intents: ${open.length ? open.map((i) => `#${i.id} ${i.summary}`).join(" ; ") : "(none)"}`,
    `running_intents: ${running.length ? running.map((i) => `#${i.id} ${i.summary}`).join(" ; ") : "(none)"}`,
    `recent_done_intents:${olderDoneCount > 0 ? ` (+${olderDoneCount} older done, omitted)` : ""}`,
    ...recentDone.map((i) => `  #${i.id}[${i.state}] ${i.summary.slice(0, 120)}${i.error ? ` (err: ${i.error.slice(0, 80)})` : ""}`),
    `recent_facts:`,
    ...facts.map((f) => `  fact#${f.id}[${f.confidence}]${f.intentId ? `(from intent#${f.intentId})` : ""} ${f.summary}${f.evidence ? ` | ev: ${f.evidence.slice(0, 100)}` : ""}`),
    `findings(${findings.length}):`,
    ...findings.map((f) => `  finding#${f.id}[${f.severity}] ${f.name}`),
  ];
  return lines.join("\n");
};
