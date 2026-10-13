/** File-backed exploration graph — stateless port of velric's exploration store. */
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

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
}

export interface Finding {
  readonly id: number;
  readonly intentId: number | null;
  name: string;
  vulnclass: string;
  severity: "low" | "medium" | "high" | "critical";
  summary: string;
  poc: string;
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
  goal: string;
  constraints: Constraint[];
  goals: Goal[];
  intents: Intent[];
  facts: Fact[];
  findings: Finding[];
  assets: AssetRec[];
  nextId: number;
}

export const emptyGraph = (goal: string): Graph => ({
  goal,
  constraints: [],
  goals: [],
  intents: [],
  facts: [],
  findings: [],
  assets: [],
  nextId: 1,
});

const PATH = (root: string) => join(root, "graph.json");

export const loadGraph = async (root: string): Promise<Graph> => {
  try {
    return JSON.parse(await readFile(PATH(root), "utf8")) as Graph;
  } catch {
    return emptyGraph("");
  }
};

export const saveGraph = async (root: string, g: Graph): Promise<void> => {
  g.nextId = Math.max(
    g.nextId,
    ...g.goals.map((x) => x.id + 1),
    ...g.intents.map((x) => x.id + 1),
    ...g.facts.map((x) => x.id + 1),
    ...g.findings.map((x) => x.id + 1),
    1,
  );
  await writeFile(PATH(root), JSON.stringify(g, null, 2), "utf8");
};

/** The situational overview handed to the planner each round (graph_overview). */
export const graphOverview = (g: Graph): string => {
  const open = g.intents.filter((i) => i.state === "open");
  const running = g.intents.filter((i) => i.state === "running");
  const recentDone = g.intents
    .filter((i) => i.state === "done" || i.state === "exhausted" || i.state === "blocked")
    .slice(-10);
  const facts = g.facts.slice(-15);
  const findings = g.findings;
  const lines = [
    `task goal: ${g.goal}`,
    `constraints: ${g.constraints.map((c) => `${c.type}:${c.rule}`).join(" | ") || "(none)"}`,
    `goals: ${g.goals.map((x) => `#${x.id}[${x.met ? "met" : "open"}] ${x.summary}`).join("\n  ") || "(none decomposed)"}`,
    `assets(${g.assets.length}): ${[...new Set(g.assets.map((a) => a.type))].map((t) => `${t}=${g.assets.filter((a) => a.type === t).length}`).join(", ")}`,
    `open_intents: ${open.length ? open.map((i) => `#${i.id} ${i.summary}`).join(" ; ") : "(none)"}`,
    `running_intents: ${running.length ? running.map((i) => `#${i.id} ${i.summary}`).join(" ; ") : "(none)"}`,
    `recent_done_intents:`,
    ...recentDone.map((i) => `  #${i.id}[${i.state}] ${i.summary}${i.error ? ` (err: ${i.error.slice(0, 80)})` : ""}`),
    `recent_facts:`,
    ...facts.map((f) => `  fact#${f.id}[${f.confidence}]${f.intentId ? `(from intent#${f.intentId})` : ""} ${f.summary}${f.evidence ? ` | ev: ${f.evidence.slice(0, 100)}` : ""}`),
    `findings(${findings.length}):`,
    ...findings.map((f) => `  finding#${f.id}[${f.severity}] ${f.name}`),
  ];
  return lines.join("\n");
};
