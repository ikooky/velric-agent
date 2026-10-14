import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { fetchUrl } from "../adapters/http.js";

/** Finding retest (velric agent/retester.go, deterministic port): re-run a
 *  recorded PoC against the target and classify the outcome as
 *  reproduced / fixed / inconclusive. Retest history is append-only; a
 *  `fixed` verdict flips the finding's disposition, later retests can flip
 *  it back (regression). No LLM — verdicts come from status/body predicates
 *  the operator records alongside the PoC. */

export interface RetestPredicate {
  /** Response statuses that indicate the vulnerability is GONE. */
  readonly fixedStatuses?: number[];
  /** Substrings whose presence indicates the vulnerability is GONE. */
  readonly fixedBodyAny?: string[];
  /** Substrings whose presence indicates the vulnerability is PRESENT. */
  readonly vulnerableBodyAny?: string[];
}

export interface RetestRecord {
  readonly id: string;
  readonly findingId: string;
  readonly ts: string;
  readonly verdict: "reproduced" | "fixed" | "inconclusive";
  readonly request: { method: string; url: string; headers?: Record<string, string>; body?: string };
  readonly observed: { status: number | null; bodySnippet: string; err?: string };
  readonly note?: string;
}

export interface FindingRecord {
  readonly id: string;
  readonly name: string;
  readonly severity: "low" | "medium" | "high" | "critical";
  /** pending | fixed — flips on retest verdicts. */
  disposition: "pending" | "fixed";
  readonly createdAt: string;
  poc: { method: string; url: string; headers?: Record<string, string>; body?: string };
  predicates: RetestPredicate;
  retests: RetestRecord[];
}

export interface RetestStore {
  findings: Record<string, FindingRecord>;
}

const STORE = "retest_store.json";

const loadStore = async (root: string): Promise<RetestStore> => {
  try { return JSON.parse(await readFile(join(root, STORE), "utf8")) as RetestStore; }
  catch { return { findings: {} }; }
};

const saveStore = async (root: string, st: RetestStore): Promise<void> => {
  await mkdir(root, { recursive: true });
  const tmp = join(root, STORE + ".tmp");
  await writeFile(tmp, JSON.stringify(st, null, 2));
  await import("node:fs/promises").then((fs) => fs.rename(tmp, join(root, STORE)));
};

/** Register a finding for retesting (idempotent upsert of PoC/predicates). */
export const registerFinding = async (input: {
  root: string;
  id: string;
  name: string;
  severity: FindingRecord["severity"];
  poc: FindingRecord["poc"];
  predicates?: RetestPredicate;
}): Promise<{ ok: true; created: boolean }> => {
  const st = await loadStore(input.root);
  const existed = Boolean(st.findings[input.id]);
  const prev = st.findings[input.id];
  st.findings[input.id] = {
    id: input.id,
    name: input.name,
    severity: input.severity,
    disposition: prev?.disposition ?? "pending",
    createdAt: prev?.createdAt ?? new Date().toISOString(),
    poc: input.poc,
    predicates: input.predicates ?? {},
    retests: prev?.retests ?? [],
  };
  await saveStore(input.root, st);
  return { ok: true, created: !existed };
};

const classify = (pred: RetestPredicate, status: number | null, body: string, err?: string): RetestRecord["verdict"] => {
  if (status == null) return "inconclusive"; // unreachable / network error
  if (pred.fixedStatuses?.includes(status)) return "fixed";
  if (pred.fixedBodyAny?.some((s) => body.includes(s))) return "fixed";
  if (pred.vulnerableBodyAny?.some((s) => body.includes(s))) return "reproduced";
  // No predicate matched: with zero predicates we cannot distinguish a real
  // PoC landing from a login redirect / catch-all 2xx — the conservative
  // verdict is inconclusive, NOT reproduced (a false "vulnerable" is worse
  // than a shrug for consumers tracking fixed findings).
  return "inconclusive";
};

/** Run one retest: replays the PoC, appends the record, flips disposition. */
export const runRetest = async (input: {
  root: string;
  findingId: string;
  proxy?: string;
  timeoutMs?: number;
  note?: string;
}): Promise<RetestRecord & { disposition: FindingRecord["disposition"] }> => {
  const st = await loadStore(input.root);
  const f = st.findings[input.findingId];
  if (!f) throw new Error(`finding ${input.findingId} not registered`);
  let status: number | null = null;
  let body = "";
  let err: string | undefined;
  try {
    const r = await fetchUrl(f.poc.url, {
      method: f.poc.method,
      headers: f.poc.headers,
      body: f.poc.body,
      proxy: input.proxy,
      timeoutMs: input.timeoutMs ?? 15000,
    });
    status = r.status;
    body = r.body.slice(0, 2000);
  } catch (e) {
    err = String((e as Error).message ?? e).slice(0, 200);
  }
  const verdict = classify(f.predicates, status, body, err);
  const rec: RetestRecord = {
    id: `rt${f.retests.length + 1}`,
    findingId: f.id,
    ts: new Date().toISOString(),
    verdict,
    request: f.poc,
    observed: { status, bodySnippet: body.slice(0, 400), err },
    note: input.note,
  };
  f.retests.push(rec);
  // Disposition follows the LATEST verdict (fixed → regression → pending).
  f.disposition = verdict === "fixed" ? "fixed" : "pending";
  await saveStore(input.root, st);
  return { ...rec, disposition: f.disposition };
};

export const listRetests = async (root: string): Promise<{ findings: { id: string; name: string; severity: string; disposition: string; retests: number; lastVerdict: string | null }[] }> => {
  const st = await loadStore(root);
  return {
    findings: Object.values(st.findings).map((f) => ({
      id: f.id,
      name: f.name,
      severity: f.severity,
      disposition: f.disposition,
      retests: f.retests.length,
      lastVerdict: f.retests.at(-1)?.verdict ?? null,
    })),
  };
};
