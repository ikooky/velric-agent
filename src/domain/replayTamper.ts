import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";

/** Recorded-flow tamper-replay: takes a traffic recording (exchanges.json +
 *  blobs/ from traffic_record), re-fires selected exchanges with parameter
 *  tampering (business-logic probes: price/negative/step-skip/quantity),
 *  and diffs responses against the recorded baseline.
 *
 *  This is the business-logic layer the static probes cannot reach: replay
 *  a recorded "create order" with price=0.01, qty=-1, or a skipped step,
 *  and see whether the server re-validates. Deterministic differential
 *  verdicts, session-aware (cookie passthrough), no LLM. */

export interface ReplayExchange {
  readonly id: string;
  readonly method: string;
  readonly url: string;
  readonly reqHeaders: Record<string, string>;
  readonly reqBody: string | null;
  readonly baselineStatus: number | null;
  readonly baselineBodyHash: string | null;
}

export interface TamperRule {
  /** JSON body field name to tamper (query param when in: "query"). */
  readonly field: string;
  readonly in: "body" | "query";
  /** literal replacement value */
  readonly value: string | number | boolean | null;
  /** human label for the report */
  readonly label: string;
}

export interface ReplayInput {
  /** traffic outputRoot (contains exchanges.json + blobs/) */
  readonly recordRoot: string;
  readonly outputRoot: string;
  /** exchange id filter; default: all mutating (POST/PUT/PATCH) exchanges */
  readonly exchangeIds?: readonly string[];
  /** tamper rules applied to every selected exchange that has the field */
  readonly rules: readonly TamperRule[];
  readonly cookie?: string;
  readonly extraHeaders?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxExchanges?: number;
  /** Fire the TAMPERED replays (the live baseline replay always runs).
   *  Default OFF: a tampered POST/PUT against a live target can repeat a
   *  state change (double order, price edit) — opt in per run. */
  readonly applyTamper?: boolean;
}

export interface ReplayOutcome {
  readonly exchangeId: string;
  readonly method: string;
  readonly url: string;
  readonly rule: string;
  readonly field: string;
  readonly value: string;
  readonly baselineStatus: number | null;
  readonly replayStatus: number;
  readonly verdict: "accepted-tamper" | "rejected" | "same-response" | "error" | "skip" | "dry-run";
  /** response body hash moved AND status stayed 2xx — server acted on tampered input */
  readonly contentChanged: boolean;
}

export interface ReplayResult {
  readonly replayed: number;
  readonly outcomes: ReplayOutcome[];
  /** accepted tampers = server accepted business-illogical input */
  readonly accepted: ReplayOutcome[];
  readonly artifacts: { path: string; bytes: number }[];
}

interface RecordedExchange {
  readonly id: string;
  readonly method: string;
  readonly url: string;
  readonly reqHeaders: Record<string, string>;
  readonly reqBodyHash: string | null;
  readonly status: number | null;
  readonly respBodyHash: string | null;
}

const loadBlob = async (recordRoot: string, hash: string | null): Promise<string | null> => {
  if (!hash) return null;
  try {
    return await readFile(join(recordRoot, "blobs", hash.slice(0, 2), `${hash}.bin`), "utf8");
  } catch { return null; }
};

const tamperBody = (body: string, field: string, value: string | number | boolean | null): string | null => {
  // JSON body: replace the field's value wherever it appears (top level or nested).
  try {
    const j = JSON.parse(body) as unknown;
    const walk = (node: unknown): unknown => {
      if (Array.isArray(node)) return node.map(walk);
      if (node && typeof node === "object") {
        const out: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
          out[k] = k === field ? value : walk(v);
        }
        return out;
      }
      return node;
    };
    return JSON.stringify(walk(j));
  } catch { return null; }
};

const tamperQuery = (url: string, field: string, value: string | number | boolean | null): string => {
  const u = new URL(url);
  u.searchParams.set(field, String(value));
  return u.toString();
};

const DEFAULT_RULES: readonly TamperRule[] = [
  { field: "price", in: "body", value: 0.01, label: "price=0.01" },
  { field: "amount", in: "body", value: 0.01, label: "amount=0.01" },
  { field: "total", in: "body", value: 0.01, label: "total=0.01" },
  { field: "quantity", in: "body", value: -1, label: "quantity=-1" },
  { field: "qty", in: "body", value: -1, label: "qty=-1" },
  { field: "count", in: "body", value: -1, label: "count=-1" },
  { field: "discount", in: "body", value: 100, label: "discount=100" },
  { field: "step", in: "body", value: 999, label: "step-skip" },
  { field: "status", in: "body", value: "paid", label: "status=paid" },
  { field: "role", in: "body", value: "admin", label: "role=admin" },
  { field: "is_admin", in: "body", value: true, label: "is_admin=true" },
];

export const replayTamper = async (input: ReplayInput): Promise<ReplayResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  // traffic.ndjson: one RecordedExchange per line (trafficRecorder format).
  const lines = (await readFile(join(input.recordRoot, "traffic.ndjson"), "utf8")).split("\n").filter(Boolean);
  const all: RecordedExchange[] = [];
  for (const l of lines) {
    try { all.push(JSON.parse(l) as RecordedExchange); } catch { /* skip torn line */ }
  }
  const exchanges = all
    .filter((e) => (input.exchangeIds ? input.exchangeIds.includes(e.id) : ["POST", "PUT", "PATCH"].includes(e.method.toUpperCase())))
    .slice(0, input.maxExchanges ?? 20);

  const rules = input.rules.length > 0 ? input.rules : DEFAULT_RULES;
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10000 };
  const outcomes: ReplayOutcome[] = [];

  for (const e of exchanges) {
    const body = await loadBlob(input.recordRoot, e.reqBodyHash);
    const headers: Record<string, string> = { ...e.reqHeaders, ...input.extraHeaders };
    if (input.cookie) headers.cookie = input.cookie;
    // strip hop-by-hop / length headers that no longer match
    delete headers["content-length"];
    delete headers["host"];
    delete headers["connection"];

    // LIVE baseline: re-fire the untampered exchange first. The recorded
    // respBodyHash may be stale (server state moved) — comparing tampered
    // responses against a stale baseline produces false "accepted" verdicts
    // for every rule. The live baseline is the only sound reference.
    const live = await fetchUrl(e.url, { ...opts, method: e.method, headers, body: body ?? undefined });
    const liveFp = `${live.status}:${live.sha256?.slice(0, 16) ?? ""}`;
    if (live.status === 0) continue; // endpoint unreachable now — skip exchange

    for (const rule of rules) {
      let target = e.url;
      let reqBody: string | undefined;
      let applied = false;
      if (rule.in === "body") {
        if (!body) continue;
        const t = tamperBody(body, rule.field, rule.value);
        if (t === null) continue; // field not present or non-JSON
        reqBody = t;
        applied = true;
      } else {
        const u = new URL(e.url);
        if (!u.searchParams.has(rule.field)) continue;
        target = tamperQuery(e.url, rule.field, rule.value);
        applied = true;
      }
      if (!applied) continue;

      if (input.applyTamper !== true) {
        // Dry-run (default): the differential was computed, but firing the
        // tampered mutation against the live target needs an explicit opt-in.
        outcomes.push({
          exchangeId: e.id, method: e.method, url: e.url, rule: rule.label, field: rule.field,
          value: String(rule.value), baselineStatus: live.status, replayStatus: -1,
          verdict: "dry-run", contentChanged: false,
        });
        continue;
      }
      const r = await fetchUrl(target, { ...opts, method: e.method, headers, body: reqBody });
      const rFp = `${r.status}:${r.sha256?.slice(0, 16) ?? ""}`;
      const contentChanged = rFp !== liveFp;
      let verdict: ReplayOutcome["verdict"];
      if (r.status === 0) verdict = "error";
      else if (r.status >= 200 && r.status < 300 && contentChanged) verdict = "accepted-tamper";
      else if (r.status >= 400 && r.status < 500) verdict = "rejected";
      else verdict = "same-response";
      outcomes.push({
        exchangeId: e.id, method: e.method, url: e.url, rule: rule.label, field: rule.field,
        value: String(rule.value), baselineStatus: live.status, replayStatus: r.status,
        verdict, contentChanged,
      });
    }
  }

  const accepted = outcomes.filter((o) => o.verdict === "accepted-tamper");
  const bodyStr = JSON.stringify({ replayed: exchanges.length, outcomes, accepted }, null, 2);
  const path = join(input.outputRoot, "replay_tamper.json");
  await writeFile(path, bodyStr, "utf8");
  return { replayed: exchanges.length, outcomes, accepted, artifacts: [{ path, bytes: Buffer.byteLength(bodyStr) }] };
};
