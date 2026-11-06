import { fetchUrl } from "../adapters/http.js";
import { normalizeBody, charSimilarity } from "./normalize.js";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

/** IDOR deep probe: beyond the numeric +1 prescreen — path-segment IDs,
 *  UUID/numeric swaps, POST body ID params, and response-content
 *  differentials (not just status). */

export interface IdorDeepInput {
  /** endpoints merged.json-style: [{method, path, fields:[{name,in}]}] */
  readonly endpoints: { method: string; path: string; fields: { name: string; in: string }[] }[];
  readonly outputRoot: string;
  readonly baseUrl?: string;
  readonly cookie?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxTargets?: number;
  readonly applyBodyIdor?: boolean;
  /** Extra attacker-visible object IDs to try (from other roles' responses). */
  readonly objectIds?: readonly string[];
}

export interface IdorDeepCandidate {
  readonly url: string;
  readonly method: string;
  readonly param: string;
  readonly location: "path" | "query" | "body";
  readonly original: string;
  readonly variant: string;
  readonly originalStatus: number;
  readonly variantStatus: number;
  /** content differential (sha256 prefix) — same status but different body = data leak */
  readonly contentDiff: boolean;
  readonly verdict: "idor-suspect" | "idor-confirmed" | "idor-confirmed-identity" | "public-or-unprotected" | "same-response" | "not-found" | "denied" | "skip";
  /** Three-reference oracle detail (owner/attacker/denied): similarity to
   *  baseline and to the anonymous reference. */
  readonly oracle?: { simOwner: number; simDenied: number };
  /** Identity-field evidence: distinct owner-marker values across variant
   *  responses proves cross-principal data (email/username/phone). */
  readonly identityEvidence?: string;
}

export interface IdorDeepResult {
  readonly probed: number;
  readonly candidates: IdorDeepCandidate[];
  readonly artifacts: { path: string; bytes: number }[];
}

const ID_RE = /(?:^|[-_])(?:id|uid|user_?id|oid|cid|order_?id|rid|pid|fid|aid|tid|sid|no|num|number|uuid|guid)$/i;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const variantsOf = (value: string, objectIds: readonly string[]): string[] => {
  const out: string[] = [];
  if (/^\d+$/.test(value)) {
    const n = Number(value);
    out.push(String(n + 1), String(Math.max(n - 1, 0)), "1");
  } else if (UUID_RE.test(value)) {
    out.push(value.slice(0, -1) + (value.slice(-1) === "a" ? "b" : "a"), "1");
  } else {
    out.push("1");
  }
  for (const oid of objectIds) if (oid && oid !== value) out.push(oid);
  return [...new Set(out)].slice(0, 6);
};

/** Encoded-ID variants (Auto-IDor ENCODINGS registry): when a slot value looks
 *  like base64/hex WRAPPING a meaningful id (eyJpZCI6MTB9 = {"id":10}), blind
 *  substitution of the encoded string can never hit a valid object — decode,
 *  swap the inner id, re-encode in the same shape. */

/** Identity-field extraction (pentest-ai sequential-identity confirmation):
 *  pull owner-identifying values from a JSON/HTML response. */
const IDENTITY_KEYS = /(?:email|username|user_name|userName|phone|mobile|nickname|nick_name|full_?name)/i;
const extractIdentities = (body: string): Record<string, string> => {
  const out: Record<string, string> = {};
  try {
    const walk = (o: unknown): void => {
      if (o && typeof o === "object") {
        if (Array.isArray(o)) { for (const x of o) walk(x); return; }
        for (const [k, v] of Object.entries(o as Record<string, unknown>)) {
          if (IDENTITY_KEYS.test(k) && typeof v === "string" && v.length > 0) out[k] = v;
          walk(v);
        }
      }
    };
    walk(JSON.parse(body));
  } catch {
    // HTML fallback: input values / meta content
    for (const m of body.matchAll(/<input[^>]*name="(email|username|phone|nickname)"[^>]*value="([^"]*)"/gi)) {
      out[m[1]!.toLowerCase()] = m[2]!;
    }
  }
  return out;
};

const sub = (s: string, from: string, to: string): string => s.split(from).join(to);

interface IdTarget { kind: "path" | "query" | "body"; name: string; value: string }

/** Drop credential headers for the anonymous reference request. */
const stripCredentialHeaders = (headers?: Record<string, string>): Record<string, string> | undefined => {
  if (!headers) return undefined;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (/^(cookie|authorization|proxy-authorization|x-api-key|api-key|apikey|x-auth-token|x-access-token|x-csrf-token|x-xsrf-token)$/i.test(k)) continue;
    out[k] = v;
  }
  return Object.keys(out).length > 0 ? out : undefined;
};

export const probeIdorDeep = async (input: IdorDeepInput): Promise<IdorDeepResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 8000, cookie: input.cookie, headers: input.headers };
  const objectIds = input.objectIds ?? [];

  const targets = input.endpoints
    .map((e) => {
      const segIds: IdTarget[] = [...e.path.matchAll(/\/(\d{3,})(?=\/|$)/g)].map((m) => ({ kind: "path" as const, name: `segment:${m[1]}`, value: m[1]! }));
      const qIds: IdTarget[] = e.fields.filter((f) => f.in === "query" && ID_RE.test(f.name.replace(/\[\]$/, ""))).map((f) => ({ kind: "query" as const, name: f.name.replace(/\[\]$/, ""), value: "" }));
      const bIds: IdTarget[] = e.fields.filter((f) => f.in === "body" && ID_RE.test(f.name.replace(/\[\]$/, ""))).map((f) => ({ kind: "body" as const, name: f.name.replace(/\[\]$/, ""), value: "" }));
      return { e, ids: [...segIds, ...qIds, ...bIds] };
    })
    .filter((t) => t.ids.length > 0)
    .slice(0, input.maxTargets ?? 25);

  const candidates: IdorDeepCandidate[] = [];

  for (const { e, ids } of targets) {
    let url: URL;
    try {
      url = new URL(e.path.startsWith("http") ? e.path : `${input.baseUrl ?? ""}${e.path.startsWith("/") ? "" : "/"}${e.path}`);
    } catch { continue; }

    for (const id of ids.slice(0, 3)) {
      // Determine original value per location.
      let original: string;
      if (id.kind === "path") original = id.value;
      else if (id.kind === "query") original = url.searchParams.get(id.name) ?? "1";
      else original = "1";

      const method = e.method.toUpperCase();
      // State-change discipline: body-kind ID variants on mutating methods
      // re-fire POST/PUT/PATCH with attacker-chosen values — skip unless the
      // caller explicitly opted in (same gate as massAssign/replayTamper).
      if (id.kind === "body" && !["GET", "HEAD", "OPTIONS"].includes(method) && input.applyBodyIdor !== true) continue;
      const baseBody = id.kind === "body" ? JSON.stringify({ [id.name]: original }) : undefined;
      const baseCall = await fetchUrl(url.toString(), { ...opts, method, body: baseBody });
      if (baseCall.status === 0 || baseCall.status >= 400) continue;
      const baseFp = `${baseCall.status}:${baseCall.sha256?.slice(0, 16) ?? ""}`;
      // Baseline stability: fetch the SAME url twice — if the body hash moves
      // between two identical requests the endpoint embeds per-request noise
      // (timestamp/nonce/render id) and raw-hash differentials are worthless;
      // degrade to status-only verdicts for this endpoint.
      const baseCall2 = await fetchUrl(url.toString(), { ...opts, method, body: baseBody });
      const noisy = baseCall2.status === baseCall.status && (baseCall2.sha256?.slice(0, 16) ?? "") !== (baseCall.sha256?.slice(0, 16) ?? "");

      // Deno-refs: three-reference oracle (Auto-IDOR) needs the anonymous
      // "correct denial" reference for the SAME object the baseline owns.
      const deniedRef = await fetchUrl(url.toString(), { ...opts, method, body: baseBody, cookie: undefined, headers: stripCredentialHeaders(input.headers) });
      let deniedRefBody: string | null = deniedRef.status >= 200 && deniedRef.status < 300 ? deniedRef.body : null;

      for (const v of variantsOf(original, objectIds)) {
        let target: string;
        let body: string | undefined;
        if (id.kind === "path") {
          target = sub(url.toString(), original, v);
        } else if (id.kind === "query") {
          const u2 = new URL(url.toString());
          u2.searchParams.set(id.name, v);
          target = u2.toString();
        } else {
          target = url.toString();
          body = JSON.stringify({ [id.name]: v });
        }
        const r = await fetchUrl(target, { ...opts, method, body });
        if (r.status === 0) continue;
        const fp = `${r.status}:${r.sha256?.slice(0, 16) ?? ""}`;
        const common = { url: target, method: e.method, param: id.kind === "path" ? `segment:${original}` : id.name, location: id.kind, original, variant: v, originalStatus: baseCall.status, variantStatus: r.status };
        const effFp = noisy ? `${r.status}:` : fp;
        if (effFp === (noisy ? `${baseCall.status}:` : baseFp)) {
          candidates.push({ ...common, contentDiff: false, verdict: "same-response" });
        } else if (r.status === 404) {
          candidates.push({ ...common, contentDiff: false, verdict: "not-found" });
        } else if (r.status === 401 || r.status === 403) {
          candidates.push({ ...common, contentDiff: false, verdict: "denied" });
        } else if (r.status >= 200 && r.status < 300) {
          // 2xx with DIFFERENT content than the caller's own object = data of another principal.
          // Three-reference oracle (Auto-IDOR): confirmed ⟺ attacker ≈ owner
          // AND attacker ≉ denied(anon). attacker ≈ denied → public endpoint,
          // not IDOR. Owner baseline failed → inconclusive, stay suspect.
          const nVar = normalizeBody(r.body);
          const nOwn = normalizeBody(baseCall.body);
          const simOwner = charSimilarity(nVar, nOwn);
          const simDenied = deniedRefBody === null ? 0 : charSimilarity(nVar, normalizeBody(deniedRefBody));
          const idsVar = extractIdentities(r.body);
          const idsOwn = extractIdentities(baseCall.body);
          const distinctIdentity = Object.keys(idsVar).filter(
            (k) => idsOwn[k] !== undefined && idsVar[k] !== idsOwn[k],
          );
          if (simDenied > 0.9) {
            candidates.push({ ...common, contentDiff: false, oracle: { simOwner, simDenied }, verdict: "public-or-unprotected" });
          } else if (simOwner >= 0.85 && distinctIdentity.length > 0) {
            candidates.push({ ...common, contentDiff: true, oracle: { simOwner, simDenied }, identityEvidence: distinctIdentity.map((k) => `${k}: ${idsOwn[k]} → ${idsVar[k]}`).join("; "), verdict: "idor-confirmed-identity" });
          } else if (simOwner >= 0.85) {
            candidates.push({ ...common, contentDiff: true, oracle: { simOwner, simDenied }, verdict: "idor-confirmed" });
          } else {
            candidates.push({ ...common, contentDiff: true, oracle: { simOwner, simDenied }, verdict: "idor-suspect" });
          }
        } else {
          candidates.push({ ...common, contentDiff: false, verdict: "skip" });
        }
      }
    }
  }

  const bodyStr = JSON.stringify({ probed: targets.length, candidates }, null, 2);
  const path = join(input.outputRoot, "idor_deep.json");
  await writeFile(path, bodyStr, "utf8");
  return { probed: targets.length, candidates, artifacts: [{ path, bytes: Buffer.byteLength(bodyStr) }] };
};
