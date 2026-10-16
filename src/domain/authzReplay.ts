import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir, readFile } from "node:fs/promises";
import { normalizeBody, tokenSimilarity } from "./normalize.js";
import { join } from "node:path";
import { createHash } from "node:crypto";

/** Autorize-style authorization enforcement replay: takes a traffic recording
 *  (traffic.ndjson + blobs/ from traffic_record — the high-priv user's real
 *  browsing), re-fires each recorded exchange VERBATIM (method + body + all
 *  original headers) under each LOW-privilege context, and diffs the response
 *  against the high-priv baseline to produce the enforcement verdict:
 *
 *    enforced    — low-priv context got denied (401/403/redirect-to-login or a
 *                  denial-shaped 2xx) while the baseline succeeded
 *    bypassed    — low-priv context got the SAME successful-looking response
 *                  as the baseline (status class + body fingerprint match)
 *    unknown     — inconclusive differential (needs manual fingerprints)
 *
 *  The whole point: roleMatrix only GETs endpoint paths; this replays the
 *  real POST/PUT/PATCH/DELETE traffic with real bodies — the mutations an
 *  attacker would actually steal. Deterministic, no LLM. */

export interface AuthzReplayInput {
  /** traffic outputRoot (contains traffic.ndjson + blobs/) recorded as the
   *  high-privilege user (or with per-exchange role provenance). */
  readonly recordRoot: string;
  readonly outputRoot: string;
  /** role name -> credential replay context. Same syntax as roleMatrix:
   *  bare "Cookie: a=b" / "Authorization: Bearer x" / raw values. */
  readonly roles: Record<string, string>;
  /** Extra per-role header overrides (e.g. { "x-tenant": "acme" }). */
  readonly roleHeaders?: Record<string, Record<string, string>>;
  /** Exchange id filter; default: all exchanges with a recorded response. */
  readonly exchangeIds?: readonly string[];
  /** Restrict replay to these methods (default: GET/POST/PUT/PATCH/DELETE). */
  readonly methods?: readonly string[];
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxExchanges?: number;
  /** Manual enforcement fingerprints (Autorie detectors): body strings or
   *  regex sources that mark a response as a denial for this app. */
  readonly denyFingerprints?: readonly string[];
  /** Skip replaying mutating requests (POST/PUT/PATCH/DELETE) — read-only
   *  authorization audit. Default: false (recorded traffic IS the authz
   *  question; replays are the point). */
  readonly readOnly?: boolean;
  /** Fire the replays. Default true; set false for a dry inventory of what
   *  WOULD be replayed per role. */
  readonly apply?: boolean;
  /** Per-role canary markers (Authz-ExeC identity markers): strings exclusive
   *  to that principal (tenant name, seeded test data). Another role's marker
   *  appearing in a replay body is content-level proof of cross-principal
   *  leakage — checked before all structural comparisons. */
  readonly markers?: Record<string, readonly string[]>;
  /** Add a pseudo-role "__anonymous__" that strips ALL credential headers
   *  (Autorize's unauthenticated third state): anonymous ≈ baseline → the
   *  endpoint is public (downgrades bypass noise); anonymous denied while a
   *  role is bypassed → confidence upgrade. Default: true. */
  readonly anonymous?: boolean;
}

export interface EnforcementCell {
  readonly exchangeId: string;
  readonly method: string;
  readonly url: string;
  readonly role: string;
  readonly baselineStatus: number;
  readonly replayStatus: number;
  /** Final landing path differed (redirect-to-login chains) — auth redirect. */
  readonly redirectedAway: boolean;
  readonly verdict: "enforced" | "bypassed" | "unknown";
  readonly note: string;
}

export interface AuthzReplayResult {
  readonly replayed: number;
  readonly cells: EnforcementCell[];
  readonly bypassed: EnforcementCell[];
  readonly enforced: EnforcementCell[];
  readonly unknown: EnforcementCell[];
  readonly artifacts: { path: string; bytes: number }[];
}

/** Headers that must never be replayed verbatim: the credential carriers
 *  (replaced per-role), hop-by-hop, and length/identity headers tied to the
 *  original request bytes. */
const CREDENTIAL_HEADER_RE = /^(cookie|authorization|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token|api-key)$/i;
const HOP_HEADERS = new Set([
  "host", "content-length", "connection", "transfer-encoding", "keep-alive", "upgrade",
  "proxy-authorization", "proxy-connection", "te", "trailer",
  // Conditional validators: replaying a recorded If-None-Match yields 304 empty
  // bodies that mismatch every fingerprint and drown the diff in unknown
  // (Autorize's handle_304_status_code_prevention).
  "if-none-match", "if-modified-since",
]);

const credentialHeaders = (roleHeader: string): Record<string, string> => {
  const isAuthHeader = /^authorization\s*:/i.test(roleHeader);
  const isCookieHeader = /^cookie\s*:/i.test(roleHeader);
  const isBearerValue = /^bearer\s+\S/i.test(roleHeader);
  if (isAuthHeader || isBearerValue) {
    return { authorization: roleHeader.replace(/^authorization\s*:\s*/i, "") };
  }
  return { cookie: isCookieHeader ? roleHeader.replace(/^cookie\s*:\s*/i, "") : roleHeader };
};

/** A 2xx that is actually a denial in disguise — same discipline as
 *  roleMatrix (content, not bare status). */
const hashOf = (s: string): string => createHash("sha256").update(s).digest("hex").slice(0, 12);

/** Raw recorded body text, or null when the blob is absent. */
const readRawBlob = async (recordRoot: string, hash: string | null): Promise<string | null> => {
  if (!hash) return null;
  try {
    return await readFile(join(recordRoot, "blobs", hash.slice(0, 2), `${hash}.bin`), "utf8");
  } catch { return null; }
};

/** Akto percentage_match: flatten JSON to key→value-set, fraction of keys whose
 *  value-sets are equal. Non-JSON degrades to 0 (structural tier handles it). */
const keyValueMatch = (a: string, b: string | null): number => {
  if (b === null) return 0;
  const flat = (s: string): Map<string, Set<string>> | null => {
    try {
      const out = new Map<string, Set<string>>();
      const walk = (o: unknown, prefix: string): void => {
        if (o && typeof o === "object") {
          if (Array.isArray(o)) { o.forEach((x) => walk(x, prefix)); return; }
          for (const [k, v] of Object.entries(o as Record<string, unknown>)) {
            const key = `${prefix}.${k}`;
            const leaf = v && typeof v === "object" ? null : String(v);
            if (leaf !== null) {
              if (!out.has(key)) out.set(key, new Set());
              out.get(key)!.add(leaf);
            }
            walk(v, key);
          }
        }
      };
      walk(JSON.parse(s), "");
      return out;
    } catch { return null; }
  };
  const fa = flat(a);
  const fb = flat(b);
  if (fa === null || fb === null || fa.size === 0 || fb.size === 0) return 0;
  let eq = 0;
  for (const [k, va] of fa) {
    const vb = fb.get(k);
    if (vb === undefined) continue;
    if (va.size === vb.size && [...va].every((x) => vb.has(x))) eq++;
  }
  return eq / Math.max(fa.size, fb.size);
};

/** Normalized recorded body text, or null when the blob is absent. */
const readNormalizedBlob = async (recordRoot: string, hash: string | null): Promise<string | null> => {
  if (!hash) return null;
  try {
    const raw = await readFile(join(recordRoot, "blobs", hash.slice(0, 2), `${hash}.bin`), "utf8");
    return normalizeBody(raw);
  } catch { return null; }
};

const DENIAL_BODY_RE = /access[- ]?denied|forbidden|unauthori[sz]ed|permission denied|not allowed|insufficient|you don't have|login required|请登录|无权|没有权限/i;

const fingerprint = (status: number, bodyHash: string, hasBody: boolean): string =>
  `${Math.floor(status / 100)}:${hasBody ? bodyHash.slice(0, 12) : "nobody"}`;

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

export const replayAuthz = async (input: AuthzReplayInput): Promise<AuthzReplayResult> => {
  await mkdir(input.outputRoot, { recursive: true });

  const lines = (await readFile(join(input.recordRoot, "traffic.ndjson"), "utf8")).split("\n").filter(Boolean);
  const all: RecordedExchange[] = [];
  for (const l of lines) {
    try { all.push(JSON.parse(l) as RecordedExchange); } catch { /* torn line */ }
  }
  const methods = new Set((input.methods ?? ["GET", "POST", "PUT", "PATCH", "DELETE"]).map((m) => m.toUpperCase()));
  const mutating = new Set(["POST", "PUT", "PATCH", "DELETE"]);
  const exchanges = all
    .filter((e) => methods.has(e.method.toUpperCase()))
    .filter((e) => e.status != null && e.status >= 200 && e.status < 400) // baseline must have succeeded
    .filter((e) => (input.readOnly ? !mutating.has(e.method.toUpperCase()) : true))
    .filter((e) => (input.exchangeIds ? input.exchangeIds.includes(e.id) : true))
    .slice(0, input.maxExchanges ?? 25);

  const roleNames = Object.keys(input.roles);
  // Anonymous third state (Autorize): strip ALL credential carriers, inject
  // nothing — separates public endpoints from real cross-principal access.
  const withAnonymous = input.anonymous !== false;
  const replayRoles = withAnonymous ? [...roleNames, "__anonymous__"] : roleNames;
  const extraDeny = (input.denyFingerprints ?? []).map((f) => f.replace(/[/\\^$*+?.()|[\]{}]/g, (c) => `\\${c}`));
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10000 };
  const cells: EnforcementCell[] = [];

  if (input.apply === false) {
    // Dry inventory: what would be replayed per role.
    for (const e of exchanges) for (const role of roleNames) {
      cells.push({ exchangeId: e.id, method: e.method, url: e.url, role, baselineStatus: e.status ?? 0, replayStatus: -1, redirectedAway: false, verdict: "unknown", note: "dry-run inventory" });
    }
  } else {
    for (const e of exchanges) {
      // Conditional/No-Content baselines carry no diffable body — skip rather
      // than pollute the matrix (Autorize ignore304).
      if (e.status === 304 || e.status === 204) {
        cells.push({ exchangeId: e.id, method: e.method, url: e.url, role: "-", baselineStatus: e.status ?? 0, replayStatus: 0, redirectedAway: false, verdict: "unknown", note: "skip: conditional/no-content baseline" });
        continue;
      }
      const body = await loadBlob(input.recordRoot, e.reqBodyHash);
      if (e.reqBodyHash && body == null) {
        // Missing request blob: replaying bodyless would draw a 400/422 that
        // masquerades as "enforced". Record as unknown-skip, not a verdict.
        for (const role of roleNames) {
          cells.push({ exchangeId: e.id, method: e.method, url: e.url, role, baselineStatus: e.status ?? 0, replayStatus: -1, redirectedAway: false, verdict: "unknown", note: "skip: recorded request body blob missing" });
        }
        continue;
      }
      const baseHeaders: Record<string, string> = {};
      for (const [k, v] of Object.entries(e.reqHeaders)) {
        const lk = k.toLowerCase();
        if (CREDENTIAL_HEADER_RE.test(lk) || HOP_HEADERS.has(lk)) continue;
        baseHeaders[lk] = v;
      }
      for (const role of replayRoles) {
        // Anonymous: no injected credentials AND strip any residual credential
        // carriers from the recorded baseline headers.
        const headers = role === "__anonymous__"
          ? Object.fromEntries(Object.entries(baseHeaders).filter(([k]) => !CREDENTIAL_HEADER_RE.test(k)))
          : { ...credentialHeaders(input.roles[role]!), ...(input.roleHeaders?.[role] ?? {}), ...baseHeaders };
        const r = await fetchUrl(e.url, { ...opts, method: e.method, headers, body: body ?? undefined });
        if (r.status === 0) {
          cells.push({ exchangeId: e.id, method: e.method, url: e.url, role, baselineStatus: e.status ?? 0, replayStatus: 0, redirectedAway: false, verdict: "unknown", note: `unreachable: ${r.error ?? "network"}` });
          continue;
        }
        let landed = "";
        try { landed = new URL(r.finalUrl ?? e.url).pathname.replace(/\/$/, ""); } catch { landed = ""; }
        const probed = new URL(e.url).pathname.replace(/\/$/, "");
        const redirectedAway = r.finalUrl != null && landed !== probed;
        const deniedish = r.status >= 200 && r.status < 300 && (DENIAL_BODY_RE.test(r.body.slice(0, 2048)) || extraDeny.some((f) => new RegExp(f).test(r.body.slice(0, 4096))));
        const baseSuccess = (e.status ?? 0) >= 200 && (e.status ?? 0) < 300;
        // Empty-shell denial (menu-only HTML, no data rows) — same heuristic as roleMatrix.
        const shellDenied = r.status === 200 && r.contentType.includes("html") && (r.body.match(/<td/g) ?? []).length <= 2 && r.body.length > 3000;

        let verdict: EnforcementCell["verdict"];
        let note: string;
        // Canary markers (Authz-ExeC foreignMarkerHit): another principal's
        // exclusive string in this replay body = content-level proof of
        // cross-principal leakage. Checked FIRST — outranks all structural
        // comparisons. The BASELINE identity's markers count (that's the
        // victim's data); the replay role's own markers do NOT (self-data).
        const baseMarkerOwner = "__recorder__";
        const foreignMarkers = Object.entries(input.markers ?? {})
          .filter(([mRole]) => mRole !== role)
          .flatMap(([, ms]) => ms);
        const hitMarker = role === "__anonymous__" || role === baseMarkerOwner
          ? undefined
          : foreignMarkers.find((m) => m.length > 0 && r.body.includes(m));
        if (hitMarker !== undefined && r.status >= 200 && r.status < 300) {
          verdict = "bypassed"; note = `marker leak: foreign canary "${hitMarker.slice(0, 24)}" in response body — content-level cross-principal proof`;
        } else if (r.status === 429 || (r.status >= 500 && r.status < 600)) {
          // Infrastructure noise ≠ application authz verdict (Authz-ExeC WAF tier):
          // rate limiting / WAF / origin errors are not authorization evidence.
          verdict = "unknown"; note = `infra-blocked (status ${r.status}) — not an authz signal`;
        } else if (redirectedAway) {
          verdict = "enforced"; note = "redirected away (auth wall)";
        } else if (r.status === 401 || r.status === 403) {
          verdict = "enforced"; note = `denied with ${r.status}`;
        } else if (deniedish || shellDenied) {
          verdict = "enforced"; note = "2xx denial-shaped body";
        } else if ((r.status >= 200 && r.status < 300) && ["[]", "{}", ""].includes(r.body.trim()) && baseSuccess && (e.respBodyHash ?? "") !== "") {
          // Empty success on a baseline that HAD content = row-level filtering,
          // a soft denial (Authz-ExeC "empty success" tier).
          verdict = "enforced"; note = "2xx empty body (row-level filtered) while baseline had content";
        } else if ((r.status >= 200 && r.status < 300) && baseSuccess) {
          // Low-priv got a SUCCESS-shaped response for a resource the baseline
          // (high-priv) accessed. Same fingerprint = same content = bypass;
          // different fingerprint but still 2xx = needs eyes.
          const baseFp = await blobFingerprint(input.recordRoot, e.respBodyHash);
          const replayFp = fingerprint(r.status, r.sha256, r.bytes > 0);
          // Normalized-hash comparison: blobFingerprint now hashes the
          // NORMALIZED recorded body (2n: prefix); build the matching live
          // fingerprint from the normalized replay body so the two formats
          // align — otherwise every normalized blob mismatches by construction.
          const nReplayFp = `2n:${normalizeBody(r.body).length}:${hashOf(normalizeBody(r.body))}`;
          // Volatile-normalized second opinion (Authz-ExeC): identical after
          // stripping timestamps/request-ids/nonces → same content.
          const nReplay = normalizeBody(r.body);
          const nBase = await readNormalizedBlob(input.recordRoot, e.respBodyHash);
          const sim = nBase === null ? 0 : tokenSimilarity(nReplay, nBase);
          if (baseFp === replayFp || (baseFp.startsWith("2n:") && baseFp === nReplayFp)) {
            verdict = "bypassed"; note = `same response fingerprint as baseline (normalized ${baseFp.startsWith("2n:") ? "hash" : "raw"})`;
          } else if (nBase !== null && sim >= 0.9) {
            verdict = "bypassed"; note = `normalized bodies match (token similarity ${sim.toFixed(2)} — volatile noise stripped)`;
          } else if (nBase !== null && keyValueMatch(r.body, await readRawBlob(input.recordRoot, e.respBodyHash)) >= 0.9) {
            // Akto percentage_match: JSON flattened key→value-set overlap — the
            // differing keys are typically the owner fields themselves, which
            // is exactly the BOLA shape (same object type, different owner).
            verdict = "bypassed"; note = `key-value match ≥90% (owner-field drift only)`;
          } else {
            verdict = "unknown"; note = `2xx but body differs from baseline (${replayFp} vs ${baseFp}, sim ${sim.toFixed(2)}) — manual check`;
          }
        } else if (r.status === 404) {
          // ACL-based invisibility: 404 for a resource the baseline reached
          // is hidden-or-missing, never a confirmed denial (fail-open-to-unknown).
          verdict = "unknown"; note = "404 — hidden-or-missing, ACL-based invisibility is plausible";
        } else if (r.status >= 400 && r.status < 500) {
          verdict = "enforced"; note = `client error ${r.status}`;
        } else {
          verdict = "unknown"; note = `status ${r.status} — inconclusive`;
        }
        cells.push({ exchangeId: e.id, method: e.method, url: e.url, role, baselineStatus: e.status ?? 0, replayStatus: r.status, redirectedAway, verdict, note });
        if (role === "__anonymous__" && verdict === "bypassed") {
          // Anonymous got the SAME content as the recorded baseline → the
          // endpoint is public; ANY role that also read it is not a finding.
          // Rewrite this exchange's role cells from bypassed → public noise.
          for (const c of cells) {
            if (c.exchangeId === e.id && c.verdict === "bypassed" && c.role !== "__anonymous__") {
              (c as { verdict: EnforcementCell["verdict"]; note: string }).verdict = "unknown";
              (c as { note: string }).note = "downgraded: endpoint is public (anonymous replay read the same content)";
            }
          }
        }
      }
    }
  }

  const bypassed = cells.filter((c) => c.verdict === "bypassed");
  const enforced = cells.filter((c) => c.verdict === "enforced");
  const unknown = cells.filter((c) => c.verdict === "unknown");
  const bodyStr = JSON.stringify({ replayed: exchanges.length, cells, bypassed, enforced, unknown }, null, 2);
  const path = join(input.outputRoot, "authz_replay.json");
  await writeFile(path, bodyStr, "utf8");
  return { replayed: exchanges.length, cells, bypassed, enforced, unknown, artifacts: [{ path, bytes: Buffer.byteLength(bodyStr) }] };
};

/** Baseline body fingerprint from the stored blob. Only invoked for
 *  successful (2xx) baselines — the caller gates on baseSuccess — so the
 *  status class prefix is pinned to 2. */
const blobFingerprint = async (recordRoot: string, hash: string | null): Promise<string> => {
  if (!hash) return "nobody";
  // Normalized fingerprint: read the recorded body and strip volatile tokens
  // (timestamps/request-ids/nonces) BEFORE hashing, symmetric with the live
  // replay side — raw-hash comparisons drown in per-request noise.
  try {
    const raw = await readFile(join(recordRoot, "blobs", hash.slice(0, 2), `${hash}.bin`), "utf8");
    return `2n:${normalizeBody(raw).length}:${hashOf(normalizeBody(raw))}`;
  } catch {
    return `2:${hash.slice(0, 12)}`;
  }
};
