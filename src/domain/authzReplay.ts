import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir, readFile } from "node:fs/promises";
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
const HOP_HEADERS = new Set(["host", "content-length", "connection", "transfer-encoding", "keep-alive", "upgrade", "proxy-authorization", "proxy-connection", "te", "trailer"]);

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
      const body = await loadBlob(input.recordRoot, e.reqBodyHash);
      // Original headers minus credentials/hop-by-hop — the low-priv context
      // supplies its own credentials. Content-type stays so the server parses
      // the body the same way.
      const baseHeaders: Record<string, string> = {};
      for (const [k, v] of Object.entries(e.reqHeaders)) {
        const lk = k.toLowerCase();
        if (CREDENTIAL_HEADER_RE.test(lk) || HOP_HEADERS.has(lk)) continue;
        baseHeaders[lk] = v;
      }
      for (const role of roleNames) {
        const headers = { ...credentialHeaders(input.roles[role]!), ...(input.roleHeaders?.[role] ?? {}), ...baseHeaders };
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
        if (redirectedAway) {
          verdict = "enforced"; note = "redirected away (auth wall)";
        } else if (r.status === 401 || r.status === 403) {
          verdict = "enforced"; note = `denied with ${r.status}`;
        } else if (deniedish || shellDenied) {
          verdict = "enforced"; note = "2xx denial-shaped body";
        } else if ((r.status >= 200 && r.status < 300) && baseSuccess) {
          // Low-priv got a SUCCESS-shaped response for a resource the baseline
          // (high-priv) accessed. Same fingerprint = same content = bypass;
          // different fingerprint but still 2xx = needs eyes.
          const baseFp = await blobFingerprint(input.recordRoot, e.respBodyHash);
          const replayFp = fingerprint(r.status, r.sha256, r.bytes > 0);
          if (baseFp === replayFp) {
            verdict = "bypassed"; note = `same response fingerprint as baseline (${replayFp})`;
          } else {
            verdict = "unknown"; note = `2xx but body differs from baseline (${replayFp} vs ${baseFp}) — manual check`;
          }
        } else if (r.status >= 400 && r.status < 500) {
          verdict = "enforced"; note = `client error ${r.status}`;
        } else if (r.status === 404) {
          verdict = "unknown"; note = "404 — hidden-or-missing, ACL-based invisibility is plausible";
        } else {
          verdict = "unknown"; note = `status ${r.status} — inconclusive`;
        }
        cells.push({ exchangeId: e.id, method: e.method, url: e.url, role, baselineStatus: e.status ?? 0, replayStatus: r.status, redirectedAway, verdict, note });
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
const blobFingerprint = async (_recordRoot: string, hash: string | null): Promise<string> => {
  if (!hash) return "nobody";
  return `2:${hash.slice(0, 12)}`;
};
