import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** Password-reset depth beyond "does it send mail": host-header poisoning,
 *  email-alias bypass, token shape/entropy analysis (uuid4 vs sequential vs
 *  timestamped vs JWT — the predictable kinds), token reuse after a completed
 *  reset, and Referer leakage of the token-bearing URL to third-party hosts. */

export interface ResetInput {
  /** Reset request endpoint; body template carries {EMAIL}. */
  readonly requestUrl: string;
  readonly bodyTemplate: string;
  readonly email: string;
  readonly outputRoot: string;
  /** Token from the delivered mail — unlocks shape analysis, reuse and referer checks. */
  readonly token?: string;
  /** Reset-submit URL template carrying {TOKEN} and {PASS}. */
  readonly submitUrl?: string;
  /** Login URL template carrying {EMAIL} and {PASS}, used to prove the new password. */
  readonly loginUrl?: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly headers?: Record<string, string>;
}

export type ResetVerdict = "poison-suspect" | "alias-accepted" | "reusable" | "predictable" | "safe" | "inconclusive";

export interface ResetProbe {
  readonly name: string;
  readonly status: number;
  readonly verdict: ResetVerdict;
  readonly evidence: string;
}

export interface ResetResult {
  readonly baseline: number;
  readonly probes: ResetProbe[];
  readonly tokenShape?: string;
  readonly refererHosts: string[];
  readonly artifacts: { path: string; bytes: number }[];
}

const contentTypeOf = (tpl: string): string => (tpl.trim().startsWith("{") ? "application/json" : "application/x-www-form-urlencoded");
const HOST_CANARY = "velric-poison.test";

const analyseToken = (token: string): { shape: string; verdict: ResetVerdict } => {
  if (/^eyJ[\w-]+\.[\w-]+\.[\w-]*$/.test(token)) return { shape: `JWT (${token.length} chars)`, verdict: "predictable" };
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(token)) return { shape: `uuid-v4 (${token.length})`, verdict: "safe" };
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(token)) return { shape: `uuid-v1 timestamped (${token.length})`, verdict: "predictable" };
  if (/^\d{10,13}$/.test(token)) {
    const n = Number(token.length === 13 ? Number(token) / 1000 : token);
    const plausible = n > 1_500_000_000 && n < 2_500_000_000;
    return { shape: `numeric${token.length === 13 ? " (epoch ms)" : ""}`, verdict: plausible ? "predictable" : "inconclusive" };
  }
  const hexTs = /^([0-9a-f]{8})[0-9a-f]{8,}$/i.exec(token);
  if (hexTs) {
    const secs = parseInt(hexTs[1] ?? "0", 16);
    if (secs > 1_500_000_000 && secs < 2_500_000_000) return { shape: `hex timestamp prefix (${token.length})`, verdict: "predictable" };
  }
  if (/^[0-9a-f]{32,64}$/i.test(token)) return { shape: `hex ${token.length}`, verdict: "safe" };
  if (/^[A-Za-z0-9_-]{22}$/.test(token)) return { shape: `base64url 128-bit (${token.length})`, verdict: "safe" };
  return { shape: `opaque ${token.length} chars`, verdict: token.length < 16 ? "predictable" : "inconclusive" };
};

export const probeResetDeep = async (input: ResetInput): Promise<ResetResult> => {
  const ct = contentTypeOf(input.bodyTemplate);
  const hdrs = (extra?: Record<string, string>): Record<string, string> => ({ "content-type": ct, ...(input.headers ?? {}), ...(extra ?? {}) });
  const isJson = ct.includes("json");
  const request = async (extra?: Record<string, string>, email = input.email): Promise<{ status: number; body: string }> => {
    const r = await fetchUrl(input.requestUrl, {
      method: "POST", body: input.bodyTemplate.replaceAll("{EMAIL}", isJson ? email : encodeURIComponent(email)),
      headers: hdrs(extra), maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10_000, maxBytes: 256 * 1024,
    });
    return { status: r.status, body: r.body };
  };

  const baseline = await request();
  const probes: ResetProbe[] = [];

  // Host-header poisoning: same request must carry the attacker host into the
  // delivered link. Measured as "request still accepted" — the link itself
  // lives in the mail (host-poison covers reflection separately).
  const xfh = await request({ "x-forwarded-host": HOST_CANARY });
  probes.push({ name: "host-header-poison", status: xfh.status, verdict: xfh.status === baseline.status ? "poison-suspect" : "safe", evidence: `x-forwarded-host canary answered ${xfh.status} (baseline ${baseline.status})` });
  const hostHdr = await request({ host: HOST_CANARY });
  probes.push({ name: "host-header-raw", status: hostHdr.status, verdict: hostHdr.status === baseline.status ? "poison-suspect" : "safe", evidence: `Host: ${HOST_CANARY} answered ${hostHdr.status}` });

  // Email alias: +tag must not change the account but often bypasses the
  // "already requested" throttle.
  const [local, domain] = input.email.split("@");
  const alias = `${local}+velric@${domain ?? "example.com"}`;
  const aliasRes = await request(undefined, alias);
  probes.push({ name: "email-alias", status: aliasRes.status, verdict: aliasRes.status >= 200 && aliasRes.status < 300 ? "alias-accepted" : "safe", evidence: `${alias} → ${aliasRes.status}` });

  let tokenShape: string | undefined;
  const refererHosts: string[] = [];
  if (input.token) {
    const a = analyseToken(input.token);
    tokenShape = a.shape;
    probes.push({ name: "token-shape", status: 0, verdict: a.verdict, evidence: a.shape });
    if (input.submitUrl) {
      const resetUrl = input.submitUrl.replaceAll("{TOKEN}", encodeURIComponent(input.token));
      const page = await fetchUrl(resetUrl, { headers: input.headers ?? {}, maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10_000, maxBytes: 512 * 1024 });
      for (const m of page.body.matchAll(/(?:src|href)="(https?:\/\/[^"/]+)/g)) {
        const host = m[1]?.replace(/^https?:\/\//, "");
        if (host && !refererHosts.includes(host)) refererHosts.push(host);
      }
      if (refererHosts.length) probes.push({ name: "referer-leak-surface", status: page.status, verdict: "inconclusive", evidence: `token URL loads ${refererHosts.length} third-party host(s)` });

      // Reuse: complete the reset once, log in, complete it again with the
      // same token, log in with the second password.
      if (input.loginUrl) {
        const pass1 = `Velric!${Date.now().toString(36)}a`;
        const pass2 = `Velric!${Date.now().toString(36)}b`;
        const doReset = (pass: string) => fetchUrl(resetUrl, { method: "POST", body: input.bodyTemplate.trim().startsWith("{") ? JSON.stringify({ token: input.token, password: pass }) : `token=${encodeURIComponent(input.token ?? "")}&password=${encodeURIComponent(pass)}`, headers: hdrs(), maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10_000, maxBytes: 128 * 1024 });
        const login = (pass: string) => fetchUrl(input.loginUrl!.replaceAll("{EMAIL}", encodeURIComponent(input.email)).replaceAll("{PASS}", encodeURIComponent(pass)), { method: "POST", headers: hdrs(), maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10_000, maxBytes: 128 * 1024 });
        const r1 = await doReset(pass1);
        const l1 = await login(pass1);
        const r2 = await doReset(pass2);
        const l2 = await login(pass2);
        const reusable = r1.status < 400 && l1.status < 400 && r2.status < 400 && l2.status < 400;
        probes.push({ name: "token-reuse", status: r2.status, verdict: reusable ? "reusable" : "safe", evidence: `reset1 ${r1.status}/login1 ${l1.status}; reset2 ${r2.status}/login2 ${l2.status}` });
      }
    }
  }
  const body = JSON.stringify({ requestUrl: input.requestUrl, baseline: baseline.status, probes, tokenShape, refererHosts }, null, 2);
  const artifact = await writeArtifact(input.outputRoot, "reset_deep.json", body);
  return { baseline: baseline.status, probes, tokenShape, refererHosts, artifacts: [artifact] };
};
