import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** OTP/2FA brute-force surface: measures whether the verify endpoint
 *  rate-limits repeated wrong codes. Sends a bounded sample of wrong
 *  codes; if the endpoint keeps answering with the same "wrong code"
 *  semantic (never 429 / no lockout / no CAPTCHA escalation), the
 *  remaining keyspace is brute-forceable in proportion. */

export interface OtpInput {
  readonly url: string;
  /** body template with {CODE} placeholder */
  readonly bodyTemplate: string;
  readonly outputRoot: string;
  readonly samples?: number;
  readonly cookie?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}
export interface OtpResult {
  /** 2FA setup/status endpoints leaking the TOTP secret in plaintext (bypass material) */
  readonly secretLeak: { endpoint: string; secret: string }[];
  readonly sent: number;
  readonly wrongSemantics: { status: number; count: number }[];
  readonly rateLimited: number;
  readonly lockoutSigns: string[];
  readonly bruteForceable: boolean;
  readonly estimateSeconds: number | null;
  readonly artifacts: { path: string; bytes: number }[];
}

export const probeOtpBrute = async (input: OtpInput): Promise<OtpResult> => {
  const n = Math.min(input.samples ?? 30, 60);
  // 2FA secret 泄漏检测: setup/status 姐妹端点(base同路径)明文回显 totpSecret
  const secretLeak: { endpoint: string; secret: string }[] = [];
  const base2fa = new URL(input.url);
  for (const probe of ["/rest/2fa/status"]) {
    try {
      const u = new URL(probe, base2fa.origin);
      const r = await fetchUrl(u.toString(), { method: "GET", cookie: input.cookie, headers: input.headers ?? {}, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10000, maxAttempts: 1 });
      const m = /(?:totpSecret|"secret")\s*[:=]\s*"([A-Z2-7]{16,})"/.exec(r.body);
      if (m && m[1]) secretLeak.push({ endpoint: u.toString(), secret: m[1] });
    } catch { /* optional */ }
  }
  const statusCount = new Map<number, number>();
  const lockoutSigns: string[] = [];
  let rateLimited = 0;
  let wrongCode = 0;
  const t0 = Date.now();
  for (let i = 0; i < n; i++) {
    // 错误码: 递增序列但避开用户可能的真实码
    const code = String(900000 + i);
    const body = input.bodyTemplate.replaceAll("{CODE}", code);
    try {
      const r = await fetchUrl(input.url, { method: "POST", body, cookie: input.cookie, headers: { "content-type": "application/json", ...(input.headers ?? {}) }, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10000 });
      statusCount.set(r.status, (statusCount.get(r.status) ?? 0) + 1);
      if (r.status === 429) rateLimited++;
      const b = r.body.slice(0, 500).toLowerCase();
      // verify类端点常以 400/401 + 简短/空体表示"码不对"; 明确的429/锁定词才算节流
      if ((r.status === 400 || r.status === 401 || r.status === 403) || /invalid|wrong|incorrect|denied|expired/.test(b)) wrongCode++;
      if (/lock|blocked|suspended|too many|captcha|challenge/.test(b) && !/invalid|wrong|incorrect/.test(b)) lockoutSigns.push(`#${i}: ${r.body.slice(0, 80)}`);
    } catch { statusCount.set(0, (statusCount.get(0) ?? 0) + 1); }
  }
  const elapsed = (Date.now() - t0) / 1000;
  const perReq = elapsed / n;
  // 全程无429无锁定且始终"错误码"语义 = 可爆破; 6位TOTP通常30s窗口内需爆破的量级给出时间估算
  const bruteForceable = rateLimited === 0 && lockoutSigns.length === 0 && wrongCode >= n * 0.8;
  const estimateSeconds = bruteForceable ? Math.round(perReq * 1000000) : null; // 10^6 全空间串行
  const artifacts = [
    await writeArtifact(input.outputRoot, "otp_brute.json", JSON.stringify({ sent: n, statusCount: [...statusCount], rateLimited, lockoutSigns, bruteForceable, estimateSeconds }, null, 2)),
    await writeArtifact(input.outputRoot, "otp_brute.md", [`# OTP brute-force surface`, ``, `- sent ${n} wrong codes in ${elapsed.toFixed(1)}s (${(perReq * 1000).toFixed(0)}ms/req)`, `- rate-limited responses: ${rateLimited}`, `- lockout/captcha signs: ${lockoutSigns.length}`, `- verdict: **${bruteForceable ? `NO THROTTLING within ${n} attempts` : "throttled within sample"}**${estimateSeconds !== null ? ` — serial 10^6 keyspace ≈ ${estimateSeconds}s; note: budget-limited throttlers (e.g. 100/5min) stay invisible below their threshold — raise --samples to probe higher limits` : ""}`].join("\n")),
  ];
  return { secretLeak, sent: n, wrongSemantics: [...statusCount].map(([status, count]) => ({ status, count })), rateLimited, lockoutSigns, bruteForceable, estimateSeconds, artifacts };
};
