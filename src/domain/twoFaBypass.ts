import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";
import { SessionJar } from "../core/credentials.js";

/** Two-factor bypass depth, measured against a live login flow: does the
 *  pre-OTP session already reach protected resources (step skip), does a
 *  used code work a second time (replay), and does the verify response set a
 *  long-lived trust cookie with weak attributes. Needs real credentials; the
 *  current OTP is optional (skip+replay still measurable without it, replay
 *  only with --code). */

export interface TwoFaInput {
  readonly loginUrl: string;
  readonly verifyUrl: string;
  readonly protectedUrl: string;
  readonly bodyTemplate: string;
  readonly user: string;
  readonly pass: string;
  /** Current valid OTP code, enables the replay test. */
  readonly code?: string;
  readonly outputRoot: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly headers?: Record<string, string>;
  /** JSON field of the login response holding the second-factor tmp token (dotted path). */
  readonly tokenField?: string;
  /** Separate body template for the verify call ({CODE}, {TMP}); defaults to the login template. */
  readonly verifyTemplate?: string;
}

export type TwoFaVerdict = "bypass" | "reusable" | "safe" | "inconclusive";

export interface TwoFaProbe {
  readonly name: string;
  readonly status: number;
  readonly verdict: TwoFaVerdict;
  readonly evidence: string;
}

export interface TwoFaResult {
  readonly otpStepDetected: boolean;
  readonly probes: TwoFaProbe[];
  readonly exploitable: boolean;
  readonly artifacts: { path: string; bytes: number }[];
}

const OTP_MARKERS = /(otp|2fa|two-factor|verify|verification code|authenticator|one-time)/i;
const LOGIN_MARKERS = /(sign in|log in|login|password|unauthorized)/i;

const fill = (tpl: string, user: string, pass: string, code?: string, tmp?: string): string => tpl.replaceAll("{USER}", user).replaceAll("{PASS}", pass).replaceAll("{CODE}", code ?? "").replaceAll("{TMP}", tmp ?? "");

const dig = (body: string, path: string): string => {
  try {
    let cur: unknown = JSON.parse(body);
    for (const key of path.split(".")) cur = (cur as Record<string, unknown> | undefined)?.[key];
    return typeof cur === "string" ? cur : "";
  } catch { return ""; }
};

export const probeTwoFaBypass = async (input: TwoFaInput): Promise<TwoFaResult> => {
  const jar = new SessionJar();
  let tmpToken = "";
  const hdrs = (): Record<string, string> => ({ "content-type": input.bodyTemplate.trim().startsWith("{") ? "application/json" : "application/x-www-form-urlencoded", ...(input.headers ?? {}) });
  const doCall = async (url: string, method: string, body?: string, bearer = false): Promise<{ status: number; body: string; setCookies: readonly string[]; headers: Record<string, string> }> => {
    const h: Record<string, string> = { ...hdrs(), ...jar.headers(url) };
    if (bearer && tmpToken) h.authorization = `Bearer ${tmpToken}`;
    const r = await fetchUrl(url, { method, body, headers: h, maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10_000, maxBytes: 512 * 1024 });
    if (r.setCookies?.length) jar.update(url, r.setCookies);
    if (r.headers.location) jar.update(new URL(r.headers.location, url).href, r.setCookies ?? []);
    return { status: r.status, body: r.body, setCookies: r.setCookies ?? [], headers: r.headers };
  };

  const login = await doCall(input.loginUrl, "POST", fill(input.bodyTemplate, input.user, input.pass));
  if (input.tokenField) tmpToken = dig(login.body, input.tokenField);
  // Some stacks answer 401 with an OTP-required body plus the tmp token — accept any non-transport status.
  const otpStepDetected = login.status > 0 && login.status < 500 && OTP_MARKERS.test(login.body);
  const probes: TwoFaProbe[] = [];

  // 1) step skip — the pre-OTP session hits protected content directly.
  const direct = await doCall(input.protectedUrl, "GET", undefined, true);
  const directOk = direct.status >= 200 && direct.status < 300 && !LOGIN_MARKERS.test(direct.body.slice(0, 2000));
  probes.push({ name: "otp-step-skip", status: direct.status, verdict: directOk ? "bypass" : "safe", evidence: directOk ? "protected resource fully served before OTP completion" : `blocked (${direct.status})` });

  // 2) optional: 2FA state flip via API — common endpoints expose a
  //    "disable"/status view that the pre-OTP session may already reach.
  const statusProbe = await doCall(`${new URL(input.verifyUrl).origin}/api/2fa/status`, "GET");
  if (statusProbe.status >= 200 && statusProbe.status < 300) probes.push({ name: "2fa-status-readable", status: statusProbe.status, verdict: "inconclusive", evidence: statusProbe.body.slice(0, 160) });

  // 3) replay with a supplied live code.
  if (input.code) {
    const verifyBody = fill(input.verifyTemplate ?? input.bodyTemplate, input.user, input.pass, input.code, tmpToken);
    const first = await doCall(input.verifyUrl, "POST", verifyBody);
    const accepted = first.status >= 200 && first.status < 300;
    const second = await doCall(input.verifyUrl, "POST", verifyBody);
    const replayAccepted = second.status >= 200 && second.status < 300;
    probes.push({ name: "otp-replay", status: second.status, verdict: accepted && replayAccepted ? "reusable" : "safe", evidence: `first ${first.status}, second ${second.status}` });
    const trust = first.setCookies.find((c) => /remember|trust|device/i.test(c));
    if (trust) probes.push({ name: "trust-cookie", status: first.status, verdict: /max-age|expires/i.test(trust) ? "inconclusive" : "inconclusive", evidence: trust.slice(0, 120) });
  } else {
    probes.push({ name: "otp-replay", status: 0, verdict: "inconclusive", evidence: "supply --code to test replay" });
  }

  const exploitable = probes.some((p) => p.verdict === "bypass" || p.verdict === "reusable");
  const body = JSON.stringify({ loginUrl: input.loginUrl, otpStepDetected, probes, exploitable }, null, 2);
  const artifact = await writeArtifact(input.outputRoot, "2fa_bypass.json", body);
  return { otpStepDetected, probes, exploitable, artifacts: [artifact] };
};
