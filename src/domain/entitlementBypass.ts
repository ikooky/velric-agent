import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";
import { charSimilarity, normalizeBody } from "./normalize.js";

/** Subscription / paywall enforcement testing. Answers one question: is the
 *  entitlement checked server-side or only in the UI? Four probes with a free
 *  account — anonymous premium call, authenticated premium call, similarity
 *  of the two (identical payload = gate is pure UI), and plan-claim header
 *  forgery. A NEGATIVE on every probe means the backend really enforces. */

export interface EntBypassInput {
  /** Premium-only API or page (e.g. /api/pro/export). */
  readonly premiumUrl: string;
  /** Account endpoint returning the caller's own plan/subscription JSON. */
  readonly accountUrl: string;
  readonly outputRoot: string;
  readonly cookie?: string;
  readonly bearer?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}

export type EntVerdict = "no-server-gate" | "client-side-only" | "teaser-paywall" | "free-account-access" | "claim-forgery-accepted" | "server-enforced";

export interface EntProbe {
  readonly name: string;
  readonly status: number;
  readonly bytes: number;
  readonly similarToBaseline: number;
  readonly verdict: EntVerdict | "informational";
  readonly evidence: string;
}

export interface EntBypassResult {
  readonly plan: string;
  readonly verdicts: EntProbe[];
  readonly exploitable: boolean;
  readonly artifacts: { path: string; bytes: number }[];
}

const PLAN_KEY = /^(plan|plan_name|tier|subscription|subscription_plan|edition|product|license|license_type)$/i;
const PAYWALL_MARKERS = /(subscribe|upgrade|paywall|premium|pro plan|free trial|start.{0,5}trial)/i;
const LOGIN_MARKERS = /(sign in|log in|login|unauthorized|forbidden)/i;

const authHeaders = (input: EntBypassInput, extra?: Record<string, string>): Record<string, string> => {
  const h: Record<string, string> = { ...(input.headers ?? {}) };
  if (input.cookie) h.cookie = input.cookie;
  if (input.bearer) h.authorization = `Bearer ${input.bearer}`;
  if (extra) Object.assign(h, extra);
  return h;
};

const get = (url: string, input: EntBypassInput, extra?: { headers?: Record<string, string>; anon?: boolean }) => fetchUrl(url, {
  headers: authHeaders(input, extra?.headers),
  maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10_000, maxBytes: 1024 * 1024,
});

const findPlan = (body: string): string => {
  try {
    const walk = (o: unknown, depth: number): string | null => {
      if (depth > 4 || !o || typeof o !== "object") return null;
      if (Array.isArray(o)) { for (const x of o) { const r = walk(x, depth + 1); if (r) return r; } return null; }
      for (const [k, v] of Object.entries(o as Record<string, unknown>)) {
        if (PLAN_KEY.test(k) && (typeof v === "string" || typeof v === "number" || typeof v === "boolean")) return String(v);
        if (typeof v === "object") { const r = walk(v, depth + 1); if (r) return r; }
      }
      return null;
    };
    return walk(JSON.parse(body), 0) ?? "unknown";
  } catch { return "unknown"; }
};

export const probeEntitlementBypass = async (input: EntBypassInput): Promise<EntBypassResult> => {
  const acct = await get(input.accountUrl, input);
  const plan = findPlan(acct.body);
  const verdicts: EntProbe[] = [];

  // 1) anonymous access — does the backend even look at the session?
  const anon = await fetchUrl(input.premiumUrl, {
    headers: { ...(input.headers ?? {}), accept: "text/html,application/json" },
    maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10_000, maxBytes: 1024 * 1024,
  });
  const anonJson = /json/i.test(anon.contentType) || /^[\s[{]/.test(anon.body);
  const anonLooksLikeLogin = !anonJson && anon.status === 200 && LOGIN_MARKERS.test(anon.body) && !PAYWALL_MARKERS.test(anon.body);
  if (anon.status >= 200 && anon.status < 300 && !anonLooksLikeLogin) {
    verdicts.push({ name: "anonymous-access", status: anon.status, bytes: anon.bytes, similarToBaseline: 0, verdict: "no-server-gate", evidence: "premium resource served without any session" });
  } else {
    verdicts.push({ name: "anonymous-access", status: anon.status, bytes: anon.bytes, similarToBaseline: 0, verdict: "informational", evidence: anonLooksLikeLogin ? "redirected to login/teaser" : `status ${anon.status}` });
  }

  // 2) authenticated free-account call = baseline
  const base = await get(input.premiumUrl, input);
  const baseOk = base.status >= 200 && base.status < 300;
  let gate: EntVerdict = "server-enforced";
  if (baseOk) {
    if (verdicts[0]!.verdict === "no-server-gate") gate = "no-server-gate";
    else gate = "free-account-access"; // free account reached it where anon could not
  } else if (anon.status >= 200 && anon.status < 300 && !anonLooksLikeLogin) gate = "no-server-gate";
  if (!baseOk && anon.status >= 200 && anon.status < 300 && anonLooksLikeLogin) gate = "teaser-paywall";
  verdicts.push({ name: "free-account-access", status: base.status, bytes: base.bytes, similarToBaseline: 1, verdict: baseOk ? gate : "informational", evidence: baseOk ? `free plan "${plan}" reached premium resource` : `blocked (${base.status})` });

  // 3) body similarity anon vs authenticated — identical payload means the UI
  //    hides it rather than the backend serving less.
  const sim = anon.status >= 200 && anon.status < 300 && baseOk ? charSimilarity(normalizeBody(anon.body), normalizeBody(base.body)) : 0;
  if (sim >= 0.98 && baseOk && anon.status >= 200 && anon.status < 300) gate = "client-side-only";
  if (anon.status >= 200 && anon.status < 300 && PAYWALL_MARKERS.test(anon.body) && sim < 0.8) gate = "teaser-paywall";
  verdicts.push({ name: "payload-identical-anon-vs-auth", status: 0, bytes: anon.bytes, similarToBaseline: Number(sim.toFixed(3)), verdict: "informational", evidence: sim >= 0.98 ? "identical payload → gating is UI-only" : `payload differs (sim ${sim.toFixed(2)})` });

  // 4) plan-claim forgery — does the backend read the plan from a header?
  const claims: [string, string][] = [];
  for (const h of ["x-plan", "x-subscription", "x-entitlement", "x-feature-flags", "x-user-plan"]) for (const v of ["pro", "premium", "enterprise"]) claims.push([h, v]);
  let forgery: EntProbe["verdict"] = "informational";
  let forgeryEvidence = "no claim header changed the response";
  for (const [h, v] of claims) {
    const r = await get(input.premiumUrl, input, { headers: { [h]: v } });
    const d = r.status >= 200 && r.status < 300 && base.body ? charSimilarity(normalizeBody(r.body), normalizeBody(base.body)) : 0;
    if (r.status >= 200 && r.status < 300 && (!baseOk || Math.abs(d - 1) > 0.02)) {
      forgery = "claim-forgery-accepted";
      forgeryEvidence = `${h}: ${v} → ${r.status}, payload deviates from baseline (sim ${d.toFixed(2)})`;
      break;
    }
  }
  verdicts.push({ name: "plan-claim-forgery", status: 0, bytes: 0, similarToBaseline: 0, verdict: forgery, evidence: forgeryEvidence });

  const exploitable = gate === "no-server-gate" || gate === "client-side-only" || gate === "free-account-access" || gate === "teaser-paywall" || forgery === "claim-forgery-accepted";
  const body = JSON.stringify({ premiumUrl: input.premiumUrl, plan, gate, verdicts, exploitable }, null, 2);
  const artifact = await writeArtifact(input.outputRoot, "entitlement_bypass.json", body);
  return { plan, verdicts, exploitable, artifacts: [artifact] };
};
