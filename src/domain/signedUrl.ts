import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** Signed-URL enforcement: does the storage backend really verify the
 *  signature, or only the presence of a token? Strips signature, strips
 *  expiry, rewrites expiry, case-mangles the key, walks `..` across keys and
 *  re-orders the query. A 200 with real content (not an XML error) on a
 *  stripped variant is an open bucket through a signed door. */

export interface SignedUrlInput {
  readonly url: string;
  readonly outputRoot: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}

export type SignedVerdict = "unchecked" | "signature-ignored" | "expiry-ignored" | "intact" | "blocked";

export interface SignedCase {
  readonly name: string;
  readonly status: number;
  readonly bytes: number;
  readonly verdict: SignedVerdict;
  readonly evidence: string;
}

export interface SignedUrlResult {
  /** Whether the input actually carried signature/expiry params. */
  readonly signed: boolean;
  readonly cases: SignedCase[];
  readonly exploitable: boolean;
  readonly artifacts: { path: string; bytes: number }[];
}

const SIG_KEYS = ["X-Amz-Signature", "X-Amz-Credential", "X-Amz-Date", "sig", "Signature", "se", "sp", "sv", "sr"];
const EXPIRY_KEYS = ["X-Amz-Expires", "Expires", "se"];
const ERROR_BODY = /(SignatureDoesNotMatch|AuthenticationFailed|ExpiredToken|AccessDenied|AuthorizationFailure|Request has expired|signature mismatch)/i;

const rebuild = (u: URL, mutate: (q: URLSearchParams) => void): string => {
  const c = new URL(u.href);
  mutate(c.searchParams);
  return c.href;
};

export const probeSignedUrl = async (input: SignedUrlInput): Promise<SignedUrlResult> => {
  const u = new URL(input.url);
  const signed = [...u.searchParams.keys()].some((k) => SIG_KEYS.includes(k) || EXPIRY_KEYS.includes(k));
  const cases: SignedCase[] = [];
  const get = (url: string) => fetchUrl(url, { maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10_000, maxBytes: 512 * 1024 });
  const realContent = (status: number, body: string): boolean => status >= 200 && status < 300 && !ERROR_BODY.test(body);

  const base = await get(u.href);
  cases.push({ name: "baseline", status: base.status, bytes: base.bytes, verdict: "intact", evidence: `original ${base.status}, ${base.bytes}B` });

  const variants: { name: string; url: string; kind: "sig" | "exp" | "other" }[] = [
    { name: "signature-stripped", url: rebuild(u, (q) => { for (const k of SIG_KEYS) q.delete(k); }), kind: "sig" },
    { name: "expiry-stripped", url: rebuild(u, (q) => { for (const k of EXPIRY_KEYS) q.delete(k); }), kind: "exp" },
    { name: "signature+expiry-stripped", url: rebuild(u, (q) => { for (const k of [...SIG_KEYS, ...EXPIRY_KEYS]) q.delete(k); }), kind: "sig" },
    { name: "expiry-extended", url: rebuild(u, (q) => { for (const k of EXPIRY_KEYS) if (q.has(k)) q.set(k, "604800"); }), kind: "exp" },
    { name: "signature-garbage", url: rebuild(u, (q) => { if (q.has("X-Amz-Signature")) q.set("X-Amz-Signature", "0".repeat(64)); else if (q.has("sig")) q.set("sig", "AAAA"); }), kind: "sig" },
    { name: "path-case-changed", url: (() => { const c = new URL(u.href); c.pathname = c.pathname.replace(/[^/]+$/, (s) => s.toUpperCase()); return c.href; })(), kind: "other" },
    { name: "path-dot-segment", url: (() => { const c = new URL(u.href); c.pathname = c.pathname.replace(/\/[^/]+$/, (s) => `${s}/..${s}`); return c.href; })(), kind: "other" },
    { name: "query-reordered", url: (() => { const c = new URL(u.href); const entries = [...c.searchParams.entries()].reverse(); c.search = ""; for (const [k, v] of entries) c.searchParams.append(k, v); return c.href; })(), kind: "other" },
  ];

  for (const v of variants) {
    const r = await get(v.url);
    const ok = realContent(r.status, r.body);
    let verdict: SignedVerdict = "blocked";
    let evidence = `${r.status}, ${r.bytes}B${ERROR_BODY.test(r.body) ? ` (${ERROR_BODY.exec(r.body)?.[0]})` : ""}`;
    if (ok) {
      verdict = v.kind === "sig" ? "signature-ignored" : v.kind === "exp" ? "expiry-ignored" : "unchecked";
      if (v.kind === "other") verdict = "intact";
      evidence = `${r.status}, ${r.bytes}B served without valid ${v.kind === "sig" ? "signature" : v.kind === "exp" ? "expiry" : "identifier"}`;
    }
    cases.push({ name: v.name, status: r.status, bytes: r.bytes, verdict, evidence });
  }

  const exploitable = cases.some((c) => c.verdict === "signature-ignored" || c.verdict === "expiry-ignored");
  const body = JSON.stringify({ url: input.url, signed, cases, exploitable }, null, 2);
  const artifact = await writeArtifact(input.outputRoot, "signed_url.json", body);
  return { signed, cases, exploitable, artifacts: [artifact] };
};
