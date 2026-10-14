import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

/** OAuth2/OIDC/SAML configuration discovery and weakness checks: standard
 *  well-known endpoints, then static checks (PKCE support hints, implicit
 *  flow grants, state/nonce enforcement are dynamic — record config only). */

export interface OidcProbeInput {
  readonly baseUrl: string;
  readonly outputRoot: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}

export interface OidcProbeResult {
  readonly baseUrl: string;
  readonly found: {
    kind: "oidc" | "oauth" | "saml";
    url: string;
    config: Record<string, unknown>;
  }[];
  readonly findings: { severity: "high" | "medium" | "low"; issue: string; detail: string }[];
  readonly artifacts: { path: string; bytes: number }[];
}

const WELL_KNOWN: { kind: "oidc" | "oauth" | "saml"; path: string }[] = [
  { kind: "oidc", path: "/.well-known/openid-configuration" },
  { kind: "oauth", path: "/.well-known/oauth-authorization-server" },
  { kind: "saml", path: "/saml/metadata" },
  { kind: "saml", path: "/shibboleth" },
];

export const probeOidc = async (input: OidcProbeInput): Promise<OidcProbeResult> => {
  const base = input.baseUrl.replace(/\/$/, "");
  await mkdir(input.outputRoot, { recursive: true });
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10000 };
  const found: OidcProbeResult["found"] = [];
  const findings: OidcProbeResult["findings"] = [];

  for (const wk of WELL_KNOWN) {
    const r = await fetchUrl(base + wk.path, opts);
    if (r.status !== 200) continue;
    const body = r.body.trim();
    if (wk.kind === "saml") {
      if (!body.includes("EntityDescriptor") && !body.includes("md:")) continue;
      found.push({ kind: wk.kind, url: r.url, config: { xml: body.slice(0, 4000) } });
      continue;
    }
    try {
      const cfg = JSON.parse(body) as Record<string, unknown>;
      if (typeof cfg.issuer !== "string") continue;
      found.push({ kind: wk.kind, url: r.url, config: cfg });

      // Static weakness checks from the discovered configuration.
      const grants = Array.isArray(cfg.grant_types_supported) ? cfg.grant_types_supported.map(String) : [];
      if (grants.includes("implicit")) {
        findings.push({ severity: "high", issue: "implicit flow enabled", detail: "token returned via front-channel URL fragment" });
      }
      const resp = Array.isArray(cfg.response_modes_supported) ? cfg.response_modes_supported.map(String) : [];
      if (resp.includes("fragment")) {
        findings.push({ severity: "medium", issue: "fragment response mode supported", detail: "token leakage via browser history/referrer" });
      }
      const pkce = Array.isArray(cfg.code_challenge_methods_supported) ? cfg.code_challenge_methods_supported.map(String) : [];
      if (grants.includes("authorization_code") && pkce.length === 0) {
        findings.push({ severity: "medium", issue: "PKCE not advertised", detail: "authorization_code without code_challenge_methods" });
      }
      const scopes = typeof cfg.scopes_supported === "object" && Array.isArray(cfg.scopes_supported) ? cfg.scopes_supported.map(String) : [];
      if (scopes.some((s) => /offline|refresh/i.test(s))) {
        findings.push({ severity: "low", issue: "offline/refresh scopes exposed", detail: scopes.filter((s) => /offline|refresh/i.test(s)).join(", ") });
      }
    } catch {
      /* not JSON */
    }
  }

  const result: OidcProbeResult = { baseUrl: base, found, findings, artifacts: [] };
  if (found.length > 0 || findings.length > 0) {
    const path = join(input.outputRoot, "oidc_probe.json");
    const body = JSON.stringify(result, null, 2);
    await writeFile(path, body);
    result.artifacts.push({ path, bytes: Buffer.byteLength(body) });
  }
  return result;
};
