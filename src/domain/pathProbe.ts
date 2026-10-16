import { fetchUrl, type FetchResult } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";
import { randomUUID } from "node:crypto";

/** Sensitive-path probing with soft-404 calibration: a random-path baseline is
 *  taken first; responses isomorphic to the baseline (same status + same body
 *  signature) are treated as the 404 page, not a finding. No calibration =
 *  all false positives; calibration is the whole point. */

export interface PathProbeInput {
  readonly baseUrl: string;
  readonly outputRoot: string;
  readonly paths?: string[];
  readonly cookie?: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly concurrency?: number;
}

export interface PathProbeResult {
  readonly baseUrl: string;
  readonly probed: number;
  readonly found: { path: string; status: number; bytes: number; contentType: string; signature?: string }[];
  readonly soft404: { status: number; bytes: number } | null;
  /** Catch-all route clusters (same body signature across many probe paths). */
  readonly catchAllClusters?: { signature: string; count: number; representative: string; members: string[] }[];
  readonly artifacts: { path: string; bytes: number }[];
}

/** High-signal sensitive paths. Keep it tight: 60 paths × fast baseline beat
 *  5000-path dumps on both speed and precision. */
export const SENSITIVE_PATHS: readonly string[] = [
  "/.git/config", "/.git/HEAD", "/.svn/entries", "/.DS_Store", "/.env", "/.env.local",
  "/.env.production", "/config.php.bak", "/web.config", "/robots.txt",
  "/crossdomain.xml", "/clientaccesspolicy.xml", "/phpinfo.php", "/info.php",
  "/server-status", "/server-info", "/.htaccess", "/.htpasswd",
  "/swagger", "/swagger/", "/swagger-ui", "/swagger-ui.html", "/swagger.json",
  "/api-docs", "/api-docs/swagger.json", "/v2/api-docs", "/v3/api-docs",
  "/openapi.json", "/openapi.yaml", "/api/openapi.json", "/graphql",
  "/actuator", "/actuator/health", "/actuator/env", "/actuator/heapdump",
  "/actuator/configprops", "/actuator/beans", "/druid/", "/druid/index.html",
  "/druid/login.html", "/console/", "/admin/", "/manager/html", "/manager/status",
  "/debug/pprof", "/debug/pprof/", "/debug/vars", "/metrics", "/health",
  "/status", "/_cat/indices", "/es/_cat/indices", "/solr/admin",
  "/backup.sql", "/backup.zip", "/dump.sql", "/db.sql", "/database.sql",
  "/WEB-INF/web.xml", "/META-INF/", "/composer.json", "/package.json",
  "/.well-known/security.txt", "/sitemap.xml", "/sitemap_index.xml",
  "/.well-known/openid-configuration",
  "/.well-known/oauth-authorization-server",
  "/saml/metadata",
];

/** Probe URLs are always resolved against the origin, never string-concatenated. */
export const discoveryOrigin = (raw: string): string => {
  const u = new URL(/^[a-z][a-z0-9+.-]*:/i.test(raw) ? raw : `https://${raw}`);
  if (!/^https?:$/.test(u.protocol) || u.username || u.password) throw new Error("invalid discovery origin");
  return u.origin;
};
export const discoveryUrl = (origin: string, path: string): string | null => {
  if (typeof path !== "string" || !path || /[\\\x00-\x20\x7f]/.test(path)) return null;
  try {
    const u = new URL(path, `${origin}/`);
    if (u.origin !== origin || u.username || u.password || u.hash) return null;
    return u.href;
  } catch { return null; }
};

/** Exact stable content plus transport/type/shape; similarity alone is not exclusion evidence. */
export const discoverySignature = (r: FetchResult): string => JSON.stringify([
  r.status, r.contentType.split(";")[0]!.trim().toLowerCase(), r.sha256, r.bytes,
  r.body.trim() ? r.body.trim().split(/\s+/).length : 0, r.body.split("\n").length,
  r.headers.location ?? "",
]);
export const stableDiscoverySignatures = (responses: readonly FetchResult[]): Set<string> => {
  const counts = new Map<string, number>();
  for (const r of responses) {
    if (!r.status || r.complete === false || r.truncated || r.error) continue;
    const sig = discoverySignature(r); counts.set(sig, (counts.get(sig) ?? 0) + 1);
  }
  return new Set([...counts].filter(([, n]) => n >= 2).map(([sig]) => sig));
};

export const probePaths = async (input: PathProbeInput): Promise<PathProbeResult> => {
  const base = discoveryOrigin(input.baseUrl);
  const opts = { cookie: input.cookie, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10000, redirect: "manual" as const };
  const baselines: FetchResult[] = [];
  for (let i = 0; i < 3; i++) baselines.push(await fetchUrl(new URL(`/zzqq-${randomUUID()}`, base).href, opts));
  const stable = stableDiscoverySignatures(baselines);
  const soft = baselines.find(r => stable.has(discoverySignature(r)));
  const paths = input.paths ?? SENSITIVE_PATHS;
  const found: PathProbeResult["found"] = [];
  let probed = 0, cursor = 0;
  const worker = async (): Promise<void> => {
    while (cursor < paths.length) {
      const p = paths[cursor++];
      const url = p === undefined ? null : discoveryUrl(base, p);
      if (!url) continue;
      const r = await fetchUrl(url, opts); probed++;
      if (!r.status || r.status === 404 || r.status === 410 || r.complete === false || r.truncated || r.error) continue;
      const signature = discoverySignature(r);
      if (r.status >= 200 && r.status < 300 && stable.has(signature)) continue;
      const u = new URL(url);
      found.push({ path: `${u.pathname}${u.search}`, status: r.status, bytes: r.bytes, contentType: r.contentType, signature });
    }
  };
  const concurrency = Number.isFinite(input.concurrency) ? Math.max(1, Math.min(32, Math.floor(input.concurrency!))) : 8;
  await Promise.all(Array.from({ length: Math.min(concurrency, paths.length) }, worker));
  found.sort((a, b) => a.path.localeCompare(b.path));
  const groups = new Map<string, string[]>();
  for (const f of found) { const members = groups.get(f.signature!) ?? []; members.push(f.path); groups.set(f.signature!, members); }
  const clusters = [...groups].filter(([, members]) => members.length >= 3).map(([signature, members]) => ({ signature, count: members.length, representative: members[0]!, members }));
  const body = found.map(f => `${f.status}\t${f.path}\t${f.bytes}b\t${f.contentType}`).join("\n");
  const art = await writeArtifact(input.outputRoot, "sensitive_paths.txt", body);
  return { baseUrl: base, probed, found, soft404: soft ? { status: soft.status, bytes: soft.bytes } : null, catchAllClusters: clusters, artifacts: [art] };
};
