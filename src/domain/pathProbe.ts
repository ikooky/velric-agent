import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

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
  readonly catchAllClusters?: { signature: string; count: number; representative: string }[];
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

/** Body signature robust to embedded random tokens: bucket by length bands +
 *  structural markers (json/html/text) rather than exact bytes. */
const bodySignature = (status: number, bytes: number, contentType: string, body: string): string => {
  const kind = contentType.includes("json") ? "json" : contentType.includes("html") ? "html" : "other";
  const band = bytes < 512 ? "s" : bytes < 2048 ? "m" : bytes < 16384 ? "l" : "xl";
  const marker = kind === "json"
    ? (body.match(/"(?:error|message|code|msg|status)"\s*:/) ?? [""])[0]
    : kind === "html"
      ? (body.match(/<(?:title|h1)[^>]*>([^<]{0,60})/) ?? [""])[0]
      : "";
  return `${status}:${kind}:${band}:${marker}`;
};

export const probePaths = async (input: PathProbeInput): Promise<PathProbeResult> => {
  const base = input.baseUrl.startsWith("http") ? input.baseUrl : `https://${input.baseUrl}`;
  await mkdir(input.outputRoot, { recursive: true });
  const opts = { cookie: input.cookie, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10000 };
  // Signature tally for catch-all route clustering (post-hoc).
  const sigCounts = new Map<string, number>();

  // Soft-404 calibration: 3 random paths → consensus signature + real byte
  // sizes (exact, not band midpoints — used for the size-proximity guard).
  // Baseline pages can render in more than one shape: some platforms answer
  // unknown top-level paths with a "not found" page but rewrite dot-file-ish
  // names to the HOME page (Shopify: 430KB 404 title vs 715KB home title).
  // Both shapes are catch-alls — collect the baseline <title> set as a second
  // discriminator so a home-rewrite never scores as a sensitive-path hit.
  const baselineSigs = new Set<string>();
  const baselineTitles = new Set<string>();
  let baselineBytes = 0;
  let baselineN = 0;
  const titleOf = (body: string): string =>
    (body.match(/<title[^>]*>([^<]{0,120})<\/title>/i)?.[1] ?? "").trim().toLowerCase();
  const BASELINE_RANDOM_PATHS = ["/zzqq-velric-404-a", "/zzqq-velric-404-b", "/zzqq-velric-404-c"];
  for (const rnd of BASELINE_RANDOM_PATHS) {
    const r = await fetchUrl(base + rnd, opts);
    if (r.status > 0) {
      baselineSigs.add(bodySignature(r.status, r.bytes, r.contentType, r.body));
      const bt = titleOf(r.body);
      if (bt !== "") baselineTitles.add(bt);
      baselineBytes += r.bytes;
      baselineN += 1;
    }
  }
  // Direct home-page shape: fetch "/" once — a probe path whose body title
  // equals the HOME title (and is HTML) is a home-rewrite catch-all too.
  try {
    const home = await fetchUrl(base + "/", opts);
    const ht = titleOf(home.body);
    if (home.status > 0 && ht !== "") baselineTitles.add(ht);
  } catch { /* home fetch failure: title channel simply stays smaller */ }
  const soft404Signature = baselineSigs.size > 0 ? [...baselineSigs] : null;
  const soft404Bytes = baselineN > 0 ? Math.round(baselineBytes / baselineN) : null;
  const soft404StatusBytes = soft404Signature
    ? (() => {
        const first = soft404Signature[0]!.split(":");
        // Signature carries a size BAND (s/m/l/xl), not exact bytes — report
        // the band midpoint so the artifact stops claiming a fake 0.
        const band = first[2] ?? "m";
        const bandBytes = band === "s" ? 256 : band === "m" ? 1024 : band === "l" ? 8192 : 32768;
        return { status: Number(first[0]), bytes: bandBytes };
      })()
    : null;

  const paths = input.paths ?? SENSITIVE_PATHS;
  const concurrency = input.concurrency ?? 8;
  const found: PathProbeResult["found"] = [];
  const probed = { n: 0 };
  let cursor = 0;
  const worker = async (): Promise<void> => {
    while (cursor < paths.length) {
      const p = paths[cursor++];
      if (p === undefined) continue;
      const r = await fetchUrl(base + p, opts);
      probed.n++;
      if (r.status === 0) continue;
      const respSig = bodySignature(r.status, r.bytes, r.contentType, r.body);
      // Rule: 200-family that matches the soft-404 shape = not a finding —
      // BUT only when the body LENGTH is also close (within 2.5x): the band
      // signature intentionally coarsens sizes, so a 300B error JSON and a
      // 12KB real endpoint page can share a signature. Size proximity keeps
      // distinct real pages that merely share a band out of the drop.
      if (r.status >= 200 && r.status < 300 && soft404Signature?.includes(respSig)
        && soft404Bytes !== null && soft404Bytes > 0 && r.bytes > 0
        && (r.bytes / soft404Bytes < 2.5 && soft404Bytes / r.bytes < 2.5)) continue;
      // Second shape channel: HTML whose <title> matches a baseline page
      // (random-404 or home) is that catch-all page wearing a different size
      // band — the Shopify-style home rewrite. Real endpoints (JSON, XML,
      // distinct titles) are never affected by this rule.
      if (r.status >= 200 && r.status < 300 && r.contentType.includes("html") && baselineTitles.size > 0) {
        const t = titleOf(r.body);
        if (t !== "" && baselineTitles.has(t)) continue;
      }
      // Third shape channel: redirect-followed responses that landed on a
      // path OTHER than the probed one are platform rewrites (e.g.
      // /dump.sql → 301 → /{username} profile). Following fetch records the
      // FINAL body/status; if finalUrl differs from the probe path, the hit
      // is a rewrite, not the sensitive endpoint.
      if (r.finalUrl) {
        let finalPath = "";
        try { finalPath = new URL(r.finalUrl).pathname; } catch { /* keep */ }
        const probedPath = p.replace(/\/$/, "");
        if (finalPath !== "" && finalPath.replace(/\/$/, "") !== probedPath) {
          found.push({ path: `${p}  [redirectrw: → ${finalPath}]`, status: r.status, bytes: r.bytes, contentType: r.contentType.slice(0, 60), signature: respSig });
          continue;
        }
      }
      if (r.status === 404 || r.status === 410) continue;
      // 401/403 are interesting (path exists, protected) — record with flag
      sigCounts.set(respSig, (sigCounts.get(respSig) ?? 0) + 1);
      // Wildcard-route suspect: page <title> echoes the probed segment
      // (e.g. a /{owner} route renders the segment as a profile page) —
      // a /{owner}-style catch-all rendering this name, not the sensitive
      // endpoint we probed for. Flag for review instead of dropping.
      let flag = "";
      const seg = p.replace(/\/$/, "").split("/").pop() ?? p;
      const title = r.body.match(/<title[^>]*>([^<]{0,120})<\/title>/i)?.[1] ?? "";
      if (title.toLowerCase().includes(seg.toLowerCase())) {
        flag = `  [wildcard-suspect: title echoes "${seg}" — likely /{param} route]`;
      }
      found.push({ path: p + flag, status: r.status, bytes: r.bytes, contentType: r.contentType.slice(0, 60), signature: respSig });
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, paths.length) }, worker));

  // Wildcard/catch-all clustering: a body signature shared by >= 6 distinct
  // probe paths is a catch-all route rendering the same page (e.g. /{owner}).
  // Keep ONE representative finding + a cluster note instead of N false hits.
  const CATCHALL_THRESHOLD = 6;
  const catchAllSigs = new Set([...sigCounts.entries()].filter(([, n]) => n >= CATCHALL_THRESHOLD).map(([sig]) => sig));
  const clusters: { signature: string; count: number; representative: string }[] = [];
  if (catchAllSigs.size > 0) {
    for (const sig of catchAllSigs) {
      const members = found.filter((f) => f.signature === sig);
      const rep = members[0]!;
      clusters.push({ signature: sig, count: members.length, representative: rep.path });
      // drop all members, re-add one flagged representative
      for (const m of members) {
        const idx = found.indexOf(m);
        if (idx >= 0) found.splice(idx, 1);
      }
      found.push({ ...rep, path: `${rep.path}  [catch-all ×${members.length}: same page for ${members.length} probe paths]` });
    }
  }
  // Keep f.signature in the RETURNED structure (scanPlatform assets read
  // meta.signature); the .txt artifact below never included it anyway.
  found.sort((a, b) => a.path.localeCompare(b.path));

  const path = join(input.outputRoot, "sensitive_paths.txt");
  const body = found.map((f) => `${f.status}\t${f.path}\t${f.bytes}b\t${f.contentType}`).join("\n");
  await writeFile(path, body);
  return {
    baseUrl: base,
    probed: probed.n,
    found,
    soft404: soft404StatusBytes,
    catchAllClusters: clusters,
    artifacts: [{ path, bytes: Buffer.byteLength(body) }],
  };
};
