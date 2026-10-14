import { resolveHost } from "./application/dns.js";
import { httpProbe } from "./application/probe.js";
import { harvestStatic } from "./application/harvest.js";
import { spiderMpa } from "./application/spider.js";
import { buildPermissionTree } from "./application/permTreeService.js";
import { mergeParamSamples } from "./application/paramMerge.js";
import { captureRuntime } from "./application/runtime.js";
import { DEFAULT_HOOK_CONFIG } from "./domain/preload.js";
import { PRODUCT_IDENTITY } from "./identity.js";

const num = (v: string | boolean | undefined): number | undefined => {
  if (typeof v !== "string" || v.trim() === "") return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined; // NaN flags silently corrupt timeouts/slices
};

/** Minimal argv parser: command-first, --flag value pairs, --bool flags. */
interface ParsedArgs {
  readonly command: string;
  readonly positional: string[];
  readonly flags: Record<string, string | boolean>;
}

const parseArgs = (argv: readonly string[]): ParsedArgs => {
  const [command = "help", ...rest] = argv;
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = rest[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(a);
    }
  }
  return { command, positional, flags };
};

const USAGE = `velric-agent ${PRODUCT_IDENTITY.packageVersion} — stateless recon toolset (CLI + MCP)

Usage:
  velric-agent mcp                        start the stdio MCP server
  velric-agent dns-resolve <host> [...]   resolve A/AAAA/CNAME
  velric-agent http-probe <url>           probe one URL (status/title/hash)
  velric-agent harvest <url> <outdir>     static SPA bundle harvest
  velric-agent extract-routes <jsdir> <outdir>
  velric-agent spider <url> <outdir>      MPA crawl (--cookie/--max/--depth/--exclude)
  velric-agent runtime <url> <outdir>     headless runtime capture (--chromium/--routes/--wait/--per-route/--api-pattern)
  velric-agent perm-tree <jsdir> <outdir> permission tree rebuild (--role NAME)
  velric-agent merge-params <samples.json> <outdir>
  velric-agent enrich <seed...> --out DIR        asset graph from seeds (DNS+HTTP)
  velric-agent gen-report <report.json> <outdir> render findings markdown report
  velric-agent save-evidence <items.json> <outdir> content-addressed evidence blobs
  velric-agent auto <seed> <outdir>            deterministic pipeline (+subdomains/paths/cors/fingerprint/sourcemaps; --fresh 重跑; checkpoint 断点续跑)
  velric-agent run-diff <oldDir> <newDir>      diff two recon runs (attack-surface monitoring)
  velric-agent probe-params <params_merged.json> <outdir>
                                               per-param differential probe (--max N)
  velric-agent subdomains <domain> <outdir>     subdomain enum (crt.sh + CNAME + wordlist)
  velric-agent port-scan <host> <outdir>        TCP top-ports scan (--ports/--timeout)
  velric-agent paths <baseUrl> <outdir>         sensitive paths w/ soft-404 calibration
  velric-agent cors <baseUrl> <outdir>          CORS misconfiguration probe
  velric-agent fingerprint <baseUrl> <outdir>   WAF/CDN id + method enum + cookie audit
  velric-agent wayback <domain> <outdir>        historical URLs from web.archive.org
  velric-agent sourcemaps <jsDir> <outdir>      source-map leak detection (--base URL)
  velric-agent auto-batch <seeds.txt> <outdir>  batch pipeline + summary (--notify URL)
  velric-agent auth-probe <api_merged.txt> <outdir>  anonymous vs auth access mapping
  velric-agent idor-prescreen <params_merged.json> <outdir>  IDOR candidate prescreen
  velric-agent git-restore <baseUrl> <outdir>  rebuild source from leaked .git
  velric-agent dom-sinks <jsDir> <outdir>      DOM-XSS taint chain scan
  velric-agent jwt-inspect <outdir>            JWT decode + weak-secret crack
  velric-agent ws-schema <runtime_api.json> <outdir>  WS message field schemas
  velric-agent oidc-probe <baseUrl> <outdir>   OAuth/OIDC/SAML config probe
  velric-agent smuggle-probe <baseUrl> <outdir>  request-smuggling differential
  velric-agent archive-recover <url> <outdir>  blocked-page archive recovery
  velric-agent ws-origin-check <wsUrl> <outdir>  WS cross-origin check (CSWSH)
  velric-agent graphql-deep <endpoint> <outdir>  GraphQL introspection + schema
  velric-agent proto-decode <hex|base64> <outdir>  protobuf heuristic decode
  velric-agent nuclei-lite <baseUrl> <outdir>   template matcher (panels/leaks)
  velric-agent login-replay <url> <u> <p> <outdir>  login + cookie export
  velric-agent backup-unpack <urls.txt> <outdir>  dump unpack + secret scan
  velric-agent sqlite-read <file.db> <outdir>   SQLite leak reader
  velric-agent analyze-gates <jsDir> <outdir>   auth-gate static analysis
  velric-agent coverage <baseUrl> <outdir>     interactive coverage enumeration
  velric-agent site-map <baseUrl> <outdir>     structured site map
  velric-agent traffic-recorder <outdir>       traffic recording proxy
  velric-agent asset-graph <dir> <action>      asset graph store
  velric-agent exploration-graph <dir> <action>  exploration lineage graph
  velric-agent evidence <dir> <action>         evidence blob store
  velric-agent cold-graph <dir> <action>       exploration graph compaction
  velric-agent retest <dir> <action>           finding retest lifecycle
  velric-agent traffic-query <dir> <action>    traffic search/get
  velric-agent export-findings <f> <dir> <fmt> findings csv/json/md export
  velric-agent evidence-bind <dir> <action>     evidence binding lifecycle
  velric-agent help

Common flags: --proxy URL | --proxy-pool FILE, --rps N (global rate limit), --cookie STR, --timeout MS
`;


/** Resolve effective proxy: --proxy single URI, or round-robin from
 *  --proxy-pool <file>. Applies global --rps when set. */
let poolState: { pool: import("./domain/proxyPool.js").ProxyPool } | null = null;
const resolveProxy = async (flags: Record<string, string | boolean | undefined>): Promise<string | undefined> => {
  const { setGlobalRateLimit } = await import("./adapters/http.js");
  if (typeof flags.rps === "string" && Number(flags.rps) > 0) setGlobalRateLimit(Number(flags.rps));
  if (typeof flags.proxy === "string") return flags.proxy;
  if (typeof flags["proxy-pool"] === "string") {
    if (!poolState) {
      const { ProxyPool } = await import("./domain/proxyPool.js");
      poolState = { pool: await ProxyPool.fromFile(flags["proxy-pool"]) };
    }
    return poolState.pool.next() ?? undefined;
  }
  return undefined;
};

/** Run one CLI command; returns the process exit code. */
export const runCli = async (argv: readonly string[]): Promise<number> => {
  const { command, positional, flags } = parseArgs(argv);
  const out = (v: unknown) => console.log(JSON.stringify(v, null, 2));
  try {
    switch (command) {
      case "mcp":
      case "--mcp":
        console.error("use `velric-agent mcp` (handled by the bin shim)");
        return 2;
      case "help":
      case "--help":
      case "-h":
        console.log(USAGE);
        return 0;
      case "dns-resolve": {
        if (positional.length === 0) {
          console.error("usage: dns-resolve <host> [...]");
          return 2;
        }
        const results = [];
        for (const host of positional) results.push(await resolveHost(host));
        out({ results });
        return 0;
      }
      case "http-probe": {
        const url = positional[0];
        if (!url) {
          console.error("usage: http-probe <url>");
          return 2;
        }
        out(
          await httpProbe({
            url,
            cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
            proxy: await resolveProxy(flags),
            timeoutMs: typeof flags.timeout === "string" ? Number(flags.timeout) : undefined,
          }),
        );
        return 0;
      }
      case "harvest": {
        const [base, dir] = positional;
        if (!base || !dir) {
          console.error("usage: harvest <url> <outdir>");
          return 2;
        }
        out(
          await harvestStatic({
            baseUrl: base,
            outputRoot: dir,
            proxy: await resolveProxy(flags),
            cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
            timeoutMs: typeof flags.timeout === "string" ? Number(flags.timeout) : undefined,
          }),
        );
        return 0;
      }
      case "extract-routes": {
        const [jsDir, dir] = positional;
        if (!jsDir || !dir) {
          console.error("usage: extract-routes <jsdir> <outdir>");
          return 2;
        }
        const { readJsCorpus } = await import("./application/harvest.js");
        const { writeArtifact } = await import("./adapters/artifacts.js");
        const { classifyPaths, extractPathLiterals, extractRoutes } = await import(
          "./domain/endpoints.js"
        );
        const corpus = await readJsCorpus(jsDir);
        if (corpus.length === 0) {
          console.error(`no .js files under ${jsDir}`);
          return 1;
        }
        const api = new Set<string>();
        const other = new Set<string>();
        const routes = new Set<string>();
        for (const f of corpus) {
          const c = classifyPaths(extractPathLiterals(f.text));
          for (const p of c.api) api.add(p);
          for (const p of c.other) other.add(p);
          for (const r of extractRoutes(f.text)) routes.add(r);
        }
        await writeArtifact(dir, "api_static.txt", [...api].sort().join("\n"));
        await writeArtifact(dir, "paths_other.txt", [...other].sort().join("\n"));
        await writeArtifact(dir, "routes.txt", [...routes].sort().join("\n"));
        out({ files: corpus.length, api: api.size, other: other.size, routes: routes.size });
        return 0;
      }
      case "spider": {
        const [base, dir] = positional;
        if (!base || !dir) {
          console.error("usage: spider <url> <outdir>");
          return 2;
        }
        out(
          await spiderMpa({
            baseUrl: base,
            outputRoot: dir,
            cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
            proxy: await resolveProxy(flags),
            maxPages: typeof flags.max === "string" ? Number(flags.max) : undefined,
            depth: typeof flags.depth === "string" ? Number(flags.depth) : undefined,
            exclude: typeof flags.exclude === "string" ? flags.exclude : undefined,
          }),
        );
        return 0;
      }
      case "runtime": {
        const [base, dir] = positional;
        if (!base || !dir) {
          console.error(
            "usage: runtime <url> <outdir> [--chromium PATH] [--routes /a,/b] [--wait MS] [--per-route MS] [--route-timeout MS] [--api-pattern RE] [--headless false] [--proxy URL]",
          );
          return 2;
        }
        const strList = (v: string | boolean | undefined): string[] | undefined =>
          typeof v === "string" && v.trim() !== ""
            ? v.split(",").map((s) => s.trim()).filter(Boolean)
            : undefined;
        out(
          await captureRuntime({
            baseUrl: base,
            outputRoot: dir,
            chromiumPath: typeof flags.chromium === "string" ? flags.chromium : undefined,
            proxy: await resolveProxy(flags),
            routes: strList(flags.routes),
            maxRoutes: num(flags["max-routes"]),
            waitMs: num(flags.wait),
            perRouteMs: num(flags["per-route"]),
            routeTimeoutMs: num(flags["route-timeout"]),
            headless: flags.headless === "false" ? false : undefined,
            hook: typeof flags["api-pattern"] === "string"
              ? { ...DEFAULT_HOOK_CONFIG, apiPattern: flags["api-pattern"] }
              : undefined,
          }),
        );
        return 0;
      }
      case "perm-tree": {
        const [jsDir, dir] = positional;
        if (!jsDir || !dir) {
          console.error("usage: perm-tree <jsdir> <outdir> [--role NAME]");
          return 2;
        }
        out(
          await buildPermissionTree({
            jsDir,
            outputRoot: dir,
            role: typeof flags.role === "string" ? flags.role : undefined,
          }),
        );
        return 0;
      }
      case "merge-params": {
        const [samples, dir] = positional;
        if (!samples || !dir) {
          console.error("usage: merge-params <samples.json> <outdir>");
          return 2;
        }
        out(await mergeParamSamples({ samplesFile: samples, outputRoot: dir }));
        return 0;
      }
      case "enrich": {
        const seeds = positional.filter((p) => !p.startsWith("-"));
        const dir = flags.out as string | undefined;
        if (seeds.length === 0 || !dir) {
          console.error("usage: enrich <seed...> --out DIR [--no-http] [--proxy URL] [--cookie STR] [--timeout MS]");
          return 2;
        }
        const { enrichAssets } = await import("./application/enrich.js");
        out(
          await enrichAssets({
            seeds,
            outputRoot: dir,
            proxy: await resolveProxy(flags),
            cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
            timeoutMs: num(flags.timeout),
            http: flags["no-http"] !== true,
          }),
        );
        return 0;
      }
      case "gen-report": {
        const [reportJson, dir] = positional;
        if (!reportJson || !dir) {
          console.error("usage: gen-report <report.json> <outdir>");
          return 2;
        }
        const { readFile } = await import("node:fs/promises");
        const { generateReport } = await import("./application/report.js");
        const content = await readFile(reportJson, "utf8");
        out(await generateReport({ reportJson: content, outputRoot: dir }));
        return 0;
      }
      case "save-evidence": {
        const [inFile, dir] = positional;
        if (!inFile || !dir) {
          console.error("usage: save-evidence <items.json> <outdir>   (items: [{source,label?,content}])");
          return 2;
        }
        const { readFile } = await import("node:fs/promises");
        const { saveEvidence } = await import("./application/evidence.js");
        const items = JSON.parse(await readFile(inFile, "utf8")) as {
          source: string; label?: string; content: string;
        }[];
        out(await saveEvidence({ outputRoot: dir, items }));
        return 0;
      }
      case "auto": {
        const [seed, dir] = positional;
        if (!seed || !dir) {
          console.error("usage: auto <seed> <outdir> [--chromium PATH] [--skip-runtime] [--proxy URL] [--cookie STR] [--timeout MS] [--max-pages N]");
          return 2;
        }
        const { runAutoPipeline } = await import("./application/auto.js");
        out(
          await runAutoPipeline({
            seed,
            outputRoot: dir,
            chromiumPath: typeof flags.chromium === "string" ? flags.chromium : undefined,
            proxy: await resolveProxy(flags),
            cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
            timeoutMs: num(flags.timeout),
            skipRuntime: flags["skip-runtime"] === true,
            maxPages: num(flags["max-pages"]),
            resume: flags.fresh !== true,
          }),
        );
        return 0;
      }
      case "run-diff": {
        const [oldRoot, newRoot] = positional;
        if (!oldRoot || !newRoot) {
          console.error("usage: run-diff <oldOutdir> <newOutdir>");
          return 2;
        }
        const { runDiff } = await import("./application/runDiff.js");
        out(await runDiff({ oldRoot, newRoot }));
        return 0;
      }
      case "probe-params": {
        const [mergedFile, dir] = positional;
        if (!mergedFile || !dir) {
          console.error("usage: probe-params <params_merged.json> <outdir> [--max N] [--cookie STR]");
          return 2;
        }
        const { probeParams } = await import("./application/paramProbe.js");
        out(
          await probeParams({
            mergedFile,
            outputRoot: dir,
            cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
            proxy: await resolveProxy(flags),
            timeoutMs: num(flags.timeout),
            maxEndpoints: num(flags.max),
          }),
        );
        return 0;
      }
      case "subdomains": {
        const [domain, dir] = positional;
        if (!domain || !dir) {
          console.error("usage: subdomains <domain> <outdir> [--wordlist FILE]");
          return 2;
        }
        const { discoverSubdomains } = await import("./domain/subdomains.js");
        out(await discoverSubdomains({ domain, outputRoot: dir, proxy: await resolveProxy(flags) }));
        return 0;
      }
      case "port-scan": {
        const [host, dir] = positional;
        if (!host || !dir) {
          console.error("usage: port-scan <host|ip> <outdir> [--ports 80,443 [--timeout MS] [--concurrency N]");
          return 2;
        }
        const ports = typeof flags.ports === "string" ? flags.ports.split(",").map((x) => Number(x.trim())).filter((n) => n > 0) : undefined;
        const { scanPorts } = await import("./domain/portScan.js");
        out(await scanPorts({ host, outputRoot: dir, ports, timeoutMs: num(flags.timeout), concurrency: num(flags.concurrency) }));
        return 0;
      }
      case "paths": {
        const [base, dir] = positional;
        if (!base || !dir) {
          console.error("usage: paths <baseUrl> <outdir> [--paths FILE] [--cookie STR]");
          return 2;
        }
        const { probePaths } = await import("./domain/pathProbe.js");
        out(await probePaths({ baseUrl: base, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, proxy: await resolveProxy(flags) }));
        return 0;
      }
      case "cors": {
        const [base, dir] = positional;
        if (!base || !dir) {
          console.error("usage: cors <baseUrl> <outdir>");
          return 2;
        }
        const { probeCors } = await import("./domain/cors.js");
        out(await probeCors({ baseUrl: base, outputRoot: dir, proxy: await resolveProxy(flags) }));
        return 0;
      }
      case "fingerprint": {
        const [base, dir] = positional;
        if (!base || !dir) {
          console.error("usage: fingerprint <baseUrl> <outdir>");
          return 2;
        }
        const { fingerprint } = await import("./domain/fingerprint.js");
        out(await fingerprint({ baseUrl: base, outputRoot: dir, proxy: await resolveProxy(flags) }));
        return 0;
      }
      case "wayback": {
        const [target, dir] = positional;
        if (!target || !dir) {
          console.error("usage: wayback <domain> <outdir> [--max N]");
          return 2;
        }
        const { fetchWayback } = await import("./domain/sourcemap.js");
        out(await fetchWayback({ target, outputRoot: dir, maxUrls: num(flags.max), proxy: await resolveProxy(flags) }));
        return 0;
      }
      case "sourcemaps": {
        const [dir, outDir] = positional;
        if (!dir || !outDir) {
          console.error("usage: sourcemaps <jsDir> <outdir> [--base URL]");
          return 2;
        }
        const { detectSourceMaps } = await import("./domain/sourcemap.js");
        out(await detectSourceMaps({ outputRoot: outDir, jsDir: dir, baseUrl: typeof flags.base === "string" ? flags.base : undefined, proxy: await resolveProxy(flags) }));
        return 0;
      }
      case "auto-batch": {
        const [seedsFile, dir] = positional;
        if (!seedsFile || !dir) {
          console.error("usage: auto-batch <seeds.txt> <outdir> [--chromium PATH] [--skip-runtime] [--notify URL]");
          return 2;
        }
        const { runBatch } = await import("./application/batch.js");
        out(await runBatch({
          seedsFile, outputRoot: dir,
          chromiumPath: typeof flags.chromium === "string" ? flags.chromium : undefined,
          proxy: await resolveProxy(flags),
          cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
          skipRuntime: flags["skip-runtime"] === true,
          notifyWebhook: typeof flags.notify === "string" ? flags.notify : undefined,
        }));
        return 0;
      }
      case "auth-probe": {
        const [endpointsFile, dir] = positional;
        if (!endpointsFile || !dir) {
          console.error("usage: auth-probe <api_merged.txt> <outdir> [--cookie STR]");
          return 2;
        }
        const { probeAuth } = await import("./domain/authProbe.js");
        out(await probeAuth({ endpointsFile, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, proxy: await resolveProxy(flags) }));
        return 0;
      }
      case "idor-prescreen": {
        const [mergedFile, dir] = positional;
        if (!mergedFile || !dir) {
          console.error("usage: idor-prescreen <params_merged.json> <outdir> [--cookie STR]");
          return 2;
        }
        const { prescreenIdor } = await import("./domain/authProbe.js");
        out(await prescreenIdor({ mergedFile, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, proxy: await resolveProxy(flags) }));
        return 0;
      }
      case "git-restore": {
        const [base, dir] = positional;
        if (!base || !dir) {
          console.error("usage: git-restore <baseUrl> <outdir>");
          return 2;
        }
        const { restoreGit } = await import("./domain/gitRestore.js");
        out(await restoreGit({ baseUrl: base, outputRoot: dir, proxy: await resolveProxy(flags) }));
        return 0;
      }
      case "dom-sinks": {
        const [jsDir, dir] = positional;
        if (!jsDir || !dir) {
          console.error("usage: dom-sinks <jsDir> <outdir>");
          return 2;
        }
        const { scanDomSinks } = await import("./domain/domSinks.js");
        out(await scanDomSinks({ jsDir, outputRoot: dir }));
        return 0;
      }
      case "jwt-inspect": {
        const dir = positional[0];
        if (!dir) {
          console.error("usage: jwt-inspect <outdir> [--secrets FILE] [--js DIR] [--token STR]");
          return 2;
        }
        const { inspectJwt } = await import("./domain/jwt.js");
        out(await inspectJwt({
          outputRoot: dir,
          secretsFile: typeof flags.secrets === "string" ? flags.secrets : undefined,
          jsDir: typeof flags.js === "string" ? flags.js : undefined,
          token: typeof flags.token === "string" ? flags.token : undefined,
        }));
        return 0;
      }
      case "ws-schema": {
        const [runtimeFile, dir] = positional;
        if (!runtimeFile || !dir) {
          console.error("usage: ws-schema <runtime_api.json> <outdir>");
          return 2;
        }
        const { extractWsSchema } = await import("./domain/wsSchema.js");
        out(await extractWsSchema({ runtimeFile, outputRoot: dir }));
        return 0;
      }
      case "oidc-probe": {
        const [b, dir] = positional;
        if (!b || !dir) { console.error("usage: oidc-probe <baseUrl> <outdir>"); return 2; }
        const { probeOidc } = await import("./domain/oidc.js");
        out(await probeOidc({ baseUrl: b, outputRoot: dir, proxy: await resolveProxy(flags) }));
        return 0;
      }
      case "smuggle-probe": {
        const [b, dir] = positional;
        if (!b || !dir) { console.error("usage: smuggle-probe <baseUrl> <outdir>"); return 2; }
        const { probeSmuggle } = await import("./domain/smuggle.js");
        out(await probeSmuggle({ baseUrl: b, outputRoot: dir, proxy: await resolveProxy(flags) }));
        return 0;
      }
      case "archive-recover": {
        const [u, dir] = positional;
        if (!u || !dir) { console.error("usage: archive-recover <url> <outdir>"); return 2; }
        const { recoverUrl } = await import("./domain/archive.js");
        out(await recoverUrl({ url: u, outputRoot: dir, proxy: await resolveProxy(flags) }));
        return 0;
      }
      case "ws-origin-check": {
        const [u, dir] = positional;
        if (!u || !dir) { console.error("usage: ws-origin-check <wsUrl> <outdir>"); return 2; }
        const { probeWsOrigin } = await import("./domain/wsOrigin.js");
        out(await probeWsOrigin({ url: u, outputRoot: dir }));
        return 0;
      }
      case "graphql-deep": {
        const [ep, dir] = positional;
        if (!ep || !dir) { console.error("usage: graphql-deep <endpoint> <outdir> [--prev FILE]"); return 2; }
        const { probeGraphqlDeep } = await import("./domain/graphqlDeep.js");
        out(await probeGraphqlDeep({ endpoint: ep, outputRoot: dir, previousSchemaFile: typeof flags.prev === "string" ? flags.prev : undefined, proxy: await resolveProxy(flags) }));
        return 0;
      }
      case "proto-decode": {
        const [data, dir] = positional;
        if (!data || !dir) { console.error("usage: proto-decode <hex|base64> <outdir> [--enc hex|base64]"); return 2; }
        const { decodeProtoHeuristic } = await import("./domain/protoDecode.js");
        out(await decodeProtoHeuristic({ data, encoding: (flags.enc === "hex" ? "hex" : "base64") as "hex" | "base64", outputRoot: dir }));
        return 0;
      }
      case "nuclei-lite": {
        const [b, dir] = positional;
        if (!b || !dir) { console.error("usage: nuclei-lite <baseUrl> <outdir>"); return 2; }
        const { runNucleiLite } = await import("./domain/nucleiLite.js");
        out(await runNucleiLite({ baseUrl: b, outputRoot: dir, proxy: await resolveProxy(flags) }));
        return 0;
      }
      case "login-replay": {
        const [b, user, pass, dir] = positional;
        if (!b || !user || !pass || !dir) { console.error("usage: login-replay <loginUrl> <user> <pass> <outdir> [--chromium PATH]"); return 2; }
        const { replayLogin } = await import("./domain/loginReplay.js");
        out(await replayLogin({ baseUrl: b, username: user, password: pass, outputRoot: dir, chromiumPath: typeof flags.chromium === "string" ? flags.chromium : undefined, proxy: await resolveProxy(flags) }));
        return 0;
      }
      case "backup-unpack": {
        const [urlFile, dir] = positional;
        if (!urlFile || !dir) { console.error("usage: backup-unpack <urls.txt> <outdir>"); return 2; }
        const { readFile: rf } = await import("node:fs/promises");
        const urls = (await rf(urlFile, "utf8")).split("\n").map((l) => l.trim()).filter(Boolean);
        const { unpackBackups } = await import("./domain/backupUnpack.js");
        out(await unpackBackups({ urls, outputRoot: dir, proxy: await resolveProxy(flags) }));
        return 0;
      }
      case "sqlite-read": {
        const [f, dir] = positional;
        if (!f || !dir) { console.error("usage: sqlite-read <file.db> <outdir>"); return 2; }
        const { readSqlite } = await import("./domain/sqliteRead.js");
        out(await readSqlite({ file: f, outputRoot: dir }));
        return 0;
      }
      case "analyze-gates": {
        const [jsDir, dir] = positional;
        if (!jsDir || !dir) { console.error("usage: analyze-gates <jsDir> <outdir>"); return 2; }
        const { analyzeGates } = await import("./domain/gates.js");
        out(await analyzeGates({ jsDir, outputRoot: dir }));
        return 0;
      }
      case "coverage": {
        const [b, dir] = positional;
        if (!b || !dir) { console.error("usage: coverage <baseUrl> <outdir> [--cookie C] [--chromium P] [--max N]"); return 2; }
        const { runCoverage } = await import("./domain/coverage.js");
        out(await runCoverage({ baseUrl: b, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, chromiumPath: typeof flags.chromium === "string" ? flags.chromium : undefined, maxClicksPerCategory: num(flags.max), proxy: await resolveProxy(flags) }));
        return 0;
      }
      case "site-map": {
        const [b, dir] = positional;
        if (!b || !dir) { console.error("usage: site-map <baseUrl> <outdir> [--mode m] [--app t]"); return 2; }
        const { buildSiteMap } = await import("./domain/siteMap.js");
        out(await buildSiteMap({ baseUrl: b, outputRoot: dir, runtimeMode: (flags.mode === "depth" || flags.mode === "coverage" || flags.mode === "both" ? flags.mode : "static-only"), appType: typeof flags.app === "string" ? flags.app : undefined }));
        return 0;
      }
      case "traffic-recorder": {
        const [dir] = positional;
        if (!dir) { console.error("usage: traffic-recorder <outdir> [--port N] [--upstream P] [--max N] [--daemon] [--seconds S]"); return 2; }
        const { TrafficRecorder } = await import("./domain/trafficRecorder.js");
        const rec = new TrafficRecorder({ outputRoot: dir, port: num(flags.port), upstreamProxy: typeof flags.upstream === "string" ? flags.upstream : undefined, maxExchanges: num(flags.max), mitm: flags.mitm === true });
        const port = await rec.start(num(flags.port) || 0);
        console.error(`recorder listening on 127.0.0.1:${port}`);
        if (flags.daemon) {
          const secs = num(flags.seconds) || 3600;
          await new Promise((r) => setTimeout(r, secs * 1000));
        } else {
          console.error("press Ctrl-C to stop; exchanges: " + rec.getExchanges().length);
          await new Promise(() => {});
        }
        await rec.stop();
        return 0;
      }
      case "asset-graph": {
        const [dir, action] = positional;
        if (!dir || !action) { console.error("usage: asset-graph <outdir> counts|query <type>|upsert <type> <value>|upsert_url <url>"); return 2; }
        const { AssetStore } = await import("./domain/graphs.js");
        const st = new AssetStore(dir);
        await st.load();
        if (action === "counts") { out(st.countsByType()); return 0; }
        if (action === "query") { out(st.queryByType((positional[2] ?? "subdomain") as never).slice(0, 300)); return 0; }
        if (action === "upsert") { st.upsert({ type: positional[2] as never, value: positional[3] ?? "" }); await st.save(); out({ ok: true }); return 0; }
        if (action === "upsert_url") { st.upsertUrl(positional[2] ?? ""); await st.save(); out({ ok: true }); return 0; }
        console.error("unknown action"); return 2;
      }
      case "exploration-graph": {
        const [dir, action] = positional;
        if (!dir || !action) { console.error("usage: exploration-graph <outdir> overview|add_node <kind> <summary>|add_edge <from> <rel> <to>|anchor <node> <asset>|lineage <node>|set_state <node> <state>"); return 2; }
        const { ExplorationGraph } = await import("./domain/graphs.js");
        const g = new ExplorationGraph(dir);
        await g.load();
        if (action === "overview") { out(g.overview()); return 0; }
        if (action === "add_node") { const n = g.addNode(positional[2] as never, positional[3] ?? ""); await g.save(); out({ id: n.id }); return 0; }
        if (action === "add_edge") { g.addEdge(positional[2] ?? "", positional[3] as never, positional[4] ?? ""); await g.save(); out({ ok: true }); return 0; }
        if (action === "anchor") { g.anchor(positional[2] ?? "", positional[3] ?? ""); await g.save(); out({ ok: true }); return 0; }
        if (action === "lineage") { out(g.lineage(positional[2] ?? "")); return 0; }
        if (action === "set_state") { g.setState(positional[2] ?? "", positional[3] as never); await g.save(); out({ ok: true }); return 0; }
        console.error("unknown action"); return 2;
      }
      case "evidence": {
        const [dir, action] = positional;
        if (!dir || !action) { console.error("usage: evidence <outdir> put <file> [tag]|get <hash>|list"); return 2; }
        const { EvidenceStore } = await import("./domain/graphs.js");
        const store = new EvidenceStore(dir);
        await store.load();
        if (action === "put") {
          const { readFile: rf } = await import("node:fs/promises");
          const blob = await store.put(await rf(positional[2] ?? ""), positional[3]);
          await store.save();
          out({ hash: blob.hash, bytes: blob.bytes });
          return 0;
        }
        if (action === "get") { const b = await store.get(positional[2] ?? ""); out({ found: b !== null, bytes: b?.length ?? 0 }); return 0; }
        if (action === "list") { out(store.entries()); return 0; }
        console.error("unknown action"); return 2;
      }
      case "cold-graph": {
        const [dir, action] = positional;
        if (!dir || !action) { console.error("usage: cold-graph <outdir> compact|expand <digestId> [--round N]"); return 2; }
        const { ExplorationGraph } = await import("./domain/graphs.js");
        const cg = await import("./domain/coldGraph.js");
        const g = new ExplorationGraph(dir);
        await g.load();
        const { stamps, round: prev } = await cg.loadStamps(dir);
        const round = num(flags.round) ?? prev + 1;
        if (action === "compact") {
          cg.touchLive(g, stamps, round - 1);
          const r = cg.compactGraph(g, stamps, round);
          await g.save(); await cg.saveStamps(dir, stamps, round);
          out({ digests: r.digests, folded: r.folded.length, rescued: r.rescued.length });
        } else {
          const r = cg.expandDigest(g, positional[2] ?? "", stamps, round);
          await g.save(); await cg.saveStamps(dir, stamps, round);
          out(r);
        }
        return 0;
      }
      case "retest": {
        const [dir, action] = positional;
        if (!dir || !action) { console.error("usage: retest <outdir> register <id> <json>|run <id>|list [--proxy P]"); return 2; }
        const mod = await import("./domain/retest.js");
        if (action === "list") { out(await mod.listRetests(dir)); return 0; }
        if (action === "run") {
          out(await mod.runRetest({ root: dir, findingId: positional[2] ?? "", proxy: await resolveProxy(flags) }));
          return 0;
        }
        if (action === "register") {
          const spec = JSON.parse(positional[3] ?? "{}");
          out(await mod.registerFinding({ root: dir, id: positional[2] ?? "", name: spec.name ?? positional[2], severity: spec.severity ?? "medium", poc: spec.poc, predicates: spec.predicates }));
          return 0;
        }
        console.error("unknown action"); return 2;
      }
      case "traffic-query": {
        const [dir, action] = positional;
        if (!dir || !action) { console.error("usage: traffic-query <outdir> search [--host H --status N --method M --text T --page N]|get <id>"); return 2; }
        const mod = await import("./domain/trafficRecorder.js");
        if (action === "get") { out(await mod.getTraffic({ outputRoot: dir, id: positional[2] ?? "" })); return 0; }
        out(await mod.searchTraffic({ outputRoot: dir, host: typeof flags.host === "string" ? flags.host : undefined, status: num(flags.status), method: typeof flags.method === "string" ? flags.method : undefined, text: typeof flags.text === "string" ? flags.text : undefined, page: num(flags.page), pageSize: num(flags.pageSize) }));
        return 0;
      }
      case "export-findings": {
        const [file, dir, fmt] = positional;
        if (!file || !dir || !fmt) { console.error("usage: export-findings <report.json> <outdir> csv|json|md-all"); return 2; }
        const { readFile } = await import("node:fs/promises");
        const { generateReportExports } = await import("./application/report.js");
        const rep = JSON.parse(await readFile(file, "utf8")) as { findings?: unknown[] };
        const files = await generateReportExports({ outputRoot: dir, format: fmt as "csv" | "json" | "md-all", findings: (rep.findings ?? []) as never[] });
        out({ files });
        return 0;
      }
      case "evidence-bind": {
        const [dir, action] = positional;
        if (!dir || !action) { console.error("usage: evidence-bind <outdir> bind <findingId> <expectedV> <refsJson>|update|unbind|reorder|get <findingId>|export <findingId> <zipPath>"); return 2; }
        const mod = await import("./domain/evidenceBinding.js");
        if (action === "get") { out(await mod.getBindings(dir, positional[2] ?? "")); return 0; }
        if (action === "export") { out(await mod.exportBindings({ root: dir, findingId: positional[2] ?? "", zipPath: positional[3] ?? "evidence.zip" })); return 0; }
        if (action === "bind") {
          const refs = JSON.parse(positional[4] ?? "[]");
          out(await mod.bindEvidence({ root: dir, findingId: positional[2] ?? "", expectedVersion: Number(positional[3] ?? 0), refs }));
          return 0;
        }
        if (action === "reorder") {
          const order = JSON.parse(positional[4] ?? "[]");
          out(await mod.reorderBindings({ root: dir, findingId: positional[2] ?? "", expectedVersion: Number(positional[3] ?? 0), order }));
          return 0;
        }
        if (action === "update" || action === "unbind") {
          const fn = action === "update" ? mod.updateBinding : mod.unbindEvidence;
          out(await fn({ root: dir, findingId: positional[2] ?? "", bindingId: positional[3] ?? "", expectedVersion: Number(positional[4] ?? 0) } as never));
          return 0;
        }
        console.error("unknown action"); return 2;
      }
      default:
        console.error(`unknown command: ${command}\n`);
        console.log(USAGE);
        return 2;
    }
  } catch (cause) {
    const e = cause as { code?: string; message?: string };
    console.error(
      JSON.stringify({ error: { code: e.code ?? "internal_error", message: e.message ?? String(cause) } }, null, 2),
    );
    return 1;
  }
};