import { join } from "node:path";
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

const USAGE = `velric-agent ${PRODUCT_IDENTITY.packageVersion} — stateless recon toolset (CLI)

Usage:
      velric-agent hunt-begin <goal> <outdir>    open hunt loop (budget: --max-rounds/--max-cost/--max-duration-min)
  velric-agent hunt-record <outdir> --record[-file] F   write host observations back (goals/facts/findings/assets)
  velric-agent hunt-overview <outdir>    read hunt state + snapshot ledger evidence
  velric-agent replay-tamper <recordRoot> <outdir>   replay recorded exchanges with tamper rules (--rules-file JSON, --apply)
  velric-agent waf-adapt <url> <payload> <outdir>    payload transport adaptation vs WAF (--in query|body|header|path)
  velric-agent session-crawl <baseUrl> <loginUrl> <user> <pass> <outdir>   authenticated crawl w/ relogin
  velric-agent deobfuscate <jsDir> <outdir>   JS corpus deobfuscation (--action analyze for stats)
  velric-agent oob-confirm <url> <outdir> --payloads a,b   OOB callback confirmation (interactsh)
  velric-agent role-matrix <reconRoot> <outdir> --roles[-file] JSON   cross-role access matrix
  velric-agent authz-replay <recordRoot> <outdir> --roles[-file] JSON   authz differential replay (live-baseline verdicts)
  velric-agent mass-assign <recordRoot> <outdir>   mass-assignment sink probe (--fields a,b)
  velric-agent pii-scan <recordRoot> <outdir>     PII/credential exposure scan over recorded traffic
  velric-agent mine-params <outdir> (--url URL [--in query|cookie|header] | --remove-diff --merged F --base URL)   hidden param mining (bucket bisection / remove-diff)
  velric-agent subdomain-alter <domain> <outdir> --hosts a,b    alteration-based subdomain generation (+ --resolve)
  velric-agent url-refine <outdir> --urls a,b   URL dedupe/classify (--action classify, --fuzzy, --params has|none)
  velric-agent screenshot <outdir> --urls a,b   headless screenshot capture (--cluster)
  velric-agent jwt-attack <token> <endpoint> <outdir>   JWT attack suite (alg confusion/weak key/kid)
  velric-agent idor-deep <outdir> --endpoints[-file] JSON   three-reference IDOR oracle probing
  velric-agent header-bypass <outdir> --urls a,b   auth-header bypass variants (X-Original-URL etc.)
  velric-agent verb-matrix <outdir> --urls a,b     HTTP verb override matrix probe
  velric-agent admin-surface <baseUrl> <outdir>    admin/panel surface map
  velric-agent graphql-authz <endpoint> <schemaFile> <outdir>   GraphQL per-field authz differential
  velric-agent dir-fuzz <outdir> (--url URL [--wordlist-file F] | --preset sensitive|backups --base URL)   wordlist fuzzing
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
  velric-agent dex-disasm <file.dex|.apk> <outdir>  Dalvik bytecode disassembly (smali-level, string xrefs, per-class filter, direct APK input)
  velric-agent wasm-disasm <file.wasm> <outdir>  Full WASM disassembly (all opcodes incl. SIMD/sat-trunc/bulk-memory, function-local offsets, call targets resolved to names, callgraph edges)
  velric-agent elf-analyze <binary> <outdir>   ELF static analysis (sections/segments/symbols/imports, hardening: PIE RELRO NX canary stripped, dynamic deps, build-id)
  velric-agent wasm-analyze <file.wasm> <outdir>  WASM static analysis (sections, imports/exports, memories, name-section symbol recovery, runtime hints)
  velric-agent dex-analyze <file.dex|.apk> <outdir>  DEX static analysis (strings/classes/methods/fields, URL+secret extraction from string table)
  velric-agent vm-analyze <jsDir> <outdir>     JS VM interpreter static reverse (opcode table, dispatch, state slots)
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
  velric-agent export-findings <f> <dir> <fmt> findings csv/json/md/sarif export
  velric-agent evidence-bind <dir> <action>     evidence binding lifecycle
  velric-agent scan-platform <dir> <action>     native scan platform (projects/tasks/pipeline/assets)
  velric-agent help

Common flags: --proxy URL | --proxy-pool FILE, --rps N (global rate limit), --cookie STR, --timeout MS
Hunt binding: --run-id ID [--observation-ledger-root DIR] — record every request into the observation ledger for hunt-record verification
`;


/** Resolve effective proxy: --proxy single URI, or round-robin from
 *  --proxy-pool <file>. Applies global --rps when set. */
let poolState: { pool: import("./domain/proxyPool.js").ProxyPool } | null = null;
/** Comma-separated flag → string[] (e.g. --urls a,b,c). */
const jarr = (flags: Record<string, string | boolean | undefined>, key: string): string[] | undefined => {
  const v = flags[key];
  if (typeof v !== "string" || v.trim() === "") return undefined;
  return v.split(",").map((x) => x.trim()).filter(Boolean);
};

/** Structured flag: `--<key>-file FILE` (JSON file) wins, else inline `--<key> JSON`. */
const jobj = async <T>(flags: Record<string, string | boolean | undefined>, key: string): Promise<T | undefined> => {
  const file = flags[`${key}-file`];
  if (typeof file === "string" && file !== "") {
    const { readFile: rf } = await import("node:fs/promises");
    return JSON.parse(await rf(file, "utf8")) as T;
  }
  const inline = flags[key];
  if (typeof inline === "string" && inline.trim() !== "") return JSON.parse(inline) as T;
  return undefined;
};

/** Array-of-objects flag: file or inline JSON, else comma-split scalars. */
const jarrObj = async <T>(flags: Record<string, string | boolean | undefined>, key: string): Promise<T[] | undefined> => {
  const v = await jobj<T[]>(flags, key);
  if (v !== undefined) return v;
  return jarr(flags, key) as unknown as T[] | undefined;
};

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

/** Dispatch one parsed command to its case; returns the process exit code. */
const dispatch = async (command: string, positional: readonly string[], flags: Record<string, string | boolean>, out: (v: unknown) => void): Promise<number> => {
  switch (command) {
      case "help":
      case "--help":
      case "-h":
        console.log(USAGE);
        return 0;
      case "hunt-begin": {
        const [goal, dir] = positional;
        if (!goal || !dir) {
          console.error("usage: hunt-begin <goal> <outdir> [--max-rounds N] [--max-cost N] [--max-duration-min N]");
          return 2;
        }
        const { huntBegin } = await import("./application/huntDriver.js");
        out(await huntBegin({ goal, outputRoot: dir, maxRounds: num(flags["max-rounds"]), maxCost: num(flags["max-cost"]), maxDurationMin: num(flags["max-duration-min"]) }));
        return 0;
      }
      case "hunt-record": {
        const dir = positional[0];
        const rec = await jobj<Record<string, unknown>>(flags, "record");
        if (!dir || !rec) {
          console.error("usage: hunt-record <outdir> --record[-file] <record.json>  (fields: goals/intents/facts/findings/assets/goalsMet/round/costDelta/intentId/intentSummary)");
          return 2;
        }
        const { huntRecord } = await import("./application/huntDriver.js");
        const r = await huntRecord({ outputRoot: dir, ...rec } as never);
        out({ accepted: r.accepted, dropped: r.dropped, dropReasons: r.dropReasons, goalsMet: r.graph.goals.filter((x) => x.met).length, goalsTotal: r.graph.goals.length, facts: r.graph.facts.length, findings: r.graph.findings.length, assets: r.graph.assets.length });
        return 0;
      }
      case "hunt-overview": {
        const dir = positional[0];
        if (!dir) {
          console.error("usage: hunt-overview <outdir>");
          return 2;
        }
        const { huntOverview, exportLedgerEvidence } = await import("./application/huntDriver.js");
        try { await exportLedgerEvidence(dir); } catch { /* best-effort */ }
        out(await huntOverview(dir));
        return 0;
      }
      case "replay-tamper": {
        const [recordRoot, dir] = positional;
        const rules = await jarrObj<{ field: string; in: "body" | "query"; value: string | number | boolean | null; label?: string }>(flags, "rules");
        if (!recordRoot || !dir) {
          console.error("usage: replay-tamper <recordRoot> <outdir> [--ids a,b] [--rules-file JSON] [--apply] [--max N]");
          return 2;
        }
        const { replayTamper } = await import("./domain/replayTamper.js");
        out(await replayTamper({
          recordRoot, outputRoot: dir,
          exchangeIds: jarr(flags, "ids"),
          rules: (rules ?? []).map((x) => ({ ...x, label: x.label ?? `${x.field}=${String(x.value)}` })),
          cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
          extraHeaders: await jobj<Record<string, string>>(flags, "headers"),
          proxy: await resolveProxy(flags),
          timeoutMs: num(flags.timeout),
          maxExchanges: num(flags.max),
          applyTamper: flags.apply === true,
        }));
        return 0;
      }
      case "waf-adapt": {
        const [url, payload, dir] = positional;
        if (!url || !payload || !dir) {
          console.error("usage: waf-adapt <url> <payload> <outdir> [--param NAME] [--in query|body|header|path] [--method M] [--max-attempts N]");
          return 2;
        }
        const { probeWafAdapt } = await import("./domain/wafAdapt.js");
        const p = flags.param;
        const inWhere = flags.in;
        out(await probeWafAdapt({
          url, payload, outputRoot: dir,
          param: typeof p === "string" ? p : undefined,
          in: inWhere === "query" || inWhere === "body" || inWhere === "header" || inWhere === "path" ? inWhere : undefined,
          method: typeof flags.method === "string" ? flags.method : undefined,
          headers: await jobj<Record<string, string>>(flags, "headers"),
          proxy: await resolveProxy(flags),
          timeoutMs: num(flags.timeout),
          maxAttempts: num(flags["max-attempts"]),
        }));
        return 0;
      }
      case "session-crawl": {
        const [baseUrl, loginUrl, user, pass, dir] = positional;
        if (!baseUrl || !loginUrl || !user || !pass || !dir) {
          console.error("usage: session-crawl <baseUrl> <loginUrl> <user> <pass> <outdir> [--login-mode form|json] [--user-field F] [--pass-field F] [--endpoints a,b] [--max-pages N]");
          return 2;
        }
        const { crawlSession } = await import("./domain/sessionCrawl.js");
        const lm = flags["login-mode"];
        out(await crawlSession({
          baseUrl, loginUrl, username: user, password: pass, outputRoot: dir,
          loginMode: lm === "form" || lm === "json" ? lm : undefined,
          usernameField: typeof flags["user-field"] === "string" ? flags["user-field"] : undefined,
          passwordField: typeof flags["pass-field"] === "string" ? flags["pass-field"] : undefined,
          endpoints: jarr(flags, "endpoints"),
          proxy: await resolveProxy(flags),
          timeoutMs: num(flags.timeout),
          maxPages: num(flags["max-pages"]),
          maxRelogins: num(flags["max-relogins"]),
          headers: await jobj<Record<string, string>>(flags, "headers"),
          loggedInRegex: typeof flags["logged-in"] === "string" ? flags["logged-in"] : undefined,
          loggedOutRegex: typeof flags["logged-out"] === "string" ? flags["logged-out"] : undefined,
        }));
        return 0;
      }
      case "deobfuscate": {
        const [jsDir, dir] = positional;
        if (!jsDir || !dir) {
          console.error("usage: deobfuscate <jsDir> <outdir> [--action deobf|analyze] [--max-files N] [--max-file-bytes N]");
          return 2;
        }
        const action = flags.action;
        if (action === "analyze") {
          const { analyzeCorpus } = await import("./domain/jsAnalyze.js");
          out(await analyzeCorpus({ jsDir, outputRoot: dir, maxFiles: num(flags["max-files"]), maxFileBytes: num(flags["max-file-bytes"]) }));
        } else {
          const { deobfuscateCorpus } = await import("./domain/deobf.js");
          out(await deobfuscateCorpus({ jsDir, outputRoot: dir, maxFiles: num(flags["max-files"]), maxFileBytes: num(flags["max-file-bytes"]) }));
        }
        return 0;
      }
      case "oob-confirm": {
        const [url, dir] = positional;
        const payloads = jarr(flags, "payloads");
        if (!url || !dir || !payloads) {
          console.error("usage: oob-confirm <url> <outdir> --payloads a,b [--positions-file JSON] [--method M] [--body STR]");
          return 2;
        }
        const { probeOob } = await import("./domain/oobConfirm.js");
        out(await probeOob({
          url, outputRoot: dir, payloads,
          positions: await jarrObj<{ param: string; in: "query" | "body" | "header" | "path" }>(flags, "positions"),
          method: typeof flags.method === "string" ? flags.method : undefined,
          body: typeof flags.body === "string" ? flags.body : undefined,
          headers: await jobj<Record<string, string>>(flags, "headers"),
          proxy: await resolveProxy(flags),
          timeoutMs: num(flags.timeout),
          pollMs: num(flags.poll),
        }));
        return 0;
      }
      case "role-matrix": {
        const [reconRoot, dir] = positional;
        const roles = await jobj<Record<string, string>>(flags, "roles");
        if (!reconRoot || !dir || !roles) {
          console.error("usage: role-matrix <reconRoot> <outdir> --roles[-file] '{\"admin\":\"cookie=..\"}' [--max-endpoints N]");
          return 2;
        }
        const { probeRoleMatrix } = await import("./domain/roleMatrix.js");
        out(await probeRoleMatrix({
          reconRoot, outputRoot: dir, roles,
          proxy: await resolveProxy(flags),
          timeoutMs: num(flags.timeout),
          maxEndpoints: num(flags["max-endpoints"]),
        }));
        return 0;
      }
      case "authz-replay": {
        const [recordRoot, dir] = positional;
        const roles = await jobj<Record<string, string>>(flags, "roles");
        if (!recordRoot || !dir || !roles) {
          console.error("usage: authz-replay <recordRoot> <outdir> --roles[-file] '{\"admin\":\"Cookie: ..\"}' [--role-headers-file JSON] [--markers-file JSON] [--ids a,b] [--methods a,b] [--anonymous] [--read-only] [--apply]");
          return 2;
        }
        const { replayAuthz } = await import("./domain/authzReplay.js");
        const r = await replayAuthz({
          recordRoot, outputRoot: dir, roles,
          roleHeaders: await jobj<Record<string, Record<string, string>>>(flags, "role-headers"),
          markers: await jobj<Record<string, string[]>>(flags, "markers"),
          anonymous: flags.anonymous === true,
          exchangeIds: jarr(flags, "ids"),
          methods: jarr(flags, "methods"),
          proxy: await resolveProxy(flags),
          timeoutMs: num(flags.timeout),
          maxExchanges: num(flags.max),
          denyFingerprints: jarr(flags, "deny-fingerprints"),
          readOnly: flags["read-only"] === true,
          apply: flags.apply === true,
        });
        out({ replayed: r.replayed, bypassed: r.bypassed.map((c) => ({ url: c.url, role: c.role, note: c.note })), enforced: r.enforced.length, unknown: r.unknown.length, artifacts: r.artifacts });
        return 0;
      }
      case "mass-assign": {
        const [recordRoot, dir] = positional;
        if (!recordRoot || !dir) {
          console.error("usage: mass-assign <recordRoot> <outdir> [--credential STR] [--ids a,b] [--fields a,b] [--apply] [--max N]");
          return 2;
        }
        const { probeMassAssign } = await import("./domain/massAssign.js");
        const r = await probeMassAssign({
          recordRoot, outputRoot: dir,
          credential: typeof flags.credential === "string" ? flags.credential : undefined,
          exchangeIds: jarr(flags, "ids"),
          fields: jarr(flags, "fields"),
          proxy: await resolveProxy(flags),
          timeoutMs: num(flags.timeout),
          maxExchanges: num(flags.max),
          apply: flags.apply === true,
        });
        out({ probed: r.probed, sinks: r.sinks.map((o) => ({ url: o.url, field: o.field, verdict: o.verdict, note: o.note })), outcomes: r.outcomes, artifacts: r.artifacts });
        return 0;
      }
      case "pii-scan": {
        const [recordRoot, dir] = positional;
        if (!recordRoot || !dir) {
          console.error("usage: pii-scan <recordRoot> <outdir> [--skip-binary] [--max-blobs N]");
          return 2;
        }
        const { scanTrafficPii } = await import("./domain/piiScan.js");
        const r = await scanTrafficPii({
          recordRoot, outputRoot: dir,
          skipBinary: flags["skip-binary"] === true,
          maxBlobs: num(flags["max-blobs"]),
        });
        out({ blobsScanned: r.blobsScanned, exposures: r.exposures.map((e) => ({ method: e.method, url: e.url, kinds: e.kinds })), credentialPairs: r.credentialPairs.map((c) => ({ name: c.name, url: c.url, method: c.method })), artifacts: r.artifacts });
        return 0;
      }
      case "mine-params": {
        const dir = positional[0];
        const mergedFile = typeof flags.merged === "string" ? flags.merged : undefined;
        const url = typeof flags.url === "string" ? flags.url : undefined;
        if (!dir || (!mergedFile && !url)) {
          console.error("usage: mine-params <outdir> (--merged params_merged.json | --url URL [--in query|cookie|header] [--learn] [--max-words N] [--bucket N] | --remove-diff --merged F --base URL) [--max-endpoints N]");
          return 2;
        }
        if (flags["remove-diff"] === true) {
          if (!mergedFile) { console.error("--remove-diff requires --merged"); return 2; }
          const { probeParams } = await import("./application/paramProbe.js");
          out(await probeParams({ mergedFile, outputRoot: dir, baseUrl: typeof flags.base === "string" ? flags.base : undefined, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout), maxEndpoints: num(flags["max-endpoints"]) }));
          return 0;
        }
        if (!url) { console.error("--url required for name-guess"); return 2; }
        const { mineHiddenParams } = await import("./domain/hiddenParams.js");
        const inWhere = flags.in;
        out(await mineHiddenParams({
          url, outputRoot: dir,
          in: inWhere === "query" || inWhere === "cookie" || inWhere === "header" ? inWhere : undefined,
          words: jarr(flags, "words"),
          learn: flags.learn === true,
          method: typeof flags.method === "string" ? flags.method : undefined,
          body: typeof flags.body === "string" ? flags.body : undefined,
          headers: await jobj<Record<string, string>>(flags, "headers"),
          cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
          proxy: await resolveProxy(flags),
          timeoutMs: num(flags.timeout),
          maxWords: num(flags["max-words"]),
          bucketSize: num(flags.bucket),
        }));
        return 0;
      }
      case "subdomain-alter": {
        const [domain, dir] = positional;
        const hosts = jarr(flags, "hosts");
        if (!domain || !dir || !hosts) {
          console.error("usage: subdomain-alter <domain> <outdir> --hosts a,b [--resolve] [--max-candidates N] [--nameservers a,b] [--concurrency N]");
          return 2;
        }
        const { alterSubdomains } = await import("./domain/subdomainAlter.js");
        const r = await alterSubdomains({
          hosts, domain,
          resolve: flags.resolve === true,
          maxCandidates: num(flags["max-candidates"]),
          nameservers: jarr(flags, "nameservers"),
          concurrency: num(flags.concurrency),
        });
        const { writeFile: wf, mkdir: mk } = await import("node:fs/promises");
        await mk(dir, { recursive: true });
        const { join } = await import("node:path");
        const bodyStr = JSON.stringify({ generated: r.generated, resolved: r.resolved, samples: r.samples }, null, 2);
        const path = join(dir, "subdomain_alterations.json");
        await wf(path, bodyStr, "utf8");
        out({ generated: r.generated, resolved: r.resolved, artifacts: [{ path, bytes: Buffer.byteLength(bodyStr) }] });
        return 0;
      }
      case "url-refine": {
        const dir = positional[0];
        const urls = jarr(flags, "urls") ?? (typeof flags["urls-file"] === "string" ? (await (await import("node:fs/promises")).readFile(flags["urls-file"], "utf8")).split("\n").map((l) => l.trim()).filter(Boolean) : undefined);
        if (!dir || !urls || urls.length === 0) {
          console.error("usage: url-refine <outdir> --urls a,b (or --urls-file FILE) [--action dedupe|classify] [--keep-static] [--fuzzy] [--params has|none]");
          return 2;
        }
        const { dedupeUrls, classifyUrls } = await import("./domain/urlRefine.js");
        const { writeFile: wf, mkdir: mk } = await import("node:fs/promises");
        await mk(dir, { recursive: true });
        const { join } = await import("node:path");
        if (flags.action === "classify") {
          const r = classifyUrls(urls);
          const bodyStr = JSON.stringify(r, null, 2);
          const path = join(dir, "classified_urls.json");
          await wf(path, bodyStr, "utf8");
          out({ ...r, artifacts: [{ path, bytes: Buffer.byteLength(bodyStr) }] });
        } else {
          const r = dedupeUrls({ urls, keepStatic: flags["keep-static"] === true, keepContent: flags["keep-content"] === true, fuzzy: flags.fuzzy === true, whitelist: jarr(flags, "whitelist"), params: flags.params === "has" || flags.params === "none" ? flags.params : undefined });
          const bodyStr = JSON.stringify(r, null, 2);
          const path = join(dir, "deduped_urls.json");
          await wf(path, bodyStr, "utf8");
          out({ ...r, artifacts: [{ path, bytes: Buffer.byteLength(bodyStr) }] });
        }
        return 0;
      }
      case "screenshot": {
        const dir = positional[0];
        const urls = jarr(flags, "urls");
        if (!dir || !urls) {
          console.error("usage: screenshot <outdir> --urls a,b [--chromium PATH] [--concurrency N] [--cluster] [--timeout MS]");
          return 2;
        }
        const { captureScreenshots } = await import("./domain/screenshot.js");
        out(await captureScreenshots({
          urls, outputRoot: dir,
          chromiumPath: typeof flags.chromium === "string" ? flags.chromium : undefined,
          concurrency: num(flags.concurrency),
          timeoutMs: num(flags.timeout),
          cluster: flags.cluster === true,
          proxy: await resolveProxy(flags),
        }));
        return 0;
      }
      case "jwt-attack": {
        const [token, endpoint, dir] = positional;
        if (!token || !endpoint || !dir) {
          console.error("usage: jwt-attack <token> <endpoint> <outdir> [--secrets-file FILE] [--candidates a,b]");
          return 2;
        }
        const { probeJwtAttack } = await import("./domain/jwtAttack.js");
        const cand = jarr(flags, "candidates");
        out(await probeJwtAttack({
          token, endpoint, outputRoot: dir,
          headers: await jobj<Record<string, string>>(flags, "headers"),
          proxy: await resolveProxy(flags),
          timeoutMs: num(flags.timeout),
          secretCandidates: cand,
        }));
        return 0;
      }
      case "idor-deep": {
        const dir = positional[0];
        const endpoints = await jarrObj<{ method: string; path: string; fields: { name: string; in: string }[] }>(flags, "endpoints");
        if (!dir || !endpoints) {
          console.error("usage: idor-deep <outdir> --endpoints[-file] '[{\"method\":\"GET\",\"path\":\"/api/x\",\"fields\":[{\"name\":\"id\",\"in\":\"query\"}]}]' [--base URL] [--ids a,b] [--max-targets N]");
          return 2;
        }
        const { probeIdorDeep } = await import("./domain/idorDeep.js");
        out(await probeIdorDeep({
          endpoints, outputRoot: dir,
          baseUrl: typeof flags.base === "string" ? flags.base : undefined,
          cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
          headers: await jobj<Record<string, string>>(flags, "headers"),
          proxy: await resolveProxy(flags),
          timeoutMs: num(flags.timeout),
          maxTargets: num(flags["max-targets"]),
          objectIds: jarr(flags, "ids"),
        }));
        return 0;
      }
      case "header-bypass": {
        const dir = positional[0];
        const urls = jarr(flags, "urls");
        if (!dir || !urls) {
          console.error("usage: header-bypass <outdir> --urls a,b [--max N]");
          return 2;
        }
        const { probeHeaderBypass } = await import("./domain/headerBypass.js");
        out(await probeHeaderBypass({
          urls, outputRoot: dir,
          cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
          headers: await jobj<Record<string, string>>(flags, "headers"),
          proxy: await resolveProxy(flags),
          timeoutMs: num(flags.timeout),
          maxUrls: num(flags.max),
        }));
        return 0;
      }
      case "verb-matrix": {
        const dir = positional[0];
        const urls = jarr(flags, "urls");
        if (!dir || !urls) {
          console.error("usage: verb-matrix <outdir> --urls a,b [--max N]");
          return 2;
        }
        const { probeVerbMatrix } = await import("./domain/verbMatrix.js");
        out(await probeVerbMatrix({
          urls, outputRoot: dir,
          cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
          headers: await jobj<Record<string, string>>(flags, "headers"),
          proxy: await resolveProxy(flags),
          timeoutMs: num(flags.timeout),
          maxUrls: num(flags.max),
        }));
        return 0;
      }
      case "admin-surface": {
        const [baseUrl, dir] = positional;
        if (!baseUrl || !dir) {
          console.error("usage: admin-surface <baseUrl> <outdir>");
          return 2;
        }
        const { probeAdminSurface } = await import("./domain/adminSurface.js");
        out(await probeAdminSurface({
          baseUrl, outputRoot: dir,
          cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
          headers: await jobj<Record<string, string>>(flags, "headers"),
          proxy: await resolveProxy(flags),
          timeoutMs: num(flags.timeout),
        }));
        return 0;
      }
      case "graphql-authz": {
        const [endpoint, schemaFile, dir] = positional;
        if (!endpoint || !schemaFile || !dir) {
          console.error("usage: graphql-authz <endpoint> <schemaFile> <outdir> [--token STR] [--max-fields N]");
          return 2;
        }
        const { probeGraphqlAuthz } = await import("./domain/graphqlAuthz.js");
        out(await probeGraphqlAuthz({
          endpoint, schemaFile, outputRoot: dir,
          token: typeof flags.token === "string" ? flags.token : undefined,
          headers: await jobj<Record<string, string>>(flags, "headers"),
          proxy: await resolveProxy(flags),
          timeoutMs: num(flags.timeout),
          maxFields: num(flags["max-fields"]),
        }));
        return 0;
      }
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
            timeoutMs: num(flags.timeout),
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
            timeoutMs: num(flags.timeout),
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
            maxPages: num(flags.max),
            depth: num(flags.depth),
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
        const dir = typeof flags.out === "string" ? flags.out : undefined;
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
          console.error("usage: auto <seed> <outdir> [--chromium PATH] [--skip-runtime] [--proxy URL] [--cookie STR] [--timeout MS] [--max-pages N] [--rps N]");
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
            rps: num(flags.rps),
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
        let wl: string[] | undefined;
        if (typeof flags.wordlist === "string" && flags.wordlist.trim() !== "") {
          try {
            const t = await (await import("node:fs/promises")).readFile(flags.wordlist, "utf8");
            wl = t.split("\n").map((l) => l.trim()).filter((l) => l !== "" && !l.startsWith("#"));
          } catch (err) {
            // A requested-but-unreadable wordlist must be loud, not a silent
            // empty brute pass the user believes ran.
            console.error(`wordlist unreadable (${(err as Error).message}) — falling back to built-in prefixes`);
          }
        }
        out(await discoverSubdomains({ domain, outputRoot: dir, proxy: await resolveProxy(flags), wordlist: await wl }));
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
          console.error("usage: paths <baseUrl> <outdir> [--cookie STR]");
          return 2;
        }
        const { probePaths } = await import("./domain/pathProbe.js");
        out(await probePaths({ baseUrl: base, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, proxy: await resolveProxy(flags) }));
        return 0;
      }
      case "dir-fuzz": {
        const dir = positional[0];
        const preset = flags.preset;
        const base = typeof flags.base === "string" ? flags.base : undefined;
        const url = typeof flags.url === "string" ? flags.url : undefined;
        if (preset === "sensitive" || preset === "backups") {
          if (!dir || !base) {
            console.error(`usage: dir-fuzz <outdir> --preset ${preset} --base URL [--cookie STR]`);
            return 2;
          }
          if (preset === "sensitive") {
            const { probePaths } = await import("./domain/pathProbe.js");
            out(await probePaths({ baseUrl: base, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout) }));
          } else {
            const { findBackups } = await import("./domain/backupFind.js");
            out(await findBackups({ baseUrl: base, outputRoot: dir, targets: jarr(flags, "targets"), proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout), maxCandidates: num(flags.max) }));
          }
          return 0;
        }
        if (!dir || !url) {
          console.error("usage: dir-fuzz <outdir> --url URL [--wordlist-file F] [--extensions html,php] [--recursion] [--calibration N] [--match-status 200,301] [--filter-size N] [--delay-ms N]");
          return 2;
        }
        const { dirFuzz } = await import("./domain/dirFuzz.js");
        out(await dirFuzz({
          url, outputRoot: dir,
          wordlistFile: typeof flags["wordlist-file"] === "string" ? flags["wordlist-file"] : undefined,
          words: jarr(flags, "words"),
          extensions: jarr(flags, "extensions"),
          recursion: flags.recursion === true,
          recursionDepth: num(flags["recursion-depth"]),
          calibration: num(flags.calibration),
          matchStatus: (typeof flags["match-status"] === "string" ? flags["match-status"].split(",").map((x) => Number(x.trim())).filter((n) => n > 0) : undefined),
          filterSize: (typeof flags["filter-size"] === "string" ? flags["filter-size"].split(",").map((x) => Number(x.trim())).filter((n) => n >= 0) : undefined),
          cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
          headers: await jobj<Record<string, string>>(flags, "headers"),
          proxy: await resolveProxy(flags),
          timeoutMs: num(flags.timeout),
          maxWords: num(flags.max),
          delayMs: num(flags["delay-ms"]),
        }));
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
      case "dex-disasm": {
        const [file, dir] = positional;
        if (!file || !dir) {
          console.error("usage: dex-disasm <file.dex|.apk> <outdir> [--max-methods N] [--class-filter RE]");
          return 2;
        }
        const { disassembleDex } = await import("./domain/dexDisasm.js");
        let target = file;
        if (/\.apk$/i.test(file)) {
          const { readFile } = await import("node:fs/promises");
          const { execFile } = await import("node:child_process");
          const { promisify } = await import("node:util");
          const buf = await readFile(file);
          if (buf.readUInt32LE(0) === 0x04034b50) {
            const zipDir = join(dir, "_apk");
            const fs = await import("node:fs/promises");
            await fs.mkdir(zipDir, { recursive: true });
            await promisify(execFile)("unzip", ["-o", "-j", file, "classes.dex", "-d", zipDir]);
            target = join(zipDir, "classes.dex");
          }
        }
        const r = await disassembleDex({ file: target, outputRoot: dir, maxMethods: num(flags["max-methods"]), classFilter: typeof flags["class-filter"] === "string" ? flags["class-filter"] : undefined });
        out({ file: r.file, bytes: r.bytes, methods: r.methods, disassembled: r.disassembled, sample: r.details.slice(0, 3), topStringXrefs: r.stringXrefs.filter(x => /^(?:https?:|str )/.test(x.str) || x.str.length > 8).slice(0, 20), artifacts: r.artifacts });
        return 0;
      }
      case "wasm-disasm": {
        const [file, dir] = positional;
        if (!file || !dir) {
          console.error("usage: wasm-disasm <file.wasm> <outdir> [--max-functions N]");
          return 2;
        }
        const { disassembleWasm } = await import("./domain/wasmDisasm.js");
        const r = await disassembleWasm({ file, outputRoot: dir, maxFunctions: num(flags["max-functions"]) });
        out({ file: r.file, bytes: r.bytes, functions: r.functions, disassembled: r.disassembled, callgraphEdges: r.callgraph.length, topCalls: r.callgraph.slice(0, 20), artifacts: r.artifacts });
        return 0;
      }
      case "elf-analyze": {
        const [file, dir] = positional;
        if (!file || !dir) {
          console.error("usage: elf-analyze <binary> <outdir>");
          return 2;
        }
        const { analyzeElf } = await import("./domain/elfAnalyze.js");
        out(await analyzeElf({ file, outputRoot: dir }));
        return 0;
      }
      case "wasm-analyze": {
        const [file, dir] = positional;
        if (!file || !dir) {
          console.error("usage: wasm-analyze <file.wasm> <outdir>");
          return 2;
        }
        const { analyzeWasm } = await import("./domain/wasmAnalyze.js");
        out(await analyzeWasm({ file, outputRoot: dir }));
        return 0;
      }
      case "dex-analyze": {
        const [file, dir] = positional;
        if (!file || !dir) {
          console.error("usage: dex-analyze <file.dex|file.apk> <outdir>");
          return 2;
        }
        const { analyzeDex } = await import("./domain/dexAnalyze.js");
        let target = file;
        // APK: extract classes.dex in-place to a temp dir next to output
        if (/\.apk$/i.test(file)) {
          const { readFile } = await import("node:fs/promises");
          const { execFile } = await import("node:child_process");
          const { promisify } = await import("node:util");
          const buf = await readFile(file);
          if (buf.readUInt32LE(0) === 0x04034b50) {
            const zipDir = join(dir, "_apk");
            await import("node:fs/promises").then(fs => fs.mkdir(zipDir, { recursive: true }));
            await promisify(execFile)("unzip", ["-o", "-j", file, "classes.dex", "-d", zipDir]);
            target = join(zipDir, "classes.dex");
          }
        }
        out(await analyzeDex({ file: target, outputRoot: dir }));
        return 0;
      }
      case "vm-analyze": {
        const [jsDir, dir] = positional;
        if (!jsDir || !dir) {
          console.error("usage: vm-analyze <jsDir> <outdir> [--max-files N] [--min-score N]");
          return 2;
        }
        const { analyzeVmCorpus } = await import("./domain/vmAnalyze.js");
        out(await analyzeVmCorpus({ jsDir, outputRoot: dir, maxFiles: num(flags["max-files"]), minInterpreterScore: num(flags["min-score"]) }));
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
        if (!data || !dir || (flags.enc !== undefined && flags.enc !== "hex" && flags.enc !== "base64")) { console.error("usage: proto-decode <hex|base64> <outdir> [--enc hex|base64]"); return 2; }
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
        const [b, user, passArg, dir] = positional;
        // --pass-file reads the password from a file (0600) instead of argv,
        // where local users can see it in /proc.
        let pass = passArg;
        if (typeof flags["pass-file"] === "string") {
          const { readFile: rf } = await import("node:fs/promises");
          pass = (await rf(flags["pass-file"], "utf8")).trim();
        }
        if (!b || !user || !pass || !dir) { console.error("usage: login-replay <loginUrl> <user> <pass|--> <outdir> [--chromium PATH] [--pass-file F]"); return 2; }
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
        // Ctrl-C must flush and release the port so rec.stop() stays
        // reachable.
        const stopped = new Promise<void>((resolve) => {
          const stop = (): void => { void rec.stop().finally(resolve); };
          process.once("SIGINT", stop);
          process.once("SIGTERM", stop);
        });
        if (flags.daemon) {
          const secs = num(flags.seconds) || 3600;
          await new Promise((r) => setTimeout(r, secs * 1000));
          await rec.stop();
        } else {
          console.error("press Ctrl-C to stop; exchanges: " + rec.getExchanges().length);
          await stopped;
        }
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
        if (!file || !dir || !fmt || !["csv", "json", "md-all", "sarif"].includes(fmt)) { console.error("usage: export-findings <report.json> <outdir> csv|json|md-all|sarif"); return 2; }
        const { readFile } = await import("node:fs/promises");
        const { generateReportExports } = await import("./application/report.js");
        const rep = JSON.parse(await readFile(file, "utf8")) as { findings?: unknown[] };
        const files = await generateReportExports({ outputRoot: dir, format: fmt as "csv" | "json" | "md-all" | "sarif", findings: (rep.findings ?? []) as never[] });
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
      case "scan-platform": {
        const [dir, action] = positional;
        if (!dir || !action) { console.error("usage: scan-platform <outdir> create-project|create-task|run-task|get-task|list-tasks|list-projects|list-assets|count-assets ..."); return 2; }
        const mod = await import("./domain/scanPlatform.js");
        if (action === "create-project") {
          const [name, ...targets] = positional.slice(2);
          if (!name || targets.length === 0) { console.error("usage: scan-platform <dir> create-project <name> <target...>"); return 2; }
          out(await mod.createProject(dir, { name, targets }));
          return 0;
        }
        if (action === "create-task") {
          const [projectId, name, modulesCsv, targetsCsv] = positional.slice(2);
          if (!projectId || !name || !modulesCsv) { console.error("usage: scan-platform <dir> create-task <projectId> <name> <mod1,mod2> [target1,target2 | @sourceTaskId]"); return 2; }
          const modules = modulesCsv.split(",");
          const sourceTask = targetsCsv?.startsWith("@") ? targetsCsv.slice(1) : undefined;
          const targets = sourceTask ? undefined : targetsCsv?.split(",").filter(Boolean);
          out(await mod.createTask(dir, { projectId, name, modules, targets, sourceTask }));
          return 0;
        }
        if (action === "run-task") {
          const [taskId] = positional.slice(2);
          if (!taskId) { console.error("usage: scan-platform <dir> run-task <taskId> [--proxy p] [--cookie c]"); return 2; }
          out(await mod.runTask(dir, { taskId, proxy: typeof flags.proxy === "string" ? flags.proxy : undefined, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined }));
          return 0;
        }
        if (action === "get-task") { out(await mod.getTask(dir, positional[2] ?? "")); return 0; }
        if (action === "list-tasks") { out(await mod.listTasks(dir, positional[2])); return 0; }
        if (action === "list-projects") { out(await mod.listProjects(dir)); return 0; }
        if (action === "list-assets" || action === "count-assets") {
          const query: { type?: string; taskTag?: string; valuePrefix?: string; valueRegex?: string } = {};
          const [type, taskTag, valuePrefix, valueRegex] = positional.slice(2);
          if (type && type !== "-") query.type = type;
          if (taskTag && taskTag !== "-") query.taskTag = taskTag;
          if (valuePrefix && valuePrefix !== "-") query.valuePrefix = valuePrefix;
          if (valueRegex && valueRegex !== "-") query.valueRegex = valueRegex;
          if (action === "list-assets") { out(await mod.listAssets(dir, query, num(flags.page) ?? 1, num(flags.pageSize) ?? 50)); return 0; }
          out(await mod.countAssets(dir, query));
          return 0;
        }
        console.error("unknown action"); return 2;
      }
      default:
        console.error(`unknown command: ${command}\n`);
        console.log(USAGE);
        return 2;
  }
};

export const runCli = async (argv: readonly string[]): Promise<number> => {
  const { command, positional, flags } = parseArgs(argv);
  const out = (v: unknown) => console.log(JSON.stringify(v, null, 2));
  // --run-id (+ optional --observation-ledger-root) binds every network
  // request this process makes into the observation ledger — required when
  // running recon commands inside a hunt context so hunt-record's
  // anti-hallucination gate can verify observed facts.
  const runBody = async (): Promise<number> => {
    if (typeof flags["run-id"] === "string" && flags["run-id"]) {
      const { withExecution } = await import("./core/execution.js");
      return withExecution({
        tool: `cli:${command}`,
        runId: flags["run-id"],
        ledgerRoot: typeof flags["observation-ledger-root"] === "string" ? flags["observation-ledger-root"] : undefined,
      }, () => dispatch(command, positional, flags, out));
    }
    return dispatch(command, positional, flags, out);
  };
  try {
    return await runBody();
  } catch (cause) {
    const e = cause as { code?: string; message?: string };
    console.error(
      JSON.stringify({ error: { code: e.code ?? "internal_error", message: e.message ?? String(cause) } }, null, 2),
    );
    return 1;
  }
};