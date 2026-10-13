import { resolveHost } from "./application/dns.js";
import { httpProbe } from "./application/probe.js";
import { harvestStatic } from "./application/harvest.js";
import { spiderMpa } from "./application/spider.js";
import { buildPermissionTree } from "./application/permTreeService.js";
import { mergeParamSamples } from "./application/paramMerge.js";
import { captureRuntime } from "./application/runtime.js";
import { DEFAULT_HOOK_CONFIG } from "./domain/preload.js";
import { PRODUCT_IDENTITY } from "./identity.js";

const num = (v: string | boolean | undefined): number | undefined =>
  typeof v === "string" && v.trim() !== "" ? Number(v) : undefined;

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
  velric-agent auto <seed> <outdir>            deterministic pipeline (enrich→classify→recon→runtime→structure→report)
  velric-agent hunt <goal> <outdir>            LLM-orchestrated hunt (goals→planner/worker loop)
  velric-agent help

Common flags: --proxy URL, --cookie STR, --timeout MS
`;

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
            proxy: typeof flags.proxy === "string" ? flags.proxy : undefined,
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
            proxy: typeof flags.proxy === "string" ? flags.proxy : undefined,
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
            proxy: typeof flags.proxy === "string" ? flags.proxy : undefined,
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
            proxy: typeof flags.proxy === "string" ? flags.proxy : undefined,
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
            proxy: typeof flags.proxy === "string" ? flags.proxy : undefined,
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
      case "hunt": {
        const [goal, dir] = positional;
        if (!goal || !dir) {
          console.error("usage: hunt <goal> <outdir> [--model NAME] [--base-url URL] [--api-key KEY] [--chromium PATH] [--proxy URL] [--max-rounds N] [--max-steps N]");
          return 2;
        }
        const { runHunt } = await import("./application/hunt.js");
        const baseUrl = (typeof flags["base-url"] === "string" ? flags["base-url"] : undefined)
          ?? process.env.LLM_BASE_URL ?? "https://z-api.pp.ua/v1";
        const apiKey = (typeof flags["api-key"] === "string" ? flags["api-key"] : undefined)
          ?? process.env.LLM_API_KEY ?? process.env.NEWAPI_KEY ?? "";
        const model = (typeof flags.model === "string" ? flags.model : undefined)
          ?? process.env.LLM_MODEL ?? "glm-5.3-flash";
        const r = await runHunt({
          goal, outputRoot: dir,
          llm: { baseUrl, apiKey, model },
          chromiumPath: typeof flags.chromium === "string" ? flags.chromium : undefined,
          proxy: typeof flags.proxy === "string" ? flags.proxy : undefined,
          maxRounds: num(flags["max-rounds"]),
          maxSteps: num(flags["max-steps"]),
        });
        out(r);
        return 0;
      }
      case "auto": {
        const [seed, dir] = positional;
        if (!seed || !dir) {
          console.error("usage: auto <seed> <outdir> [--chromium PATH] [--skip-runtime] [--proxy URL] [--cookie STR] [--timeout MS]");
          return 2;
        }
        const { runAutoPipeline } = await import("./application/auto.js");
        out(
          await runAutoPipeline({
            seed,
            outputRoot: dir,
            chromiumPath: typeof flags.chromium === "string" ? flags.chromium : undefined,
            proxy: typeof flags.proxy === "string" ? flags.proxy : undefined,
            cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
            timeoutMs: num(flags.timeout),
            skipRuntime: flags["skip-runtime"] === true,
            maxPages: num(flags["max-pages"]),
          }),
        );
        return 0;
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