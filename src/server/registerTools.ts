import { join } from "node:path";
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/server";

import { ALL_CONTRACTS } from "../contracts/contracts.js";
import { PHASE_TAGS } from "./workflow.js";
import type { ToolContract } from "../contracts/toolContract.js";
import { deliver } from "./delivery.js";
import { resolveHost } from "../application/dns.js";
import { httpProbe } from "../application/probe.js";
import { harvestStatic, readJsCorpus } from "../application/harvest.js";
import { spiderMpa } from "../application/spider.js";
import { buildPermissionTree } from "../application/permTreeService.js";
import { mergeParamSamples } from "../application/paramMerge.js";
import { captureRuntime } from "../application/runtime.js";
import { DEFAULT_HOOK_CONFIG } from "../domain/preload.js";
import { writeArtifact } from "../adapters/artifacts.js";
import { classifyPaths, extractPathLiterals, extractRoutes } from "../domain/endpoints.js";

type Handler = (input: Record<string, unknown>) => Promise<unknown>;

export const handlers: Readonly<Record<string, Handler>> = {
  dns_resolve: async (raw) => {
    const input = z.object({ hosts: z.array(z.string()) }).parse(raw);
    const results = [];
    for (const host of input.hosts) results.push(await resolveHost(host));
    return { results };
  },
  http_probe: async (raw) => {
    const input = z
      .object({
        url: z.string(),
        cookie: z.string().optional(),
        proxy: z.string().optional(),
        timeoutMs: z.number().optional(),
        headers: z.record(z.string(), z.string()).optional(),
      })
      .parse(raw);
    return httpProbe(input);
  },
  harvest_static: (raw) =>
    harvestStatic(
      z
        .object({
          baseUrl: z.string(),
          outputRoot: z.string(),
          timeoutMs: z.number().optional(),
          maxRounds: z.number().optional(),
          concurrency: z.number().optional(),
          proxy: z.string().optional(),
          cookie: z.string().optional(),
        })
        .parse(raw),
    ),
  extract_routes: async (raw) => {
    const input = z
      .object({ jsDir: z.string(), outputRoot: z.string() })
      .parse(raw);
    const corpus = await readJsCorpus(input.jsDir);
    if (corpus.length === 0) {
      throw {
        code: "no_js_corpus",
        message: `no .js files under ${input.jsDir}`,
        remediation: "run harvest_static first",
      };
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
    const artifacts = [];
    artifacts.push(await writeArtifact(input.outputRoot, "api_static.txt", [...api].sort().join("\n")));
    artifacts.push(await writeArtifact(input.outputRoot, "paths_other.txt", [...other].sort().join("\n")));
    artifacts.push(await writeArtifact(input.outputRoot, "routes.txt", [...routes].sort().join("\n")));
    return {
      files: corpus.length,
      api: api.size,
      other: other.size,
      routes: routes.size,
      artifacts,
    };
  },
  spider_mpa: (raw) =>
    spiderMpa(
      z
        .object({
          baseUrl: z.string(),
          outputRoot: z.string(),
          cookie: z.string().optional(),
          proxy: z.string().optional(),
          maxPages: z.number().optional(),
          depth: z.number().optional(),
          delayMs: z.number().optional(),
          include: z.string().optional(),
          exclude: z.string().optional(),
        })
        .parse(raw),
    ),
  capture_runtime: (raw) => {
    const i = z
      .object({
        baseUrl: z.string(),
        outputRoot: z.string(),
        routes: z.array(z.string()).optional(),
        cookies: z
          .array(
            z.object({
              name: z.string(),
              value: z.string(),
              path: z.string().optional(),
            }),
          )
          .optional(),
        localStorage: z.record(z.string(), z.string()).optional(),
        stubs: z.array(z.object({ match: z.string(), body: z.unknown() })).optional(),
        chromiumPath: z.string().optional(),
        headless: z.boolean().optional(),
        proxy: z.string().optional(),
        waitMs: z.number().optional(),
        perRouteMs: z.number().optional(),
        routeTimeoutMs: z.number().optional(),
        recordWs: z.boolean().optional(),
        apiPattern: z.string().optional(),
      })
      .parse(raw);
    return captureRuntime({
      ...i,
      hook: i.apiPattern ? { ...DEFAULT_HOOK_CONFIG, apiPattern: i.apiPattern } : undefined,
    });
  },
  build_perm_tree: (raw) =>
    buildPermissionTree(
      z
        .object({
          jsDir: z.string(),
          outputRoot: z.string(),
          role: z.string().optional(),
          roots: z.array(z.string()).optional(),
          prefixParent: z.record(z.string(), z.string()).optional(),
          extraParent: z.record(z.string(), z.string()).optional(),
        })
        .parse(raw),
    ),
  merge_params: (raw) =>
    mergeParamSamples(
      z
        .object({ samplesFile: z.string(), outputRoot: z.string() })
        .parse(raw),
    ),
  enrich_assets: async (raw) => {
    const { enrichAssets } = await import("../application/enrich.js");
    return enrichAssets(
      z
        .object({
          seeds: z.array(z.string()).min(1),
          outputRoot: z.string(),
          proxy: z.string().optional(),
          cookie: z.string().optional(),
          timeoutMs: z.number().optional(),
          http: z.boolean().optional(),
        })
        .parse(raw),
    );
  },
  gen_report: async (raw) => {
    const p = z
      .object({ reportFile: z.string(), outputRoot: z.string() })
      .parse(raw);
    const { readFile } = await import("node:fs/promises");
    const { generateReport } = await import("../application/report.js");
    return generateReport({ reportJson: await readFile(p.reportFile, "utf8"), outputRoot: p.outputRoot });
  },
  auto_recon: async (raw) => {
    // Async start + auto_status poll (MCP clients default to a 60s request
    // timeout; the full pipeline takes minutes). Mirrors the hunt pattern.
    const p = z
      .object({
        seed: z.string(),
        outputRoot: z.string(),
        chromiumPath: z.string().optional(),
        proxy: z.string().optional(),
        cookie: z.string().optional(),
        timeoutMs: z.number().optional(),
        skipRuntime: z.boolean().optional(),
        maxPages: z.number().optional(),
      })
      .parse(raw);
    const { join } = await import("node:path");
    const statusFile = join(p.outputRoot, "auto_status.json");
    const { writeFile, mkdir } = await import("node:fs/promises");
    await mkdir(p.outputRoot, { recursive: true });
    await writeFile(statusFile, JSON.stringify({ state: "running", startedAt: new Date().toISOString() }));
    void (async () => {
      try {
        const { runAutoPipeline } = await import("../application/auto.js");
        const result = await runAutoPipeline(p);
        await writeFile(statusFile, JSON.stringify({ state: "done", startedAt: new Date().toISOString(), result }));
      } catch (e) {
        await writeFile(statusFile, JSON.stringify({ state: "error", error: String((e as Error).message ?? e) }));
      }
    })();
    return { started: true, outputRoot: p.outputRoot, statusFile, pollWith: "auto_status" };
  },
  auto_status: async (raw) => {
    const p = z.object({ outputRoot: z.string() }).parse(raw);
    const { readFile } = await import("node:fs/promises");
    const { join } = await import("node:path");
    try {
      const status = JSON.parse(await readFile(join(p.outputRoot, "auto_status.json"), "utf8"));
      // Stage-level progress: pipeline.json is written stage-by-stage when the
      // pipeline runs in-progress mode; merge what exists into the status.
      try {
        const pipeline = JSON.parse(await readFile(join(p.outputRoot, "pipeline.json"), "utf8"));
        if (Array.isArray(pipeline.stages)) {
          return { ...status, stages: pipeline.stages };
        }
      } catch { /* pipeline.json not written yet — fine */ }
      return status;
    } catch {
      return { state: "unknown", hint: "call auto_recon first" };
    }
  },
  hunt_begin: async (raw) => {
    const { huntBegin } = await import("../application/huntDriver.js");
    const p = z.object({ goal: z.string(), outputRoot: z.string() }).parse(raw);
    return huntBegin(p);
  },
  hunt_record: async (raw) => {
    const { huntRecord } = await import("../application/huntDriver.js");
    const p = z
      .object({
        outputRoot: z.string(),
        intentId: z.number().optional(),
        intentSummary: z.string().optional(),
        goals: z.array(z.object({ summary: z.string(), vulnclass: z.string().optional() })).optional(),
        intents: z.array(z.object({ summary: z.string(), state: z.string().optional() })).optional(),
        facts: z.array(z.object({
          summary: z.string().optional(),
          detail: z.string().optional(),
          evidence: z.string().optional(),
          confidence: z.string().optional(),
        })).optional(),
        findings: z.array(z.object({
          name: z.string().optional(),
          vulnclass: z.string().optional(),
          severity: z.string().optional(),
          summary: z.string().optional(),
          poc: z.string().optional(),
        })).optional(),
        assets: z.array(z.object({
          type: z.string().optional(),
          key: z.string().optional(),
          props: z.record(z.string(), z.unknown()).optional(),
        })).optional(),
        goalsMet: z.array(z.object({ id: z.number(), reason: z.string().optional() })).optional(),
      })
      .parse(raw);
    const r = await huntRecord(p);
    return {
      accepted: r.accepted,
      dropped: r.dropped,
      dropReasons: r.dropReasons,
      goalsMet: r.graph.goals.filter((x) => x.met).length,
      goalsTotal: r.graph.goals.length,
      facts: r.graph.facts.length,
      findings: r.graph.findings.length,
      assets: r.graph.assets.length,
    };
  },
  hunt_overview: async (raw) => {
    const { huntOverview, exportLedgerEvidence } = await import("../application/huntDriver.js");
    const p = z.object({ outputRoot: z.string() }).parse(raw);
    // Best-effort: snapshot the ledger as a content-addressed evidence blob on
    // every overview read, so hunts self-verify without an explicit step.
    try { await exportLedgerEvidence(p.outputRoot); } catch { /* best-effort */ }
    return huntOverview(p.outputRoot);
  },
  run_diff: async (raw) => {
    const p = z.object({ oldRoot: z.string(), newRoot: z.string() }).parse(raw);
    const { runDiff } = await import("../application/runDiff.js");
    return runDiff(p);
  },
  probe_params: async (raw) => {
    const p = z
      .object({
        mergedFile: z.string(),
        outputRoot: z.string(),
        cookie: z.string().optional(),
        proxy: z.string().optional(),
        timeoutMs: z.number().optional(),
        maxEndpoints: z.number().optional(),
      })
      .parse(raw);
    const { probeParams } = await import("../application/paramProbe.js");
    return probeParams(p);
  },
  subdomain_enum: async (raw) => {
    const p = z.object({ domain: z.string(), outputRoot: z.string(), proxy: z.string().optional() }).parse(raw);
    const { discoverSubdomains } = await import("../domain/subdomains.js");
    return discoverSubdomains(p);
  },
  port_scan: async (raw) => {
    const p = z.object({ host: z.string(), outputRoot: z.string(), ports: z.array(z.number()).optional(), timeoutMs: z.number().optional(), concurrency: z.number().optional() }).parse(raw);
    const { scanPorts } = await import("../domain/portScan.js");
    return scanPorts(p);
  },
  probe_paths: async (raw) => {
    const p = z.object({ baseUrl: z.string(), outputRoot: z.string(), paths: z.array(z.string()).optional(), cookie: z.string().optional(), proxy: z.string().optional() }).parse(raw);
    const { probePaths } = await import("../domain/pathProbe.js");
    return probePaths(p);
  },
  probe_cors: async (raw) => {
    const p = z.object({ baseUrl: z.string(), outputRoot: z.string(), origins: z.array(z.string()).optional(), proxy: z.string().optional() }).parse(raw);
    const { probeCors } = await import("../domain/cors.js");
    return probeCors(p);
  },
  fingerprint: async (raw) => {
    const p = z.object({ baseUrl: z.string(), outputRoot: z.string(), cookie: z.string().optional(), proxy: z.string().optional() }).parse(raw);
    const { fingerprint } = await import("../domain/fingerprint.js");
    return fingerprint(p);
  },
  wayback_urls: async (raw) => {
    const p = z.object({ target: z.string(), outputRoot: z.string(), maxUrls: z.number().optional(), proxy: z.string().optional() }).parse(raw);
    const { fetchWayback } = await import("../domain/sourcemap.js");
    return fetchWayback(p);
  },
  detect_sourcemaps: async (raw) => {
    const p = z.object({ outputRoot: z.string(), jsDir: z.string().optional(), baseUrl: z.string().optional(), proxy: z.string().optional() }).parse(raw);
    const { detectSourceMaps } = await import("../domain/sourcemap.js");
    return detectSourceMaps(p);
  },
  auto_batch: async (raw) => {
    const p = z.object({ seedsFile: z.string(), outputRoot: z.string(), chromiumPath: z.string().optional(), skipRuntime: z.boolean().optional(), notifyWebhook: z.string().optional() }).parse(raw);
    // Async start (batch = N × minutes); poll each target's pipeline.json.
    const { join } = await import("node:path");
    const { writeFile, mkdir } = await import("node:fs/promises");
    const statusFile = join(p.outputRoot, "batch_status.json");
    await mkdir(p.outputRoot, { recursive: true });
    await writeFile(statusFile, JSON.stringify({ state: "running", startedAt: new Date().toISOString() }));
    void (async () => {
      try {
        const { runBatch } = await import("../application/batch.js");
        const result = await runBatch(p);
        await writeFile(statusFile, JSON.stringify({ state: "done", result }));
      } catch (e) {
        await writeFile(statusFile, JSON.stringify({ state: "error", error: String((e as Error).message ?? e) }));
      }
    })();
    return { started: true, outputRoot: p.outputRoot, statusFile, pollHint: "read batch_status.json / each target's pipeline.json" };
  },
  auth_probe: async (raw) => {
    const p = z.object({ endpointsFile: z.string(), outputRoot: z.string(), cookie: z.string().optional(), proxy: z.string().optional() }).parse(raw);
    const { probeAuth } = await import("../domain/authProbe.js");
    return probeAuth(p);
  },
  idor_prescreen: async (raw) => {
    const p = z.object({ mergedFile: z.string(), outputRoot: z.string(), cookie: z.string().optional(), proxy: z.string().optional() }).parse(raw);
    const { prescreenIdor } = await import("../domain/authProbe.js");
    return prescreenIdor(p);
  },
  git_restore: async (raw) => {
    const p = z.object({ baseUrl: z.string(), outputRoot: z.string(), proxy: z.string().optional() }).parse(raw);
    const { restoreGit } = await import("../domain/gitRestore.js");
    return restoreGit(p);
  },
  dom_sinks: async (raw) => {
    const p = z.object({ jsDir: z.string(), outputRoot: z.string() }).parse(raw);
    const { scanDomSinks } = await import("../domain/domSinks.js");
    return scanDomSinks(p);
  },
  jwt_inspect: async (raw) => {
    const p = z.object({ outputRoot: z.string(), secretsFile: z.string().optional(), jsDir: z.string().optional(), token: z.string().optional() }).parse(raw);
    const { inspectJwt } = await import("../domain/jwt.js");
    return inspectJwt(p);
  },
  ws_schema: async (raw) => {
    const p = z.object({ runtimeFile: z.string(), outputRoot: z.string() }).parse(raw);
    const { extractWsSchema } = await import("../domain/wsSchema.js");
    return extractWsSchema(p);
  },
  workflow_guide: async () => {
    const { WORKFLOW_GUIDE } = await import("./workflow.js");
    return WORKFLOW_GUIDE;
  },
  save_evidence: async (raw) => {
    const p = z
      .object({ itemsFile: z.string(), outputRoot: z.string() })
      .parse(raw);
    const { readFile } = await import("node:fs/promises");
    const { saveEvidence } = await import("../application/evidence.js");
    return saveEvidence({
      outputRoot: p.outputRoot,
      items: JSON.parse(await readFile(p.itemsFile, "utf8")),
    });
  },
};

/** Register every contract on one MCP server instance. */
/** Best-effort extraction of URLs a tool truly touched (from args + result). */
const extractTouchedUrls = (
  input: Record<string, unknown>,
  out: unknown,
): { url: string; status: number | null }[] => {
  const urls: { url: string; status: number | null }[] = [];
  const add = (u: unknown, status: number | null = null): void => {
    if (typeof u === "string" && /^https?:\/\//.test(u)) {
      // Upsert: a known-status observation upgrades an earlier statusless
      // entry (e.g. the arg URL recorded before the result carried 200).
      const prior = urls.find((e) => e.url === u);
      if (!prior) urls.push({ url: u, status });
      else if (prior.status == null && status != null) prior.status = status;
    }
  };
  // 1) explicit URL-ish args
  for (const key of ["url", "baseUrl", "seed", "urls", "seeds", "hosts"]) {
    const v = input[key];
    if (typeof v === "string") add(v);
    if (Array.isArray(v)) for (const x of v) add(x);
  }
  // 2) deep-walk the tool RESULT for any http(s) URL + adjacent status codes.
  // Harvest/spider/runtime touch dozens of URLs that never appear in args;
  // without this the evidence gate under-covers and would drop valid facts.
  const seen = new Set<unknown>();
  const MAX_WALK = 5000;
  let walked = 0;
  const walk = (node: unknown, depth: number): void => {
    if (walked++ > MAX_WALK || depth > 6 || node == null) return;
    if (typeof node === "string") {
      if (/^https?:\/\//.test(node)) add(node);
      return;
    }
    if (typeof node !== "object") return;
    if (seen.has(node)) return;
    seen.add(node);
    if (Array.isArray(node)) {
      for (const x of node) walk(x, depth + 1);
      return;
    }
    const o = node as Record<string, unknown>;
    if (typeof o.url === "string" && /^https?:\/\//.test(o.url) && typeof o.status === "number") {
      add(o.url, o.status);
    }
    for (const v of Object.values(o)) walk(v, depth + 1);
  };
  walk(out, 0);
  return urls;
};

export const registerAllTools = (server: McpServer): void => {
  for (const contract of ALL_CONTRACTS) {
    const handler = handlers[contract.name];
    // Fail loud at startup: a contract without a handler once shipped silently
    // (workflow_guide) and masked the regression for days.
    if (!handler) throw new Error(`no handler registered for contract: ${contract.name}`);
    server.registerTool(
      contract.name,
      {
        title: contract.title,
        description: `${PHASE_TAGS[contract.name] ? PHASE_TAGS[contract.name] + " — " : ""}${contract.description}`,
        inputSchema: contract.inputSchema as z.ZodType<Record<string, unknown>>,
      },
      async (input) =>
        deliver(contract, async () => {
          const out = await handler(input as Record<string, unknown>);
          // Observation ledger: record what this tool ACTUALLY touched, so the
          // host's evidence citations can be gated against reality. Never
          // trusts narration; derived from the tool's own result.
          const ledgerRoot = (input as Record<string, unknown>).observationLedgerRoot;
          if (typeof ledgerRoot === "string" && ledgerRoot && contract.name !== "hunt_record") {
            try {
              const { appendLedger } = await import("../application/huntDriver.js");
              const urls = extractTouchedUrls(input as Record<string, unknown>, out);
              const byUrl = new Map<string, number | null>();
              for (const e of urls) byUrl.set(e.url, e.status);
              if (byUrl.size > 0) {
                await appendLedger(ledgerRoot, [...byUrl.entries()].map(([url, status]) => ({
                  tool: contract.name, url, status, at: new Date().toISOString(),
                })));
              }
            } catch { /* ledger is best-effort; never fail the tool */ }
          }
          return out;
        }),
    );
  }
};

export type { ToolContract };