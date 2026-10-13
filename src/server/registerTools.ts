import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/server";

import { ALL_CONTRACTS } from "../contracts/contracts.js";
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

const handlers: Readonly<Record<string, Handler>> = {
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
    const { runAutoPipeline } = await import("../application/auto.js");
    return runAutoPipeline(
      z
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
        .parse(raw),
    );
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
export const registerAllTools = (server: McpServer): void => {
  for (const contract of ALL_CONTRACTS) {
    const handler = handlers[contract.name];
    if (!handler) continue;
    server.registerTool(
      contract.name,
      {
        title: contract.title,
        description: contract.description,
        inputSchema: contract.inputSchema as z.ZodType<Record<string, unknown>>,
      },
      async (input) => deliver(contract, () => handler(input as Record<string, unknown>)),
    );
  }
};

export type { ToolContract };