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
        maxRoutes: z.number().int().min(1).max(200).optional(),
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
        baseUrl: z.string().optional(),
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
  probe_oidc: async (raw) => {
    const p = z.object({ baseUrl: z.string(), outputRoot: z.string(), proxy: z.string().optional() }).parse(raw);
    const { probeOidc } = await import("../domain/oidc.js");
    return probeOidc(p);
  },
  probe_smuggle: async (raw) => {
    const p = z.object({ baseUrl: z.string(), outputRoot: z.string(), proxy: z.string().optional() }).parse(raw);
    const { probeSmuggle } = await import("../domain/smuggle.js");
    return probeSmuggle(p);
  },
  archive_recover: async (raw) => {
    const p = z.object({ url: z.string(), outputRoot: z.string(), proxy: z.string().optional() }).parse(raw);
    const { recoverUrl } = await import("../domain/archive.js");
    return recoverUrl(p);
  },
  ws_origin_check: async (raw) => {
    const p = z.object({ url: z.string(), outputRoot: z.string(), headers: z.record(z.string(), z.string()).optional() }).parse(raw);
    const { probeWsOrigin } = await import("../domain/wsOrigin.js");
    return probeWsOrigin(p);
  },
  graphql_deep: async (raw) => {
    const p = z.object({ endpoint: z.string(), outputRoot: z.string(), previousSchemaFile: z.string().optional(), headers: z.record(z.string(), z.string()).optional(), proxy: z.string().optional() }).parse(raw);
    const { probeGraphqlDeep } = await import("../domain/graphqlDeep.js");
    return probeGraphqlDeep(p);
  },
  proto_decode: async (raw) => {
    const p = z.object({ data: z.string(), encoding: z.enum(["hex", "base64"]).optional(), outputRoot: z.string() }).parse(raw);
    const { decodeProtoHeuristic } = await import("../domain/protoDecode.js");
    return decodeProtoHeuristic(p);
  },
  nuclei_lite: async (raw) => {
    const p = z.object({ baseUrl: z.string(), outputRoot: z.string(), proxy: z.string().optional() }).parse(raw);
    const { runNucleiLite } = await import("../domain/nucleiLite.js");
    return runNucleiLite(p);
  },
  login_replay: async (raw) => {
    const p = z.object({ baseUrl: z.string(), username: z.string(), password: z.string(), outputRoot: z.string(), chromiumPath: z.string().optional(), proxy: z.string().optional() }).parse(raw);
    const { replayLogin } = await import("../domain/loginReplay.js");
    return replayLogin(p);
  },
  backup_unpack: async (raw) => {
    const p = z.object({ urls: z.array(z.string()), outputRoot: z.string(), proxy: z.string().optional() }).parse(raw);
    const { unpackBackups } = await import("../domain/backupUnpack.js");
    return unpackBackups(p);
  },
  sqlite_read: async (raw) => {
    const p = z.object({ file: z.string(), outputRoot: z.string() }).parse(raw);
    const { readSqlite } = await import("../domain/sqliteRead.js");
    return readSqlite(p);
  },
  analyze_gates: async (raw) => {
    const p = z.object({ jsDir: z.string(), outputRoot: z.string() }).parse(raw);
    const { analyzeGates } = await import("../domain/gates.js");
    return analyzeGates(p);
  },
  run_coverage: async (raw) => {
    const p = z.object({ baseUrl: z.string(), outputRoot: z.string(), hook: z.record(z.string(), z.unknown()).optional(), cookie: z.string().optional(), chromiumPath: z.string().optional(), maxClicksPerCategory: z.number().optional() }).parse(raw);
    const { runCoverage } = await import("../domain/coverage.js");
    return runCoverage(p);
  },
  build_site_map: async (raw) => {
    const p = z.object({ baseUrl: z.string(), outputRoot: z.string(), runtimeMode: z.enum(["depth", "coverage", "both", "static-only"]).optional(), appType: z.string().optional(), limitations: z.string().optional() }).parse(raw);
    const { buildSiteMap } = await import("../domain/siteMap.js");
    return buildSiteMap(p);
  },
  traffic_record: async (raw) => {
    const p = z.object({ outputRoot: z.string(), port: z.number().optional(), upstreamProxy: z.string().optional(), maxExchanges: z.number().optional(), stop: z.boolean().optional(), mitm: z.boolean().optional() }).parse(raw);
    // One recorder per process, keyed by outputRoot; stop:true tears it down
    // (an explicit lifecycle instead of an untracked immortal listener).
    const g = globalThis as { __velricRecorders?: Map<string, import("../domain/trafficRecorder.js").TrafficRecorder> };
    const recs = g.__velricRecorders ?? (g.__velricRecorders = new Map());
    if (p.stop) {
      const rec = recs.get(p.outputRoot);
      if (rec) { await rec.stop(); recs.delete(p.outputRoot); return { port: 0, stopped: true, exchanges: rec.getExchanges().length }; }
      return { port: 0, stopped: false, exchanges: 0 };
    }
    const existing = recs.get(p.outputRoot);
    if (existing) return { port: -1, note: "recorder already bound for this outputRoot; pass stop:true to release" };
    const { TrafficRecorder } = await import("../domain/trafficRecorder.js");
    const rec = new TrafficRecorder(p);
    const port = await rec.start();
    recs.set(p.outputRoot, rec);
    return { port, note: "recorder bound; call again with stop:true to release" };
  },
  asset_graph: async (raw) => {
    const p = z.object({ outputRoot: z.string(), action: z.enum(["upsert", "upsert_url", "counts", "query"]), type: z.enum(["root_domain", "subdomain", "ip", "service", "app", "endpoint"]).optional(), value: z.string().optional(), parent: z.string().optional(), meta: z.record(z.string(), z.unknown()).optional(), taskTag: z.string().optional() }).parse(raw);
    const { AssetStore } = await import("../domain/graphs.js");
    const st = new AssetStore(p.outputRoot);
    await st.load();
    if (p.action === "upsert_url") {
      if (!p.value) throw new Error("value required");
      st.upsertUrl(p.value, p.taskTag);
    } else if (p.action === "upsert") {
      if (!p.type || !p.value) throw new Error("type+value required");
      st.upsert({ type: p.type, value: p.value, parent: p.parent, taskTag: p.taskTag, meta: p.meta });
    } else if (p.action === "counts") {
      return { ok: true, counts: st.countsByType() };
    } else if (p.action === "query") {
      if (!p.type) throw new Error("type required");
      return { ok: true, assets: st.queryByType(p.type).slice(0, 500).map((a) => ({ key: a.key, value: a.value, parent: a.parent })) };
    }
    await st.save();
    return { ok: true };
  },
  exploration_graph: async (raw) => {
    const p = z.object({ outputRoot: z.string(), action: z.enum(["add_node", "add_edge", "anchor", "set_state", "lineage", "overview"]), kind: z.enum(["goal", "intent", "fact", "finding", "hint"]).optional(), summary: z.string().optional(), payload: z.record(z.string(), z.unknown()).optional(), from: z.string().optional(), rel: z.enum(["spawns", "derived_from", "yields", "proves"]).optional(), to: z.string().optional(), nodeId: z.string().optional(), assetKey: z.string().optional(), state: z.enum(["open", "met", "dead", "pending"]).optional() }).parse(raw);
    const { ExplorationGraph } = await import("../domain/graphs.js");
    const g = new ExplorationGraph(p.outputRoot);
    await g.load();
    if (p.action === "add_node") {
      if (!p.kind || !p.summary) throw new Error("kind+summary required");
      const n = g.addNode(p.kind, p.summary, p.payload);
      await g.save();
      return { ok: true, node: { id: n.id, kind: n.kind, summary: n.summary } };
    }
    if (p.action === "add_edge") {
      if (!p.from || !p.rel || !p.to) throw new Error("from+rel+to required");
      g.addEdge(p.from, p.rel, p.to);
      await g.save();
      return { ok: true };
    }
    if (p.action === "anchor") {
      if (!p.nodeId || !p.assetKey) throw new Error("nodeId+assetKey required");
      g.anchor(p.nodeId, p.assetKey);
      await g.save();
      return { ok: true };
    }
    if (p.action === "set_state") {
      if (!p.nodeId || !p.state) throw new Error("nodeId+state required");
      g.setState(p.nodeId, p.state);
      await g.save();
      return { ok: true };
    }
    if (p.action === "lineage") {
      if (!p.nodeId) throw new Error("nodeId required");
      return { ok: true, lineage: g.lineage(p.nodeId) };
    }
    const ov = g.overview();
    await g.save();
    return { ok: true, overview: ov };
  },
  evidence_store: async (raw) => {
    const p = z.object({ outputRoot: z.string(), action: z.enum(["put", "get", "list"]), file: z.string().optional(), hash: z.string().optional(), tag: z.string().optional() }).parse(raw);
    const { EvidenceStore } = await import("../domain/graphs.js");
    const store = new EvidenceStore(p.outputRoot);
    await store.load();
    if (p.action === "put") {
      if (!p.file) throw new Error("file required");
      const { readFile: rf } = await import("node:fs/promises");
      const buf = await rf(p.file);
      const blob = await store.put(buf, p.tag);
      await store.save();
      return { hash: blob.hash, bytes: blob.bytes };
    }
    if (p.action === "get") {
      if (!p.hash) throw new Error("hash required");
      const buf = await store.get(p.hash);
      return { hash: p.hash, bytes: buf ? buf.length : 0, found: buf !== null };
    }
    return { entries: store.entries() };
  },
  cold_graph: async (raw) => {
    const p = z.object({ outputRoot: z.string(), action: z.enum(["compact", "expand"]), digestId: z.string().optional(), round: z.number().optional(), coldAfterRounds: z.number().optional(), maxDigestSize: z.number().optional() }).parse(raw);
    const { ExplorationGraph } = await import("../domain/graphs.js");
    const { compactGraph, expandDigest, loadStamps, saveStamps, touchLive, DEFAULT_COLD_PARAMS } = await import("../domain/coldGraph.js");
    const g = new ExplorationGraph(p.outputRoot);
    await g.load();
    const { stamps, round: prevRound } = await loadStamps(p.outputRoot);
    const round = p.round ?? prevRound + 1;
    if (p.action === "compact") {
      touchLive(g, stamps, round - 1); // nodes alive now were touched last round
      const r = compactGraph(g, stamps, round, { coldAfterRounds: p.coldAfterRounds ?? DEFAULT_COLD_PARAMS.coldAfterRounds, maxDigestSize: p.maxDigestSize ?? DEFAULT_COLD_PARAMS.maxDigestSize });
      await g.save();
      await saveStamps(p.outputRoot, stamps, round);
      return { digests: r.digests, folded: r.folded.length, rescued: r.rescued.length };
    }
    if (!p.digestId) throw new Error("digestId required for expand");
    const r = expandDigest(g, p.digestId, stamps, round);
    await g.save();
    await saveStamps(p.outputRoot, stamps, round);
    return { digests: [], expanded: r.expanded.length };
  },
  finding_retest: async (raw) => {
    const p = z.object({ outputRoot: z.string(), action: z.enum(["register", "run", "list"]), id: z.string().optional(), name: z.string().optional(), severity: z.enum(["low", "medium", "high", "critical"]).optional(), poc: z.object({ method: z.string(), url: z.string(), headers: z.record(z.string(), z.string()).optional(), body: z.string().optional() }).optional(), predicates: z.object({ fixedStatuses: z.array(z.number()).optional(), fixedBodyAny: z.array(z.string()).optional(), vulnerableBodyAny: z.array(z.string()).optional() }).optional(), proxy: z.string().optional(), note: z.string().optional() }).parse(raw);
    const mod = await import("../domain/retest.js");
    if (p.action === "register") {
      if (!p.id || !p.poc) throw new Error("id+poc required");
      return mod.registerFinding({ root: p.outputRoot, id: p.id, name: p.name ?? p.id, severity: p.severity ?? "medium", poc: p.poc, predicates: p.predicates });
    }
    if (p.action === "run") {
      if (!p.id) throw new Error("id required");
      return await mod.runRetest({ root: p.outputRoot, findingId: p.id, proxy: p.proxy, note: p.note });
    }
    return mod.listRetests(p.outputRoot);
  },
  traffic_query: async (raw) => {
    const p = z.object({ outputRoot: z.string(), action: z.enum(["search", "get"]), id: z.string().optional(), host: z.string().optional(), status: z.number().optional(), method: z.string().optional(), text: z.string().optional(), page: z.number().optional(), pageSize: z.number().optional() }).parse(raw);
    const mod = await import("../domain/trafficRecorder.js");
    if (p.action === "search") {
      return mod.searchTraffic({ outputRoot: p.outputRoot, host: p.host, status: p.status, method: p.method, text: p.text, page: p.page, pageSize: p.pageSize });
    }
    if (!p.id) throw new Error("id required");
    const r = await mod.getTraffic({ outputRoot: p.outputRoot, id: p.id });
    return { exchange: r.exchange, requestBytes: r.bodies?.request?.length ?? 0, responseBytes: r.bodies?.response?.length ?? 0 };
  },
  export_findings: async (raw) => {
    const p = z.object({ reportJsonFile: z.string(), outputRoot: z.string(), format: z.enum(["csv", "json", "md-all"]) }).parse(raw);
    const { readFile } = await import("node:fs/promises");
    const { generateReportExports } = await import("../application/report.js");
    const rep = JSON.parse(await readFile(p.reportJsonFile, "utf8")) as { findings?: unknown[] };
    const findings = (rep.findings ?? []) as never[];
    const files = await generateReportExports({ outputRoot: p.outputRoot, format: p.format, findings });
    return { files: files.length };
  },
  evidence_bind: async (raw) => {
    const p = z.object({ outputRoot: z.string(), action: z.enum(["bind", "update", "unbind", "reorder", "get", "export"]), findingId: z.string().optional(), expectedVersion: z.number().optional(), refs: z.array(z.object({ hash: z.string(), role: z.enum(["baseline", "proof", "verification", "supporting"]), note: z.string().optional() })).optional(), bindingId: z.string().optional(), role: z.enum(["baseline", "proof", "verification", "supporting"]).optional(), note: z.string().optional(), order: z.array(z.string()).optional(), zipPath: z.string().optional() }).parse(raw);
    const mod = await import("../domain/evidenceBinding.js");
    if (p.action === "bind") {
      if (!p.findingId || !p.refs) throw new Error("findingId+refs required");
      return await mod.bindEvidence({ root: p.outputRoot, findingId: p.findingId, expectedVersion: p.expectedVersion ?? 0, refs: p.refs });
    }
    if (p.action === "update") {
      if (!p.findingId || !p.bindingId) throw new Error("findingId+bindingId required");
      return await mod.updateBinding({ root: p.outputRoot, findingId: p.findingId, bindingId: p.bindingId, expectedVersion: p.expectedVersion ?? 0, role: p.role, note: p.note });
    }
    if (p.action === "unbind") {
      if (!p.findingId || !p.bindingId) throw new Error("findingId+bindingId required");
      return await mod.unbindEvidence({ root: p.outputRoot, findingId: p.findingId, bindingId: p.bindingId, expectedVersion: p.expectedVersion ?? 0 });
    }
    if (p.action === "reorder") {
      if (!p.findingId || !p.order) throw new Error("findingId+order required");
      return await mod.reorderBindings({ root: p.outputRoot, findingId: p.findingId, expectedVersion: p.expectedVersion ?? 0, order: p.order });
    }
    if (p.action === "export") {
      if (!p.findingId || !p.zipPath) throw new Error("findingId+zipPath required");
      return await mod.exportBindings({ root: p.outputRoot, findingId: p.findingId, zipPath: p.zipPath });
    }
    if (!p.findingId) throw new Error("findingId required");
    const b = await mod.getBindings(p.outputRoot, p.findingId);
    return b ?? { findingId: p.findingId, version: 0, bindings: [] };
  },
  replay_tamper: async (raw) => {
    const p = z.object({ recordRoot: z.string(), outputRoot: z.string(), exchangeIds: z.array(z.string()).optional(), rules: z.array(z.object({ field: z.string(), in: z.enum(["body", "query"]), value: z.union([z.string(), z.number(), z.boolean(), z.null()]), label: z.string().optional() })).optional(), cookie: z.string().optional(), extraHeaders: z.record(z.string(), z.string()).optional(), proxy: z.string().optional(), timeoutMs: z.number().optional(), maxExchanges: z.number().optional() }).parse(raw);
    const { replayTamper } = await import("../domain/replayTamper.js");
    return replayTamper({ ...p, rules: (p.rules ?? []).map((x) => ({ ...x, label: x.label ?? `${x.field}=${String(x.value)}` })) });
  },
  deobfuscate_js: async (raw) => {
    const p = z.object({ jsDir: z.string(), outputRoot: z.string(), maxFiles: z.number().optional(), maxFileBytes: z.number().optional() }).parse(raw);
    const { deobfuscateCorpus } = await import("../domain/deobf.js");
    return deobfuscateCorpus(p);
  },
  oob_confirm: async (raw) => {
    const p = z.object({ url: z.string(), outputRoot: z.string(), payloads: z.array(z.string()), positions: z.array(z.object({ param: z.string(), in: z.enum(["query", "body", "header", "path"]) })).optional(), method: z.string().optional(), body: z.string().optional(), headers: z.record(z.string(), z.string()).optional(), proxy: z.string().optional(), timeoutMs: z.number().optional(), pollMs: z.number().optional() }).parse(raw);
    const { probeOob } = await import("../domain/oobConfirm.js");
    return probeOob(p);
  },
  role_matrix: async (raw) => {
    const p = z.object({ reconRoot: z.string(), outputRoot: z.string(), roles: z.record(z.string(), z.string()), proxy: z.string().optional(), timeoutMs: z.number().optional(), maxEndpoints: z.number().optional() }).parse(raw);
    const { probeRoleMatrix } = await import("../domain/roleMatrix.js");
    return probeRoleMatrix(p);
  },
  jwt_attack: async (raw) => {
    const p = z.object({ token: z.string(), endpoint: z.string(), outputRoot: z.string(), headers: z.record(z.string(), z.string()).optional(), proxy: z.string().optional(), timeoutMs: z.number().optional(), secretCandidates: z.array(z.string()).optional() }).parse(raw);
    const { probeJwtAttack } = await import("../domain/jwtAttack.js");
    return probeJwtAttack(p);
  },
  idor_deep: async (raw) => {
    const p = z.object({ endpoints: z.array(z.object({ method: z.string(), path: z.string(), fields: z.array(z.object({ name: z.string(), in: z.string() })) })), outputRoot: z.string(), baseUrl: z.string().optional(), cookie: z.string().optional(), headers: z.record(z.string(), z.string()).optional(), proxy: z.string().optional(), timeoutMs: z.number().optional(), maxTargets: z.number().optional(), objectIds: z.array(z.string()).optional() }).parse(raw);
    const { probeIdorDeep } = await import("../domain/idorDeep.js");
    return probeIdorDeep(p);
  },
  header_bypass: async (raw) => {
    const p = z.object({ urls: z.array(z.string()), outputRoot: z.string(), cookie: z.string().optional(), headers: z.record(z.string(), z.string()).optional(), proxy: z.string().optional(), timeoutMs: z.number().optional(), maxUrls: z.number().optional() }).parse(raw);
    const { probeHeaderBypass } = await import("../domain/headerBypass.js");
    return probeHeaderBypass(p);
  },
  verb_matrix: async (raw) => {
    const p = z.object({ urls: z.array(z.string()), outputRoot: z.string(), cookie: z.string().optional(), headers: z.record(z.string(), z.string()).optional(), proxy: z.string().optional(), timeoutMs: z.number().optional(), maxUrls: z.number().optional() }).parse(raw);
    const { probeVerbMatrix } = await import("../domain/verbMatrix.js");
    return probeVerbMatrix(p);
  },
  admin_surface: async (raw) => {
    const p = z.object({ baseUrl: z.string(), outputRoot: z.string(), cookie: z.string().optional(), headers: z.record(z.string(), z.string()).optional(), proxy: z.string().optional(), timeoutMs: z.number().optional() }).parse(raw);
    const { probeAdminSurface } = await import("../domain/adminSurface.js");
    return probeAdminSurface(p);
  },
  graphql_authz: async (raw) => {
    const p = z.object({ endpoint: z.string(), schemaFile: z.string(), outputRoot: z.string(), token: z.string().optional(), headers: z.record(z.string(), z.string()).optional(), proxy: z.string().optional(), timeoutMs: z.number().optional(), maxFields: z.number().optional() }).parse(raw);
    const { probeGraphqlAuthz } = await import("../domain/graphqlAuthz.js");
    return probeGraphqlAuthz(p);
  },
  scan_platform: async (raw) => {
    const p = z.object({ outputRoot: z.string(), action: z.enum(["create_project", "create_task", "run_task", "get_task", "list_tasks", "list_projects", "list_assets", "count_assets"]), name: z.string().optional(), targets: z.array(z.string()).optional(), projectId: z.string().optional(), taskId: z.string().optional(), modules: z.array(z.string()).optional(), sourceTask: z.string().optional(), query: z.object({ type: z.string().optional(), taskTag: z.string().optional(), valuePrefix: z.string().optional(), valueRegex: z.string().optional() }).optional(), page: z.number().optional(), pageSize: z.number().optional(), proxy: z.string().optional(), cookie: z.string().optional(), timeoutMs: z.number().optional() }).parse(raw);
    const mod = await import("../domain/scanPlatform.js");
    if (p.action === "create_project") {
      if (!p.name || !p.targets) throw new Error("name+targets required");
      return await mod.createProject(p.outputRoot, { name: p.name, targets: p.targets });
    }
    if (p.action === "create_task") {
      if (!p.projectId || !p.name || !p.modules) throw new Error("projectId+name+modules required");
      return await mod.createTask(p.outputRoot, { projectId: p.projectId, name: p.name, modules: p.modules, targets: p.targets, sourceTask: p.sourceTask });
    }
    if (p.action === "run_task") {
      if (!p.taskId) throw new Error("taskId required");
      return await mod.runTask(p.outputRoot, { taskId: p.taskId, proxy: p.proxy, cookie: p.cookie, timeoutMs: p.timeoutMs });
    }
    if (p.action === "get_task") {
      if (!p.taskId) throw new Error("taskId required");
      const t = await mod.getTask(p.outputRoot, p.taskId);
      if (!t) throw new Error("task not found");
      return t;
    }
    if (p.action === "list_tasks") return await mod.listTasks(p.outputRoot, p.projectId);
    if (p.action === "list_projects") return await mod.listProjects(p.outputRoot);
    if (p.action === "list_assets") return await mod.listAssets(p.outputRoot, p.query ?? {}, p.page ?? 1, p.pageSize ?? 50);
    if (!p.query) return await mod.countAssets(p.outputRoot, {}); // empty query = total count, not an error
    return await mod.countAssets(p.outputRoot, p.query);
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
  // 2) request-bearing result fields only. A deep walk over the whole result
  // would also harvest URLs merely QUOTED in response bodies (a target API
  // echoing arbitrary links) — the evidence gate must only vouch for URLs
  // the tool itself requested.
  const REQUEST_FIELDS = ["url", "finalUrl", "requested", "touched", "fetched", "visited", "crawled", "endpoint", "host", "target", "service", "value", "path", "url_ish"];
  const seen = new Set<unknown>();
  const MAX_WALK = 2000;
  let walked = 0;
  const isRequestField = (key: string): boolean => REQUEST_FIELDS.includes(key) || /(?:url|host|origin|endpoint|requested|touched|fetched|visited)/i.test(key);
  const walk = (node: unknown, key: string, depth: number): void => {
    if (walked++ > MAX_WALK || depth > 6 || node == null) return;
    if (typeof node === "string") {
      if (isRequestField(key) && /^https?:\/\//.test(node)) add(node);
      return;
    }
    if (typeof node !== "object") return;
    if (seen.has(node)) return;
    seen.add(node);
    if (Array.isArray(node)) {
      for (const x of node) walk(x, key, depth);
      return;
    }
    const o = node as Record<string, unknown>;
    // {url, status} records are the canonical request+observation pair.
    if (typeof o.url === "string" && /^https?:\/\//.test(o.url) && typeof o.status === "number") {
      add(o.url, o.status);
    }
    for (const [k, v] of Object.entries(o)) walk(v, k, depth + 1);
  };
  walk(out, "", 0);
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