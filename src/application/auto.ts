import { mkdir, readFile, writeFile, rename } from "node:fs/promises";
import { join } from "node:path";
import { enrichAssets } from "./enrich.js";
import { harvestStatic } from "./harvest.js";
import { spiderMpa } from "./spider.js";
import { captureRuntime } from "./runtime.js";
import { buildPermissionTree } from "./permTreeService.js";
import { mergeParamSamples } from "./paramMerge.js";
import { generateReport } from "./report.js";
import { saveEvidence } from "./evidence.js";
import { writeArtifact } from "./enrich.js";

/**
 * Deterministic autonomous pipeline: stages run in dependency order against one
 * outputRoot; every stage is one of the 11 standalone tools; failure of a
 * non-critical stage is recorded and the pipeline continues. State lives in
 * files under outputRoot only — zero DB, resumable by re-run.
 *
 * Stage graph:
 *   enrich (DNS+HTTP asset graph)
 *     → classify: SPA (script bundles + pushState) vs MPA (server forms)
 *     → harvest_static (SPA) or spider_mpa (MPA)
 *     → capture_runtime (browser traffic)   [if chromium available]
 *     → build_perm_tree + merge_params      [when artifacts exist]
 *     → gen_report + save_evidence
 */

export interface AutoInput {
  readonly seed: string; // domain or URL
  readonly outputRoot: string;
  readonly chromiumPath?: string;
  readonly proxy?: string;
  readonly cookie?: string;
  readonly timeoutMs?: number;
  readonly skipRuntime?: boolean;
  /** Resume from checkpoint.json when true (default true). */
  readonly resume?: boolean;
  readonly maxPages?: number;
}

export interface StageResult {
  readonly stage: string;
  readonly status: "ok" | "skip" | "fail";
  readonly detail: string;
}

export interface AutoResult {
  readonly seed: string;
  readonly stages: StageResult[];
  readonly reportPath: string | null;
  readonly artifactCounts: Record<string, number>;
}

const exists = async (p: string): Promise<boolean> => {
  const { stat } = await import("node:fs/promises");
  try { await stat(p); return true; } catch { return false; }
};

const readJson = async <T>(p: string): Promise<T | null> => {
  try { return JSON.parse(await readFile(p, "utf8")) as T; } catch { return null; }
};

/** GraphQL introspection disabled detection: explicit error mentioning it. */
const introspectionBlocked = (body: string): boolean =>
  // Only denial semantics count; the bare phrase "GraphQL introspection"
  // also appears in SUCCESSFUL responses (schema descriptions).
  /introspection[^]{0,80}(disabled|not enabled|not allowed|has been disabled)/i.test(body);

const statMtime = async (p: string): Promise<number> => {
  const { stat } = await import("node:fs/promises");
  return (await stat(p)).mtimeMs;
};

export const runAutoPipeline = async (input: AutoInput): Promise<AutoResult> => {
  const runStartMs = Date.now();
  const stages: StageResult[] = [];
  const root = input.outputRoot;
  await mkdir(root, { recursive: true });

  // Checkpoint resume: stages already marked ok in checkpoint.json are skipped
  // (their artifacts are on disk). Wipe checkpoint.json for a fresh run.
  const { readCheckpoint, writeStageDone } = await import("../domain/rateLimit.js");
  const cp = input.resume === false ? { stages: {} } : await readCheckpoint(root, input.seed);
  const done = (stage: string): boolean => cp.stages[stage]?.status === "ok";
  const mark = async (stage: string): Promise<void> => { await writeStageDone(root, stage, input.seed); };

  // ---- Stage 0: fingerprint (WAF/CDN, methods, cookies) ----
  if (!done("fingerprint")) {
    try {
      const { fingerprint } = await import("../domain/fingerprint.js");
      const fp = await fingerprint({ baseUrl: input.seed, outputRoot: root, proxy: input.proxy, cookie: input.cookie, timeoutMs: input.timeoutMs });
      stages.push({ stage: "fingerprint", status: "ok", detail: `waf=${fp.waf.join(",") || "none"} methods=${fp.methods.allowed.length}` });
      await mark("fingerprint");
    } catch (e) {
      stages.push({ stage: "fingerprint", status: "fail", detail: String((e as Error).message ?? e).slice(0, 120) });
    }
  } else stages.push({ stage: "fingerprint", status: "skip", detail: "checkpoint" });

  // ---- Stage 0b: subdomain enumeration (domains only) ----
  const isDomainSeed = !/^https?:\/\//.test(input.seed) || /^https?:\/\/[^\/]+\/?$/.test(input.seed);
  if (!done("subdomains") && isDomainSeed) {
    try {
      // Strip scheme, path AND leading www. — subdomain enumeration must
      // target the registrable apex (www.host.tld → host.tld), else every
      // subdomain probe looks for www.host.tld.<word>.
      let domain = input.seed.replace(/^https?:\/\//, "").split("/")[0]!;
      domain = domain.replace(/^(?:www|m|mobile)\./, "");
      const { discoverSubdomains } = await import("../domain/subdomains.js");
      const sub = await discoverSubdomains({ domain, outputRoot: root, proxy: input.proxy });
      domain = sub.domain;
      stages.push({ stage: "subdomains", status: "ok", detail: `${sub.total.length} subdomains (crt.sh=${sub.crtSh.length} brute=${sub.bruteFound.length})` });
      await mark("subdomains");
    } catch (e) {
      stages.push({ stage: "subdomains", status: "fail", detail: String((e as Error).message ?? e).slice(0, 120) });
    }
  } else stages.push({ stage: "subdomains", status: "skip", detail: done("subdomains") ? "checkpoint" : "non-domain seed" });

  // ---- Stage 1: enrich asset graph ----
  let assetCounts: Record<string, number> = {};
  if (!done("enrich")) {
    try {
      const r = await enrichAssets({ seeds: [input.seed], outputRoot: root, proxy: input.proxy, cookie: input.cookie, timeoutMs: input.timeoutMs });
      assetCounts = r.counts;
      stages.push({ stage: "enrich", status: "ok", detail: `${r.assets.length} assets` });
      await mark("enrich");
    } catch (e) {
      stages.push({ stage: "enrich", status: "fail", detail: String((e as Error).message ?? e).slice(0, 120) });
    }
  } else {
    // checkpointed: reuse counts from the durable artifact the stage wrote
    try {
      const sync = JSON.parse(await readFile(join(root, "asset_graph_sync.json"), "utf8")) as { counts?: Record<string, number>; perRunCounts?: Record<string, number> };
      // perRunCounts mirrors the fresh-run return shape (counts is the
      // cumulative AssetStore total — a different number than a fresh run
      // would report for the same stage).
      assetCounts = sync.perRunCounts ?? sync.counts ?? {};
    } catch { /* artifact absent — zero counts */ }
    stages.push({ stage: "enrich", status: "skip", detail: "checkpoint" });
  }

  // ---- Stage 2: classify SPA vs MPA (fetch entry HTML once) ----
  // heuristic: heavy <script src> bundle + SPA framework markers → SPA; else MPA
  const { fetchUrl } = await import("../adapters/http.js");
  const base = /^https?:\/\//i.test(input.seed) ? input.seed : `https://${input.seed}`;
  let mode: "spa" | "mpa" = "mpa";
  try {
    const res = await fetchUrl(base, { proxy: input.proxy, cookie: input.cookie, timeoutMs: input.timeoutMs ?? 20000 });
    const html = res.body;
    const scripts = (html.match(/<script[^>]+src=/gi) ?? []).length;
    const spaMark = /__NUXT__|__NEXT_DATA__|data-v-app|ng-app/i.test(html);
    // MPA strong signal: server-rendered internal links. Real SPAs ship an
    // app shell with almost none; content MPA pages (~100) have many.
    const internalLinks = (html.match(/<a[^>]+href=["']?\/[^"']+["']?/gi) ?? []).length;
    const forms = (html.match(/<form/i) ?? []).length;
    // SPA detection needs converging signals, not a single marker:
    //   1. framework marker (NUXT/NEXT/vue/ng) AND sparse shell (<40 links), OR
    //   2. bundle dominance: 10+ external scripts and near-zero server links
    //      (SSR-rendered SPA shells: 20+ scripts, 0-2 server links), OR
    //   3. micro-frontend marker with few links.
    // Content MPAs (framework-widget + 100+ links) must stay MPA.
    if ((spaMark && internalLinks < 40) || (scripts >= 10 && internalLinks <= 2)) mode = "spa";
    else mode = "mpa";
    stages.push({ stage: "classify", status: "ok", detail: `mode=${mode} scripts=${scripts} forms=${forms}` });
  } catch (e) {
    stages.push({ stage: "classify", status: "fail", detail: String((e as Error).message ?? e).slice(0, 120) });
  }

  // ---- Stage 3: static recon (harvest for SPA / spider for MPA) ----
  if (mode === "spa") {
    try {
      const r = await harvestStatic({ baseUrl: base, outputRoot: root, proxy: input.proxy, cookie: input.cookie, timeoutMs: input.timeoutMs, maxRounds: 3 });
      stages.push({ stage: "harvest_static", status: "ok", detail: `api=${r.apiEndpoints} routes=${r.routes} js=${r.jsDownloaded}` });
    } catch (e) {
      stages.push({ stage: "harvest_static", status: "fail", detail: String((e as Error).message ?? e).slice(0, 120) });
    }
  } else {
    const runSpider = (): ReturnType<typeof spiderMpa> =>
      spiderMpa({ baseUrl: base, outputRoot: root, proxy: input.proxy, cookie: input.cookie, maxPages: input.maxPages ?? 30, depth: 2, delayMs: 500 });
    try {
      let r = await runSpider();
      // Entry-page fetches sometimes hit an edge challenge or flaky proxy and
      // yield a single page with no links — a hollow crawl that poisons every
      // downstream stage. Retry once in that case before accepting.
      if (r.crawled <= 1 && r.links === 0) {
        r = await runSpider();
      }
      stages.push({ stage: "spider_mpa", status: "ok", detail: `crawled=${r.crawled} forms=${r.forms} js=${r.scriptsDownloaded}` });
    } catch (e) {
      stages.push({ stage: "spider_mpa", status: "fail", detail: String((e as Error).message ?? e).slice(0, 120) });
    }
  }

  // ---- Stage 4: runtime capture (if chromium) ----
  // Let captureRuntime's env-aware resolver (VELRIC_CHROMIUM/CHROMIUM +
  //  common paths) pick the binary — a hardcoded default shadowed it.
  const chromium = input.chromiumPath;
  let runtimeCalls = 0;
  if (!input.skipRuntime) {
    // Heavy SPAs can crash the renderer under memory pressure (gitlab: Target
    // crashed). One retry with a shorter wait often lands it; a partial
    // runtime_api.json from the crashed run still contributes endpoints.
    let lastErr = "";
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const r = await captureRuntime({ baseUrl: base, outputRoot: root, chromiumPath: chromium, proxy: input.proxy, routes: ["/"], waitMs: attempt === 0 ? 4000 : 2000, perRouteMs: 2000 });
        runtimeCalls = r.uniqueCalls.length;
        stages.push({ stage: "capture_runtime", status: "ok", detail: `calls=${r.uniqueCalls.length} details=${r.details}` + (attempt > 0 ? " (retry)" : "") });
        lastErr = "";
        break;
      } catch (e) {
        lastErr = String((e as Error).message ?? e).slice(0, 120);
      }
    }
    if (lastErr) {
      // Salvage: did the crashed run still write runtime_api.json?
      const raPath = join(root, "runtime_api.json");
      let stale = false;
      try {
        const st = await statMtime(raPath);
        stale = st < runStartMs - 1000; // written before this run began → previous run's data
      } catch { stale = true; // stat failed: fail closed — treat as stale rather than trusting unknown provenance
      }
      if (!stale && await exists(raPath)) {
        try {
          const salvaged = await readJson<{ uniqueCalls?: string[] }>(join(root, "runtime_api.json"));
          runtimeCalls = salvaged?.uniqueCalls?.length ?? 0;
          stages.push({ stage: "capture_runtime", status: "ok", detail: `salvaged calls=${runtimeCalls} (renderer crashed mid-run)` });
        } catch {
          stages.push({ stage: "capture_runtime", status: "fail", detail: lastErr });
        }
      } else {
        stages.push({ stage: "capture_runtime", status: "fail", detail: lastErr });
      }
    }
  } else {
    stages.push({ stage: "capture_runtime", status: "skip", detail: "skipRuntime=true" });
    // Without runtime, api_merged never gets written (runtime owns that
    // merge). Fall back to the static list so downstream consumers
    // (batch summary, run_diff) still have an endpoint file.
    if (!(await exists(join(root, "api_merged.txt"))) && (await exists(join(root, "api_static.txt")))) {
      const { writeFile: wf } = await import("node:fs/promises");
      const staticList = await readFile(join(root, "api_static.txt"), "utf8");
      await wf(join(root, "api_merged.txt"), staticList);
    }
  }

  // ---- Stage 5: perm tree + param matrix (when artifacts exist) ----
  const jsDir = join(root, "js");
  if (await exists(join(root, "api_static.txt"))) {
    try {
      const perm = await buildPermissionTree({ jsDir, outputRoot: root });
      stages.push({ stage: "build_perm_tree", status: "ok", detail: `${(perm as { codes?: number }).codes ?? "?"} codes` });
    } catch {
      stages.push({ stage: "build_perm_tree", status: "skip", detail: "no auth markers in corpus" });
    }
  }
  const samplesFile = join(root, "param_samples.json");
  if (await exists(samplesFile) && !done("merge_params")) {
    try {
      const r = await mergeParamSamples({ samplesFile, outputRoot: root });
      stages.push({ stage: "merge_params", status: "ok", detail: `endpoints=${r.endpoints}` });
      await mark("merge_params");
    } catch (e) {
      stages.push({ stage: "merge_params", status: "fail", detail: String((e as Error).message ?? e).slice(0, 120) });
    }
  } else if (done("merge_params")) stages.push({ stage: "merge_params", status: "skip", detail: "checkpoint" });



  // ---- Stage 5b: sensitive paths (soft-404 calibrated) ----
  if (!done("paths")) {
    try {
      const { probePaths } = await import("../domain/pathProbe.js");
      const pp = await probePaths({ baseUrl: base, outputRoot: root, proxy: input.proxy, cookie: input.cookie, timeoutMs: input.timeoutMs });
      stages.push({ stage: "paths", status: "ok", detail: `${pp.found.length} found / ${pp.probed} probed` });
      await mark("paths");
    } catch (e) {
      stages.push({ stage: "paths", status: "fail", detail: String((e as Error).message ?? e).slice(0, 120) });
    }
  } else stages.push({ stage: "paths", status: "skip", detail: "checkpoint" });

  // ---- Stage 5c: CORS probe ----
  if (!done("cors")) {
    try {
      const { probeCors } = await import("../domain/cors.js");
      const co = await probeCors({ baseUrl: base, outputRoot: root, proxy: input.proxy, timeoutMs: input.timeoutMs });
      stages.push({ stage: "cors", status: "ok", detail: co.misconfigured ? "MISCONFIGURED" : "clean" });
      await mark("cors");
    } catch (e) {
      stages.push({ stage: "cors", status: "fail", detail: String((e as Error).message ?? e).slice(0, 120) });
    }
  } else stages.push({ stage: "cors", status: "skip", detail: "checkpoint" });

  // ---- Stage 5d: source-map leak detection ----
  if (!done("sourcemaps")) {
    try {
      const { detectSourceMaps } = await import("../domain/sourcemap.js");
      const sm = await detectSourceMaps({ outputRoot: root, baseUrl: input.seed.startsWith("http") ? input.seed : `https://${input.seed}`, proxy: input.proxy });
      stages.push({ stage: "sourcemaps", status: "ok", detail: `${sm.leaked.length} leaked / ${sm.checked} checked` });
      await mark("sourcemaps");
    } catch (e) {
      stages.push({ stage: "sourcemaps", status: "fail", detail: String((e as Error).message ?? e).slice(0, 120) });
    }
  } else stages.push({ stage: "sourcemaps", status: "skip", detail: "checkpoint" });

  // ---- Stage 5e: verification passes (auth surface / dom sinks / jwt) ----
  // Runtime capture can fail (both retries) leaving api_merged.txt absent —
  // auth_probe then silently skipped despite api_static.txt existing. Fall
  // back to the static corpus so the stage never starves.
  const authCorpus = (await exists(join(root, "api_merged.txt"))) ? join(root, "api_merged.txt") : (await exists(join(root, "api_static.txt"))) ? join(root, "api_static.txt") : null;
  if (!done("auth_probe") && authCorpus) {
    try {
      const { probeAuth } = await import("../domain/authProbe.js");
      const au = await probeAuth({ endpointsFile: authCorpus, outputRoot: root, proxy: input.proxy, cookie: input.cookie, timeoutMs: input.timeoutMs, maxEndpoints: 60 });
      stages.push({ stage: "auth_probe", status: "ok", detail: `anon=${au.anonymous.length} authReq=${au.authRequired.length}` });
      await mark("auth_probe");
    } catch (e) {
      stages.push({ stage: "auth_probe", status: "fail", detail: String((e as Error).message ?? e).slice(0, 120) });
    }
  } else stages.push({ stage: "auth_probe", status: "skip", detail: done("auth_probe") ? "checkpoint" : "no endpoints" });

  if (!done("dom_sinks") && (await exists(join(root, "js")))) {
    try {
      const { scanDomSinks } = await import("../domain/domSinks.js");
      const ds = await scanDomSinks({ jsDir: join(root, "js"), outputRoot: root });
      stages.push({ stage: "dom_sinks", status: "ok", detail: `${ds.chains.length} chains / ${ds.scanned} files` });
      await mark("dom_sinks");
    } catch (e) {
      stages.push({ stage: "dom_sinks", status: "fail", detail: String((e as Error).message ?? e).slice(0, 120) });
    }
  } else stages.push({ stage: "dom_sinks", status: "skip", detail: done("dom_sinks") ? "checkpoint" : "no js corpus" });

  if (!done("jwt_inspect")) {
    try {
      const { inspectJwt } = await import("../domain/jwt.js");
      const resumeOk = Object.keys(cp.stages).some((k) => cp.stages[k]?.status === "ok");
      const jt = await inspectJwt({ outputRoot: root, secretsFile: (await exists(join(root, "secrets.txt")) && resumeOk) ? join(root, "secrets.txt") : undefined, jsDir: (await exists(join(root, "js")) && resumeOk) ? join(root, "js") : undefined });
      stages.push({ stage: "jwt_inspect", status: "ok", detail: `${jt.tokens} tokens` });
      await mark("jwt_inspect");
    } catch (e) {
      stages.push({ stage: "jwt_inspect", status: "fail", detail: String((e as Error).message ?? e).slice(0, 120) });
    }
  } else stages.push({ stage: "jwt_inspect", status: "skip", detail: "checkpoint" });

  // ---- Stage 6: report + evidence ----
  const apiStatic = join(root, "api_static.txt");
  let findings = 0;
  const fList: unknown[] = [];
  // Freshness gate: artifacts written BEFORE this run began belong to a
  // previous seed — feeding them into this seed's findings is cross-target
  // contamination. Same mtime rule as the runtime salvage path.
  const fresh = async (p: string): Promise<boolean> => {
    if (!(await exists(p))) return false;
    if ((await statMtime(p)) >= runStartMs - 1000) return true;
    // Resumed run: an artifact written by a checkpoint-completed stage of THIS
    // seed is still valid (seed isolation is enforced by readCheckpoint) —
    // the mtime gate would otherwise silently drop its findings.
    // Any completed checkpoint stage proves this is a resumed run of the SAME
    // seed (readCheckpoint resets stages on seed mismatch), so older artifacts
    // under this root are still valid input.
    if (Object.values(cp.stages).some((v) => v.status === "ok")) return true;
    return false;
  };
  // auto-findings: exposed API surface from artifacts (deterministic heuristics)
  try {
    const apiList = (await fresh(apiStatic) ? (await readFile(apiStatic, "utf8")).split("\n").filter(Boolean) : []);
    const runtimeJson = (await fresh(join(root, "runtime_api.json"))) ? await readJson<{ uniqueCalls?: string[] }>(join(root, "runtime_api.json")) : undefined;
    const liveCalls = runtimeJson?.uniqueCalls ?? [];
    if (apiList.length > 0) {
      fList.push({
        name: `静态 bundle 暴露 ${apiList.length} 个 API 端点`,
        severity: apiList.length > 100 ? "high" : apiList.length > 10 ? "medium" : "low",
        summary: `harvest 从 JS bundle 提取 ${apiList.length} 个端点路径(含 ${apiList.filter((x) => /admin|manage|internal/.test(x)).length} 个管理/内部命名)`,
        poc: apiList.slice(0, 20).join("\n"),
      });
    }
    if (liveCalls.length > 0) {
      fList.push({
        name: `运行时确认 ${liveCalls.length} 个活跃 API 调用`,
        severity: "medium",
        summary: "capture_runtime 录制到真实后端流量(匿名可达)",
        poc: liveCalls.slice(0, 20).join("\n"),
      });
    }
    // Non-web open ports are direct findings
    const portsFile = join(root, "ports_open.txt");
    if (await fresh(portsFile)) {
      const lines = (await readFile(portsFile, "utf8")).split("\n").filter(Boolean);
      const risky = lines.filter((l) => /redis|mongodb|elasticsearch|mysql|postgres|memcached|kafka|docker|kubelet|solr|kibana|vnc|rdp|mssql|oracle/.test(l));
      if (risky.length > 0) {
        fList.push({
          name: `高危端口暴露 ${risky.length} 个`,
          severity: "high",
          summary: "TCP 扫描发现数据库/中间件/管理端口对外开放(未鉴权服务风险前置)",
          poc: risky.join("\n"),
        });
      }
    }
    // Sensitive paths that survived soft-404 calibration
    const sensFile = join(root, "sensitive_paths.txt");
    if (await fresh(sensFile)) {
      const lines = (await readFile(sensFile, "utf8")).split("\n").filter(Boolean);
      // wildcard-suspect rows are /{param} route renderings (title echoes the
      // probed segment, e.g. a username-profile page), never the endpoint
      // itself — excluded from the HIGH bucket, still visible in the artifact.
      const high = lines.filter((l) => /^200/.test(l) && !l.includes("[wildcard-suspect") && !l.includes("[redirectrw") && !l.includes("[profile-route")
        && /\.git|\.env|swagger|api-docs|actuator\/env|heapdump|druid|pprof|backup|dump\.sql|WEB-INF|\.well-known\/openid-configuration|\.well-known\/oauth-authorization-server/.test(l));
      if (high.length > 0) {
        fList.push({
          name: `敏感路径命中 ${high.length} 个`,
          severity: "high",
          summary: "soft-404 校准后仍 200 的高价值路径(.git/.env/swagger/actuator/druid/oidc-discovery 等)",
          poc: high.join("\n"),
        });
      }
      // Auth-relevant statuses: 401/403 (explicit auth) and 302 (auth
      // redirect to login) — plain 301/303 rewrites are NOT protected paths.
      // Auth-wall cluster: N probe paths collapsing onto one 401/403 sign-in
      // landing is a whole-site auth wall, not N individually protected
      // endpoints — report once with the cluster note, drop the duplicates.
      const wallCluster = lines.find((l) => /^40[13]|^302/.test(l) && l.includes("[catch-all"));
      if (wallCluster) {
        const n = Number(wallCluster.match(/×(\d+)/)?.[1] ?? "1");
        fList.push({
          name: `统一拦截/${n >= 10 ? "全站鉴权墙(auth-wall)" : `同页拦截簇 ×${n}`}`,
          severity: "low",
          summary: "多个探测路径落到同一 401/403 页 — 站点统一访问控制/WAF 规则, 非逐路径独立漏洞",
          poc: wallCluster,
        });
      }
      const protectedPaths = lines.filter((l) => (/^40[13]|^302/.test(l) || l.includes("[authwall")) && !l.includes("[catch-all") && !l.includes("[redirectrw"));
      if (protectedPaths.length > 0) {
        fList.push({
          name: `受保护路径存在 ${protectedPaths.length} 个`,
          severity: "low",
          summary: "401/403 路径=存在但需鉴权(目录爆破/绕过候选)",
          poc: protectedPaths.slice(0, 15).join("\n"),
        });
      }
    }
    // CORS misconfiguration
    const corsJson = (await fresh(join(root, "cors_probe.json"))) ? await readJson<{ misconfigured: boolean; results: { origin: string; acao: string | null; acac: boolean; verdict: string }[] }>(join(root, "cors_probe.json")) : undefined;
    if (corsJson?.misconfigured) {
      const bad = corsJson.results.filter((r) => r.acac && (r.verdict === "reflect" || r.verdict === "null"));
      fList.push({
        name: "CORS 配置缺陷",
        severity: "high",
        summary: `ACAO 反射任意 Origin 且允许 credentials(${bad.map((b) => b.origin).slice(0, 3).join(", ")})`,
        poc: JSON.stringify(bad, null, 2).slice(0, 800),
      });
    }
    // Source-map leaks
    const smFile = join(root, "sourcemaps.txt");
    if (await fresh(smFile)) {
      const lines = (await readFile(smFile, "utf8")).split("\n").filter(Boolean);
      if (lines.length > 0) {
        fList.push({
          name: `Source map 泄漏 ${lines.length} 个`,
          severity: "medium",
          summary: "生产 bundle 的 .map 可访问,原始源码可完整恢复",
          poc: lines.slice(0, 10).join("\n"),
        });
      }
    }
    // WAF/CDN presence (informational, recorded as fact via report meta)
    const fpJson = (await fresh(join(root, "fingerprint.json"))) ? await readJson<{ waf: string[] }>(join(root, "fingerprint.json")) : undefined;
    if (fpJson && fpJson.waf.length > 0) {
      fList.push({
        name: `WAF/CDN 在位: ${fpJson.waf.join(", ")}`,
        severity: "low",
        summary: "header 指纹识别的防护层,后续测试需降速/换路径",
        poc: JSON.stringify(fpJson.waf),
      });
    }
    // Anonymous-reachable endpoints (auth surface)
    const authJson = (await fresh(join(root, "auth_surface.json"))) ? await readJson<{ anonymous: { url: string }[]; authRequired: { url: string }[]; edgeBlocked?: boolean }>(join(root, "auth_surface.json")) : undefined;
    if (authJson?.edgeBlocked) {
      fList.push({
        name: "边缘级阻断(全站同码 403/429)",
        severity: "low",
        summary: "auth-probe 全部端点统一 403/429 = IP/UA 级边缘拦截,非端点鉴权;需代理/cookie 复测",
        poc: `dominant-status 检测:${authJson.authRequired?.length ?? 0} 条统一拦截`,
      });
    }
    if (authJson && !authJson.edgeBlocked && authJson.anonymous.length > 0) {
      fList.push({
        name: `匿名可达 API ${authJson.anonymous.length} 个`,
        severity: authJson.anonymous.length > 30 ? "medium" : "low",
        summary: `鉴权面测绘:${authJson.anonymous.length} 端点匿名 200(其中含写操作/管理命名的需重点复核),${authJson.authRequired?.length ?? 0} 端点需鉴权`,
        poc: authJson.anonymous.slice(0, 20).map((a) => a.url).join("\n"),
      });
    }
    // DOM-XSS taint chains
    const domJson = (await fresh(join(root, "dom_sinks.json"))) ? await readJson<{ chains: { file: string; source: string; sink: string }[] }>(join(root, "dom_sinks.json")) : undefined;
    if (domJson && domJson.chains.length > 0) {
      fList.push({
        name: `DOM-XSS 候选链 ${domJson.chains.length} 条`,
        severity: "medium",
        summary: "location.* → innerHTML/eval 类污点链(静态预筛,需宿主构造 PoC 复核)",
        poc: domJson.chains.slice(0, 10).map((c) => `${c.file}: ${c.source} → ${c.sink}`).join("\n"),
      });
    }
    // JWT weak secrets
    const jwtJson = (await fresh(join(root, "jwt_analysis.json"))) ? await readJson<{ analyses: { tokenPreview: string; algNone: boolean; weakSecret: string | null; expired: boolean | null }[] }>(join(root, "jwt_analysis.json")) : undefined;
    const weakJwts = jwtJson?.analyses.filter((a) => a.weakSecret || a.algNone) ?? [];
    if (weakJwts.length > 0) {
      fList.push({
        name: `JWT 弱凭据 ${weakJwts.length} 个`,
        severity: "high",
        summary: "HS256 弱密钥可爆破或 alg=none,token 可伪造",
        poc: weakJwts.map((a) => `${a.tokenPreview} ${a.algNone ? "alg=none" : "secret=" + a.weakSecret}`).join("\n"),
      });
    }
    // Secrets leaked into bundles (harvest's regex scan artifact)
    const secretsFile = join(root, "secrets.txt");
    if (await fresh(secretsFile)) {
      const lines = (await readFile(secretsFile, "utf8")).split("\n").filter(Boolean);
      if (lines.length > 0) {
        fList.push({
          name: `Bundle 内疑似凭据/秘密 ${lines.length} 处`,
          severity: "high",
          summary: "harvest 秘密扫描在 JS bundle 中命中疑似 key/token/内网地址(见 secrets.txt)",
          poc: lines.slice(0, 20).join("\n"),
        });
      }
    }
    // GraphQL introspection probe (deterministic, one POST)
    try {
      const gqlUrl = new URL("/graphql", base).href;
      const { fetchUrl } = await import("../adapters/http.js");
      const intro = await fetchUrl(gqlUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ query: "{ __schema { queryType { name } } }" }),
        timeoutMs: 8000,
        proxy: input.proxy,
      });
      // 'errors' alone is NOT evidence of a GraphQL endpoint — 200+errors is
      // the standard GraphQL AUTH-FAILURE shape; require schema structure.
      const looksGql = intro.status === 200 && /__schema|queryType/.test(intro.body);
      const denied = intro.status === 200 && introspectionBlocked(intro.body);
      if (looksGql && !denied) {
        fList.push({
          name: "GraphQL endpoint 可达",
          severity: "medium",
          summary: `POST ${gqlUrl} 响应含 schema 结构(introspection ${"疑似开放"})`,
          poc: intro.body.slice(0, 500),
        });
      }
    } catch { /* graphql probe is best-effort */ }
    const permTreeJson = await readJson<{ tree?: unknown[] }>(join(root, "permissions_tree.json"));
    if (permTreeJson?.tree && (permTreeJson.tree as unknown[]).length > 0) {
      fList.push({
        name: "前端权限树可还原",
        severity: "medium",
        summary: `perm-tree 从 bundle 重建权限层级(${(permTreeJson.tree as unknown[]).length} roots)`,
        poc: JSON.stringify(permTreeJson.tree).slice(0, 2000),
      });
    }
    // MPA branch: forms + inline api urls are the attack surface
    const formsFile = join(root, "forms.txt");
    if (await exists(formsFile)) {
      const formsTxt = await readFile(formsFile, "utf8");
      const formCount = formsTxt.split("\n").filter((l) => /^[A-Z]+ /.test(l)).length;
      if (formCount > 0) {
        fList.push({
          name: `MPA 表单攻击面 ${formCount} 个`,
          severity: formCount >= 5 ? "medium" : "low",
          summary: "spider_mpa 发现登录/搜索/提交表单(参数与 action 已记录)",
          poc: formsTxt.slice(0, 2000),
        });
      }
    }
    const inlineFile = join(root, "api_inline.txt");
    if (await exists(inlineFile)) {
      const inlineTxt = (await readFile(inlineFile, "utf8")).split("\n").filter(Boolean);
      if (inlineTxt.length > 0) {
        fList.push({
          name: `内联脚本 API 引用 ${inlineTxt.length} 条`,
          severity: "low",
          summary: "spider_mpa 从页面内联 ajax 调用中提取的接口引用",
          poc: inlineTxt.slice(0, 30).join("\n"),
        });
      }
    }
    findings = fList.length;
    stages.push({ stage: "auto_findings", status: "ok", detail: `${findings} findings` });
  } catch (e) {
    stages.push({ stage: "auto_findings", status: "fail", detail: String((e as Error).message ?? e).slice(0, 120) });
  }

  let reportPath: string | null = null;
  try {
    const reportIn = {
      title: `${new URL(base).hostname} 攻击面测绘`,
      goal: "autonomous recon pipeline: assets → classify → static → runtime → structure → report",
      assetCounts,
      findings: fList,
    };
    const r = await generateReport({ reportJson: JSON.stringify(reportIn), outputRoot: root });
    reportPath = r.artifacts[0]?.path ?? null;
    stages.push({ stage: "gen_report", status: "ok", detail: `${findings} findings → report.md` });
  } catch (e) {
    stages.push({ stage: "gen_report", status: "fail", detail: String((e as Error).message ?? e).slice(0, 120) });
  }

  try {
    const evItems: { source: string; label?: string; content: string }[] = [];
    if (await exists(apiStatic)) {
      evItems.push({ source: "api_static.txt", label: `${(await readFile(apiStatic, "utf8")).split("\n").filter(Boolean).length} endpoints`, content: await readFile(apiStatic, "utf8") });
    }
    const rt = await readJson<{ uniqueCalls?: string[] }>(join(root, "runtime_api.json"));
    if (rt?.uniqueCalls) {
      evItems.push({ source: "runtime_api.json#uniqueCalls", label: `${rt.uniqueCalls.length} live calls`, content: JSON.stringify(rt.uniqueCalls) });
    }
    if (await exists(join(root, "forms.txt"))) {
      const t = await readFile(join(root, "forms.txt"), "utf8");
      evItems.push({ source: "forms.txt", label: "MPA forms", content: t });
    }
    if (await exists(join(root, "api_inline.txt"))) {
      const t = await readFile(join(root, "api_inline.txt"), "utf8");
      evItems.push({ source: "SPA MPA inline api", label: "api_inline.txt", content: t });
    }
    if (evItems.length > 0) {
      await saveEvidence({ outputRoot: root, items: evItems });
      stages.push({ stage: "save_evidence", status: "ok", detail: `${evItems.length} blobs` });
    } else {
      stages.push({ stage: "save_evidence", status: "skip", detail: "no evidence artifacts" });
    }
  } catch (e) {
    stages.push({ stage: "save_evidence", status: "fail", detail: String((e as Error).message ?? e).slice(0, 120) });
  }

  // pipeline.json: the run ledger
  const artifactCounts: Record<string, number> = {};
  try {
    const entries = await import("node:fs/promises").then((m) => m.readdir(root, { recursive: true }));
    for (const e of entries) artifactCounts[e] = 1;
  } catch { /* ignore */ }
  // Atomic (tmp+rename): a crash mid-write must not leave a half JSON that
  // poisons the next resume's checkpoint read.
  {
    const tmp = join(root, `pipeline.json.${process.pid}.tmp`);
    await writeFile(tmp, JSON.stringify({ seed: input.seed, base, mode, stages, generatedAt: new Date().toISOString() }, null, 2), "utf8");
    await rename(tmp, join(root, "pipeline.json"));
  }
  return { seed: input.seed, stages, reportPath, artifactCounts };
};
