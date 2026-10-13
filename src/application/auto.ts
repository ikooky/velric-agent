import { mkdir, readFile, writeFile } from "node:fs/promises";
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
 * Deterministic autonomous pipeline (stateless port of velric's
 * planner/worker split): stages run in dependency order against one
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
  try { await readFile(p, "utf8"); return true; } catch { return false; }
};

const readJson = async <T>(p: string): Promise<T | null> => {
  try { return JSON.parse(await readFile(p, "utf8")) as T; } catch { return null; }
};

export const runAutoPipeline = async (input: AutoInput): Promise<AutoResult> => {
  const stages: StageResult[] = [];
  const root = input.outputRoot;
  await mkdir(root, { recursive: true });

  // ---- Stage 1: enrich asset graph ----
  let assetCounts: Record<string, number> = {};
  try {
    const r = await enrichAssets({ seeds: [input.seed], outputRoot: root, proxy: input.proxy, cookie: input.cookie, timeoutMs: input.timeoutMs });
    assetCounts = r.counts;
    stages.push({ stage: "enrich", status: "ok", detail: `${r.assets.length} assets` });
  } catch (e) {
    stages.push({ stage: "enrich", status: "fail", detail: String((e as Error).message ?? e).slice(0, 120) });
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
    const spaMark = /__NUXT__|__NEXT_DATA__|data-v-app|ng-app|id=["']?app["']?/i.test(html);
    const forms = (html.match(/<form/i) ?? []).length;
    if (scripts >= 3 && spaMark) mode = "spa";
    else if (scripts >= 5) mode = "spa";
    else if (forms > 0 && scripts < 3) mode = "mpa";
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
    try {
      const r = await spiderMpa({ baseUrl: base, outputRoot: root, proxy: input.proxy, cookie: input.cookie, maxPages: input.maxPages ?? 30, depth: 2, delayMs: 500 });
      stages.push({ stage: "spider_mpa", status: "ok", detail: `crawled=${r.crawled} forms=${r.forms}` });
    } catch (e) {
      stages.push({ stage: "spider_mpa", status: "fail", detail: String((e as Error).message ?? e).slice(0, 120) });
    }
  }

  // ---- Stage 4: runtime capture (if chromium) ----
  const chromium = input.chromiumPath ?? "/usr/bin/chromium";
  let runtimeCalls = 0;
  if (!input.skipRuntime) {
    try {
      const r = await captureRuntime({ baseUrl: base, outputRoot: root, chromiumPath: chromium, proxy: input.proxy, routes: ["/"], waitMs: 4000, perRouteMs: 2000 });
      runtimeCalls = r.uniqueCalls.length;
      stages.push({ stage: "capture_runtime", status: "ok", detail: `calls=${r.uniqueCalls.length} details=${r.details}` });
    } catch (e) {
      stages.push({ stage: "capture_runtime", status: "fail", detail: String((e as Error).message ?? e).slice(0, 120) });
    }
  } else {
    stages.push({ stage: "capture_runtime", status: "skip", detail: "skipRuntime=true" });
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
  if (await exists(samplesFile)) {
    try {
      const r = await mergeParamSamples({ samplesFile, outputRoot: root });
      stages.push({ stage: "merge_params", status: "ok", detail: `endpoints=${r.endpoints}` });
    } catch (e) {
      stages.push({ stage: "merge_params", status: "fail", detail: String((e as Error).message ?? e).slice(0, 120) });
    }
  }

  // ---- Stage 6: report + evidence ----
  const apiStatic = join(root, "api_static.txt");
  let findings = 0;
  const fList: unknown[] = [];
  // auto-findings: exposed API surface from artifacts (deterministic heuristics)
  try {
    const apiList = (await exists(apiStatic) ? (await readFile(apiStatic, "utf8")).split("\n").filter(Boolean) : []);
    const runtimeJson = await readJson<{ uniqueCalls?: string[] }>(join(root, "runtime_api.json"));
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
  await writeFile(join(root, "pipeline.json"), JSON.stringify({ seed: input.seed, base, mode, stages, generatedAt: new Date().toISOString() }, null, 2), "utf8");
  return { seed: input.seed, stages, reportPath, artifactCounts };
};
