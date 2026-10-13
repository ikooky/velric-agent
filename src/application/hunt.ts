/**
 * Hunt engine — LLM-driven stateless port of velric's orchestration
 * (goals decomposer + planner/worker loop). Zero DB: state lives in
 * graph.json under outputRoot. Worker agents execute the recon toolset
 * through a JSON-action loop.
 *
 * Trust model (hardened on real e2e): the model's narration is NEVER the
 * evidence channel. Every tool execution returns a system digest built
 * from the tool's real output; observed facts must cite a digest, and any
 * http(s) URL cited in evidence must have been actually requested this run.
 */
import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { chat, extractJson, type LlmConfig } from "./llm.js";
import {
  loadGraph, saveGraph, graphOverview,
  type Graph, type Intent,
} from "./graph.js";
import { goalsPrompt, plannerPrompt, workerPrompt, PLANNER_MAX_INTENTS } from "./prompts.js";
import { generateReport } from "./report.js";
import { saveEvidence } from "./evidence.js";

export interface HuntInput {
  readonly goal: string;
  readonly outputRoot: string;
  readonly llm: LlmConfig;
  readonly chromiumPath?: string;
  readonly proxy?: string;
  readonly maxRounds?: number;
  readonly maxSteps?: number;
  readonly maxIntentsPerRound?: number;
}

export interface HuntResult {
  readonly rounds: number;
  readonly goalsTotal: number;
  readonly goalsMet: number;
  readonly intents: number;
  readonly facts: number;
  readonly findings: number;
  readonly assets: number;
  readonly reportPath: string | null;
  readonly transcript: { round: number; actor: string; text: string }[];
}

interface WorkerAction {
  readonly tool?: string;
  readonly args?: Record<string, unknown>;
  readonly final?: Record<string, unknown[]>;
}

interface ToolExec {
  readonly result: unknown;
  readonly digest: string | null;
  readonly urls: string[];
}

const execTool = async (
  tool: string,
  args: Record<string, unknown>,
  ctx: { root: string; intentDir: string; chromium?: string; proxy?: string },
): Promise<ToolExec> => {
  const str = (k: string, d?: string): string =>
    typeof args[k] === "string" ? (args[k] as string) : d ?? "";
  const outDir = (k: string, d: string): string => {
    const v = args[k];
    if (typeof v === "string" && v.startsWith("/")) return v;
    return join(ctx.intentDir, d);
  };
  switch (tool) {
    case "http_req": {
      const { httpProbe } = await import("./probe.js");
      const url = str("url");
      const headers: Record<string, string> = {};
      if (args.headers && typeof args.headers === "object") {
        for (const [k, v] of Object.entries(args.headers as Record<string, unknown>)) {
          if (typeof v === "string") headers[k] = v;
        }
      }
      let body: string | undefined;
      if (typeof args.body === "string") body = args.body;
      else if (args.body !== undefined) body = JSON.stringify(args.body);
      const r = await httpProbe({
        url,
        proxy: ctx.proxy,
        headers: {
          ...headers,
          ...(body !== undefined ? { "content-type": str("contentType", "application/json") } : {}),
        },
      });
      const bodyP = (r as { body?: string }).body?.slice(0, 3000);
      return {
        result: { status: r.status, title: r.title, bodyPreview: bodyP },
        digest: `${str("method", "GET")} ${url} → ${r.status} | ${(bodyP ?? "").replace(/\s+/g, " ").slice(0, 280)}`,
        urls: [url],
      };
    }
    case "http_probe": {
      const { httpProbe } = await import("./probe.js");
      const url = str("url");
      const r = await httpProbe({ url, proxy: ctx.proxy });
      return {
        result: r,
        digest: `probe ${url} → ${r.status} ${r.title ?? ""}`,
        urls: [url],
      };
    }
    case "dns_resolve": {
      const { resolveHost } = await import("./dns.js");
      const host = str("host");
      const r = await resolveHost(host);
      const parts: string[] = [];
      const rr = r as unknown as Record<string, unknown> | null;
      if (typeof r === "object" && r) {
        for (const [k, v] of Object.entries(rr ?? {})) {
          if (Array.isArray(v) && v.length > 0) parts.push(`${k}=${(v as string[]).join(",")}`);
        }
      }
      return { result: r, digest: parts.length ? `dns ${host}: ${parts.join(" ")}` : null, urls: [] };
    }
    case "harvest_static": {
      const { harvestStatic } = await import("./harvest.js");
      const url = str("url", str("baseUrl"));
      const r = await harvestStatic({ baseUrl: url, outputRoot: outDir("out", "harvest"), proxy: ctx.proxy });
      return {
        result: r,
        digest: `harvest ${url}: js=${r.jsDownloaded} api=${r.apiEndpoints} routes=${r.routes}`,
        urls: [url],
      };
    }
    case "extract_routes": {
      const { readdir, readFile: rf } = await import("node:fs/promises");
      const { extractRoutes } = await import("../domain/endpoints.js");
      const dir = str("jsDir");
      const routes = new Set<string>();
      for (const f of await readdir(dir).catch(() => [] as string[])) {
        if (!f.endsWith(".js")) continue;
        const text = await rf(join(dir, f), "utf8").catch(() => "");
        for (const r of extractRoutes(text)) routes.add(r);
      }
      const list = [...routes].sort();
      return {
        result: { routes: list.slice(0, 500) },
        digest: `extract_routes ${dir}: ${list.length} routes`,
        urls: [],
      };
    }
    case "spider_mpa": {
      const { spiderMpa } = await import("./spider.js");
      const url = str("url", str("baseUrl"));
      const r = await spiderMpa({ baseUrl: url, outputRoot: outDir("out", "spider"), proxy: ctx.proxy, maxPages: 20 });
      return {
        result: r,
        digest: `spider ${url}: crawled=${r.crawled} forms=${r.forms}`,
        urls: [url],
      };
    }
    case "capture_runtime": {
      const { captureRuntime } = await import("./runtime.js");
      const url = str("url", str("baseUrl"));
      const r = await captureRuntime({
        baseUrl: url,
        outputRoot: outDir("out", "runtime"),
        chromiumPath: ctx.chromium ?? "/usr/bin/chromium",
        proxy: ctx.proxy,
        routes: typeof args.routes === "string"
          ? (args.routes as string).split(",").map((x) => x.trim()).filter(Boolean)
          : undefined,
      });
      return {
        result: r,
        digest: `runtime ${url}: calls=${r.uniqueCalls.length} details=${r.details}`,
        urls: [url],
      };
    }
    case "build_perm_tree": {
      const { buildPermissionTree } = await import("./permTreeService.js");
      const r = await buildPermissionTree({ jsDir: str("jsDir"), outputRoot: outDir("out", "perm") });
      return {
        result: r,
        digest: `perm_tree ${str("jsDir")}: codes=${r.codes} roots=${r.treeRoots}`,
        urls: [],
      };
    }
    case "merge_params": {
      const { mergeParamSamples } = await import("./paramMerge.js");
      const r = await mergeParamSamples({ samplesFile: str("samplesFile"), outputRoot: outDir("out", "params") });
      return {
        result: r,
        digest: `merge_params ${str("samplesFile")}: endpoints=${r.endpoints}`,
        urls: [],
      };
    }
    case "enrich_assets": {
      const { enrichAssets } = await import("./enrich.js");
      const seed = str("seed", str("url"));
      const r = await enrichAssets({ seeds: [seed], outputRoot: outDir("out", "enrich"), proxy: ctx.proxy });
      return { result: r, digest: `enrich ${seed}: ${JSON.stringify(r.counts)}`, urls: [seed] };
    }
    case "auto_recon": {
      const { runAutoPipeline } = await import("./auto.js");
      const seed = str("seed", str("url"));
      const r = await runAutoPipeline({
        seed, outputRoot: outDir("out", "auto"),
        chromiumPath: ctx.chromium, proxy: ctx.proxy,
        skipRuntime: args.skipRuntime === true,
      });
      return {
        result: r,
        digest: `auto ${seed}: ${r.stages.map((x) => `${x.stage}:${x.status}`).join(" ")}`,
        urls: [seed],
      };
    }
    case "read_file": {
      const t = await readFile(str("path"), "utf8").catch((e: Error) => `read error: ${e.message}`);
      return {
        result: t.slice(0, 8000),
        digest: `read ${str("path")}: ${t.slice(0, 200).replace(/\s+/g, " ")}`,
        urls: [],
      };
    }
    default:
      return { result: { error: `unknown tool: ${tool}` }, digest: null, urls: [] };
  }
};

const writeBack = (
  g: Graph,
  intent: Intent,
  fin: Record<string, unknown[]>,
  touchedUrls: Set<string>,
  systemDigests: string[],
): { assets: number; facts: number; findings: number; dropped: number } => {
  const assets = (fin.assets ?? []) as { type: string; key: string; props?: Record<string, unknown> }[];
  const facts = (fin.facts ?? []) as { summary?: string; detail?: string; evidence?: string; confidence?: string }[];
  const findings = (fin.findings ?? []) as { name?: string; vulnclass?: string; severity?: string; summary?: string; poc?: string }[];

  // gate 1: every http(s) URL cited in evidence must have been truly requested
  const requested = [...touchedUrls];
  const citedUrls = (txt: string): string[] =>
    [...String(txt).matchAll(/https?:\/\/[^\s"'\]]+/g)].map((m) => m[0]!.replace(/[.,;)]+$/, ""));
  const urlOk = (txt: string): boolean =>
    citedUrls(txt).every((u) => requested.some((r) => u === r || u.startsWith(r) || r.startsWith(u)));

  // gate 2: observed (non-inferred) facts must cite a system digest — the
  // model's narration alone is never evidence.
  const digestKeys = systemDigests.map((d) => {
    const url = d.match(/https?:\/\/\S+/)?.[0]?.split("?")[0];
    const status = d.match(/→\s*(\d{3})/)?.[1];
    return { raw: d, url, status };
  });
  const digestOk = (f: { summary?: string; evidence?: string; confidence?: string }): boolean => {
    if (f.confidence === "inferred") return true;
    const txt = `${f.evidence ?? ""} ${f.summary ?? ""}`;
    return digestKeys.some((k) => {
      if (k.url && txt.includes(k.url)) return true;
      if (k.url && k.status && txt.includes(k.status) && txt.includes(k.url.split("/").slice(-1)[0] ?? "###")) return true;
      return false;
    });
  };

  let dropped = 0;
  for (const a of assets) {
    if (!a.type || !a.key) continue;
    g.assets.push({ type: String(a.type), key: String(a.key), props: a.props });
  }
  for (const f of facts) {
    if (!f.summary) continue;
    if (!urlOk(`${f.summary} ${f.evidence ?? ""} ${f.detail ?? ""}`) || !digestOk(f)) { dropped++; continue; }
    const id = g.nextId++;
    g.facts.push({
      id, intentId: intent.id,
      summary: String(f.summary).slice(0, 300),
      detail: f.detail, evidence: f.evidence,
      confidence: f.confidence === "inferred" ? "inferred" : "observed",
    });
    intent.yields.push(id);
  }
  for (const f of findings) {
    if (!f.name) continue;
    if (!urlOk(`${f.summary ?? ""} ${f.poc ?? ""}`)) { dropped++; continue; }
    const id = g.nextId++;
    g.findings.push({
      id, intentId: intent.id,
      name: String(f.name).slice(0, 200),
      vulnclass: String(f.vulnclass ?? ""),
      severity: (["low", "medium", "high", "critical"].includes(String(f.severity)) ? f.severity : "low") as "low",
      summary: String(f.summary ?? "").slice(0, 1000),
      poc: String(f.poc ?? "").slice(0, 4000),
    });
    intent.yields.push(id);
  }
  return { assets: assets.length, facts: facts.length, findings: findings.length, dropped };
};

const runWorker = async (
  intent: Intent,
  g: Graph,
  input: HuntInput,
  log: HuntResult["transcript"],
  round: number,
): Promise<void> => {
  const intentDir = join(input.outputRoot, "runs", `i${intent.id}`);
  await mkdir(intentDir, { recursive: true });
  const constraintBlock = g.constraints.length
    ? `\n\n【操作约束（最高优先级红线，违反即不做）】\n${g.constraints.map((c) => `- ${c.type.toUpperCase()}: ${c.rule}`).join("\n")}`
    : "";
  const system = workerPrompt({ goal: g.goal, workDir: intentDir }, intent.summary) + constraintBlock;
  const messages: { role: "user" | "assistant"; content: string }[] = [
    { role: "user", content: "开始执行你的意图。每一步输出一个 JSON（tool 调用或 final）。记住：只输出 JSON。" },
  ];
  const touchedUrls = new Set<string>();
  const systemDigests: string[] = [];

  const finalTurn = async (salvage: boolean): Promise<boolean> => {
    if (salvage) {
      messages.push({ role: "user", content: "步数预算已用完。立即输出 final JSON（把已获得的资产/事实/发现写回，没有的给空数组）。不要再调用任何工具。" });
    }
    try {
      const fr = await chat(input.llm, [{ role: "system", content: system }, ...messages]);
      const fin = extractJson<Record<string, unknown[]>>(fr);
      const wb = writeBack(g, intent, fin, touchedUrls, systemDigests);
      if (wb.dropped > 0) {
        log.push({ round, actor: `worker#${intent.id}`, text: `evidence gate dropped ${wb.dropped} unverifiable entries` });
      }
      log.push({ round, actor: `worker#${intent.id}`, text: `final${salvage ? "(salvaged)" : ""}: +${wb.assets} assets +${wb.facts} facts +${wb.findings} findings` });
      return true;
    } catch {
      return false;
    }
  };

  const maxSteps = input.maxSteps ?? 10;
  let steps = 0;
  while (steps < maxSteps) {
    steps++;
    let reply: string;
    try {
      reply = await chat(input.llm, [{ role: "system", content: system }, ...messages]);
    } catch (e) {
      intent.state = "blocked";
      intent.error = String((e as Error).message).slice(0, 120);
      return;
    }
    messages.push({ role: "assistant", content: reply });
    let act: WorkerAction;
    try {
      act = extractJson<WorkerAction>(reply);
    } catch {
      messages.push({ role: "user", content: '输出必须是单个 JSON 对象：{"tool":"...","args":{...}} 或 {"final":{...}}。重试。' });
      continue;
    }
    if (act.final !== undefined || act.tool === undefined) {
      const ok = await finalTurn(false);
      if (ok) { intent.state = "done"; return; }
      messages.push({ role: "user", content: "final JSON 解析失败，重新输出完整 final JSON。" });
      continue;
    }
    let exe: ToolExec;
    try {
      exe = await execTool(act.tool, act.args ?? {}, { root: input.outputRoot, intentDir, chromium: input.chromiumPath, proxy: input.proxy });
      for (const u of exe.urls) touchedUrls.add(u);
      if (exe.digest) systemDigests.push(exe.digest);
    } catch (e) {
      exe = { result: { error: String((e as Error).message ?? e).slice(0, 300) }, digest: null, urls: [] };
    }
    const obsText = JSON.stringify(exe.result, null, 0)?.slice(0, 6000) ?? "{}";
    log.push({ round, actor: `worker#${intent.id}`, text: `${act.tool} → ${exe.digest ?? obsText.slice(0, 160)}` });
    messages.push({ role: "user", content: `OBSERVATION (system-verified, truncated):\n${obsText}\n\n继续。下一步 tool JSON 或 final JSON。` });
  }
  const salvaged = await finalTurn(true);
  intent.state = salvaged ? "done" : "exhausted";
  if (!salvaged) intent.error = `step budget exhausted (${maxSteps})`;
};

export const runHunt = async (input: HuntInput): Promise<HuntResult> => {
  const root = input.outputRoot;
  await mkdir(root, { recursive: true });
  const transcript: HuntResult["transcript"] = [];

  let g = await loadGraph(root);
  if (g.goal === "" || g.goal !== input.goal) {
    g = { goal: input.goal, constraints: [], goals: [], intents: [], facts: [], findings: [], assets: [], nextId: 1 };
  }

  if (g.goals.length === 0) {
    const out = await chat(input.llm, [{ role: "system", content: goalsPrompt({ goal: input.goal, workDir: root }) }]);
    const parsed = extractJson<{ constraints?: { type: string; rule: string }[]; goals: { summary: string; vulnclass?: string }[] }>(out);
    g.constraints = (parsed.constraints ?? [])
      .filter((c) => c && typeof c.rule === "string")
      .map((c) => ({ type: c.type === "allow" ? "allow" as const : "deny" as const, rule: c.rule.slice(0, 300) }));
    for (const goal of parsed.goals ?? []) {
      g.goals.push({ id: g.nextId++, summary: String(goal.summary).slice(0, 300), vulnclass: String(goal.vulnclass ?? ""), met: false });
    }
    if (g.goals.length === 0) {
      g.goals.push({ id: g.nextId++, summary: input.goal, vulnclass: "", met: false });
    }
    transcript.push({ round: 0, actor: "goals", text: `${g.goals.length} goals, ${g.constraints.length} constraints` });
    await saveGraph(root, g);
  }

  const maxRounds = input.maxRounds ?? 8;
  let round = 0;
  while (round < maxRounds) {
    round++;
    const overview = graphOverview(g);
    let plan: { goals_met?: { id: number; reason?: string }[]; new_intents?: { summary: string }[]; done?: boolean };
    try {
      const out = await chat(input.llm, [{ role: "system", content: plannerPrompt({ goal: g.goal, workDir: root }, overview) }]);
      plan = extractJson(out);
    } catch (e) {
      transcript.push({ round, actor: "planner", text: `planner parse failure: ${String((e as Error).message).slice(0, 120)}` });
      break;
    }
    for (const m of plan.goals_met ?? []) {
      const goal = g.goals.find((x) => x.id === m.id);
      if (goal && !goal.met) { goal.met = true; goal.metReason = m.reason?.slice(0, 300); }
    }
    const existing = new Set(g.intents.map((i) => i.summary));
    let added = 0;
    for (const ni of (plan.new_intents ?? []).slice(0, PLANNER_MAX_INTENTS)) {
      const summary = String(ni.summary ?? "").trim().slice(0, 300);
      if (!summary || existing.has(summary)) continue;
      g.intents.push({ id: g.nextId++, summary, state: "open", parentIds: [], yields: [] });
      existing.add(summary);
      added++;
    }
    transcript.push({ round, actor: "planner", text: `met=${(plan.goals_met ?? []).length} new_intents=${added} done=${plan.done === true}` });
    await saveGraph(root, g);
    const allMet = g.goals.length > 0 && g.goals.every((x) => x.met);
    if (plan.done === true || allMet) break;

    const batch = g.intents.filter((i) => i.state === "open").slice(0, input.maxIntentsPerRound ?? 2);
    if (batch.length === 0) {
      transcript.push({ round, actor: "engine", text: "no open intents and planner added none — stopping" });
      break;
    }
    for (const intent of batch) {
      intent.state = "running";
      await saveGraph(root, g);
      await runWorker(intent, g, input, transcript, round);
      await saveGraph(root, g);
    }
  }

  const assetCounts: Record<string, number> = {};
  for (const a of g.assets) assetCounts[a.type] = (assetCounts[a.type] ?? 0) + 1;
  let reportPath: string | null = null;
  try {
    const reportIn = {
      title: g.goal.slice(0, 80),
      goal: g.goal,
      assetCounts,
      findings: g.findings.map((f) => ({ vulnClass: f.vulnclass, name: f.name, severity: f.severity, summary: f.summary, poc: f.poc })),
    };
    const r = await generateReport({ reportJson: JSON.stringify(reportIn), outputRoot: root });
    reportPath = r.artifacts[0]?.path ?? null;
  } catch { /* best-effort */ }
  try {
    const evItems = [
      { source: "graph.json", label: "final graph", content: JSON.stringify(g, null, 2) },
      ...g.findings.map((f) => ({ source: `finding#${f.id}`, label: f.name, content: `${f.summary}\n\nPOC:\n${f.poc}` })),
    ];
    await saveEvidence({ outputRoot: root, items: evItems });
  } catch { /* best-effort */ }
  await saveGraph(root, g);

  return {
    rounds: round,
    goalsTotal: g.goals.length,
    goalsMet: g.goals.filter((x) => x.met).length,
    intents: g.intents.length,
    facts: g.facts.length,
    findings: g.findings.length,
    assets: g.assets.length,
    reportPath,
    transcript,
  };
};
