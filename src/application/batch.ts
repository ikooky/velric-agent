import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

/** Batch mode: run the deterministic auto pipeline for every seed in a file,
 *  then produce one comparison report across targets. */

export interface BatchInput {
  readonly seedsFile: string;
  readonly outputRoot: string;
  readonly chromiumPath?: string;
  readonly proxy?: string;
  readonly cookie?: string;
  readonly concurrency?: number;
  readonly skipRuntime?: boolean;
  readonly notifyWebhook?: string;
}

export interface BatchResult {
  readonly targets: {
    seed: string;
    outDir: string;
    stagesOk: number;
    stagesTotal: number;
    apiEndpoints: number;
    findings: number;
    error?: string;
  }[];
  readonly summary: string;
  readonly artifacts: { path: string; bytes: number }[];
}

export const runBatch = async (input: BatchInput): Promise<BatchResult> => {
  const seedsRaw = await readFile(input.seedsFile, "utf8");
  const seeds = seedsRaw.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  await mkdir(input.outputRoot, { recursive: true });

  const results: BatchResult["targets"] = [];
  for (const seed of seeds) {
    const slug = seed.replace(/^https?:\/\//, "").replace(/[^a-zA-Z0-9.-]/g, "_").slice(0, 60);
    const outDir = join(input.outputRoot, slug);
    try {
      const { runAutoPipeline } = await import("./auto.js");
      const r = await runAutoPipeline({
        seed,
        outputRoot: outDir,
        chromiumPath: input.chromiumPath,
        proxy: input.proxy,
        cookie: input.cookie,
        skipRuntime: input.skipRuntime,
      });
      const stagesOk = r.stages.filter((s) => s.status === "ok").length;
      let apiCount = 0;
      for (const f of ["api_merged.txt", "api_static.txt"]) {
        try {
          apiCount = (await readFile(join(outDir, f), "utf8")).split("\n").filter(Boolean).length;
          break;
        } catch { /* try next */ }
      }
      let findings = 0;
      try {
        const rep = JSON.parse(await readFile(join(outDir, "report.json"), "utf8")) as { findings?: unknown[] };
        findings = rep.findings?.length ?? 0;
      } catch {
        // report.json is not the artifact name — count from the stage detail.
        const fd = r.stages.find((st) => st.stage === "auto_findings")?.detail ?? "";
        findings = Number(fd.match(/(\d+)\s*findings?/i)?.[1] ?? 0);
      }
      results.push({ seed, outDir, stagesOk, stagesTotal: r.stages.length, apiEndpoints: apiCount, findings });
    } catch (e) {
      results.push({ seed, outDir, stagesOk: 0, stagesTotal: 0, apiEndpoints: 0, findings: 0, error: String((e as Error).message ?? e).slice(0, 150) });
    }
  }

  const lines = [
    `# 批量侦察汇总 — ${seeds.length} 目标`,
    "",
    ...results.map((r) =>
      `- **${r.seed}** — ${r.error ? `❌ ${r.error}` : `${r.stagesOk}/${r.stagesTotal} 阶段 · ${r.apiEndpoints} 端点 · ${r.findings} findings`}`,
    ),
  ];
  const path = join(input.outputRoot, "batch_summary.md");
  const body = lines.join("\n");
  await writeFile(path, body);

  if (input.notifyWebhook) {
    try {
      const { fetchUrl } = await import("../adapters/http.js");
      await fetchUrl(input.notifyWebhook, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ text: `velric batch done: ${results.length} targets\n${results.map((r) => `${r.seed}: ${r.error ? "ERR" : r.apiEndpoints + " eps"}`).join("\n")}` }),
        timeoutMs: 10000,
      });
    } catch { /* webhook best-effort */ }
  }

  return {
    targets: results,
    summary: `${results.filter((r) => !r.error).length}/${results.length} ok`,
    artifacts: [{ path, bytes: Buffer.byteLength(body) }],
  };
};
