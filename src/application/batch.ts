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
  readonly note?: string;
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

  const conc = Math.max(1, Math.min(input.concurrency ?? 1, 4));
  let cursor = 0;
  const runOne = async (seed: string): Promise<BatchResult["targets"][number]> => {
    // Slug must be a safe single path segment: normalize, then refuse
    // traversal-shaped results ("..", ".", empty) before joining outputRoot.
    const slug0 = seed.replace(/^https?:\/\//, "").replace(/[^a-zA-Z0-9.-]/g, "_").slice(0, 60);
    if (slug0 === ".." || slug0 === "." || slug0 === "") throw new Error(`unsafe seed slug: ${JSON.stringify(seed.slice(0, 40))}`);
    const slug = slug0.replace(/^\.+/, "_");
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
      // report.md is the artifact (no report.json is ever written) — count
      // findings from the auto_findings stage detail.
      const fd = r.stages.find((st) => st.stage === "auto_findings")?.detail ?? "";
      const findings = Number(fd.match(/(\d+)\s*findings?/i)?.[1] ?? 0);
      return { seed, outDir, stagesOk, stagesTotal: r.stages.length, apiEndpoints: apiCount, findings };
    } catch (e) {
      return { seed, outDir, stagesOk: 0, stagesTotal: 0, apiEndpoints: 0, findings: 0, error: String((e as Error).message ?? e).slice(0, 150) };
    }
  };

  const indexed: { seed: string; res: BatchResult["targets"][number] }[] = [];
  const worker = async (): Promise<void> => {
    while (cursor < seeds.length) {
      const idx = cursor++;
      const seed = seeds[idx]!;
      const res = await runOne(seed);
      indexed.push({ seed, res });
    }
  };
  await Promise.all(Array.from({ length: conc }, worker));
  // Deterministic output: batch_summary and targets[] follow seed-file order,
  // not completion order.
  const bySeed = new Map(indexed.map((x) => [x.seed, x.res]));
  const results: BatchResult["targets"] = seeds.map((sd) => bySeed.get(sd)).filter((x): x is BatchResult["targets"][number] => x !== undefined);

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
    // Anti-exfiltration posture: https-only, and the notification body never
    // carries seed hostnames — only per-target ok/err status and counts.
    let okproto = true;
    try {
      const u = new URL(input.notifyWebhook);
      okproto = u.protocol === "https:";
    } catch { okproto = false; }
    if (!okproto) {
      return {
        targets: results,
        summary: `${results.filter((r) => !r.error).length}/${results.length} ok`,
        artifacts: [{ path, bytes: Buffer.byteLength(body) }],
        note: "notifyWebhook refused: https required, hostnames withheld",
      };
    }
    try {
      const { fetchUrl } = await import("../adapters/http.js");
      await fetchUrl(input.notifyWebhook, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ text: `velric batch done: ${results.length} targets\n${results.map((r, i) => `#${i + 1}: ${r.error ? "ERR" : r.apiEndpoints + " eps"}`).join("\n")}` }),
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
