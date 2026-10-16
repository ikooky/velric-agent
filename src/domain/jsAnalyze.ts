/**
 * JS corpus analysis facade: deterministic renaming + webpack module graph
 * over the harvested corpus (deobfuscate_js action=analyze). Writes renamed
 * sources + per-file analysis manifest; zero execution of target code.
 */
import { readdir, readFile, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { writeArtifact } from "../adapters/artifacts.js";
import { renameIdentifiers } from "./rename.js";
import { buildWebpackGraph } from "./webpackGraph.js";

export interface AnalyzeInput {
  readonly jsDir: string;
  readonly outputRoot: string;
  readonly maxFiles?: number;
  readonly maxFileBytes?: number;
}

export interface AnalyzeResult {
  readonly files: number;
  readonly renamed: { file: string; identifiers: number }[];
  readonly graphs: { file: string; modules: number; edges: number; entryIds: string[]; missingBoundary: number }[];
  readonly artifacts: { path: string; bytes: number }[];
}

export const analyzeCorpus = async (input: AnalyzeInput): Promise<AnalyzeResult> => {
  const outDir = join(input.outputRoot, "js-analyzed");
  await mkdir(outDir, { recursive: true });
  let files: string[] = [];
  try {
    files = (await readdir(input.jsDir, { withFileTypes: true })).filter((e) => e.isFile() && /\.m?js$/.test(e.name)).map((e) => join(input.jsDir, e.name));
  } catch { files = []; }

  const renamed: AnalyzeResult["renamed"] = [];
  const graphs: AnalyzeResult["graphs"] = [];
  const cap = input.maxFiles ?? 100;
  const byteCap = input.maxFileBytes ?? 4_000_000;

  for (const f of files.slice(0, cap)) {
    let src: string;
    try { src = await readFile(f, "utf8"); } catch { continue; }
    if (src.length > byteCap) src = src.slice(0, byteCap);
    const name = f.split("/").pop() ?? "x.js";
    // deterministic rename — same input ⇒ same output (regression-testable)
    const rn = renameIdentifiers(src);
    if (rn.renamed > 0) {
      await mkdir(join(outDir, "renamed"), { recursive: true });
      await writeFile(join(outDir, "renamed", name), rn.code, "utf8");
      renamed.push({ file: name, identifiers: rn.renamed });
    }
    // webpack module graph (skips non-bundles cheaply)
    const g = buildWebpackGraph({ source: src, sourceName: name });
    if (g.modules.length >= 2) {
      graphs.push({ file: name, modules: g.modules.length, edges: g.edges.length, entryIds: g.entryIds, missingBoundary: g.modules.reduce((a, m) => a + m.missing.length, 0) });
      await mkdir(join(outDir, "graphs"), { recursive: true });
      await writeFile(join(outDir, "graphs", `${name}.json`), JSON.stringify(g, null, 2), "utf8");
    }
  }

  const manifest = JSON.stringify({ files: files.length, renamed, graphs }, null, 2);
  const art = await writeArtifact(input.outputRoot, "js_analysis.json", manifest);
  return { files: files.length, renamed, graphs, artifacts: [art] };
};
