/**
 * Source map recovery (sourcemapper/shuji discipline): a leaked .map with
 * sourcesContent is a goldmine — recover the ORIGINAL source tree to disk so
 * downstream corpora (extract_routes / secrets / pii) scan pre-minification
 * source instead of bundle noise.
 *
 * - Per-source degradation (shuji): sources missing their content are listed
 *   in `missing`, never fail the whole recovery.
 * - data: URIs (unwebpack-sourcemap): inline maps are decoded directly, no
 *   fetch needed.
 * - Traversal containment: recovered paths must stay under outputRoot
 *   (no ../, no drive letters, no NUL) — same guard family as sourcemap.ts.
 */
import { writeFile, mkdir, readFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { writeArtifact } from "../adapters/artifacts.js";

export interface RecoverInput {
  /** Directory containing harvested .map files. */
  readonly mapDir: string;
  readonly outputRoot: string;
}

export interface RecoverResult {
  readonly maps: number;
  readonly recovered: number;
  readonly missing: number;
  readonly files: string[];
  readonly artifacts: { path: string; bytes: number }[];
}

interface RawMap {
  sources?: unknown[];
  sourcesContent?: unknown[];
}

const safeSegment = (p: string): string | null => {
  const clean = p.replace(/^[a-zA-Z]:/, "").replace(/^\/+/, "");
  if (clean.includes("..") || clean.includes("\0") || clean === "") return null;
  // whitelist characters (shuji cleanFileName): unicode letters/digits kept via
  // permissive class, controls dropped
  return clean.replace(/[^\w.\-/ ]/g, "_");
};

const parseMap = (text: string): RawMap | null => {
  try {
    const m = JSON.parse(text) as RawMap;
    return Array.isArray(m.sources) ? m : null;
  } catch { return null; }
};

/** Recover sources from an inline (data: URI decoded) map payload. */
export const recoverInlineMap = async (mapText: string, outputRoot: string): Promise<{ recovered: number; missing: number }> => {
  const m = parseMap(mapText);
  if (!m) return { recovered: 0, missing: 0 };
  const sources = m.sources as string[];
  const contents = (m.sourcesContent ?? []) as (string | null)[];
  let rec = 0;
  let mis = 0;
  const outDir = join(outputRoot, "sourcemap-recovered");
  for (let i = 0; i < sources.length; i++) {
    const seg = safeSegment(sources[i] ?? `anon-${i}`);
    if (seg === null) { mis++; continue; }
    const content = typeof contents[i] === "string" ? (contents[i] as string) : null;
    if (content === null) { mis++; continue; }
    const dest = join(outDir, seg);
    await mkdir(dirname(dest), { recursive: true });
    await writeFile(dest, content, "utf8");
    rec++;
  }
  return { recovered: rec, missing: mis };
};

export const recoverSourceMaps = async (input: RecoverInput): Promise<RecoverResult> => {
  // Enumerate .map files in the harvest output (flat listing suffices).
  const { readdir } = await import("node:fs/promises");
  let maps: string[] = [];
  try {
    const entries = await readdir(input.mapDir, { withFileTypes: true });
    maps = entries.filter((e) => e.isFile() && e.name.endsWith(".map")).map((e) => join(input.mapDir, e.name));
  } catch { maps = []; }

  const outDir = join(input.outputRoot, "sourcemap-recovered");
  const recovered: string[] = [];
  const missing: string[] = [];
  const manifest: { source: string; from: string; status: "recovered" | "missing" }[] = [];

  for (const mapFile of maps.slice(0, 200)) {
    const text = await readFile(mapFile, "utf8").catch(() => null);
    if (text === null) continue;
    const m = parseMap(text);
    if (!m) continue;
    const sources = m.sources as string[];
    const contents = (m.sourcesContent ?? []) as (string | null)[];
    for (let i = 0; i < sources.length; i++) {
      const seg = safeSegment(sources[i] ?? `anon-${i}`);
      if (seg === null) continue;
      const content = typeof contents[i] === "string" ? (contents[i] as string) : null;
      const dest = join(outDir, seg);
      if (content !== null) {
        await mkdir(dirname(dest), { recursive: true });
        await writeFile(dest, content, "utf8");
        recovered.push(dest);
        manifest.push({ source: sources[i]!, from: mapFile, status: "recovered" });
      } else {
        missing.push(sources[i]!);
        manifest.push({ source: sources[i]!, from: mapFile, status: "missing" });
      }
    }
  }

  const manifestBody = JSON.stringify({ maps: maps.length, recovered: recovered.length, missing, manifest }, null, 2);
  const art = await writeArtifact(input.outputRoot, "sourcemap_recovered.json", manifestBody);
  return { maps: maps.length, recovered: recovered.length, missing: missing.length, files: recovered.slice(0, 50), artifacts: [art] };
};
