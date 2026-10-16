import { readFile, readdir } from "node:fs/promises";
import { join, posix } from "node:path";
import { createHash } from "node:crypto";
import { writeArtifact } from "../adapters/artifacts.js";
import { safePath } from "../core/storage.js";

export interface MapContent {
  readonly text: string;
  readonly from: string;
  readonly bundleUrl?: string;
}
export interface RecoverInput {
  readonly mapDir: string;
  readonly outputRoot: string;
  /** Already-read remote/inline maps are consumed without a second fetch. */
  readonly mapContents?: readonly MapContent[];
}
export interface RecoverResult {
  readonly maps: number;
  readonly recovered: number;
  readonly missing: number;
  readonly files: string[];
  readonly artifacts: { path: string; bytes: number }[];
}
interface RawMap { sources: unknown[]; sourcesContent?: unknown }
const parseMap = (text: string): RawMap | null => {
  try {
    if (Buffer.byteLength(text) > 16 * 1024 * 1024) return null;
    const value: unknown = JSON.parse(text);
    return value !== null && typeof value === "object" && Array.isArray((value as RawMap).sources) ? value as RawMap : null;
  } catch { return null; }
};
const safeSource = (source: unknown): string | null => {
  if (typeof source !== "string" || !source || /[\x00-\x1f\x7f\\]/.test(source)) return null;
  const path = source.replace(/^[a-z][a-z0-9+.-]*:\/\/(?:[^/]*\/)?/i, "").replace(/^\.\//, "");
  if (!path || path.startsWith("/") || /^[a-z]:/i.test(path) || path.split("/").includes("..")) return null;
  const clean = path.split("/").filter(p => p && p !== ".").map(p => p.replace(/[^\w. -]/g, "_")).join("/");
  return clean && clean !== "." ? clean : null;
};
const hash = (value: string): string => createHash("sha256").update(value).digest("hex");

export const recoverMapContents = async (maps: readonly MapContent[], outputRoot: string): Promise<RecoverResult> => {
  const files = new Set<string>();
  const manifest: { source: unknown; from: string; bundleUrl?: string; status: "recovered" | "missing"; path?: string; sha256?: string; reason?: string; collisionWith?: string }[] = [];
  const destinations = new Map<string, string>();
  let mapCount = 0, missing = 0, bytes = 0, sources = 0;
  for (const item of maps.slice(0, 200)) {
    const map = parseMap(item.text);
    if (!map) continue;
    mapCount++;
    const contents = Array.isArray(map.sourcesContent) ? map.sourcesContent : [];
    for (let i = 0; i < Math.min(map.sources.length, 10000); i++) {
      const source = map.sources[i], content = contents[i];
      const row: (typeof manifest)[number] = { source, from: item.from, bundleUrl: item.bundleUrl, status: "missing" };
      const segment = safeSource(source);
      if (!segment || typeof content !== "string" || ++sources > 10000 || bytes + Buffer.byteLength(content) > 64 * 1024 * 1024) {
        row.reason = !segment ? "invalid-source" : typeof content !== "string" ? "missing-content" : "recovery-budget";
        manifest.push(row); missing++; continue;
      }
      const digest = hash(content);
      let name = `sourcemap-recovered/${segment}`;
      const original = name;
      let collision = false;
      try {
        for (let attempt = 0; ; attempt++) {
          const path = await safePath(outputRoot, name);
          const key = name.toLowerCase();
          const claimed = destinations.get(key);
          const existing = await readFile(path, "utf8").catch((e: NodeJS.ErrnoException) => { if (e.code === "ENOENT") return null; throw e; });
          if ((!claimed || claimed === digest) && (existing === null || existing === content)) break;
          collision = true;
          const ext = posix.extname(segment);
          const stem = ext ? original.slice(0, -ext.length) : original;
          name = `${stem}~${hash(`${item.from}:${i}:${source}:${attempt}`).slice(0, 16)}${ext}`;
          if (attempt > 100) throw new Error("collision budget exhausted");
        }
        const art = await writeArtifact(outputRoot, name, content);
        destinations.set(name.toLowerCase(), digest); files.add(art.path); bytes += art.bytes;
        Object.assign(row, { status: "recovered", path: art.path, sha256: digest, ...(collision ? { collisionWith: original } : {}) });
      } catch (error) {
        row.reason = error instanceof Error ? error.message : String(error); missing++;
      }
      manifest.push(row);
    }
  }
  const art = await writeArtifact(outputRoot, "sourcemap_recovered.json", JSON.stringify({ maps: mapCount, recovered: files.size, missing, manifest }, null, 2));
  return { maps: mapCount, recovered: files.size, missing, files: [...files], artifacts: [art] };
};

export const recoverInlineMap = async (mapText: string, outputRoot: string): Promise<{ recovered: number; missing: number }> => {
  const result = await recoverMapContents([{ text: mapText, from: "data:inline" }], outputRoot);
  return { recovered: result.recovered, missing: result.missing };
};

export const recoverSourceMaps = async (input: RecoverInput): Promise<RecoverResult> => {
  if (input.mapContents) return recoverMapContents(input.mapContents, input.outputRoot);
  const entries = await readdir(input.mapDir, { withFileTypes: true }).catch(() => []);
  const maps: MapContent[] = [];
  for (const entry of entries.filter(e => e.isFile() && e.name.endsWith(".map")).slice(0, 200)) {
    const file = join(input.mapDir, entry.name);
    const text = await readFile(file, "utf8").catch(() => null);
    if (text !== null) maps.push({ text, from: file });
  }
  return recoverMapContents(maps, input.outputRoot);
};