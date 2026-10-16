import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir } from "node:fs/promises";
import { join, dirname, resolve, relative, isAbsolute } from "node:path";
import { readdir, readFile } from "node:fs/promises";
import { writeArtifact } from "../adapters/artifacts.js";
import { recoverMapContents, type MapContent } from "./sourceRecover.js";
import { safePath } from "../core/storage.js";

/** Source-map leak detection over the harvested JS corpus + Wayback Machine
 *  historical URL recovery. Both feed the endpoint pool. */

export interface SourceMapInput {
  readonly outputRoot: string;
  readonly jsDir?: string;
  readonly baseUrl?: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  /** Recover original sources from sourcesContent into
   *  outputRoot/sourcemap-recovered/ (sourcemapper discipline: per-source
   *  degradation, traversal-contained). */
  readonly recover?: boolean;
  readonly bundles?: readonly { file: string; url: string }[];
}

export interface SourceMapResult {
  readonly checked: number;
  readonly leaked: { file: string; mapUrl: string; sourceCount: number; bundleUrl?: string }[];
  readonly recovered?: { maps: number; recovered: number; missing: number };
  readonly artifacts: { path: string; bytes: number }[];
}

const validMap = (text: string): number | null => {
  try {
    const map: unknown = JSON.parse(text);
    return map && typeof map === "object" && Array.isArray((map as { sources?: unknown }).sources) ? (map as { sources: unknown[] }).sources.length : null;
  } catch { return null; }
};
const inlineText = (uri: string): string | null => {
  if (uri.length > 24 * 1024 * 1024) return null;
  const m = uri.match(/^data:application\/json((?:;[^,]*)?),(.*)$/is);
  if (!m) return null;
  try {
    if (/;base64(?:;|$)/i.test(m[1]!)) {
      if (!/^[A-Za-z0-9+/]*={0,2}$/.test(m[2]!)) return null;
      return Buffer.from(m[2]!, "base64").toString("utf8");
    }
    return decodeURIComponent(m[2]!);
  } catch { return null; }
};
const httpUrl = (value: string, base?: string): string | null => {
  try { const u = new URL(value, base); return /^https?:$/.test(u.protocol) && !u.username && !u.password ? u.href : null; } catch { return null; }
};

export const detectSourceMaps = async (input: SourceMapInput): Promise<SourceMapResult> => {
  const jsDir = resolve(input.jsDir ?? join(input.outputRoot, "js"));
  const names = (await readdir(jsDir, { withFileTypes: true }).catch(() => [])).filter(e => e.isFile() && e.name.endsWith(".js")).map(e => join(jsDir, e.name));
  const provenance = new Map<string, string>();
  // The harvester may persist this same array; explicit call data wins.
  const saved = await readFile(join(input.outputRoot, "bundle_manifest.json"), "utf8").then(s => JSON.parse(s) as unknown).catch(() => []);
  for (const row of [...(Array.isArray(saved) ? saved : []), ...(input.bundles ?? [])]) {
    if (!row || typeof row.file !== "string" || typeof row.url !== "string") continue;
    const url = httpUrl(row.url);
    if (url) provenance.set(resolve(input.outputRoot, row.file), url);
  }
  const leaked: SourceMapResult["leaked"] = [], maps: MapContent[] = [];
  for (const file of names.slice(0, 200)) {
    const text = await readFile(file, "utf8").catch(() => null);
    if (text === null) continue;
    const bundleUrl = provenance.get(file) ?? httpUrl(file.slice(jsDir.length + 1), input.baseUrl);
    const comments = [...text.matchAll(/sourceMappingURL\s*=\s*([^\s*'"]+)/g)];
    const comment = comments.at(-1)?.[1];
    let found = false;
    if (comment?.startsWith("data:")) {
      const decoded = inlineText(comment);
      const count = decoded === null ? null : validMap(decoded);
      if (count !== null) {
        leaked.push({ file, bundleUrl: bundleUrl ?? undefined, mapUrl: "data:inline", sourceCount: count });
        maps.push({ text: decoded!, from: `${file}#inline`, bundleUrl: bundleUrl ?? undefined }); found = true;
      }
    }
    if (found) continue;
    const fallback = bundleUrl ? (() => { const u = new URL(bundleUrl); u.pathname += ".map"; u.hash = ""; return u.href; })() : `${file.slice(jsDir.length + 1)}.map`;
    for (const candidate of [...new Set([comment, fallback].filter((c): c is string => !!c && !c.startsWith("data:")))]) {
      const remote = httpUrl(candidate, bundleUrl ?? input.baseUrl);
      let local: string | null = null;
      if (!/^(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(candidate) && !candidate.startsWith("/") && !candidate.includes("\\") && !candidate.includes("\0")) {
        const path = resolve(dirname(file), candidate.split(/[?#]/)[0]!);
        const rel = relative(jsDir, path);
        if (rel && !rel.startsWith("..") && !isAbsolute(rel)) local = await safePath(jsDir, rel).catch(() => null);
      } else if (candidate === fallback) local = `${file}.map`;
      let mapText = local ? await readFile(local, "utf8").catch(() => null) : null;
      let from = local ?? candidate;
      if (mapText === null && remote) {
        const r = await fetchUrl(remote, { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 8000, redirect: "manual", maxBytes: 16 * 1024 * 1024 });
        if (r.status === 200 && r.complete !== false && !r.truncated && !r.error) { mapText = r.body; from = remote; }
      }
      const count = mapText === null ? null : validMap(mapText);
      if (count === null) continue;
      leaked.push({ file, bundleUrl: bundleUrl ?? undefined, mapUrl: from, sourceCount: count });
      maps.push({ text: mapText!, from, bundleUrl: bundleUrl ?? undefined }); break;
    }
  }
  const artifacts: SourceMapResult["artifacts"] = [];
  let recovered: SourceMapResult["recovered"];
  if (input.recover) {
    const result = await recoverMapContents(maps, input.outputRoot);
    recovered = { maps: result.maps, recovered: result.recovered, missing: result.missing };
    artifacts.push(...result.artifacts);
  }
  artifacts.push(await writeArtifact(input.outputRoot, "sourcemaps.txt", leaked.map(m => `${m.file}\t${m.sourceCount} sources\t${m.mapUrl}`).join("\n")));
  return { checked: Math.min(names.length, 200), leaked, recovered, artifacts };
};

// ---------- Wayback ----------

export interface WaybackInput {
  readonly target: string;
  readonly outputRoot: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxUrls?: number;
}

export interface WaybackResult {
  readonly target: string;
  readonly urls: string[];
  readonly artifacts: { path: string; bytes: number }[];
}

export const fetchWayback = async (input: WaybackInput): Promise<WaybackResult> => {
  const target = input.target.replace(/^https?:\/\//, "").replace(/\/$/, "");
  await mkdir(input.outputRoot, { recursive: true });
  try {
    const res = await fetchUrl(
      `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(target)}&matchType=domain&collapse=urlkey&fl=original&limit=${input.maxUrls ?? 2000}&filter=statuscode:200`,
      { timeoutMs: input.timeoutMs ?? 30000, proxy: input.proxy },
    );
    const urls = res.status === 200
      ? res.body.split("\n").map((l) => l.trim()).filter(Boolean)
      : [];
    // Sanitize archive noise: percent-encoded injection artifacts (%22, %0A,
    // %27...), pure-fragment/empty paths, and duplicated scheme variants.
    const cleanUrls = [...new Set(urls)].filter((u) => {
      try {
        const p = new URL(u).pathname;
        if (/%22|%27|%0A|%0D|%3C|%3E|%7B|%7D/i.test(u)) return false;
        if (p === "/" || p === "") return false;
        return true;
      } catch {
        return false;
      }
    }).slice(0, input.maxUrls ?? 500);
    const path = join(input.outputRoot, "wayback_urls.txt");
    const body = cleanUrls.join("\n");
    await writeFile(path, body);
    return { target, urls: cleanUrls, artifacts: [{ path, bytes: Buffer.byteLength(body) }] };
  } catch {
    return { target, urls: [], artifacts: [] };
  }
};
