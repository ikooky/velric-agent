import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { readdir, readFile } from "node:fs/promises";

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
}

export interface SourceMapResult {
  readonly checked: number;
  readonly leaked: { file: string; mapUrl: string; sourceCount: number }[];
  readonly recovered?: { maps: number; recovered: number; missing: number };
  readonly artifacts: { path: string; bytes: number }[];
}

const lastSegment = (url: string): string => {
  try {
    return new URL(url).pathname.split("/").filter(Boolean).pop() ?? "";
  } catch {
    return url;
  }
};

export const detectSourceMaps = async (input: SourceMapInput): Promise<SourceMapResult> => {
  const jsDir = input.jsDir ?? join(input.outputRoot, "js");
  await mkdir(input.outputRoot, { recursive: true });
  let files: string[] = [];
  try {
    files = (await readdir(jsDir)).filter((f) => f.endsWith(".js")).map((f) => join(jsDir, f));
  } catch {
    return { checked: 0, leaked: [], artifacts: [] };
  }

  const leaked: SourceMapResult["leaked"] = [];
  const seen = new Set<string>();
  for (const f of files.slice(0, 200)) {
    const name = lastSegment(f);
    if (seen.has(name)) continue;
    seen.add(name);
    // 1) explicit sourceMappingURL comment
    let mapUrl: string | null = null;
    try {
      const text = await readFile(f, "utf8");
      const m = text.match(/sourceMappingURL=([^\s*'"]+)/);
      if (m) mapUrl = m[1]!;
    } catch { /* unreadable */ }
    // 2) probe <file>.map next to the JS — locally first, then remote when
    //    baseUrl lets us reconstruct the original bundle URL.
    let sourceCount = 0;
    // data: URIs are INLINE maps (unwebpack-sourcemap): decode directly — no
    // candidate probing needed. Many build setups inline small maps by default;
    // skipping them (the old `!startsWith("data:")` filter) was a miss path.
    let inlineSources = 0;
    if (mapUrl?.startsWith("data:")) {
      const b64 = mapUrl.slice(mapUrl.indexOf(",") + 1);
      try {
        const text = Buffer.from(b64, "base64").toString("utf8");
        const parsed = JSON.parse(text) as { sources?: unknown[] };
        inlineSources = parsed.sources?.length ?? 0;
        leaked.push({ file: name, mapUrl: "data:inline", sourceCount: inlineSources });
      } catch { /* malformed inline map */ }
    }
    const candidates = [mapUrl, `${name}.map`].filter((x): x is string => !!x && !x.startsWith("data:"));
    for (const cand of candidates.slice(0, 2)) {
      let localName = cand.replace(/^https?:\/\/[^/]+\//, "").replace(/^\//, "");
      // The comment lives in untrusted harvested JS — the derived local file
      // name must stay inside jsDir (no ../, no absolute, no drive letters).
      if (localName.includes("..") || /^[a-zA-Z]:/.test(localName) || localName.includes("\0") || localName === "") continue;
      let text: string | null = null;
      let resolvedUrl = cand;
      try {
        text = await readFile(join(jsDir, localName), "utf8");
      } catch {
        if (input.baseUrl) {
          const remote = new URL(localName, input.baseUrl).href;
          const r = await fetchUrl(remote, { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 8000 });
          if (r.status === 200 && r.body.trimStart().startsWith("{")) {
            text = r.body;
            resolvedUrl = remote;
          }
        }
      }
      if (text) {
        try {
          const parsed = JSON.parse(text) as { sources?: unknown[] };
          sourceCount = parsed.sources?.length ?? 0;
          leaked.push({ file: name, mapUrl: resolvedUrl, sourceCount });
          break;
        } catch { /* malformed map */ }
      }
    }
  }

  let recovered: { maps: number; recovered: number; missing: number } | undefined;
  if (input.recover) {
    const { recoverSourceMaps, recoverInlineMap } = await import("./sourceRecover.js");
    const r = await recoverSourceMaps({ mapDir: input.jsDir ?? input.outputRoot, outputRoot: input.outputRoot });
    recovered = { maps: r.maps, recovered: r.recovered, missing: r.missing };
    // Inline (data: URI) maps: decode + recover in the same pass.
    for (const l of leaked) {
      if (l.mapUrl !== "data:inline") continue;
      // leaked[].file is the harvested file's FULL path already — read directly.
      const fileText = await readFile(l.file, "utf8").catch(() => null);
      const m = fileText?.match(/sourceMappingURL=data:application\/json;base64,([^\s*'"]+)/);
      if (!m) continue;
      const ir = await recoverInlineMap(Buffer.from(m[1]!, "base64").toString("utf8"), input.outputRoot);
      recovered = { maps: recovered.maps + 1, recovered: recovered.recovered + ir.recovered, missing: recovered.missing + ir.missing };
    }
  }
  const path = join(input.outputRoot, "sourcemaps.txt");
  const body = leaked.map((l) => `${l.file}\t${l.sourceCount} sources\t${l.mapUrl}`).join("\n");
  if (leaked.length > 0) await writeFile(path, body);
  return { checked: seen.size, leaked, recovered, artifacts: leaked.length > 0 ? [{ path, bytes: Buffer.byteLength(body) }] : [] };
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
