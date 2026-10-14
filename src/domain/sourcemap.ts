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
}

export interface SourceMapResult {
  readonly checked: number;
  readonly leaked: { file: string; mapUrl: string; sourceCount: number }[];
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
    const candidates = [mapUrl, `${name}.map`].filter((x): x is string => !!x && !x.startsWith("data:"));
    for (const cand of candidates.slice(0, 2)) {
      const localName = cand.replace(/^https?:\/\/[^/]+\//, "").replace(/^\//, "");
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

  const path = join(input.outputRoot, "sourcemaps.txt");
  const body = leaked.map((l) => `${l.file}\t${l.sourceCount} sources\t${l.mapUrl}`).join("\n");
  if (leaked.length > 0) await writeFile(path, body);
  return { checked: seen.size, leaked, artifacts: leaked.length > 0 ? [{ path, bytes: Buffer.byteLength(body) }] : [] };
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
