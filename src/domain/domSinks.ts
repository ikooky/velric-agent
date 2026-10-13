import { readFile, writeFile, mkdir, readdir } from "node:fs/promises";
import { join, basename } from "node:path";

/** DOM-XSS sink scan over the harvested JS corpus: taint-style source→sink
 *  chains (location.hash/search/referer/name → innerHTML/eval/document.write/
 *  insertAdjacentHTML/jQuery $()...). Pure static analysis, local files only. */

export interface DomSinkInput {
  readonly jsDir: string;
  readonly outputRoot: string;
  readonly maxFiles?: number;
}

export interface DomSinkResult {
  readonly scanned: number;
  readonly chains: {
    file: string;
    source: string;
    sink: string;
    excerpt: string;
  }[];
  readonly sinks: { file: string; sink: string; count: number }[];
  readonly artifacts: { path: string; bytes: number }[];
}

const SOURCES = [
  "location.hash", "location.search", "location.href", "location.pathname",
  "document.referrer", "document.URL", "document.documentURI", "window.name",
  "postMessage", "URLSearchParams",
] as const;

const SINKS: ReadonlyArray<readonly [string, RegExp]> = [
  ["innerHTML", /\.innerHTML\s*=/],
  ["outerHTML", /\.outerHTML\s*=/],
  ["document.write", /document\.write(?:ln)?\s*\(/],
  ["eval", /(?:^|[^\w$.])eval\s*\(/],
  ["setTimeout-string", /setTimeout\s*\(\s*['"`]/],
  ["setInterval-string", /setInterval\s*\(\s*['"`]/],
  ["insertAdjacentHTML", /\.insertAdjacentHTML\s*\(/],
  ["Function-ctor", /new\s+Function\s*\(/],
  ["jQuery-html", /\$\([^)]*\)\.html\s*\(/],
  ["attr-href-js", /\.attr\s*\(\s*['"]href['"]\s*,/],
  ["srcdoc", /\.srcdoc\s*=/],
  ["script-src", /\.src\s*=\s*[^;]*(?:hash|search|referrer|name)/],
];

/** Find source→sink chains inside one function-ish window: for each sink
 *  occurrence, look backwards up to N chars for a source reference. */
const CHAIN_WINDOW = 600;

const scanFile = (file: string, text: string): Pick<DomSinkResult, "chains" | "sinks"> => {
  const chains: DomSinkResult["chains"] = [];
  const sinks: DomSinkResult["sinks"] = [];
  for (const [sinkName, sinkRe] of SINKS) {
    let count = 0;
    const g = new RegExp(sinkRe.source, sinkRe.flags.includes("g") ? sinkRe.flags : sinkRe.flags + "g");
    let m: RegExpExecArray | null;
    while ((m = g.exec(text)) !== null) {
      count++;
      // look back for a source feeding this sink
      const back = text.slice(Math.max(0, m.index - CHAIN_WINDOW), m.index);
      for (const src of SOURCES) {
        if (back.includes(src)) {
          chains.push({
            file: basename(file),
            source: src,
            sink: sinkName,
            excerpt: text.slice(Math.max(0, m.index - 80), m.index + 80).replace(/\s+/g, " ").slice(0, 160),
          });
          break;
        }
      }
    }
    if (count > 0) sinks.push({ file: basename(file), sink: sinkName, count });
  }
  return { chains, sinks };
};

export const scanDomSinks = async (input: DomSinkInput): Promise<DomSinkResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  let files: string[] = [];
  try {
    files = (await readdir(input.jsDir)).filter((f) => f.endsWith(".js")).map((f) => join(input.jsDir, f));
  } catch {
    return { scanned: 0, chains: [], sinks: [], artifacts: [] };
  }
  const cap = input.maxFiles ?? 300;

  const allChains: DomSinkResult["chains"] = [];
  const allSinks: DomSinkResult["sinks"] = [];
  let scanned = 0;
  for (const f of files.slice(0, cap)) {
    let text: string;
    try {
      text = await readFile(f, "utf8");
    } catch {
      continue;
    }
    scanned++;
    const r = scanFile(f, text);
    allChains.push(...r.chains);
    allSinks.push(...r.sinks);
  }

  const path = join(input.outputRoot, "dom_sinks.json");
  const body = JSON.stringify({ scanned, chains: allChains.slice(0, 200), sinks: allSinks }, null, 2);
  await writeFile(path, body);
  return { scanned, chains: allChains, sinks: allSinks, artifacts: [{ path, bytes: Buffer.byteLength(body) }] };
};
