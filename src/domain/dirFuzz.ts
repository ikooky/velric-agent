import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";

/** Wordlist-driven content discovery (ffuf/feroxbuster design): FUZZ keyword
 *  substitution in path/param positions, auto-calibration against soft-404s
 *  (random-probe baseline, ffuf -ac), optional recursion into discovered
 *  directories, extension mutation, and multi-dimensional filtering
 *  (status/size/words/lines). Deterministic, single-threaded by default
 *  (rps-limited via the global throttle), no LLM. */

export interface DirFuzzInput {
  /** URL template containing FUZZ, e.g. https://target/FUZZ or …/api/FUZZ.json */
  readonly url: string;
  readonly outputRoot: string;
  /** wordlist file (one word per line) OR inline words. */
  readonly wordlistFile?: string;
  readonly words?: readonly string[];
  /** comma-joined extensions appended to each word (".php,.bak"). */
  readonly extensions?: readonly string[];
  /** recurse into discovered directories (default false). */
  readonly recursion?: boolean;
  readonly recursionDepth?: number;
  /** auto-calibration probes (default 2 random words). */
  readonly calibration?: number;
  /** status codes to MATCH (default 200-399 + 401/403). */
  readonly matchStatus?: readonly number[];
  /** exact response sizes to FILTER OUT (learned via calibration when auto). */
  readonly filterSize?: readonly number[];
  readonly cookie?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxWords?: number;
  readonly delayMs?: number;
}

export interface FuzzHit {
  readonly url: string;
  readonly status: number;
  readonly size: number;
  readonly words: number;
  readonly lines: number;
  readonly contentType: string;
  /** where this came from: depth and word. */
  readonly depth: number;
}

export interface DirFuzzResult {
  readonly probed: number;
  readonly hits: FuzzHit[];
  readonly calibration: { words: string[]; softStatus: number | null; softSizes: number[] };
  readonly artifacts: { path: string; bytes: number }[];
}

const DEFAULT_WORDS: readonly string[] = [
  "admin", "api", "backup", "config", "dashboard", "debug", "dev", "docs",
  "internal", "login", "panel", "private", "secret", "staging", "test",
  "uploads", "user", "console", "management", "monitor", "status", "health",
  ".git", ".env", ".svn", "cgi-bin", "phpmyadmin", "graphql", "rest",
  "v1", "v2", "swagger", "openapi.json", "robots.txt", "sitemap.xml",
  "actuator", "druid", "metrics", "info", "version", "changelog",
];

const words_of = (body: string): number => (body.match(/[^\s]+/g) ?? []).length;
const lines_of = (body: string): number => body.split("\n").length;

const shouldMatch = (status: number, match: readonly number[]): boolean =>
  match.length > 0 ? match.includes(status) : (status >= 200 && status < 400) || status === 401 || status === 403;

export const dirFuzz = async (input: DirFuzzInput): Promise<DirFuzzResult> => {
  await mkdir(input.outputRoot, { recursive: true });

  // wordlist resolution: inline > file > builtin
  let words = input.words ?? [];
  if (words.length === 0 && input.wordlistFile) {
    const t = await readFile(input.wordlistFile, "utf8").catch(() => "");
    words = t.split("\n").map((l) => l.trim()).filter((l) => l.length > 0 && !l.startsWith("#"));
  }
  if (words.length === 0) words = DEFAULT_WORDS;
  const exts = (input.extensions ?? []).map((e) => (e.startsWith(".") ? e : `.${e}`));
  const candidates = new Set<string>();
  for (const w of words.slice(0, input.maxWords ?? 500)) {
    candidates.add(w);
    for (const e of exts) candidates.add(`${w}${e}`);
  }

  const opts = { cookie: input.cookie, headers: input.headers, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 8000 };
  const base = input.url.includes("FUZZ")
    ? input.url
    : input.url.replace(/\/$/, "") + "/FUZZ";
  const mk = (word: string): string => base.replace(/FUZZ/g, encodeURIComponent(word));

  // --- auto-calibration (ffuf -ac): random probes learn the soft-404 shape.
  const calWords = Array.from({ length: input.calibration ?? 2 }, () => Math.random().toString(36).slice(2, 12));
  const calResponses: { status: number; size: number }[] = [];
  for (const w of calWords) {
    const r = await fetchUrl(mk(w), opts);
    if (r.status !== 0) calResponses.push({ status: r.status, size: r.bytes });
  }
  const softStatus = calResponses.length >= 2 && calResponses[0]!.status === calResponses[1]!.status ? calResponses[0]!.status : null;
  const softSizes = calResponses.map((c) => c.size).filter((s) => s > 0);
  const filterSizes = new Set<number>([...(input.filterSize ?? []), ...softSizes]);

  const maxDepth = input.recursion ? (input.recursionDepth ?? 1) : 0;
  const hits: FuzzHit[] = [];
  let probed = 0;

  const scanOne = async (tpl: string, depth: number): Promise<void> => {
    const queue: string[] = [...candidates];
    const foundDirs: string[] = [];
    for (const w of queue) {
      const url = tpl.replace(/FUZZ/g, encodeURIComponent(w));
      const r = await fetchUrl(url, opts);
      probed++;
      if (input.delayMs && input.delayMs > 0) await new Promise((res) => setTimeout(res, input.delayMs));
      if (r.status === 0) continue;
      if (!shouldMatch(r.status, input.matchStatus ?? [])) continue;
      if (filterSizes.has(r.bytes)) continue; // soft-404 size (calibrated)
      if (softStatus !== null && r.status === softStatus && softSizes.includes(r.bytes)) continue;
      hits.push({
        url, status: r.status, size: r.bytes, words: words_of(r.body), lines: lines_of(r.body),
        contentType: r.contentType, depth,
      });
      if (maxDepth > 0 && depth < maxDepth && (r.status === 200 || r.status === 301 || r.status === 302 || r.status === 401 || r.status === 403) && w !== "" && !w.includes(".")) {
        foundDirs.push(w);
      }
    }
    // recursion: discovered dirs become new FUZZ templates
    if (maxDepth > 0 && depth < maxDepth) {
      for (const d of foundDirs.slice(0, 10)) {
        const dirBase = tpl.replace(/FUZZ/g, encodeURIComponent(d)).replace(/\/?$/, "/");
        await scanOne(`${dirBase}FUZZ`, depth + 1);
      }
    }
  };

  await scanOne(base, 0);

  const bodyStr = JSON.stringify({ probed, hits, calibration: { words: calWords, softStatus, softSizes } }, null, 2);
  const path = join(input.outputRoot, "dir_fuzz.json");
  await writeFile(path, bodyStr, "utf8");
  return { probed, hits, calibration: { words: calWords, softStatus, softSizes }, artifacts: [{ path, bytes: Buffer.byteLength(bodyStr) }] };
};
