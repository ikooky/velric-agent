import { readdir, readFile, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";

import { fetchUrl } from "../adapters/http.js";
import { ensureDir, writeArtifact } from "../adapters/artifacts.js";
import { chunkUrls, originOf } from "../domain/chunks.js";
import { classifyPaths, extractPathLiterals, extractRoutes } from "../domain/endpoints.js";

/** Bounded-concurrency map pool. */
export const pooled = async <T>(
  items: readonly T[],
  limit: number,
  worker: (item: T) => Promise<void>,
): Promise<void> => {
  let cursor = 0;
  const run = async (): Promise<void> => {
    while (cursor < items.length) {
      const idx = cursor++;
      await worker(items[idx]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, run));
};

export interface HarvestInput {
  readonly baseUrl: string;
  readonly outputRoot: string;
  readonly timeoutMs?: number;
  readonly maxRounds?: number;
  readonly concurrency?: number;
  readonly proxy?: string;
  readonly cookie?: string;
}

export interface HarvestSummary {
  readonly entryUrl: string;
  readonly robotsRoutes: number;
  readonly scriptsInHtml: number;
  readonly jsDownloaded: number;
  readonly manifestUrls: number;
  readonly unreachable: number;
  readonly apiEndpoints: number;
  readonly otherPaths: number;
  readonly routes: number;
  readonly secrets: number;
  /** Actual URLs requested (entry, scripts, robots/sitemap) — feeds the
   * observation ledger so host evidence citations pass the gate. Capped. */
  readonly touchedUrls: string[];
  readonly artifacts: { path: string; bytes: number }[];
}

const SCRIPT_SRC_RE = /<script[^>]+src=("([^"]+\.js[^"]*)"|([^"\s>]+\.js))/gi;
const LINK_JS_RE = /(?:src|href)=("([^"]*\.js)"|([^"\s>]+\.js))/gi;

const normalizeBase = (raw: string): string =>
  raw.startsWith("http") ? raw : `https://${raw}`;

/**
 * Static SPA bundle harvester (port of harvest_static.py): fetch the entry,
 * download every referenced script, expand webpack/Vite chunk manifests until
 * fixpoint, then extract endpoints and routes from the full JS corpus.
 */
export const harvestStatic = async (
  input: HarvestInput,
): Promise<HarvestSummary> => {
  const base = normalizeBase(input.baseUrl);
  const origin = originOf(base);
  const root = await ensureDir(input.outputRoot);
  const jsDir = join(root, "js");
  const concurrency = input.concurrency ?? 16;
  const timeoutMs = input.timeoutMs ?? 25000;

  const entry = await fetchUrl(base, { proxy: input.proxy, cookie: input.cookie, timeoutMs });
  if (entry.status === 0) {
    throw { code: "fetch_failed", message: `entry unreachable: ${entry.error}` };
  }
  await writeFile(join(root, "index.html"), entry.body);

  // robots.txt / sitemap.xml: public routing surface, feed both the route set
  // and the extraction corpus (cheap: 2 requests, big coverage win).
  const robotsRoutes = new Set<string>();
  const fetchText = async (path: string): Promise<string | null> => {
    const r = await fetchUrl(new URL(path, base).href, { proxy: input.proxy, cookie: input.cookie, timeoutMs });
    return r.status === 200 && !r.contentType.includes("html") && r.body.length < 2_000_000 ? r.body : null;
  };
  const robots = await fetchText("/robots.txt");
  if (robots) {
    for (const m of robots.matchAll(/(?:Allow|Disallow):\s*(\/\S*)/g)) {
      if (!m[1]!.includes("*")) robotsRoutes.add(m[1]!);
    }
    const sitemapUrls = [...robots.matchAll(/Sitemap:\s*(\S+)/g)].map((m) => m[1]!);
    for (const sm of sitemapUrls.slice(0, 3)) {
      const xml = await fetchText(sm.startsWith("http") ? sm : new URL(sm, base).href);
      if (xml) for (const loc of xml.matchAll(/<loc>(?:<!\[CDATA\[)?([^<\]]+)/g)) {
        const u = loc[1]!.trim();
        try { robotsRoutes.add(new URL(u).pathname); } catch { /* skip */ }
      }
    }
  }

  const seeds = new Set<string>();
  for (const re of [SCRIPT_SRC_RE, LINK_JS_RE]) {
    for (const m of entry.body.matchAll(re)) {
      const src = m[2] ?? m[3] ?? m[1]!;
      try { seeds.add(src.startsWith("http") ? src : new URL(src, base).href); }
      catch { /* one malformed src must not kill the whole harvest */ }
    }
  }

  const have = new Map<string, string>(); // url -> local path
  const nameCounts = new Map<string, number>(); // basename dedup: same-named JS from different URLs must not overwrite each other
  const download = async (url: string): Promise<void> => {
    const base = basename(new URL(url).pathname);
    if (!base.endsWith(".js") || have.has(url)) return;
    const n = (nameCounts.get(base) ?? 0) + 1;
    nameCounts.set(base, n);
    // Disambiguate collisions: second "main.js" lands as main-2.js —
    // previously one silently overwrote the other (corpus loss).
    const name = n === 1 ? base : `${base.replace(/\.js$/, "")}-${n}.js`;
    const res = await fetchUrl(url, {
      proxy: input.proxy,
      cookie: input.cookie,
      timeoutMs,
      maxBytes: 32 * 1024 * 1024,
    });
    if (res.status !== 200 || res.bytes === 0 || res.body.trimStart().startsWith("<")) return;
    const local = join(jsDir, name);
    await writeArtifact(input.outputRoot, `js/${name}`, res.body);
    have.set(url, local);
  };

  await pooled([...seeds], concurrency, download);

  // Iteratively expand chunk manifests (chunks reference more chunks).
  const seenUrls = new Set(have.keys());
  const maxRounds = input.maxRounds ?? 6;
  for (let round = 1; round <= maxRounds; round++) {
    const frontier = [...have.values()];
    const fresh = new Set<string>();
    await pooled(frontier, concurrency, async (local) => {
      let text: string;
      try {
        text = await readFile(local, "utf8");
      } catch {
        return;
      }
      for (const cu of chunkUrls(base, text)) {
        if (!seenUrls.has(cu)) fresh.add(cu);
      }
    });
    if (fresh.size === 0) break;
    for (const u of fresh) seenUrls.add(u);
    await pooled([...fresh], concurrency, download);
  }

  // One retry pass over every manifest URL that 404'd (transient failures).
  const allManifest = new Set<string>();
  await pooled([...have.values()], concurrency, async (local) => {
    try {
      const text = await readFile(local, "utf8");
      for (const cu of chunkUrls(base, text)) allManifest.add(cu);
    } catch {
      /* unreadable chunk */
    }
  });
  const missing = [...allManifest].filter((u) => !have.has(u));
  if (missing.length > 0) await pooled(missing, concurrency, download);
  const unreachable = [...allManifest].filter((u) => !have.has(u)).length;

  // Extract from the whole corpus, including the entry HTML's inline scripts.
  const api = new Set<string>();
  const other = new Set<string>();
  const routes = new Set<string>();
  const consume = (text: string): void => {
    const classified = classifyPaths(extractPathLiterals(text));
    for (const p of classified.api) api.add(p);
    for (const p of classified.other) other.add(p);
    for (const r of extractRoutes(text)) routes.add(r);
  };
  consume(entry.body); // inline <script> API calls in the entry page
  for (const r of robotsRoutes) routes.add(r);
  let files: string[] = [];
  try {
    files = await readdir(jsDir);
  } catch {
    files = [];
  }
  await pooled(files, concurrency, async (name) => {
    let text: string;
    try {
      text = await readFile(join(jsDir, name), "utf8");
    } catch {
      return;
    }
    consume(text);
  });

  const artifacts: { path: string; bytes: number }[] = [];
  const dump = async (name: string, lines: Iterable<string>) => {
    const body = [...lines].sort().join("\n");
    artifacts.push(await writeArtifact(input.outputRoot, name, body));
  };
  await dump("api_static.txt", api);
  await dump("paths_other.txt", other);
  await dump("routes.txt", routes);
  await dump(
    "chunkmap.txt",
    [...allManifest].map((u) => basename(new URL(u).pathname)),
  );

  // Secret scan over the harvested JS corpus — pure local regex, zero cost.
  const corpus = await readJsCorpus(jsDir);
  const { scanSecrets } = await import("../domain/secrets.js");
  const secretHits = scanSecrets(corpus);
  if (secretHits.length > 0) {
    artifacts.push(
      await writeArtifact(
        input.outputRoot,
        "secrets.txt",
        secretHits.map((h) => `${h.name}\t${h.file}\t${h.match}`).join("\n"),
      ),
    );
  }

  const touched = new Set<string>([base, ...seeds, ...allManifest]);
  if (robots) touched.add(new URL("/robots.txt", base).href);

  return {
    entryUrl: base,
    robotsRoutes: robotsRoutes.size,
    scriptsInHtml: seeds.size,
    touchedUrls: [...touched].slice(0, 500),
    jsDownloaded: have.size,
    manifestUrls: allManifest.size,
    unreachable,
    apiEndpoints: api.size,
    otherPaths: other.size,
    routes: routes.size,
    secrets: secretHits.length,
    artifacts,
  };
};

export const listJsFiles = async (jsDir: string): Promise<string[]> => {
  try {
    const names = await readdir(jsDir);
    return names.filter((n) => n.endsWith(".js")).map((n) => join(jsDir, n));
  } catch {
    return [];
  }
};

export const readJsCorpus = async (
  jsDir: string,
): Promise<{ path: string; text: string }[]> => {
  const files = await listJsFiles(jsDir);
  const out: { path: string; text: string }[] = [];
  for (const p of files) {
    try {
      out.push({ path: basename(p), text: await readFile(p, "utf8") });
    } catch {
      /* skip unreadable */
    }
  }
  return out;
};

