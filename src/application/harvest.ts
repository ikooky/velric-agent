import { readdir, readFile } from "node:fs/promises";
import { basename, join, relative, dirname } from "node:path";
import { createHash } from "node:crypto";
import { SessionJar, sameOrigin } from "../core/credentials.js";
import { executionRunId } from "../core/execution.js";
import { readJson, withRootLock, writeJson } from "../core/storage.js";

import { fetchUrl } from "../adapters/http.js";
import { ensureDir, writeArtifact } from "../adapters/artifacts.js";
import { chunkUrls, originOf } from "../domain/chunks.js";
import { classifyPaths, extractPathLiterals, extractRoutes } from "../domain/endpoints.js";

/** Bounded-concurrency map pool. */
const pooled = async <T>(
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
  const workers = Math.max(1, Math.min(limit, items.length));
  await Promise.all(Array.from({ length: workers }, run));
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

const SCRIPT_SRC_RE = /<script[^>]+src=("(?:([^"]+\.js[^"]*))"|'((?:[^']+\.js[^']*))'|([^"\s>]+\.js))/gi;
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
  const jar = new SessionJar();
  if (input.cookie) jar.update(base, input.cookie.split(";").map(c => `${c.trim()}; Path=/`));
  const touched = new Set<string>();
  const request = async (url: string, maxBytes?: number) => {
    const parsed = new URL(url);
    if (!/^https?:$/.test(parsed.protocol)) throw new Error("script URL must use HTTP(S)");
    touched.add(parsed.href);
    const result = await fetchUrl(parsed.href, { proxy: input.proxy, headers: sameOrigin(url, base) ? jar.headers(url) : {}, timeoutMs, maxBytes, redirect: "manual" });
    if (sameOrigin(url, base)) jar.update(url, result.setCookies ?? []);
    return result;
  };

  const entry = await request(base);
  if (entry.status === 0) {
    throw { code: "fetch_failed", message: `entry unreachable: ${entry.error}` };
  }
  await writeArtifact(root, "index.html", entry.body);

  // robots.txt / sitemap.xml: public routing surface, feed both the route set
  // and the extraction corpus (cheap: 2 requests, big coverage win).
  const robotsRoutes = new Set<string>();
  const fetchText = async (path: string): Promise<string | null> => {
    const url = new URL(path, base).href;
    if (!sameOrigin(url, base)) return null;
    const r = await request(url);
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
        try { if (sameOrigin(u, base)) robotsRoutes.add(new URL(u).pathname); } catch { /* skip */ }
      }
    }
  }

  const seeds = new Set<string>();
  for (const re of [SCRIPT_SRC_RE, LINK_JS_RE]) {
    for (const m of entry.body.matchAll(re)) {
      const src = m[2] ?? m[3] ?? m[4]!;
      try { seeds.add(src.startsWith("http") ? src : new URL(src, base).href); }
      catch { /* one malformed src must not kill the whole harvest */ }
    }
  }

  const have = new Map<string, string>(); // url -> local path
  const downloaded: { path: string; bytes: number }[] = [];
  const download = async (url: string): Promise<void> => {
    const base = basename(new URL(url).pathname);
    if (!base.endsWith(".js") || have.has(url)) return;
    const name = `${base.replace(/\.js$/, "")}-${createHash("sha256").update(url).digest("hex").slice(0, 16)}.js`;
    const res = await request(url, 32 * 1024 * 1024);
    if (res.status !== 200 || res.complete === false || res.bytes === 0 || res.body.trimStart().startsWith("<")) return;
    const local = join(jsDir, name);
    downloaded.push(await writeArtifact(input.outputRoot, `js/${name}`, res.body));
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
  await pooled([...have.values()], concurrency, async (local) => {
    let text: string;
    try {
      text = await readFile(local, "utf8");
    } catch {
      return;
    }
    consume(text);
  });

  const artifacts: { path: string; bytes: number }[] = [...downloaded];
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
  const corpus = await Promise.all([...have.values()].map(async path => ({ path: basename(path), text: await readFile(path, "utf8") })));
  const { scanSecrets } = await import("../domain/secrets.js");
  const secretHits = scanSecrets(corpus);
  artifacts.push(await writeArtifact(root, "secrets.txt", secretHits.map(h => `${h.name}\t${h.file}\t${h.match}`).join("\n")));
  await ownCorpus(root, "harvest-static", base, [...have.values()]);
  artifacts.push(await writeOwnedManifest(root, "harvest_manifest.json", "harvest-static", base, artifacts, have.size));

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

export const writeOwnedManifest = async (root: string, name: string, producer: string, target: string, artifacts: readonly { path: string; bytes: number }[], count: number) => {
  const files = await Promise.all(artifacts.map(async a => ({ path: relative(root, a.path), bytes: a.bytes, sha256: createHash("sha256").update(await readFile(a.path)).digest("hex") })));
  return writeArtifact(root, name, JSON.stringify({ producer, target: new URL(target).href, runId: executionRunId(), count, files }, null, 2));
};

/** Only the currently owned corpus is visible, without deleting user files. */
export const ownCorpus = async (root: string, producer: string, target: string, files: readonly string[]): Promise<void> => {
  await withRootLock(root, async () => {
    type Ownership = { target: string; owners: Record<string, { path: string; sha256: string }[]> };
    const old = await readJson<Ownership>(root, "js/corpus_manifest.json", () => ({ target, owners: {} }));
    const owners = old.target === target ? old.owners : {};
    owners[producer] = await Promise.all(files.map(async path => ({ path: basename(path), sha256: createHash("sha256").update(await readFile(path)).digest("hex") })));
    await writeJson(root, "js/corpus_manifest.json", { target, owners });
  });
};

export interface BrowserParamSample { method: string; url: string; body?: string | null; query?: string | null; sources?: string[]; action?: string; [key: string]: unknown }
/** Replace one producer's samples, preserving and coalescing the others. */
export const mergeBrowserSamples = async (root: string, target: string, producer: string, fresh: readonly BrowserParamSample[]) => withRootLock(root, async () => {
  const owner = await readJson<{ target: string } | null>(root, "param_samples_manifest.json", () => null);
  const old = await readJson<BrowserParamSample[]>(root, "param_samples.json", () => []);
  if (!Array.isArray(old)) throw new Error("invalid param_samples.json");
  const retained = owner && owner.target !== new URL(target).href ? [] : old.map(row => ({ ...row, sources: (row.sources ?? ["runtime"]).filter(s => s !== producer) })).filter(row => row.sources.length);
  const merged = new Map<string, BrowserParamSample>();
  for (const row of [...retained, ...fresh.map(row => ({ ...row, sources: [producer] }))]) {
    // Disk rows are untrusted: skip rows with an invalid shape instead of crashing.
    if (!row || typeof row.method !== "string" || typeof row.url !== "string") continue;
    const normalized = { ...row, method: row.method.toUpperCase(), url: new URL(row.url, target).href };
    const key = JSON.stringify([normalized.method, normalized.url, normalized.body ?? null]);
    const prev = merged.get(key);
    merged.set(key, { ...normalized, sources: [...new Set([...(prev?.sources ?? []), ...(normalized.sources ?? [])])] });
  }
  const artifact = await writeArtifact(root, "param_samples.json", JSON.stringify([...merged.values()], null, 2));
  await writeJson(root, "param_samples_manifest.json", { producer: "browser-samples", target: new URL(target).href, runId: executionRunId(), count: merged.size, sources: [...new Set([...merged.values()].flatMap(row => row.sources ?? []))] });
  return artifact;
});

const listJsFiles = async (jsDir: string): Promise<string[]> => {
  try {
    const manifest = await readJson<{ owners: Record<string, { path: string; sha256: string }[]> } | null>(dirname(jsDir), "js/corpus_manifest.json", () => null);
    if (manifest) {
      const files = new Map(Object.values(manifest.owners).flat().map(row => [row.path, row.sha256]));
      const out: string[] = [];
      for (const [name, hash] of files) {
        if (basename(name) !== name || !name.endsWith('.js')) throw new Error('invalid corpus path');
        const path = join(jsDir, name);
        // One missing file must not discard the whole verified corpus.
        let bytes: Buffer;
        try { bytes = await readFile(path); } catch { continue; }
        if (createHash('sha256').update(bytes).digest('hex') !== hash) throw new Error('corpus integrity mismatch');
        out.push(path);
      }
      return out;
    }
    const names = await readdir(jsDir);
    return names.filter((n) => n.endsWith(".js")).map((n) => join(jsDir, n));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw err;
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

