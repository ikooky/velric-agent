import { fetchUrl } from "../adapters/http.js";
import { ensureDir, writeArtifact } from "../adapters/artifacts.js";
import { join } from "node:path";
import { parseMpaPage } from "../domain/mpa.js";
import { ownCorpus, writeOwnedManifest } from "./harvest.js";
import { SessionJar, sameOrigin } from "../core/credentials.js";
import { createHash } from "node:crypto";

const SKIP_EXT =
  /\.(?:css|png|jpe?g|gif|svg|ico|woff2?|ttf|pdf|zip|mp4|webp|js)(?:\?|$)/i;

export interface SpiderInput {
  readonly baseUrl: string;
  readonly outputRoot: string;
  readonly cookie?: string;
  readonly proxy?: string;
  readonly maxPages?: number;
  readonly depth?: number;
  readonly delayMs?: number;
  readonly include?: string;
  readonly exclude?: string;
}

export interface SpiderSummary {
  readonly crawled: number;
  readonly forms: number;
  readonly inlineApiUrls: number;
  readonly links: number;
  readonly scriptsDownloaded: number;
  readonly artifacts: { path: string; bytes: number }[];
}

/**
 * Same-origin bounded MPA crawler (port of spider_mpa.py): BFS pages, extract
 * forms (the real endpoints), inline ajax URLs, and the reached link set.
 */
export const spiderMpa = async (input: SpiderInput): Promise<SpiderSummary> => {
  const base = input.baseUrl.startsWith("http")
    ? input.baseUrl
    : `https://${input.baseUrl}`;
  // Malformed baseUrl must surface as a structured error, not a bare TypeError.
  let origin: string;
  try { origin = new URL(base).origin; } catch { throw new Error(`invalid baseUrl: ${JSON.stringify(input.baseUrl.slice(0, 60))}`); }
  const root = await ensureDir(input.outputRoot);
  const maxPages = input.maxPages ?? 200;
  const depth = input.depth ?? 4;
  const delayMs = input.delayMs ?? 100;
  // Caller-supplied patterns: compile defensively and cap length against
  // catastrophic backtracking.
  const compile = (src: string, flags?: string): RegExp => {
    if (src.length > 512) throw new Error(`regex too long (max 512 chars)`);
    try { return new RegExp(src, flags); } catch (err) { throw new Error(`invalid regex: ${(err as Error).message}`); }
  };
  const inc = input.include ? compile(input.include) : null;
  const exc = input.exclude
    ? compile(input.exclude, "i")
    : /logout|signout|delete|remove|destroy/i;

  const seen = new Set<string>([base.split("#")[0]!]);
  const queue: { url: string; d: number }[] = [{ url: base, d: 0 }];
  const forms = new Map<string, Set<string>>();
  const inline = new Set<string>();
  const links = new Set<string>();
  const scriptsSeen = new Set<string>();
  let crawled = 0;
  const jar = new SessionJar();
  if (input.cookie) jar.update(base, input.cookie.split(';').map(c => `${c.trim()}; Path=/`));
  const request = async (url: string, maxBytes?: number) => {
    const res = await fetchUrl(url, { headers: sameOrigin(url, base) ? jar.headers(url) : {}, proxy: input.proxy, timeoutMs: 20000, redirect: 'manual', maxBytes });
    if (sameOrigin(url, base)) jar.update(url, res.setCookies ?? []);
    return res;
  };

  while (queue.length > 0 && crawled < maxPages) {
    const { url, d } = queue.shift()!;
    crawled++;
    const res = await request(url);
    if (delayMs > 0) await new Promise((r) => setTimeout(r, delayMs));
    if (res.status < 200 || res.status >= 300 || res.complete === false || !res.body || (!res.contentType.includes("html") && !res.contentType.includes("xml"))) {
      continue;
    }
    const page = parseMpaPage(res.body);
    links.add(url.replace(origin, "") || "/");
    for (const sc of page.scripts) { try { const u = new URL(sc, url); if (/^https?:$/.test(u.protocol)) scriptsSeen.add(u.href); } catch {} }
    for (const f of page.forms) {
      let act: string;
      try { act = new URL(f.action || url, url).href; } catch { continue; }
      const key = `${f.method} ${sameOrigin(act, base) ? new URL(act).pathname + new URL(act).search : act}`;
      const params = forms.get(key) ?? new Set<string>();
      for (const p of f.params) params.add(p);
      forms.set(key, params);
    }
    // page.inline entries are unquoted captured literals; quoted-string regex
    // extraction can never match them — raw paths are kept directly instead.
    for (const s of page.inline) inline.add(s);
    if (d < depth) {
      for (const href of page.links) {
        if (/^(?:mailto:|tel:|javascript:|#)/.test(href)) continue;
        let next: string;
        try { next = new URL(href, url).href.split("#")[0]!; } catch { continue; }
        if (!sameOrigin(next, origin)) continue;
        if (SKIP_EXT.test(next) || exc.test(next)) continue;
        if (inc && !inc.test(next)) continue;
        if (!seen.has(next)) {
          seen.add(next);
          queue.push({ url: next, d: d + 1 });
        }
      }
    }
  }

  // External scripts seen while crawling are attack surface too: without
  // them dom_sinks has no corpus on MPA targets (js/ was SPA-harvest-only).
  const scriptUrls = new Set<string>();
  for (const u of [...scriptsSeen]) {
    try { scriptUrls.add(new URL(u, base).href); } catch { /* skip malformed */ }
  }

  const artifacts: { path: string; bytes: number }[] = [];
  const formsBody = [...forms.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, ps]) => `${k}  [${[...ps].sort().join(", ")}]`)
    .join("\n");
  artifacts.push(await writeArtifact(root, "forms.txt", formsBody));
  artifacts.push(await writeArtifact(root, "links.txt", [...links].sort().join("\n")));
  artifacts.push(await writeArtifact(root, "api_inline.txt", [...inline].sort().join("\n")));
  artifacts.push(await writeArtifact(root, "js_manifest.txt", [...scriptUrls].sort().join("\n")));

  // Download a bounded JS corpus so dom_sinks/perm-tree have material on MPAs.
  const jsDir = await ensureDir(join(root, "js"));
  let jsDownloaded = 0;
  {
    const { basename } = await import("node:path");
    const corpus: string[] = [];
    for (const u of [...scriptUrls].slice(0, 25)) {
      let name: string;
      try { name = basename(new URL(u).pathname); } catch { continue; }
      if (!name.endsWith(".js")) continue;
      const fname = `${name.replace(/\.js$/, "")}-${createHash('sha256').update(u).digest('hex').slice(0,16)}.js`;
      try {
        const res = await request(u, 32 * 1024 * 1024);
        if (res.status !== 200 || res.complete === false || res.bytes === 0 || res.body.trimStart().startsWith("<")) continue;
        const artifact = await writeArtifact(root, `js/${fname}`, res.body);
        artifacts.push(artifact); corpus.push(artifact.path);
        jsDownloaded++;
      } catch { /* one bad script must not kill the corpus */ }
    }
    await ownCorpus(root, 'spider-mpa', base, corpus);
  }
  artifacts.push(await writeOwnedManifest(root, 'spider_manifest.json', 'spider-mpa', base, artifacts, crawled));

  return {
    crawled,
    forms: forms.size,
    inlineApiUrls: inline.size,
    scriptsDownloaded: jsDownloaded,
    links: links.size,
    artifacts,
  };
};

