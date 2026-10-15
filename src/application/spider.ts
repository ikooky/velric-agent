import { fetchUrl } from "../adapters/http.js";
import { ensureDir, writeArtifact } from "../adapters/artifacts.js";
import { parseMpaPage } from "../domain/mpa.js";
import { pooled } from "./harvest.js";

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
  // Caller-supplied patterns: compile defensively (bad syntax used to throw
  // raw) and cap length against catastrophic backtracking.
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
  let crawled = 0;

  while (queue.length > 0 && crawled < maxPages) {
    const { url, d } = queue.shift()!;
    crawled++;
    const res = await fetchUrl(url, {
      cookie: input.cookie,
      proxy: input.proxy,
      timeoutMs: 20000,
    });
    if (delayMs > 0) await new Promise((r) => setTimeout(r, delayMs));
    if (!res.body || (!res.contentType.includes("html") && !res.contentType.includes("xml"))) {
      continue;
    }
    const page = parseMpaPage(res.body);
    links.add(url.replace(origin, "") || "/");
    for (const f of page.forms) {
      let act: string;
      try { act = new URL(f.action || url, url).href; } catch { continue; }
      const key = `${f.method} ${act.replace(origin, "")}`;
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
        if (!next.startsWith(origin)) continue;
        if (SKIP_EXT.test(next) || exc.test(next)) continue;
        if (inc && !inc.test(next)) continue;
        if (!seen.has(next)) {
          seen.add(next);
          queue.push({ url: next, d: d + 1 });
        }
      }
    }
  }

  const artifacts: { path: string; bytes: number }[] = [];
  const formsBody = [...forms.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, ps]) => `${k}  [${[...ps].sort().join(", ")}]`)
    .join("\n");
  artifacts.push(await writeArtifact(root, "forms.txt", formsBody));
  artifacts.push(await writeArtifact(root, "links.txt", [...links].sort().join("\n")));
  artifacts.push(await writeArtifact(root, "api_inline.txt", [...inline].sort().join("\n")));

  return {
    crawled,
    forms: forms.size,
    inlineApiUrls: inline.size,
    links: links.size,
    artifacts,
  };
};

