/**
 * Chunk-manifest parsing ported from harvest_static.py: reconstruct the full
 * lazy-chunk URL set from webpack's `__webpack_require__.u` maps and Vite's
 * `__vite__mapDeps`. Pure: js text + base URL in, absolute URLs out.
 */

export const originOf = (url: string): string => {
  const u = new URL(url);
  return `${u.protocol}//${u.host}`;
};

/** Walk back from a `}` index to its matching `{` and return the body. */
export const matchedBlock = (s: string, endBraceIdx: number): string => {
  let depth = 0;
  for (let j = endBraceIdx; j >= 0; j--) {
    const ch = s[j];
    if (ch === "}") depth++;
    else if (ch === "{") {
      depth--;
      if (depth === 0) return s.slice(j, endBraceIdx + 1);
    }
  }
  return "";
};

export interface ChunkMap {
  readonly publicPaths: string[];
  readonly ids: Record<string, string>;
}

/** Parse every `}[x]+".js"` id→hash map plus this file's publicPath hints. */
export const parseChunkMaps = (js: string): ChunkMap[] => {
  const maps: ChunkMap[] = [];
  const pubs = [...js.matchAll(/(?:\.p|publicPath)\s*=\s*"([^"]*)"/g)].map(
    (m) => m[1]!,
  );
  const re = /\}\[[A-Za-z_$][\w$]*\]\s*\+?\s*\)?\s*\+\s*"\.js"/g;
  for (const m of js.matchAll(re)) {
    const body = matchedBlock(js, m.index!);
    const pairs: Record<string, string> = {};
    for (const p of body.matchAll(/(\d+):"([0-9a-fA-F]{6,16})"/g)) {
      pairs[p[1]!] = p[2]!;
    }
    if (Object.keys(pairs).length > 0) maps.push({ publicPaths: pubs, ids: pairs });
  }
  // Vite style: __vite__mapDeps asset list
  for (const m of js.matchAll(/"((?:assets|js)\/[^"]+\.js)"/g)) {
    maps.push({ publicPaths: ["/"], ids: { __vite__: m[1]! } });
  }
  return maps;
};

/** Reconstruct absolute chunk URLs referenced by this file's manifest(s). */
export const chunkUrls = (base: string, js: string): string[] => {
  const origin = originOf(base);
  const out = new Set<string>();
  for (const { publicPaths, ids } of parseChunkMaps(js)) {
    const paths = publicPaths.length > 0 ? publicPaths : ["/assets/", "/"];
    for (const [cid, hash] of Object.entries(ids)) {
      if (cid === "__vite__") {
        for (const pp of paths) out.add(new URL(hash, `${origin}/`).href);
        continue;
      }
      for (const pp of paths) {
        if (pp.startsWith("http")) {
          const prefix = pp.endsWith("/") ? pp : `${pp}/`;
          out.add(`${prefix}${cid}.${hash}.js`);
          continue;
        }
        const prefix = pp.startsWith("/") ? pp : `/${pp}`;
        const withSlash = prefix.endsWith("/") ? prefix : `${prefix}/`;
        out.add(`${origin}${withSlash}${cid}.${hash}.js`);
      }
    }
  }
  return [...out];
};