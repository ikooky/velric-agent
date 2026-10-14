/**
 * Path/endpoint extraction logic
 * scripts (harvest_static.py). Pure functions: text in, sets out. No IO.
 */

/** Endpoint-ish hints: a path containing one of these segments is an API path. */
export const API_HINT =
  /(?:^|\/)(?:api|rest|service|services|gateway|graphql|v\d|web|admin|backend|open)(?:\/|$|\.)/i;

/** Static asset extensions that must never be treated as endpoints. */
export const ASSET_EXT =
  /\.(?:js|css|png|jpe?g|svg|gif|woff2?|ttf|ico|map|mp4|webp)(?:\?|$)/i;

export interface EndpointExtraction {
  readonly api: string[];
  readonly other: string[];
}

/** Extract quoted / concatenated / template path literals from a JS bundle. */
export const extractPathLiterals = (js: string): Set<string> => {
  const paths = new Set<string>();
  // '/...' "..." `...`
  for (const m of js.matchAll(/["'`](\/[A-Za-z0-9_\-./{}$:]+)["'`]/g)) {
    paths.add(m[1]!);
  }
  // concatenation heads: "/api/x/" + var
  for (const m of js.matchAll(/["'](\/[A-Za-z0-9_\-./]+\/)["']\s*\+/g)) {
    paths.add(m[1]!);
  }
  return paths;
};

/**
 * Split literals into API candidates and other paths, applying the api-recon
 * filters: drop assets, drop shallow non-API paths.
 */
export const classifyPaths = (paths: Iterable<string>): EndpointExtraction => {
  const api = new Set<string>();
  const other = new Set<string>();
  for (const p of paths) {
    if (ASSET_EXT.test(p)) continue;
    const slashes = (p.match(/\//g) ?? []).length;
    if (slashes < 2 && !API_HINT.test(p)) continue;
    (API_HINT.test(p) ? api : other).add(p);
  }
  return { api: [...api].sort(), other: [...other].sort() };
};

/** Extract frontend route paths from router-shaped literals. */
export const extractRoutes = (js: string): string[] => {
  const routes = new Set<string>();
  for (const key of ["path", "to", "redirect", "href"]) {
    const re = new RegExp(
      `${key}\\s*:\\s*["'](\\/[A-Za-z0-9_\\-/:]*)["']`,
      "g",
    );
    for (const m of js.matchAll(re)) {
      const p = m[1]!;
      if (!ASSET_EXT.test(p) && !API_HINT.test(p)) routes.add(p);
    }
  }
  return [...routes].sort();
};

/** Merge-named URL-ish strings found inside inline scripts / onclick handlers. */
