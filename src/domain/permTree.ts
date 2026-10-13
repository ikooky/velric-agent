/**
 * Permission-tree / route-map reconstruction ported from build_perm_tree.py and
 * extract_route_map.py. Pure heuristics: JS text in, structured maps out.
 *
 * Typical consumer chain (enterprise admin SPAs):
 *   role_permissions -> { permissions[], role_type }
 *   permissions/all  -> tree[{ code, position, children }]
 *   userRouteAuth[code].url -> frontend route path
 */

export interface RouteMapEntry {
  readonly name: string;
  readonly link: string;
}

export interface UserRouteAuthEntry {
  readonly code: string;
  readonly url: string;
  readonly control: string[];
}

export interface PermTreeNode {
  readonly code: string;
  readonly position: string;
  readonly name?: string;
  readonly children?: PermTreeNode[];
}
export const extractRouteMap = (
  files: ReadonlyArray<{ path: string; text: string }>,
): { routeMap: Record<string, RouteMapEntry>; source: string | null } => {
  const pat = /([A-Z_][A-Z0-9_]*):\{name:"([^"]*)",link:"([^"]+)"/g;
  let best: Record<string, RouteMapEntry> = {};
  let source: string | null = null;
  for (const f of files) {
    const hits = [...f.text.matchAll(pat)];
    if (hits.length > Object.keys(best).length) {
      best = {};
      for (const h of hits) best[h[1]!] = { name: h[2]!, link: h[3]! };
      source = f.path;
    }
  }
  return { routeMap: best, source };
};

/** Parse `x=o.KEY` webpack aliases appearing before userRouteAuth. */
const parseAliases = (chunk: string): Record<string, string> => {
  const aliases: Record<string, string> = {};
  for (const m of chunk.slice(0, 8000).matchAll(/([a-zA-Z_$][\w$]*)=o\.([A-Z_0-9]+)\b/g)) {
    aliases[m[1]!] = m[2]!;
  }
  return aliases;
};

const resolveRef = (
  token: string,
  aliases: Record<string, string>,
  routeMap: Record<string, RouteMapEntry>,
): string => {
  const trimmed = token.trim();
  if (trimmed.startsWith('"')) {
    try {
      return JSON.parse(trimmed) as string;
    } catch {
      return trimmed.replace(/^"|"$/g, "");
    }
  }
  if (trimmed in aliases) {
    return routeMap[aliases[trimmed]!]?.link ?? aliases[trimmed]!;
  }
  return trimmed;
};

const findRouteAuthBody = (text: string): string | null => {
  const strict = text.match(/userRouteAuth=(\{MONITOR:.*?\})\}\),/s);
  if (strict) return strict[1]!;
  const loose = text.search(/userRouteAuth=\{MONITOR:/);
  if (loose < 0) {
    const alt = text.search(/userRouteAuth=\{[A-Z_0-9]+:\{url:/);
    if (alt < 0) return null;
    const body = text.slice(alt).replace(/^userRouteAuth=/, "");
    const end = body.lastIndexOf("}");
    return end > 0 ? body.slice(0, end + 1) : body;
  }
  const body = text.slice(loose).replace(/^userRouteAuth=/, "");
  const end = body.lastIndexOf("}");
  return end > 0 ? body.slice(0, end + 1) : body;
};

/** Parse the userRouteAuth object into code→{url,control}. */
export const parseUserRouteAuth = (
  text: string,
  routeMap: Record<string, RouteMapEntry>,
): Record<string, UserRouteAuthEntry> => {
  const objSrc = findRouteAuthBody(text);
  if (objSrc === null) return {};
  const authIdx = text.indexOf("userRouteAuth");
  const aliases = parseAliases(text.slice(authIdx, authIdx + 35000));

  const entries: Record<string, UserRouteAuthEntry> = {};
  const re = /([A-Z_0-9]+):\{url:([^,}]+)(?:,control:(\[.*?\]|[^,}]+))?\}/g;
  for (const m of objSrc.matchAll(re)) {
    const code = m[1]!;
    const url = resolveRef(m[2]!, aliases, routeMap);
    const controls: string[] = [];
    if (m[3]) {
      const raw = m[3].trim();
      const vars = raw.startsWith("[")
        ? [...raw.matchAll(/([A-Za-z_$][\w$]*)/g)].map((x) => x[1]!)
        : [raw];
      for (const v of vars) controls.push(aliases[v] ?? v);
    }
    entries[code] = { code, url, control: controls };
  }
  return entries;
};

export interface PermTreeHeuristics {
  readonly roots: readonly string[];
  readonly prefixParent: Readonly<Record<string, string>>;
  readonly extraParent: Readonly<Record<string, string>>;
}

const parentOf = (
  code: string,
  h: PermTreeHeuristics,
): string | null => {
  if (code in h.extraParent) return h.extraParent[code]!;
  if (h.roots.includes(code)) return null;
  for (const [pref, par] of Object.entries(h.prefixParent)) {
    if (code.startsWith(pref)) return par;
  }
  return null;
};

/** Build a permissive permission tree from parsed auth entries. */
export const buildPermTree = (
  entries: Record<string, UserRouteAuthEntry>,
  h: PermTreeHeuristics,
): PermTreeNode[] => {
  const childrenOf: Record<string, string[]> = {};
  for (const code of Object.keys(entries)) {
    const p = parentOf(code, h);
    if (p) (childrenOf[p] ??= []).push(code);
  }
  const makeNode = (code: string): PermTreeNode => {
    const kids = (childrenOf[code] ?? []).slice().sort();
    if (kids.length === 0) {
      return {
        code,
        position: h.roots.includes(code) ? "top" : "left",
        name: code,
      };
    }
    return {
      code,
      position: h.roots.includes(code) ? "top" : "left",
      name: code,
      children: kids.map(makeNode),
    };
  };
  const tree: PermTreeNode[] = h.roots
    .filter((r) => r in entries || (childrenOf[r]?.length ?? 0) > 0)
    .map(makeNode);
  const orphans = Object.keys(entries)
    .filter((c) => parentOf(c, h) === null && !h.roots.includes(c))
    .sort();
  for (const code of orphans) tree.push(makeNode(code));
  return tree;
};

/** Flatten a permission tree to its code list. */
export const flatCodes = (nodes: readonly PermTreeNode[]): string[] => {
  const out: string[] = [];
  for (const n of nodes) {
    out.push(n.code);
    if (n.children) out.push(...flatCodes(n.children));
  }
  return out;
};

/** Default heuristics matching the reference script's enterprise-admin tuning. */
export const DEFAULT_PERM_HEURISTICS: PermTreeHeuristics = {
  roots: [
    "MONITOR",
    "THREAT",
    "ASSETS_RISK",
    "INVESTIGATION",
    "MANAGEMENT",
    "AGENT_EVIDENCE",
    "MDR",
    "PLATFORM",
  ],
  prefixParent: {
    "MONITOR_": "MONITOR",
    "THREAT_": "THREAT",
    "ASSETS_RISK_": "ASSETS_RISK",
    "INVESTIGATION_": "INVESTIGATION",
    "MANAGEMENT_": "MANAGEMENT",
    "MDR_": "MDR",
    "PLATFORM_": "PLATFORM",
    "CUSTOM_": "PLATFORM",
    "FALSE_": "PLATFORM",
  },
  extraParent: {
    LINKAGE_DISPOSAL: "MANAGEMENT",
    ASSETS_RISK_API: "ASSETS_RISK",
    ASSETS_RISK_WEAK_PWD: "ASSETS_RISK",
  },
};