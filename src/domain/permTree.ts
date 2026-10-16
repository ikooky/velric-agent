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
  /** D05 provenance: parsed heuristics are candidates, never confirmed routes. */
  readonly confidence: "candidate";
  readonly basis: string;
  readonly evidence?: { source: string; excerpt: string; range: [number, number] };
}

export interface PermTreeNode {
  readonly code: string;
  readonly position: string;
  readonly name?: string;
  readonly children?: PermTreeNode[];
  /** D05 provenance: every node states why it is in the tree. */
  readonly confidence?: "candidate";
  readonly basis?: string;
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
  // Brace-balanced extraction: walk from the opening brace after
  // `userRouteAuth=` and stop when depth returns to zero. A trailing
  // UNRELATED object after the literal must not be swallowed.
  const start = text.search(/userRouteAuth\s*=\s*\{/);
  if (start < 0) return null;
  const openAt = text.indexOf("{", start + "userRouteAuth".length);
  if (openAt < 0) return null;
  let depth = 0;
  let inStr: string | null = null;
  for (let i = openAt; i < text.length; i++) {
    const ch = text[i]!;
    if (inStr) {
      if (ch === "\\") { i++; continue; }
      if (ch === inStr) inStr = null;
      continue;
    }
    if (ch === '"' || ch === "'") { inStr = ch; continue; }
    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) return text.slice(openAt, i + 1);
    }
  }
  return null;
};

/** Parse the userRouteAuth object into code→{url,control}. */
export const parseUserRouteAuth = (
  text: string,
  routeMap: Record<string, RouteMapEntry>,
): Record<string, UserRouteAuthEntry> => {
  const start = text.search(/userRouteAuth\s*=\s*\{/);
  if (start < 0) return {};
  const objSrc = findRouteAuthBody(text);
  if (objSrc === null) return {};
  // Preceding aliases: `const x = o.HOME` binds BEFORE the object literal —
  // scan the window AHEAD of the literal (declaration precedes use, D05),
  // not after it.
  const aliases = parseAliases(text.slice(Math.max(0, start - 8000), start));

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
    const mStart = text.indexOf(m[0], Math.max(0, start));
    entries[code] = {
      code, url, control: controls,
      confidence: "candidate",
      basis: "regex-extracted userRouteAuth entry",
      evidence: {
        source: "userRouteAuth",
        excerpt: m[0].slice(0, 120),
        range: [mStart, mStart + m[0].length] as [number, number],
      },
    };
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
  // Caller-supplied extraParent can form cycles (A→B→A); makeNode must
  // never revisit a node or untrusted heuristics blow the stack.
  const makeNode = (code: string, seen: ReadonlySet<string> = new Set()): PermTreeNode => {
    const kids = (childrenOf[code] ?? []).slice().sort().filter((k) => !seen.has(k));
    const leaf: PermTreeNode = {
      code,
      position: h.roots.includes(code) ? "top" : "left",
      name: code,
    };
    if (kids.length === 0) return leaf;
    return { ...leaf, children: kids.map((k: string) => makeNode(k, new Set([...seen, code]))) };
  };
  const tree: PermTreeNode[] = h.roots
    .filter((r) => r in entries || (childrenOf[r]?.length ?? 0) > 0)
    .map((r: string) => makeNode(r));
  const orphans = Object.keys(entries)
    .filter((c) => parentOf(c, h) === null && !h.roots.includes(c))
    .sort();
  for (const code of orphans) tree.push(makeNode(code));
  // Cycle members and broken-parent entries (extraParent pointing at a
  // MISSING code, or A↔B cycles) are never silently dropped: everything
  // not reachable from roots/orphans is appended with its reason.
  const present = new Set(flatCodes(tree));
  for (const code of Object.keys(entries).sort()) {
    if (present.has(code)) continue;
    const parent = parentOf(code, h);
    tree.push({
      ...makeNode(code),
      confidence: "candidate",
      basis: parent ? `unreachable via parent ${parent} (cycle or missing intermediate)` : "unreachable entry",
    });
    present.add(code);
  }
  // Every node must state its provenance — roots and structural
  // children carry the generic basis when nothing more specific applies.
  const annotate = (nodes: PermTreeNode[]): PermTreeNode[] => nodes.map((n) => ({
    ...n,
    confidence: n.confidence ?? "candidate",
    basis: n.basis ?? "structural child of the permission tree",
    ...(n.children ? { children: annotate(n.children) } : {}),
  }));
  return annotate(tree);
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
/**
 * Generic RBAC fallback for corpora without userRouteAuth (RuoYi
 * hasPermi strings, vue-router role guards, permission: literals).
 * Extracts permission codes and route→roles pairs from plain JS text.
 */
export interface GenericRbac {
  readonly permissionCodes: string[];
  readonly routeRoles: { readonly route: string; readonly roles: string[] }[];
  readonly source: string | null;
}

export const extractGenericRbac = (
  files: ReadonlyArray<{ path: string; text: string }>,
): GenericRbac => {
  const codes = new Set<string>();
  const routeRoles: { route: string; roles: string[] }[] = [];
  let source: string | null = null;
  // permission strings: hasPermi('a:b:c'), hasRole('x'), permission: "a:b:c",
  // v-permission="'a:b:c'", plain "a:b:c" colon-triple literals
  const permRe =
    /(?:hasPermi|hasRole|checkPermi|v-hasPermi|v-permission|permission)[("'=:\s]+['"]([a-zA-Z0-9_:-]{3,80})['"]/g;
  const tripleRe = /["']([a-z][a-z0-9_]*:[a-z][a-z0-9_]*:[a-zA-Z0-9_:*]+)["']/g;
  const rolesRe =
    /(?:path|name|route)\s*[:=]\s*["']([^"']{1,60})["'][^}]{0,200}?roles\s*:\s*(\[[^\]]{0,200}\])/gs;
  for (const f of files) {
    let hit = false;
    for (const m of f.text.matchAll(permRe)) {
      codes.add(m[1]!);
      hit = true;
    }
    for (const m of f.text.matchAll(tripleRe)) {
      codes.add(m[1]!);
      hit = true;
    }
    for (const m of f.text.matchAll(rolesRe)) {
      let roles: string[] = [];
      try {
        roles = (JSON.parse(m[2]!.replace(/'/g, '"')) as unknown[])
          .filter((x): x is string => typeof x === "string")
          .slice(0, 10);
      } catch {
        roles = [...m[2]!.matchAll(/["']([^"']+)["']/g)].map((x) => x[1]!).slice(0, 10);
      }
      if (roles.length > 0) {
        routeRoles.push({ route: m[1]!, roles });
        hit = true;
      }
    }
    if (hit && source === null) source = f.path;
  }
  return {
    permissionCodes: [...codes].sort(),
    routeRoles,
    source,
  };
};

/** Build a permission tree from generic colon-style codes (RuoYi et al.): first segment is parent. */
export const buildGenericPermTree = (
  codes: readonly string[],
): PermTreeNode[] => {
  const childrenOf: Record<string, string[]> = {};
  const roots = new Set<string>();
  for (const c of codes) {
    const seg = c.split(":");
    if (seg.length < 2) {
      roots.add(c);
      continue;
    }
    const parent = seg[0]!;
    if (parent === c) continue;
    roots.add(parent);
    (childrenOf[parent] ??= []).push(c);
  }
  const makeNode = (code: string): PermTreeNode => ({
    code,
    position: roots.has(code) && !childrenOf[code] ? "left" : "top",
    name: code,
    ...(childrenOf[code] ? { children: childrenOf[code]!.slice().sort().map(makeNode) } : {}),
  });
  return [...roots].sort().map(makeNode);
};

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