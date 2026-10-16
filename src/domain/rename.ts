/**
 * Deterministic identifier renaming (synchrony rename.ts discipline): minified
 * single/double-char identifiers get semantic prefixes (fn/arg/var/cls) +
 * words seeded by the SOURCE HASH — same input always renames to the same
 * output, so renames are regression-testable and evidence-stable.
 *
 * eslint-scope provides scope analysis (pure JS); acorn parses. No execution
 * of target code, zero LLM.
 */
import { parse } from "acorn";
import * as eslintScope from "eslint-scope";
import { createHash } from "node:crypto";

const WORDS = [
  "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliett",
  "kilo", "lima", "mike", "november", "oscar", "papa", "quebec", "romeo", "sierra", "tango",
  "uniform", "victor", "whiskey", "xray", "yankee", "zulu", "amber", "basalt", "cobalt", "dune",
  "ember", "flint", "gale", "harbor", "iris", "jade", "kelp", "lumen", "moss", "nectar",
  "onyx", "prism", "quartz", "reef", "slate", "thorn", "umbra", "vellum", "willow", "zephyr",
];

/** djb2 → 32-bit (synchrony sourceHash variant) */
const sourceHash = (s: string): number => {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0;
  return h >>> 0;
};

/** Mersenne Twister seeded from the source hash (synchrony discipline). */
class MT {
  private readonly m = 0x80000000;
  private readonly a = 0x9908b0df;
  private state: number[] = [];
  private idx = 0;
  constructor(seed: number) {
    this.state[0] = seed >>> 0;
    for (let i = 1; i < 624; i++) {
      const prev = this.state[i - 1]!;
      this.state[i] = (0x6c078965 * (prev ^ (prev >>> 30)) + i) >>> 0;
    }
    this.idx = 624;
  }
  public next(): number {
    if (this.idx >= 624) {
      for (let i = 0; i < 624; i++) {
        const y = (this.state[i]! & 0x80000000) | (this.state[(i + 1) % 624]! & 0x7fffffff);
        this.state[i] = this.state[(i + 397) % 624]! ^ (y >>> 1);
        if (y % 2 !== 0) this.state[i] = (this.state[i]! ^ this.a) >>> 0;
      }
      this.idx = 0;
    }
    const y = this.state[this.idx++]!;
    return ((y ^ (y >>> 11)) ^ ((y ^ (y >>> 7) & 0x9d2c5680)) ^ (y ^ (y >>> 15) & 0xefc60000)) >>> 0;
  }
  public int(maxExclusive: number): number {
    return this.next() % maxExclusive;
  }
}

const prefixFor = (kind: "fn" | "arg" | "var" | "cls" | "import" | "catch"): string => {
  switch (kind) {
    case "fn": return "fn";
    case "cls": return "cls";
    case "import": return "imp";
    case "arg": return "arg";
    case "catch": return "err";
    default: return "var";
  }
};

export interface RenameResult {
  readonly code: string;
  readonly renamed: number;
  readonly map: Record<string, string>;
}

const MINIFIED_RE = /^[a-zA-Z$_][a-zA-Z$_\d]{0,2}$/;

export const renameIdentifiers = (source: string): RenameResult => {
  let ast: import("estree").Program;
  try {
    ast = parse(source, { ecmaVersion: "latest", sourceType: "module", ranges: true }) as unknown as import("estree").Program;
  } catch {
    try {
      ast = parse(source, { ecmaVersion: "latest", sourceType: "script", ranges: true }) as unknown as import("estree").Program;
    } catch { return { code: source, renamed: 0, map: {} }; } // unparseable → unchanged
  }
  let scopes: eslintScope.ScopeManager;
  try {
    scopes = eslintScope.analyze(ast as never, { ecmaVersion: 2026, sourceType: "module", globalReturn: false } as never);
  } catch { return { code: source, renamed: 0, map: {} }; }

  const rng = new MT(sourceHash(source));
  const taken = new Set<string>([...source.matchAll(/[A-Za-z_$][\w$]*/g)].map((m) => m[0]));
  const perScope = new Map<unknown, Map<string, string>>();

  const newName = (prefix: string): string => {
    for (let tries = 0; tries < 64; tries++) {
      const w1 = WORDS[rng.int(WORDS.length)]!;
      const w2 = WORDS[rng.int(WORDS.length)]!;
      const cand = `${prefix}_${w1}${w2.charAt(0).toUpperCase()}${w2.slice(1)}`;
      if (!taken.has(cand)) { taken.add(cand); return cand; }
    }
    let i = 0;
    while (taken.has(`${prefix}_x${i}`)) i++;
    const c = `${prefix}_x${i}`;
    taken.add(c);
    return c;
  };

  const kindOf = (v: eslintScope.Variable): "fn" | "arg" | "var" | "cls" | "import" | "catch" => {
    const def = v.defs[0];
    if (!def) return "var";
    const node = def.parent as { type?: string } | undefined;
    const t = node?.type ?? "";
    if (t === "FunctionDeclaration") return "fn";
    if (t === "FunctionExpression" || t === "ArrowFunctionExpression") return "fn";
    if (t === "MethodDefinition") return "fn";
    if (t === "ImportSpecifier" || t === "ImportDefaultSpecifier" || t === "ImportNamespaceSpecifier") return "import";
    if (t === "ClassDeclaration" || t === "ClassExpression") return "cls";
    if (t === "CatchClause") return "catch";
    if (t === "VariableDeclarator") return "var";
    if (t === "Param") return "arg";
    return "var";
  };

  let renamedCount = 0;
  const map: Record<string, string> = {};
  // walk all scopes; rename minified variables scope-locally
  const visit = (scope: eslintScope.Scope): void => {
    for (const v of scope.variables) {
      if (v.name === "arguments" || !MINIFIED_RE.test(v.name)) continue;
      if (v.defs.length === 0 && scope.type !== "global") continue; // unresolved refs — leave
      const prefix = prefixFor(kindOf(v));
      const nm = newName(prefix);
      const slot = perScope.get(scope) ?? new Map<string, string>();
      slot.set(v.name, nm);
      perScope.set(scope, slot);
      map[`${scope.type}:${scope.block?.type}:${v.name}`] = nm;
      renamedCount++;
    }
    for (const c of scope.childScopes) visit(c);
  };
  visit(scopes.scopes[0]!);

  if (renamedCount === 0) return { code: source, renamed: 0, map: {} };

  // Apply renames by source-offset replacement: each reference resolved to
  // its declaring scope's slot map.
  const edits: { start: number; end: number; text: string }[] = [];
  // scopeThatDeclared: find the scope where the variable object lives.
  const scopeOfVariable = new Map<eslintScope.Variable, eslintScope.Scope>();
  const indexVars = (scope: eslintScope.Scope): void => {
    for (const v of scope.variables) scopeOfVariable.set(v, scope);
    for (const c of scope.childScopes) indexVars(c);
  };
  indexVars(scopes.scopes[0]!);

  const pushRefs = (scope: eslintScope.Scope): void => {
    for (const ref of scope.references) {
      const resolved = ref.resolved;
      if (!resolved) continue;
      // The renaming slot lives on the DECLARING scope, not the referencing one.
      const declScope = scopeOfVariable.get(resolved);
      const target = declScope !== undefined ? perScope.get(declScope) : undefined;
      if (target?.has(resolved.name)) {
        const id = ref.identifier;
        if (id.range) edits.push({ start: id.range[0], end: id.range[1], text: target.get(resolved.name)! });
      }
    }
    for (const c of scope.childScopes) pushRefs(c);
  };
  pushRefs(scopes.scopes[0]!);
  // Definition sites: rename the declared identifier nodes themselves.
  {
    const visit2 = (scope: eslintScope.Scope): void => {
      const slot = perScope.get(scope);
      if (slot) {
        for (const v of scope.variables) {
          const nm = slot.get(v.name);
          if (nm === undefined) continue;
          for (const d of v.defs) {
            const id = (d as { name?: { range?: [number, number] } }).name;
            if (id?.range) edits.push({ start: id.range[0], end: id.range[1], text: nm });
          }
        }
      }
      for (const c of scope.childScopes) visit2(c);
    };
    visit2(scopes.scopes[0]!);
  }

  // dedupe overlapping edits (same identifier hit twice)
  edits.sort((a, b) => a.start - b.start);
  let out = "";
  let cursor = 0;
  for (const e of edits) {
    if (e.start < cursor) continue;
    out += source.slice(cursor, e.start) + e.text;
    cursor = e.end;
  }
  out += source.slice(cursor);
  return { code: out, renamed: renamedCount, map };
};
