/**
 * Webpack module graph (webcrack common-matchers discipline, narrow version):
 * locate the webpack runtime (`__webpack_require__`-shaped function), extract
 * the module container (array or object literal of factory functions), build
 * the id→factory map, and resolve `require(<id>)` edges into a dependency
 * graph. `__webpack_require__.s/e = <id>` and the first top-level call mark
 * the entry. Pure acorn AST — no execution, no LLM.
 */
import { parse } from "acorn";
import type * as ESTree from "estree";
import { createHash } from "node:crypto";

export interface WebpackGraphInput {
  readonly source: string;
  readonly sourceName: string;
}

export interface WebpackModule {
  readonly id: string;
  readonly isEntry: boolean;
  readonly bytes: number;
  /** ids this module require()s (missing ids = async chunk boundary). */
  readonly requires: string[];
  readonly missing: string[];
  /** high-signal surface markers inside the factory (endpoints/secrets-ish) */
  readonly endpoints: string[];
}

export interface WebpackGraphResult {
  readonly modules: WebpackModule[];
  readonly edges: { from: string; to: string }[];
  readonly entryIds: string[];
  readonly digest: string;
}

const requireCallRe = /__webpack_require__\(\s*(\d+)\s*\)/g;

const factoryEndpoints = (code: string): string[] =>
  [...new Set([
    ...[...code.matchAll(/["']((?:https?:)?\/[A-Za-z0-9_\-./%]{3,80})["']/g)].map((m) => m[1]!).filter((u) => /api|v\d|admin|user|auth|login|upload|export/i.test(u)),
  ])].slice(0, 12);

export const buildWebpackGraph = (input: WebpackGraphInput): WebpackGraphResult => {
  let ast: ESTree.Program;
  try {
    ast = parse(input.source, { ecmaVersion: "latest", sourceType: "script", ranges: true }) as unknown as ESTree.Program;
  } catch {
    try {
      ast = parse(input.source, { ecmaVersion: "latest", sourceType: "module", ranges: true }) as unknown as ESTree.Program;
    } catch { return { modules: [], edges: [], entryIds: [], digest: "" }; }
  }

  // 1) module container: array literal or object literal whose values are ALL
  //    functions, size >= 2 (webcrack modulesContainerMatcher approximation)
  const containers: { ids: string[]; factories: ESTree.FunctionExpression[] }[] = [];
  const walk = (node: ESTree.Node): void => {
    if (node.type === "ArrayExpression") {
      const els = node.elements.filter((e): e is ESTree.Expression => e !== null && e.type !== "SpreadElement");
      if (els.length >= 2 && els.every((e) => e.type === "FunctionExpression" || e.type === "ArrowFunctionExpression")) {
        containers.push({ ids: els.map((_, i) => String(i)), factories: els as ESTree.FunctionExpression[] });
      }
    } else if (node.type === "ObjectExpression") {
      const props = node.properties.filter((p): p is ESTree.Property => p.type === "Property" && !p.computed && (p.value.type === "FunctionExpression" || p.value.type === "ArrowFunctionExpression"));
      if (props.length >= 2) {
        containers.push({
          ids: props.map((p) => (p.key.type === "Literal" ? String(p.key.value) : (p.key as ESTree.Identifier).name)),
          factories: props.map((p) => p.value as ESTree.FunctionExpression),
        });
      }
    }
    for (const child of Object.values(node) as ESTree.Node[]) {
      if (child && typeof child === "object" && typeof (child as { type?: string }).type === "string") walk(child as ESTree.Node);
      else if (Array.isArray(child)) for (const c of child) if (c && typeof (c as { type?: string }).type === "string") walk(c as ESTree.Node);
    }
  };
  walk(ast);

  // 2) entry markers: __webpack_require__.s/.e = id, or first top-level call
  const entryIds = new Set<string>();
  const entryRe = /__webpack_require__[.][se]\s*=\s*(\d+)/g;
  for (const m of input.source.matchAll(entryRe)) entryIds.add(m[1]!);
  const firstCall = input.source.match(/__webpack_require__\(\s*(\d+)\s*\)/);
  if (firstCall) entryIds.add(firstCall[1]!);

  // 3) largest container = the module table
  const best = containers.sort((a, b) => b.ids.length - a.ids.length)[0];
  if (!best) return { modules: [], edges: [], entryIds: [...entryIds], digest: "" };

  const modules: WebpackModule[] = [];
  const edges: { from: string; to: string }[] = [];
  const idSet = new Set(best.ids);
  for (let i = 0; i < best.ids.length; i++) {
    const id = best.ids[i]!;
    const fn = best.factories[i]!;
    const code = input.source.slice(fn.range![0], fn.range![1]);
    const reqs = [...code.matchAll(requireCallRe)].map((m) => m[1]!);
    const missing = reqs.filter((r) => !idSet.has(r));
    modules.push({
      id,
      isEntry: entryIds.has(id),
      bytes: code.length,
      requires: [...new Set(reqs)],
      missing,
      endpoints: factoryEndpoints(code),
    });
    for (const r of new Set(reqs)) edges.push({ from: id, to: r });
  }

  const digest = createHash("sha256").update(input.source).digest("hex").slice(0, 16);
  return { modules, edges, entryIds: [...entryIds], digest };
};
