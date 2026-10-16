import * as eslintScope from "eslint-scope";
import type * as ESTree from "estree";
import { createHash } from "node:crypto";
import { parseJavaScript, walkAst } from "./rename.js";

export interface WebpackGraphInput { readonly source: string; readonly sourceName: string }
export interface WebpackModule {
  readonly id: string;
  readonly isEntry: boolean;
  readonly bytes: number;
  readonly requires: string[];
  /** Unresolved static ids, not proof of an asynchronous chunk. */
  readonly missing: string[];
  readonly endpoints: string[];
}
export interface WebpackGraphResult {
  readonly modules: WebpackModule[];
  readonly edges: { from: string; to: string }[];
  readonly entryIds: string[];
  readonly digest: string;
  readonly coverage: "partial" | "unsupported";
  readonly reasons: string[];
}
type Fn = ESTree.FunctionDeclaration | ESTree.FunctionExpression | ESTree.ArrowFunctionExpression;
const isFn = (n: ESTree.Node): n is Fn => /^(FunctionDeclaration|FunctionExpression|ArrowFunctionExpression)$/.test(n.type);
const staticId = (node: ESTree.Node | undefined): string | null => node?.type === "Literal" && (typeof node.value === "string" || typeof node.value === "number") ? String(node.value) : null;
const memberName = (m: ESTree.MemberExpression): string | null => !m.computed && m.property.type === "Identifier" ? m.property.name : staticId(m.property);

/** A module table is accepted only when a bound runtime invokes its indexed factory and passes itself. */
export const buildWebpackGraph = (input: WebpackGraphInput): WebpackGraphResult => {
  const empty = (reason: string): WebpackGraphResult => ({ modules: [], edges: [], entryIds: [], digest: "", coverage: "unsupported", reasons: [reason] });
  const parsed = parseJavaScript(input.source);
  if (!parsed) return empty("parse-failed");
  let manager: eslintScope.ScopeManager;
  try { manager = eslintScope.analyze(parsed.ast as never, { ecmaVersion: 2026, sourceType: parsed.sourceType } as never); }
  catch { return empty("scope-analysis-failed"); }
  const parents = new Map<ESTree.Node, ESTree.Node | null>();
  const nodes: ESTree.Node[] = [];
  walkAst(parsed.ast, (node, parent) => { nodes.push(node); parents.set(node, parent); });
  const bindings = new Map<number, eslintScope.Variable>();
  for (const scope of manager.scopes) {
    for (const v of scope.variables) {
      for (const id of v.identifiers) if (id.range) bindings.set(id.range[0], v);
      for (const ref of v.references) if (ref.resolved && ref.identifier.range) bindings.set(ref.identifier.range[0], ref.resolved);
    }
    for (const ref of scope.references) if (ref.resolved && ref.identifier.range) bindings.set(ref.identifier.range[0], ref.resolved);
  }
  const binding = (n: ESTree.Node | null | undefined): eslintScope.Variable | undefined => n?.type === "Identifier" && n.range ? bindings.get(n.range[0]) : undefined;
  const nearestFn = (node: ESTree.Node): Fn | null => {
    let p = parents.get(node);
    while (p) { if (isFn(p)) return p; p = parents.get(p); }
    return null;
  };
  const fnBinding = (fn: Fn): eslintScope.Variable | undefined => {
    if (fn.type === "FunctionDeclaration") return binding(fn.id);
    const p = parents.get(fn);
    return p?.type === "VariableDeclarator" && p.init === fn ? binding(p.id) : undefined;
  };
  const inside = (node: ESTree.Node, outer: ESTree.Node): boolean => !!node.range && !!outer.range && node.range[0] >= outer.range[0] && node.range[1] <= outer.range[1];
  type Table = { node: ESTree.Node; factories: { id: string; fn: Fn }[]; bindings: Set<eslintScope.Variable> };
  const tables: Table[] = [];
  for (const node of nodes) {
    const factories: Table["factories"] = [];
    if (node.type === "ArrayExpression") {
      let valid = true;
      node.elements.forEach((el, i) => {
        if (el === null) return; // Preserve sparse indices.
        if (!isFn(el)) valid = false;
        else factories.push({ id: String(i), fn: el });
      });
      if (!valid) continue;
    } else if (node.type === "ObjectExpression") {
      let valid = true;
      for (const p of node.properties) {
        if (p.type !== "Property" || p.computed || p.kind !== "init" || !isFn(p.value)) { valid = false; break; }
        const id = p.key.type === "Identifier" ? p.key.name : staticId(p.key);
        if (id === null || factories.some(f => f.id === id)) { valid = false; break; }
        factories.push({ id, fn: p.value });
      }
      if (!valid) continue;
    } else continue;
    if (factories.length === 0) continue;
    const tableBindings = new Set<eslintScope.Variable>();
    const parent = parents.get(node);
    if (parent?.type === "VariableDeclarator" && parent.init === node) {
      const v = binding(parent.id); if (v) tableBindings.add(v);
    }
    if (parent?.type === "CallExpression" && isFn(parent.callee)) {
      const index = parent.arguments.indexOf(node as ESTree.Expression);
      const v = binding(parent.callee.params[index]); if (v) tableBindings.add(v);
    }
    if (tableBindings.size) tables.push({ node, factories, bindings: tableBindings });
  }
  type Runtime = { table: Table; fn: Fn; variable: eslintScope.Variable; requireIndex: number };
  const runtimes: Runtime[] = [];
  for (const node of nodes) {
    if (node.type !== "CallExpression") continue;
    let lookup: ESTree.Node = node.callee;
    let argOffset = 0;
    if (lookup.type === "MemberExpression" && memberName(lookup) === "call") { lookup = lookup.object; argOffset = 1; }
    if (lookup.type !== "MemberExpression" || !lookup.computed) continue;
    const table = tables.find(t => { const b = binding(lookup.type === "MemberExpression" ? lookup.object : null); return !!b && t.bindings.has(b); });
    const fn = nearestFn(node);
    const variable = fn ? fnBinding(fn) : undefined;
    if (!table || !fn || !variable || table.factories.some(f => inside(fn, f.fn))) continue;
    const indexBinding = binding(lookup.property);
    // The factory selector must be the runtime's own id parameter.
    if (!indexBinding || !fn.params.some(p => binding(p) === indexBinding)) continue;
    const requireIndex = node.arguments.findIndex(arg => binding(arg) === variable) - argOffset;
    if (requireIndex < 0) continue;
    runtimes.push({ table, fn, variable, requireIndex });
  }
  const runtime = runtimes.sort((a, b) => b.table.factories.length - a.table.factories.length)[0];
  if (!runtime) return empty("no-supported-runtime-container-binding");
  const entries = new Set<string>();
  const isBootstrap = (node: ESTree.Node): boolean => !inside(node, runtime.fn) && !runtime.table.factories.some(f => inside(node, f.fn));
  for (const node of nodes) {
    if (!isBootstrap(node) || node.type !== "CallExpression" || binding(node.callee) !== runtime.variable) continue;
    let arg = node.arguments[0];
    if (arg?.type === "AssignmentExpression" && arg.operator === "=" && arg.left.type === "MemberExpression" && binding(arg.left.object) === runtime.variable && memberName(arg.left) === "s") arg = arg.right;
    const id = arg ? staticId(arg) : null;
    if (id !== null) entries.add(id);
  }
  const modules: WebpackModule[] = [];
  const edges: WebpackGraphResult["edges"] = [];
  const known = new Set(runtime.table.factories.map(f => f.id));
  const reasons = new Set(["static-runtime-subset-only", "missing-ids-are-unresolved-not-proven-async"]);
  for (const { id, fn } of runtime.table.factories) {
    const requireBinding = binding(fn.params[runtime.requireIndex]);
    const requires = new Set<string>();
    const endpoints = new Set<string>();
    walkAst(fn, node => {
      if (node.type === "Literal" && typeof node.value === "string" && /^(?:https?:\/\/|\/)/.test(node.value) && /api|v\d|admin|user|auth|login|upload|export/i.test(node.value)) endpoints.add(node.value);
      if (node.type !== "CallExpression") return;
      const calleeBinding = binding(node.callee);
      if (!calleeBinding || (calleeBinding !== requireBinding && calleeBinding !== runtime.variable)) return;
      const req = staticId(node.arguments[0]);
      if (req === null) reasons.add("dynamic-require-unresolved"); else requires.add(req);
    });
    const code = input.source.slice(...fn.range!);
    modules.push({ id, isEntry: entries.has(id), bytes: Buffer.byteLength(code), requires: [...requires], missing: [...requires].filter(r => !known.has(r)), endpoints: [...endpoints].slice(0, 12) });
    for (const to of requires) edges.push({ from: id, to });
  }
  if (runtimes.length > 1) reasons.add("multiple-runtimes-largest-supported-table-selected");
  return { modules, edges, entryIds: [...entries], digest: createHash("sha256").update(input.source).digest("hex").slice(0, 16), coverage: "partial", reasons: [...reasons] };
};
