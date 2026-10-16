import { parse } from "acorn";
import * as eslintScope from "eslint-scope";

/** ESTree boundary: Acorn supports newer syntax than the installed ESTree types. */
export type JsNode = { type: string; start: number; end: number; range: [number, number]; [key: string]: any };
export interface JsAnalysis {
  ast: JsNode;
  sourceType: "script" | "module";
  parents: Map<JsNode, JsNode>;
  nodes: JsNode[];
  scopes: eslintScope.ScopeManager;
  bindings: Map<JsNode, eslintScope.Variable>;
}
export function walkJs(node: JsNode, visit: (node: JsNode, parent?: JsNode) => void, parent?: JsNode): void {
  visit(node, parent);
  for (const [key, child] of Object.entries(node)) {
    if (["loc", "range"].includes(key)) continue;
    if (Array.isArray(child)) for (const c of child) { if (c?.type) walkJs(c, visit, node); }
    else if (child?.type) walkJs(child, visit, node);
  }
}
export function analyzeJs(source: string, type?: "script" | "module"): JsAnalysis {
  let ast: JsNode;
  let sourceType = type ?? "script";
  try { ast = parse(source, { ecmaVersion: "latest", sourceType, ranges: true }) as unknown as JsNode; }
  catch (e) { if (type) throw e; sourceType = "module"; ast = parse(source, { ecmaVersion: "latest", sourceType, ranges: true }) as unknown as JsNode; }
  const parents = new Map<JsNode, JsNode>(); const nodes: JsNode[] = [];
  walkJs(ast, (n, p) => { nodes.push(n); if (p) parents.set(n, p); });
  const scopes = eslintScope.analyze(ast as never, { ecmaVersion: 2026, sourceType, ignoreEval: false } as never);
  const bindings = new Map<JsNode, eslintScope.Variable>();
  for (const s of scopes.scopes) {
    for (const v of s.variables) for (const id of v.identifiers) bindings.set(id as unknown as JsNode, v);
    for (const r of s.references) if (r.resolved) bindings.set(r.identifier as unknown as JsNode, r.resolved);
  }
  return { ast, sourceType, parents, nodes, scopes, bindings };
}
export interface JsEdit { start: number; end: number; text: string }
export function applyJsEdits(source: string, edits: JsEdit[], type?: "script" | "module"): string {
  const unique = new Map<string, JsEdit>();
  for (const e of edits) {
    const key = `${e.start}:${e.end}`; const previous = unique.get(key);
    if (previous && previous.text !== e.text) throw new Error("conflicting-binding-edits");
    unique.set(key, e);
  }
  let cursor = 0, out = "";
  for (const e of [...unique.values()].sort((a,b) => a.start-b.start || a.end-b.end)) {
    if (e.start < cursor || e.end < e.start) throw new Error("overlapping-ast-edits");
    out += source.slice(cursor,e.start)+e.text; cursor=e.end;
  }
  out += source.slice(cursor); analyzeJs(out, type); return out;
}
export function propertyName(n: JsNode | undefined): string | undefined {
  if (!n) return undefined;
  const key = n.type === "Property" || n.type === "MemberExpression" ? n.key ?? n.property : n;
  if (!key) return undefined;
  if (key.type === "Literal") return String(key.value);
  if (key.type === "Identifier" && !n.computed) return key.name;
  return undefined;
}
export function objectFields(n: JsNode | undefined): Map<string, JsNode> {
  const fields = new Map<string, JsNode>();
  if (n?.type !== "ObjectExpression") return fields;
  for (const p of n.properties) { const k = propertyName(p); if (p.type !== "Property" || p.kind !== "init" || k === undefined) return new Map(); fields.set(k, p.value); }
  return fields;
}
export function immutableInit(id: JsNode, a: JsAnalysis): JsNode | undefined {
  const v = a.bindings.get(id); if (!v || v.defs.length !== 1) return undefined;
  const d = v.defs[0] as any;
  if (d.type !== "Variable" || d.parent?.kind !== "const" || d.node.id.type !== "Identifier") return undefined;
  if (v.references.some(r => r.isWrite() && r.identifier !== d.name)) return undefined;
  return d.node.init;
}
/** Restricted evaluator. Never calls code, invokes getters or follows mutable bindings. */
export function staticValue(n: JsNode | undefined, a: JsAnalysis, env = new Map<unknown, unknown>(), seen = new Set<JsNode>()): unknown {
  if (!n || seen.has(n)) return undefined;
  const next = new Set([...seen,n]);
  const val = (c: JsNode) => staticValue(c,a,env,next);
  if (n.type === "Literal" && !n.regex && !n.bigint) return n.value;
  if (n.type === "Identifier") { const b=a.bindings.get(n); if (env.has(b)) return env.get(b); const init=immutableInit(n,a); return init ? val(init) : undefined; }
  if (n.type === "UnaryExpression") { const x=val(n.argument); if (x===undefined) return undefined; if(n.operator==='-') return -Number(x); if(n.operator==='+') return Number(x); if(n.operator==='!') return !x; }
  if (n.type === "BinaryExpression") {
    const x=val(n.left), y=val(n.right); if(x===undefined || y===undefined || typeof x==='object' || typeof y==='object') return undefined;
    switch(n.operator) { case '+': return typeof x==='string'||typeof y==='string' ? String(x)+String(y) : Number(x)+Number(y); case '-': return Number(x)-Number(y); case '*': return Number(x)*Number(y); }
  }
  if (n.type === "TemplateLiteral") { let result=''; for(let i=0;i<n.quasis.length;i++){ result+=n.quasis[i].value.cooked; if(i<n.expressions.length){const x=val(n.expressions[i]);if(x===undefined || typeof x==='object') return undefined;result+=String(x);} }return result; }
  if (n.type === "ArrayExpression") { const values=n.elements.map((c:JsNode|null)=>c ? val(c) : undefined); return values.every((c:unknown)=>c!==undefined) ? values : undefined; }
  if (n.type === "ObjectExpression") { const fields=objectFields(n); if(fields.size!==n.properties.length) return undefined; const out=Object.create(null); for(const [k,c] of fields){const x=val(c);if(x===undefined)return undefined;out[k]=x;}return out; }
  if (n.type === "MemberExpression") { const obj=val(n.object); const key=n.computed ? val(n.property) : propertyName(n); if(obj && typeof obj==='object' && (typeof key==='string'||typeof key==='number') && Object.hasOwn(obj,key))return (obj as any)[key]; }
  return undefined;
}
export function globalPath(n: JsNode | undefined, a: JsAnalysis): string | undefined {
  if (!n) return undefined;
  if (n.type==='Identifier' && !a.bindings.has(n)) return n.name;
  if(n.type==='MemberExpression'){const base=globalPath(n.object,a),key=propertyName(n);return base && key ? `${base}.${key}` : undefined;}
  return undefined;
}
