import { readFile, readdir } from "node:fs/promises";
import * as eslintScope from "eslint-scope";
import type * as ESTree from "estree";
import { join } from "node:path";
import { writeArtifact } from "../adapters/artifacts.js";
import { parseJavaScript, walkAst } from "./rename.js";

export interface DeobfInput {
  readonly jsDir: string;
  readonly outputRoot: string;
  readonly maxFiles?: number;
  readonly maxFileBytes?: number;
}
export interface DeobfResult {
  readonly files: number;
  readonly processed: number;
  readonly skipped: { file: string; reason: string }[];
  readonly restored: { file: string; stringsRestored: number; switchSimplified: boolean }[];
  readonly artifacts: { path: string; bytes: number }[];
}
interface TransformResult {
  code: string;
  stringsRestored: number;
  switchSimplified: boolean;
  reason?: string;
}
type Fn = ESTree.FunctionDeclaration | ESTree.FunctionExpression | ESTree.ArrowFunctionExpression;
const isFn = (node: ESTree.Node): node is Fn => /^(?:FunctionDeclaration|FunctionExpression|ArrowFunctionExpression)$/.test(node.type);
const number = (node: ESTree.Node | undefined): number | null => node?.type === "Literal" && typeof node.value === "number" && Number.isSafeInteger(node.value) ? node.value : null;

/** Restricted, binding-aware transforms. Unknown mutability/control flow is not executed or guessed. */
export const deobfuscateSource = (source: string): TransformResult => {
  const unchanged = (reason?: string): TransformResult => ({ code: source, stringsRestored: 0, switchSimplified: false, reason });
  const parsed = parseJavaScript(source);
  if (!parsed) return unchanged("parse-failed");
  const parents = new Map<ESTree.Node, ESTree.Node | null>();
  const nodes: ESTree.Node[] = [];
  let dynamic = false;
  walkAst(parsed.ast, (node, parent) => {
    nodes.push(node); parents.set(node, parent);
    if (node.type === "WithStatement" || (node.type === "CallExpression" && node.callee.type === "Identifier" && node.callee.name === "eval")) dynamic = true;
  });
  if (dynamic) return unchanged("dynamic-scope");
  let manager: eslintScope.ScopeManager;
  try { manager = eslintScope.analyze(parsed.ast as never, { ecmaVersion: 2026, sourceType: parsed.sourceType } as never); }
  catch { return unchanged("scope-analysis-failed"); }
  const bindings = new Map<number, eslintScope.Variable>();
  for (const scope of manager.scopes) for (const v of scope.variables) {
    for (const id of v.identifiers) if (id.range) bindings.set(id.range[0], v);
    for (const ref of v.references) if (ref.resolved && ref.identifier.range) bindings.set(ref.identifier.range[0], ref.resolved);
  }
  const binding = (n: ESTree.Node | null | undefined): eslintScope.Variable | undefined => n?.type === "Identifier" && n.range ? bindings.get(n.range[0]) : undefined;
  const contains = (a: ESTree.Node, b: ESTree.Node): boolean => !!a.range && !!b.range && a.range[0] <= b.range[0] && a.range[1] >= b.range[1];
  const nearestFn = (node: ESTree.Node): Fn | null => {
    let p = parents.get(node); while (p) { if (isFn(p)) return p; p = parents.get(p); } return null;
  };
  const isRead = (member: ESTree.MemberExpression): boolean => {
    let node: ESTree.Node = member;
    let p = parents.get(node);
    while (p && !isFn(p)) {
      if ((p.type === "AssignmentExpression" && contains(p.left, node)) || (p.type === "UpdateExpression") || (p.type === "UnaryExpression" && p.operator === "delete") ||
          ((p.type === "ForInStatement" || p.type === "ForOfStatement") && contains(p.left, node))) return false;
      if (/Statement$/.test(p.type)) break;
      node = p; p = parents.get(p);
    }
    return true;
  };
  // Prove the declaration executes before the expression in the same sequential
  // block, not merely earlier in the source (switch cases/closures can skip it).
  const afterDeclaration = (node: ESTree.Node, decl: ESTree.VariableDeclarator): boolean => {
    const statement = parents.get(decl);
    const block = statement && parents.get(statement);
    if (statement?.type !== "VariableDeclaration" || (block?.type !== "BlockStatement" && block?.type !== "Program")) return false;
    if (nearestFn(node) !== nearestFn(decl)) return false;
    let top: ESTree.Node = node;
    while (parents.get(top) && parents.get(top) !== block) top = parents.get(top)!;
    return parents.get(top) === block && block.body.indexOf(top as ESTree.Statement) > block.body.indexOf(statement);
  };
  const edits: { start: number; end: number; text: string; kind: "string" | "switch" }[] = [];
  const add = (node: ESTree.Node, text: string, kind: "string" | "switch"): void => { if (node.range) edits.push({ start: node.range[0], end: node.range[1], text, kind }); };
  type ArrayInfo = { declaration: ESTree.VariableDeclarator; variable: eslintScope.Variable; values: string[] };
  const arrays: ArrayInfo[] = [];
  for (const node of nodes) {
    if (node.type !== "VariableDeclarator" || node.id.type !== "Identifier" || node.init?.type !== "ArrayExpression") continue;
    const parent = parents.get(node);
    const variable = binding(node.id);
    if (parent?.type !== "VariableDeclaration" || parent.kind !== "const" || !variable || node.init.elements.length === 0) continue;
    if (!node.init.elements.every(e => e?.type === "Literal" && typeof e.value === "string")) continue;
    if (variable.references.some(r => r.isWrite() && r.identifier !== node.id)) continue;
    // The array never escapes. Every use is an indexed read, no aliases,
    // methods, writes, destructuring targets or arguments to unknown functions.
    if (variable.references.some(ref => {
      if (ref.identifier === node.id || (ref.identifier.range?.[0] === node.id.range?.[0])) return false;
      const p = parents.get(ref.identifier as ESTree.Node);
      return p?.type !== "MemberExpression" || p.object !== ref.identifier || !p.computed || !isRead(p);
    })) continue;
    arrays.push({ declaration: node, variable, values: node.init.elements.map(e => (e as ESTree.Literal).value as string) });
  }
  for (const arr of arrays) {
    for (const ref of arr.variable.references) {
      const member = parents.get(ref.identifier as ESTree.Node);
      if (member?.type !== "MemberExpression" || member.object !== ref.identifier) continue;
      const index = number(member.property);
      if (index !== null && index >= 0 && index < arr.values.length && afterDeclaration(member, arr.declaration)) add(member, JSON.stringify(arr.values[index]), "string");
    }
    for (const node of nodes) {
      if (node.type !== "FunctionDeclaration" || !node.id || node.params.length !== 1 || node.params[0]?.type !== "Identifier" || node.body.body.length !== 1) continue;
      const ret = node.body.body[0];
      if (ret?.type !== "ReturnStatement" || ret.argument?.type !== "MemberExpression" || !ret.argument.computed || binding(ret.argument.object) !== arr.variable) continue;
      const parameter = binding(node.params[0]);
      let offset = 0;
      const prop = ret.argument.property;
      if (binding(prop) !== parameter) {
        if (prop.type !== "BinaryExpression" || prop.operator !== "-" || binding(prop.left) !== parameter || number(prop.right) === null) continue;
        offset = number(prop.right)!;
      }
      const decoder = binding(node.id);
      if (!decoder || decoder.references.some(r => r.isWrite())) continue;
      // No spread/default/extra arguments: dropping an argument could drop an effect.
      for (const ref of decoder.references) {
        const call = parents.get(ref.identifier as ESTree.Node);
        if (call?.type !== "CallExpression" || call.callee !== ref.identifier || call.arguments.length !== 1 || call.optional || !afterDeclaration(call, arr.declaration)) continue;
        const n = number(call.arguments[0]);
        if (n !== null && n - offset >= 0 && n - offset < arr.values.length) add(call, JSON.stringify(arr.values[n - offset]), "string");
      }
    }
  }
  for (const node of nodes) {
    if (node.type !== "WhileStatement" || node.test.type !== "Literal" || node.test.value !== true || node.body.type !== "BlockStatement" || node.body.body.length !== 2) continue;
    const [sw, exit] = node.body.body;
    if (sw?.type !== "SwitchStatement" || exit?.type !== "BreakStatement" || exit.label || sw.discriminant.type !== "MemberExpression" || !sw.discriminant.computed) continue;
    const arr = arrays.find(a => binding(sw.discriminant.type === "MemberExpression" ? sw.discriminant.object : null) === a.variable);
    const index = sw.discriminant.property;
    if (!arr || !afterDeclaration(node, arr.declaration) || index.type !== "UpdateExpression" || index.operator !== "++" || index.prefix || index.argument.type !== "Identifier") continue;
    const counter = binding(index.argument);
    const counterDecl = counter?.defs[0]?.node;
    if (counterDecl?.type !== "VariableDeclarator" || number(counterDecl.init ?? undefined) !== 0 || !afterDeclaration(node, counterDecl as ESTree.VariableDeclarator)) continue;
    if (counter!.references.some(r => r.identifier.range?.[0] !== counterDecl.id.range?.[0] && r.identifier.range?.[0] !== index.argument.range?.[0])) continue;
    const cases = new Map<string, string>();
    let safe = true;
    for (const c of sw.cases) {
      if (c.test?.type !== "Literal" || typeof c.test.value !== "string" || cases.has(c.test.value)) { safe = false; break; }
      const last = c.consequent[c.consequent.length - 1];
      if (last?.type !== "ContinueStatement" || last.label || !c.consequent.slice(0, -1).every(s => s.type === "ExpressionStatement" || s.type === "EmptyStatement")) { safe = false; break; }
      let dependsOnDispatcher = false;
      for (const statement of c.consequent.slice(0, -1)) walkAst(statement, n => { if (binding(n) === counter || binding(n) === arr.variable) dependsOnDispatcher = true; });
      if (dependsOnDispatcher) { safe = false; break; }
      cases.set(c.test.value, c.consequent.slice(0, -1).map(s => source.slice(...s.range!)).join("\n"));
    }
    if (!safe || !arr.values.every(value => cases.has(value))) continue;
    add(node, `{\n${arr.values.map(value => cases.get(value)).join("\n")}\n}`, "switch");
  }
  // Prefer a dispatcher edit over literal reads contained in the replaced loop.
  const selected = edits.filter(e => !edits.some(outer => outer.kind === "switch" && outer !== e && outer.start <= e.start && outer.end >= e.end));
  selected.sort((a, b) => a.start - b.start);
  let cursor = 0;
  let code = "";
  for (const edit of selected) {
    if (edit.start < cursor) return unchanged("overlapping-edits");
    code += source.slice(cursor, edit.start) + edit.text; cursor = edit.end;
  }
  code += source.slice(cursor);
  if (!parseJavaScript(code, parsed.sourceType)) return unchanged("output-parse-failed");
  return { code, stringsRestored: selected.filter(e => e.kind === "string").length, switchSimplified: selected.some(e => e.kind === "switch") };
};

export const deobfuscateCorpus = async (input: DeobfInput): Promise<DeobfResult> => {
  let names: string[];
  try { names = (await readdir(input.jsDir, { withFileTypes: true })).filter(e => e.isFile() && /\.m?js$/.test(e.name)).map(e => e.name).sort(); }
  catch (e) { if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e; names = []; }
  const restored: DeobfResult["restored"] = [];
  const skipped: DeobfResult["skipped"] = [];
  const artifacts: DeobfResult["artifacts"] = [];
  let processed = 0;
  const cap = Math.max(0, input.maxFiles ?? 200);
  for (const name of names.slice(0, cap)) {
    let source: string;
    try { source = await readFile(join(input.jsDir, name), "utf8"); }
    catch { skipped.push({ file: name, reason: "read-failed" }); continue; }
    if (Buffer.byteLength(source) > (input.maxFileBytes ?? 8 * 1024 * 1024)) { skipped.push({ file: name, reason: "byte-cap" }); continue; }
    const result = deobfuscateSource(source);
    if (result.reason) { skipped.push({ file: name, reason: result.reason }); continue; }
    processed++;
    if (result.code === source) continue;
    artifacts.push(await writeArtifact(input.outputRoot, `js-deobf/${name}`, result.code));
    restored.push({ file: name, stringsRestored: result.stringsRestored, switchSimplified: result.switchSimplified });
  }
  skipped.push(...names.slice(cap).map(file => ({ file, reason: "file-cap" })));
  artifacts.push(await writeArtifact(input.outputRoot, "deobf_summary.json", JSON.stringify({ files: names.length, processed, skipped, restored }, null, 2)));
  return { files: names.length, processed, skipped, restored, artifacts };
};
