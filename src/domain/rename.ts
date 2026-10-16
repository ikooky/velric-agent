import { parse } from "acorn";
import * as eslintScope from "eslint-scope";
import type * as ESTree from "estree";
import { createHash } from "node:crypto";

/** Parse classic scripts first: parsing a script as a module changes its public bindings. */
export const parseJavaScript = (source: string, sourceType?: "script" | "module"):
  { ast: ESTree.Program; sourceType: "script" | "module" } | null => {
  for (const mode of sourceType ? [sourceType] : ["script", "module"] as const) {
    try {
      return { ast: parse(source, { ecmaVersion: "latest", sourceType: mode, ranges: true }) as unknown as ESTree.Program, sourceType: mode };
    } catch { /* Try the other grammar, never a partial AST. */ }
  }
  return null;
};

export const walkAst = (node: ESTree.Node, visit: (node: ESTree.Node, parent: ESTree.Node | null) => void, parent: ESTree.Node | null = null): void => {
  visit(node, parent);
  for (const value of Object.values(node)) {
    if (Array.isArray(value)) {
      for (const child of value) if (child && typeof child.type === "string") walkAst(child, visit, node);
    } else if (value && typeof value === "object" && typeof value.type === "string") walkAst(value, visit, node);
  }
};

export interface RenameResult {
  readonly code: string;
  readonly renamed: number;
  /** Scope and declaration offsets are part of each binding identity. */
  readonly map: Record<string, string>;
  readonly status: "transformed" | "unchanged" | "skipped";
  readonly reason?: string;
  readonly sourceType?: "script" | "module";
}

/** Rename only statically resolved local bindings; never execute input to establish equivalence. */
export const renameIdentifiers = (source: string, options: { sourceType?: "script" | "module" } = {}): RenameResult => {
  const parsed = parseJavaScript(source, options.sourceType);
  const unchanged = (reason?: string): RenameResult => ({ code: source, renamed: 0, map: {}, status: reason ? "skipped" : "unchanged", reason, sourceType: parsed?.sourceType });
  if (!parsed) return unchanged("parse-failed");
  const parents = new Map<ESTree.Node, ESTree.Node | null>();
  const protectedIds = new Set<number>();
  const expansions = new Map<number, { before: string; after: string }>();
  let dynamic = false;
  walkAst(parsed.ast, (node, parent) => {
    parents.set(node, parent);
    if (node.type === "WithStatement" || (node.type === "CallExpression" && node.callee.type === "Identifier" && node.callee.name === "eval")) dynamic = true;
    if (node.type === "Property" && node.shorthand && !node.computed) {
      const value = node.value.type === "AssignmentPattern" ? node.value.left : node.value;
      if (value.type === "Identifier" && value.range) expansions.set(value.range[0], { before: `${source.slice(...node.key.range!)}: `, after: "" });
    }
    if (node.type === "ImportSpecifier" && node.local.range && node.imported.range && node.local.range[0] === node.imported.range[0]) {
      expansions.set(node.local.range[0], { before: `${source.slice(...node.imported.range)} as `, after: "" });
    }
    if (node.type === "ExportSpecifier" && parent?.type === "ExportNamedDeclaration" && !parent.source && node.local.range && node.exported.range && node.local.range[0] === node.exported.range[0]) {
      expansions.set(node.local.range[0], { before: "", after: ` as ${source.slice(...node.exported.range)}` });
    }
    // Preserve observable Function/Class .name, including inferred names in defaults.
    if ((node.type === "VariableDeclarator" && node.init && /^(?:FunctionExpression|ArrowFunctionExpression|ClassExpression)$/.test(node.init.type)) ||
        (node.type === "AssignmentPattern" && /^(?:FunctionExpression|ArrowFunctionExpression|ClassExpression)$/.test(node.right.type))) {
      const id = node.type === "VariableDeclarator" ? node.id : node.left;
      walkAst(id, child => { if (child.type === "Identifier" && child.range) protectedIds.add(child.range[0]); });
    }
    // Keeping direct exported declarations avoids changing public names and .name.
    if ((node.type === "ExportNamedDeclaration" || node.type === "ExportDefaultDeclaration") && node.declaration) {
      const declaration = node.declaration;
      if (declaration.type === "VariableDeclaration") {
        for (const d of declaration.declarations) walkAst(d.id, child => { if (child.type === "Identifier" && child.range) protectedIds.add(child.range[0]); });
      } else if ((declaration.type === "FunctionDeclaration" || declaration.type === "ClassDeclaration") && declaration.id?.range) protectedIds.add(declaration.id.range[0]);
    }
  });
  if (dynamic) return unchanged("dynamic-scope-eval-or-with");
  let manager: eslintScope.ScopeManager;
  try { manager = eslintScope.analyze(parsed.ast as never, { ecmaVersion: 2026, sourceType: parsed.sourceType } as never); }
  catch { return unchanged("scope-analysis-failed"); }

  const edits = new Map<number, { start: number; end: number; text: string }>();
  const map: Record<string, string> = {};
  const taken = new Set<string>();
  walkAst(parsed.ast, n => { if (n.type === "Identifier") taken.add(n.name); });
  const seed = createHash("sha256").update(source).digest("hex").slice(0, 10);
  let count = 0;
  let conflict = false;
  const add = (id: ESTree.Identifier, name: string): void => {
    if (!id.range) { conflict = true; return; }
    const [start, end] = id.range;
    const expansion = expansions.get(start);
    const text = `${expansion?.before ?? ""}${name}${expansion?.after ?? ""}`;
    const prev = edits.get(start);
    if (prev && (prev.end !== end || prev.text !== text)) conflict = true;
    edits.set(start, { start, end, text });
  };
  for (const scope of manager.scopes) {
    for (const variable of scope.variables) {
      if (!/^[a-zA-Z$_][a-zA-Z$_\d]{0,2}$/.test(variable.name) || variable.name === "arguments" || variable.defs.length === 0) continue;
      if (parsed.sourceType === "script" && scope.type === "global") continue;
      // Class declarations have two linked scope variables at one source range.
      // Preserve both slots (and all function names) rather than edit either independently.
      if (variable.defs.some(d => d.type === "ClassName" || d.type === "FunctionName")) continue;
      if (variable.identifiers.some(id => id.range && protectedIds.has(id.range[0]))) continue;
      // eslint-scope can expose references that are not statically resolved. Do not edit those.
      if (variable.references.some(r => r.resolved !== variable)) continue;
      let name = `local_${seed}_${count}`;
      while (taken.has(name)) name += "_";
      taken.add(name);
      const start = variable.identifiers[0]?.range?.[0];
      if (start === undefined) continue;
      map[`${scope.type}:${scope.block.range?.[0]}:${start}:${variable.name}`] = name;
      count++;
      for (const id of variable.identifiers) add(id as ESTree.Identifier, name);
      for (const ref of variable.references) add(ref.identifier as ESTree.Identifier, name);
    }
  }
  if (conflict) return unchanged("conflicting-binding-edits");
  if (count === 0) return unchanged();
  let code = "";
  let cursor = 0;
  for (const edit of [...edits.values()].sort((a, b) => a.start - b.start)) {
    if (edit.start < cursor) return unchanged("overlapping-binding-edits");
    code += source.slice(cursor, edit.start) + edit.text;
    cursor = edit.end;
  }
  code += source.slice(cursor);
  const verified = parseJavaScript(code, parsed.sourceType);
  if (!verified) return unchanged("output-parse-failed");
  // Re-resolve generated bindings: every generated reference must resolve to its definition.
  try {
    const after = eslintScope.analyze(verified.ast as never, { ecmaVersion: 2026, sourceType: parsed.sourceType } as never);
    const names = new Set(Object.values(map));
    if (after.scopes.some(s => s.through.some(r => names.has(r.identifier.name)))) return unchanged("output-binding-verification-failed");
    for (const name of names) if (after.scopes.flatMap(s => s.variables).filter(v => v.name === name).length !== 1) return unchanged("output-binding-verification-failed");
  } catch { return unchanged("output-scope-analysis-failed"); }
  return { code, renamed: count, map, status: "transformed", sourceType: parsed.sourceType };
};
