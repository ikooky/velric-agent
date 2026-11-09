import { readFile, readdir } from "node:fs/promises";
import type * as ESTree from "estree";
import { join } from "node:path";
import { writeArtifact } from "../adapters/artifacts.js";
import { parseJavaScript, walkAst } from "./rename.js";

export interface VmAnalyzeInput {
  readonly jsDir: string;
  readonly outputRoot: string;
  readonly maxFiles?: number;
  readonly maxFileBytes?: number;
  readonly minInterpreterScore?: number;
}
export interface OpcodeInfo {
  readonly caseValue: string;
  readonly kind: string;
  readonly evidence: string;
  readonly writesState: string[];
  readonly branchTargets: string[];
}
export interface InterpreterLoop {
  readonly function: string;
  readonly dispatch: string;
  readonly decode: { readonly mask?: string; readonly shift?: string; readonly expression: string };
  readonly cases: number;
  readonly loopBodyStatements: number;
  readonly opcodes: OpcodeInfo[];
  readonly stateSlots: number;
  readonly score: number;
}
export interface VmAnalysis {
  readonly file: string;
  readonly bytes: number;
  readonly isVm: boolean;
  readonly score: number;
  readonly signals: string[];
  readonly reason?: string;
  readonly constantMaps: { name: string; value: number }[];
  readonly tableRefs: { table: string; refs: number; distinctIndexes: number }[];
  readonly interpreters: InterpreterLoop[];
}
export interface VmAnalyzeResult {
  readonly files: number;
  readonly scanned: number;
  readonly vmFiles: { file: string; score: number; interpreters: number; opcodes: number }[];
  readonly analyses: VmAnalysis[];
  readonly artifacts: { path: string; bytes: number }[];
}


const text = (source: string, node: ESTree.Node | null | undefined): string => {
  const r = node?.range;
  return r ? source.slice(r[0], r[1]) : "";
};

const classifyCase = (stmts: ESTree.Statement[], source: string, pcSlot?: string): { kind: string; evidence: string; writes: string[]; branches: string[] } => {
  const writes = new Set<string>();
  const branches = new Set<string>();
  let calls = 0, news = 0, regex = 0, dom = 0, memberWrites = 0, hasThrow = false, hasReturn = false;
  for (const stmt of stmts) walkAst(stmt, (n) => {
    const node = n as ESTree.Node;
    if (node.type === "AssignmentExpression" && node.left.type === "MemberExpression" && node.left.object.type === "Identifier" && node.left.computed) {
      const idx = node.left.property;
      const idxText = idx.type === "Literal" ? JSON.stringify(idx.value) : text(source, idx);
      writes.add(`${text(source, node.left.object)}[${idxText}]`);
      if (node.left.object.type === "Identifier") memberWrites++;
    }
    if (node.type === "CallExpression") calls++;
    if (node.type === "NewExpression") news++;
    if (node.type === "Literal" && node.value instanceof RegExp) regex++;
    if (node.type === "MemberExpression" && node.object.type === "Identifier" && /^(?:document|window|location|navigator)$/.test(node.object.name)) dom++;
    if (node.type === "ThrowStatement") hasThrow = true;
    // Program-counter writes: only writes to the dispatch slot count as
    // control flow; writes to other state slots are data flow.
    if (node.type === "AssignmentExpression" && node.left.type === "MemberExpression" && node.left.object.type === "Identifier" && pcSlot !== undefined && text(source, node.left.object) === pcSlot.split("[")[0]) {
      const t = text(source, node.left.property).replace(/["']/g, "");
      if (t === pcSlot.split("[")[1]?.replace("]", "")) {
        const rhs = node.right.type === "Literal" ? JSON.stringify(node.right.value) : text(source, node.right);
        branches.add(rhs);
      }
    }
  });
  for (const stmt of stmts) walkAst(stmt, (n) => { if (n.type === "ReturnStatement") hasReturn = true; });
  const evidence = stmts.map(s => text(source, s)).join(" ").slice(0, 160);
  if (hasReturn || hasThrow) return { kind: "RETURN", evidence, writes: [...writes], branches: [] };
  if (dom > 0) return { kind: "DOM", evidence, writes: [...writes], branches: [] };
  if (regex > 0) return { kind: "REGEX", evidence, writes: [...writes], branches: [...branches] };
  if (news > 0) return { kind: "ALLOC", evidence, writes: [...writes], branches: [...branches] };
  if (calls > 0) return { kind: "CALL", evidence, writes: [...writes], branches: [...branches] };
  // Pure data flow into state slots: STORE unless the ONLY write is the pc slot.
  const dataWrites = [...writes].filter(w => !branches.size);
  if (writes.size > 0 && dataWrites.length > 0) return { kind: "STORE", evidence, writes: [...writes], branches: [...branches] };
  if (branches.size > 0) return { kind: "BRANCH", evidence, writes: [...writes], branches: [...branches] };
  return { kind: "OTHER", evidence, writes: [...writes], branches: [] };
};

export const analyzeVmSource = (source: string, file: string, minScore: number): VmAnalysis => {
  const signals: string[] = [];
  const parsed = parseJavaScript(source);
  const base = { file, bytes: Buffer.byteLength(source) };
  if (!parsed) return { ...base, isVm: false, score: 0, signals: ["parse-failed"], constantMaps: [], tableRefs: [], interpreters: [], reason: "parse-failed" };
  let score = 0;
  // Signal: leading IIFE.
  const head = source.slice(0, 500);
  if (/^[!-(]\s*(?:async\s+)?function|(?:!|\()\s*=>/.test(head)) { score += 10; signals.push("iife-entry"); }
  // Signal: single-letter identifier density (minified VMs map constants to names).
  const idents = source.match(/\b[A-Za-z_$][A-Za-z0-9_$]*\b/g) ?? [];
  const short = idents.filter(w => w.length <= 2).length;
  if (idents.length > 500 && short / idents.length > 0.55) { score += 15; signals.push("short-identifier-density"); }
  // Signal: numeric constant prelude `var E=15,l=10,...`.
  const constantMaps: { name: string; value: number }[] = [];
  const prelude = source.slice(0, 3000);
  const decl = parsed.ast.body.find(s => s.type === "ExpressionStatement" && (s as ESTree.ExpressionStatement).expression.type === "CallExpression");
  for (const m of prelude.matchAll(/\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(\d{1,4})\b/g)) {
    if (constantMaps.length < 64 && m[1] !== undefined && m[2] !== undefined) constantMaps.push({ name: m[1], value: Number(m[2]) });
  }
  if (constantMaps.length >= 5) { score += 10; signals.push(`constant-prelude(${constantMaps.length})`); }
  // Signal: giant single line (minified bundle).
  const firstNewline = source.indexOf("\n");
  if (firstNewline === -1 || firstNewline > 100_000) { score += 5; signals.push("single-line"); }
  // Signal: state-array slots d[N] density.
  const stateSlots = new Map<string, number>();
  for (const m of source.matchAll(/\b([A-Za-z_$][\w$]*)\[(\d{1,3})\]/g)) { const k = m[1]; if (k === undefined) continue; stateSlots.set(k, (stateSlots.get(k) ?? 0) + 1); }
  const topState = [...stateSlots.entries()].sort((a, b) => b[1] - a[1])[0];
  if (topState && topState[1] >= 20) { score += 15; signals.push(`state-array(${topState[0]}, ${topState[1]} refs)`); }
  // Signal: constant table refs C[9][x] / C[x][y] pattern.
  const tableRefs = new Map<string, { refs: number; indexes: Set<string> }>();
  for (const m of source.matchAll(/\b([A-Za-z_$][\w$]*)\[(?:\d{1,4})\]\[(\d{1,4})\]/g)) {
    const name = m[1];
    if (name === undefined || m[2] === undefined) continue;
    const e = tableRefs.get(name) ?? { refs: 0, indexes: new Set<string>() };
    e.refs++; e.indexes.add(m[2]); tableRefs.set(name, e);
  }
  const topTables = [...tableRefs.entries()].filter(([, v]) => v.indexes.size >= 8).sort((a, b) => b[1].refs - a[1].refs).slice(0, 4)
    .map(([table, v]) => ({ table, refs: v.refs, distinctIndexes: v.indexes.size }));
  if (topTables.length > 0) { score += 15; signals.push(`table-refs(${topTables.map(t => t.table).join(",")})`); }
  void decl;
  // Core: interpreter loop — while(true|cond){ switch(dispatch) { case N: ... } }
  const parents = new Map<ESTree.Node, ESTree.Node | null>();
  walkAst(parsed.ast, (node, parent) => parents.set(node, parent));
  const interpreters: InterpreterLoop[] = [];
  for (const node of walkCollect(parsed.ast)) {
    if (node.type !== "WhileStatement" && node.type !== "ForStatement") continue;
    const loop = node as ESTree.WhileStatement | ESTree.ForStatement;
    const body = loop.body.type === "BlockStatement" ? (loop.body as ESTree.BlockStatement).body : [loop.body];
    const sw = body.find(s => s.type === "SwitchStatement") as ESTree.SwitchStatement | undefined;
    if (!sw || sw.cases.length < 5) continue;
    const disc = sw.discriminant;
    // Dispatch shape A: switch(d[pc++]) — member access directly.
    // Dispatch shape B: var op = d[pc++] & 31; switch(op) — opcode precomputed.
    let stateName: string | undefined;
    let idxExpr: string | undefined;
    const discText = text(source, disc);
    const dispatchMatch = discText.match(/^([A-Za-z_$][\w$]*)\[(.+)\]$/);
    if (dispatchMatch?.[1] && dispatchMatch[2] !== undefined) {
      stateName = dispatchMatch[1];
      idxExpr = dispatchMatch[2];
    } else if (disc.type === "Identifier") {
      // Find `discName = <member> [& mask]` assignment before the loop.
      const want = disc.name;
      outer: for (const n of walkCollect(parsed.ast)) {
        if (n.type !== "VariableDeclarator") continue;
        const dt = n as ESTree.VariableDeclarator;
        if (dt.id.type !== "Identifier" || dt.id.name !== want || !dt.init) continue;
        let init: ESTree.Expression = dt.init;
        // unwrap `& mask` bit-field decode
        if (init.type === "BinaryExpression" && init.operator === "&" && init.left.type === "MemberExpression") init = init.left;
        if (init.type !== "MemberExpression" || init.object.type !== "Identifier" || !init.computed) continue;
        const mt = text(source, init.object);
        stateName = mt;
        idxExpr = text(source, init.property);
        break outer;
      }
    }
    if (!stateName || idxExpr === undefined) continue;
    // decode: & 31 / >> 5 & 31 bit-field patterns
    let mask: string | undefined;
    let shift: string | undefined;
    if (/&\s*31\b/.test(source)) { mask = "&31"; score += 10; signals.push("bitfield-decode"); }
    if (/>>\s*5\s*&\s*31/.test(source)) { shift = ">>5&31"; }
    // enclosing function name
    let fnName = "(top)";
    let p: ESTree.Node | null = node;
    while (p) { if (/Function/.test(p.type)) { const id = (p as ESTree.FunctionDeclaration).id; if (id) fnName = id.name; break; } p = parents.get(p) ?? null; }
    const opcodes: OpcodeInfo[] = sw.cases.map(c => {
      const caseValue = c.test ? text(source, c.test) : "default";
    const cls = classifyCase(c.consequent as ESTree.Statement[], source, idxExpr !== undefined ? `${stateName}[${idxExpr.replace(/\+\+|\s/g, "")}]` : undefined);
      return { caseValue, kind: cls.kind, evidence: cls.evidence, writesState: cls.writes, branchTargets: cls.branches };
    });
    const slots = [...stateSlots.entries()].filter(([n]) => n === stateName)[0]?.[1] ?? 0;
    const loopScore = Math.min(40, sw.cases.length * 2 + (slots > 50 ? 10 : 0));
    interpreters.push({
      function: fnName, dispatch: discText,
      decode: { mask, shift, expression: idxExpr },
      cases: sw.cases.length, loopBodyStatements: body.length, opcodes,
      stateSlots: slots, score: loopScore,
    });
    score += loopScore;
  }
  if (interpreters.length > 0) signals.push(`interpreter-loops(${interpreters.length})`);
  const isVm = score >= minScore && interpreters.length > 0;
  return { ...base, isVm, score, signals, constantMaps, tableRefs: topTables, interpreters, reason: isVm ? undefined : interpreters.length === 0 ? "no-interpreter-loop" : "below-score" };
};

function* walkCollect(root: ESTree.Node): Generator<ESTree.Node> {
  yield root;
  for (const value of Object.values(root)) {
    if (Array.isArray(value)) { for (const child of value) if (child && typeof child.type === "string") yield* walkCollect(child as ESTree.Node); }
    else if (value && typeof value === "object" && typeof (value as ESTree.Node).type === "string") yield* walkCollect(value as ESTree.Node);
  }
}

export const analyzeVmCorpus = async (input: VmAnalyzeInput): Promise<VmAnalyzeResult> => {
  let names: string[];
  try { names = (await readdir(input.jsDir, { withFileTypes: true })).filter(e => e.isFile() && /\.m?js$/.test(e.name)).map(e => e.name).sort(); }
  catch (e) { if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e; names = []; }
  const cap = Math.max(0, input.maxFiles ?? 100);
  const minScore = input.minInterpreterScore ?? 45;
  const analyses: VmAnalysis[] = [];
  const artifacts: VmAnalyzeResult["artifacts"] = [];
  for (const name of names.slice(0, cap)) {
    let source: string;
    try { source = await readFile(join(input.jsDir, name), "utf8"); }
    catch { continue; }
    if (Buffer.byteLength(source) > (input.maxFileBytes ?? 12 * 1024 * 1024)) continue;
    analyses.push(analyzeVmSource(source, name, minScore));
  }
  const vmFiles = analyses.filter(a => a.isVm).map(a => ({ file: a.file, score: a.score, interpreters: a.interpreters.length, opcodes: a.interpreters.reduce((n, i) => n + i.cases, 0) }));
  artifacts.push(await writeArtifact(input.outputRoot, "vm_analysis.json", JSON.stringify({ files: analyses.length, vmFiles, analyses }, null, 2)));
  if (vmFiles.length > 0) {
    const lines: string[] = ["# VM interpreter analysis", "", `files scanned: ${analyses.length}, VM files: ${vmFiles.length}`, ""];
    for (const a of analyses.filter(x => x.isVm)) {
      lines.push(`## ${a.file} (score ${a.score})`, ...a.signals.map(s => `- signal: ${s}`), "");
      for (const interp of a.interpreters) {
        lines.push(`### interpreter \`${interp.function}\` dispatch=${interp.dispatch} decode=${interp.decode.mask ?? "-"}${interp.decode.shift ? ` ${interp.decode.shift}` : ""}`, `- ${interp.cases} opcodes, ${interp.stateSlots} state refs`, "");
        for (const op of interp.opcodes) lines.push(`- \`${op.caseValue}\` **${op.kind}** ${op.writesState.length ? `writes ${op.writesState.slice(0, 3).join(" ")}` : ""}${op.branchTargets.length ? ` → ${op.branchTargets.slice(0, 4).join(",")}` : ""}`, `  > ${op.evidence.slice(0, 140)}`);
        lines.push("");
      }
      if (a.constantMaps.length) lines.push(`constant prelude: ${a.constantMaps.map(m => `${m.name}=${m.value}`).slice(0, 24).join(" ")}`);
      if (a.tableRefs.length) lines.push(`constant tables: ${a.tableRefs.map(t => `${t.table}[?](${t.distinctIndexes} idx, ${t.refs} refs)`).join(", ")}`);
      lines.push("");
    }
    artifacts.push(await writeArtifact(input.outputRoot, "vm_report.md", lines.join("\n")));
  }
  return { files: names.length, scanned: analyses.length, vmFiles, analyses, artifacts };
};
