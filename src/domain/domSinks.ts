import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import type * as ESTree from "estree";
import { writeArtifact } from "../adapters/artifacts.js";
import { parseJavaScript, walkAst } from "./rename.js";

export interface DomSinkInput { readonly jsDir: string; readonly outputRoot: string; readonly maxFiles?: number }
export interface DomSinkResult {
  readonly scanned: number;
  /** Static candidates, never confirmed taint flow or exploitability. */
  readonly chains: {
    file: string; source: string; sink: string; excerpt: string; confidence: "candidate";
    evidence: { kind: "direct-expression" | "same-function-co-occurrence" | "unresolved-message-handler"; range: [number, number]; sourceRange?: [number, number]; limitation: string };
  }[];
  readonly sinks: { file: string; sink: string; count: number }[];
  readonly skipped: { file: string; reason: string }[];
  readonly artifacts: { path: string; bytes: number }[];
}
const property = (node: ESTree.MemberExpression): string | null => !node.computed && node.property.type === "Identifier" ? node.property.name : node.property.type === "Literal" && typeof node.property.value === "string" ? node.property.value : null;
const pathOf = (node: ESTree.Node): string => node.type === "Identifier" ? node.name : node.type === "MemberExpression" ? `${pathOf(node.object)}.${property(node) ?? "?"}` : "";
const SOURCES = new Set(["location.hash", "location.search", "location.href", "location.pathname", "document.referrer", "document.URL", "document.documentURI", "window.name"]);
const scanFile = (file: string, text: string): Pick<DomSinkResult, "chains" | "sinks" | "skipped"> => {
  const parsed = parseJavaScript(text);
  if (!parsed) return { chains: [], sinks: [], skipped: [{ file, reason: "parse-failed" }] };
  const parents = new Map<ESTree.Node, ESTree.Node | null>();
  const nodes: ESTree.Node[] = [];
  walkAst(parsed.ast, (n, p) => { nodes.push(n); parents.set(n, p); });
  const scopeOf = (n: ESTree.Node): ESTree.Node => {
    let p = parents.get(n);
    while (p) { if (/^(?:FunctionDeclaration|FunctionExpression|ArrowFunctionExpression)$/.test(p.type)) return p; p = parents.get(p); }
    return parsed.ast;
  };
  const sources = nodes.flatMap(n => {
    let name = pathOf(n).replace(/^window\.location\./, "location.");
    if (n.type === "NewExpression" && pathOf(n.callee) === "URLSearchParams") name = "URLSearchParams";
    return SOURCES.has(name) || name === "URLSearchParams" ? [{ node: n, name, scope: scopeOf(n) }] : [];
  });
  const chains: DomSinkResult["chains"] = [];
  const counts = new Map<string, number>();
  const within = (inner: ESTree.Node, outer: ESTree.Node): boolean => !!inner.range && !!outer.range && inner.range[0] >= outer.range[0] && inner.range[1] <= outer.range[1];
  for (const n of nodes) {
    let sink = "";
    let input: ESTree.Node | null = null;
    if (n.type === "AssignmentExpression" && n.left.type === "MemberExpression") {
      const prop = property(n.left);
      if (["innerHTML", "outerHTML", "srcdoc"].includes(prop ?? "")) { sink = prop!; input = n.right; }
    } else if (n.type === "CallExpression" || n.type === "NewExpression") {
      const name = pathOf(n.callee);
      const tail = name.split(".").pop();
      if (name === "eval" || name === "Function" || name === "document.write" || name === "document.writeln") { sink = name; input = n.arguments[0] ?? null; }
      else if (tail === "insertAdjacentHTML") { sink = "insertAdjacentHTML"; input = n.arguments[1] ?? null; }
      else if (tail === "html" || tail === "attr") { sink = tail === "html" ? "html-call" : "attr-call"; input = n.arguments[tail === "attr" ? 1 : 0] ?? null; }
      else if (name === "setTimeout" || name === "setInterval") {
        const first = n.arguments[0];
        if (first?.type === "Literal" && typeof first.value === "string") { sink = `${name}-string`; input = first; }
      } else if (tail === "postMessage") { sink = "postMessage-call"; input = n.arguments[0] ?? null; }
      else if (tail === "addEventListener" && n.arguments[0]?.type === "Literal" && n.arguments[0].value === "message") {
        sink = "message-listener"; input = n.arguments[1] ?? null;
      }
    }
    if (!sink) continue;
    counts.set(sink, (counts.get(sink) ?? 0) + 1);
    const matches = sources.filter(s => s.scope === scopeOf(n) && (input ? within(s.node, input) : false));
    const candidates = matches.length ? matches : sources.filter(s => s.scope === scopeOf(n) && Math.abs(s.node.range![0] - n.range![0]) <= 600);
    for (const source of candidates) {
      chains.push({ file, source: source.name, sink, excerpt: text.slice(...n.range!).slice(0, 240), confidence: "candidate", evidence: {
        kind: matches.length ? "direct-expression" : "same-function-co-occurrence", range: n.range!, sourceRange: source.node.range!,
        limitation: matches.length ? "AST expression match only; receiver identity, sanitization and exploitability not established" : "No binding/dataflow proof; same-function co-occurrence only",
      } });
    }
    if (sink === "message-listener") chains.push({ file, source: "postMessage", sink, excerpt: text.slice(...n.range!).slice(0, 240), confidence: "candidate", evidence: { kind: "unresolved-message-handler", range: n.range!, limitation: "Origin validation and handler reachability not established; no missing-check conclusion" } });
  }
  return { chains, sinks: [...counts].map(([sink, count]) => ({ file, sink, count })), skipped: [] };
};
export const scanDomSinks = async (input: DomSinkInput): Promise<DomSinkResult> => {
  let names: string[];
  try { names = (await readdir(input.jsDir, { withFileTypes: true })).filter(e => e.isFile() && /\.m?js$/.test(e.name)).map(e => e.name).sort(); }
  catch (e) { if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e; names = []; }
  const chains: DomSinkResult["chains"] = [], sinks: DomSinkResult["sinks"] = [], skipped: DomSinkResult["skipped"] = [];
  let scanned = 0;
  const cap = Math.max(0, input.maxFiles ?? 300);
  for (const file of names.slice(0, cap)) {
    let text: string;
    try { text = await readFile(join(input.jsDir, file), "utf8"); } catch { skipped.push({ file, reason: "read-failed" }); continue; }
    scanned++;
    const result = scanFile(file, text);
    chains.push(...result.chains); sinks.push(...result.sinks); skipped.push(...result.skipped);
  }
  skipped.push(...names.slice(cap).map(file => ({ file, reason: "file-cap" })));
  const result = { scanned, chains, sinks, skipped };
  const artifact = await writeArtifact(input.outputRoot, "dom_sinks.json", JSON.stringify(result, null, 2));
  return { ...result, artifacts: [artifact] };
};
