import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { writeArtifact } from "../adapters/artifacts.js";

export interface WasmAnalyzeInput { readonly file: string; readonly outputRoot: string; }
export interface WasmFunction { readonly index: number; readonly name: string; readonly params: string[]; readonly results: string[]; readonly kind: "import" | "local"; }
export interface WasmAnalysis {
  readonly file: string; readonly bytes: number; readonly valid: boolean; readonly reason?: string;
  readonly version: number;
  readonly sections: { id: number; name: string; size: number }[];
  readonly imports: WasmFunction[];
  readonly exports: { name: string; kind: string; index: number }[];
  readonly functions: number;
  readonly memories: { min: number; max?: number }[];
  readonly globals: number;
  readonly customSections: { name: string; size: number }[];
  readonly nameSection?: { functions: { index: number; name: string }[] };
  readonly codeHint: string[];
  readonly artifacts: { path: string; bytes: number }[];
}

const SEC = ["custom", "type", "import", "function", "table", "memory", "global", "export", "start", "element", "code", "data", "datacount"];
const KINDS = ["function", "table", "memory", "global"];
const VT: Record<number, string> = { 0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64", 0x7B: "v128", 0x70: "funcref", 0x6F: "externref" };

class WReader {
  pos = 0;
  readonly buf: Buffer;
  constructor(buf: Buffer) { this.buf = buf; }
  byte(): number { return this.buf.readUInt8(this.pos++); }
  u32(): number { // LEB128
    let result = 0, shift = 0;
    for (;;) {
      const b = this.byte();
      result |= (b & 0x7F) << shift;
      if ((b & 0x80) === 0) return result >>> 0;
      shift += 7;
      if (shift > 35) throw new Error("leb128-too-long");
    }
  }
  str(): string { const len = this.u32(); const s = this.buf.toString("utf8", this.pos, this.pos + len); this.pos += len; return s; }
  valType(): string { const b = this.byte(); return VT[b] ?? `vt(0x${b.toString(16)})`; }
}

export const analyzeWasm = async (input: WasmAnalyzeInput): Promise<WasmAnalysis> => {
  const buf = await readFile(input.file);
  const base = { file: basename(input.file), bytes: buf.length };
  const empty = (reason: string): WasmAnalysis => ({ ...base, valid: false, reason, version: 0, sections: [], imports: [], exports: [], functions: 0, memories: [], globals: 0, customSections: [], codeHint: [], artifacts: [] });
  if (buf.length < 8) return empty("too-short");
  if (buf.readUInt32BE(0) !== 0x0061736D) return empty("not-wasm-magic");
  const r = new WReader(buf);
  r.pos = 4;
  const version = buf.readUInt32LE(4); // fixed 4-byte little-endian, NOT LEB128
  r.pos = 8;
  const sections: WasmAnalysis["sections"] = [];
  const customSections: WasmAnalysis["customSections"] = [];
  let imports: WasmFunction[] = [];
  let exports: WasmAnalysis["exports"] = [];
  let functions = 0;
  const memories: WasmAnalysis["memories"] = [];
  let globals = 0;
  let nameSection: WasmAnalysis["nameSection"] | undefined;
  const codeHint: string[] = [];
  let typeForms: string[][] = [];
  let importFnCount = 0;
  while (r.pos < buf.length) {
    const id = r.byte();
    const size = r.u32();
    const start = r.pos;
    const end = Math.min(start + size, buf.length);
    sections.push({ id, name: SEC[id] ?? `sec(${id})`, size });
    if (id === 0) {
      const name = r.str();
      customSections.push({ name, size });
      if (name === "name") {
        // name section: subsections 1=func names
        try {
          while (r.pos < end) {
            const sub = r.byte(); const subSize = r.u32(); const subEnd = r.pos + subSize;
            if (sub === 1) {
              const count = r.u32();
              const fn: { index: number; name: string }[] = [];
              for (let i = 0; i < Math.min(count, 100000); i++) {
                const idx = r.u32(); const nm = r.str();
                fn.push({ index: idx, name: nm });
              }
              nameSection = { functions: fn };
            }
            r.pos = subEnd;
          }
        } catch { /* malformed name section — keep going */ }
      }
    } else if (id === 1) { // type
      const count = r.u32();
      for (let i = 0; i < Math.min(count, 200000) && r.pos < end; i++) {
        const form = r.byte(); // 0x60 functype
        if (form === 0x60) {
          const np = r.u32(); const params: string[] = [];
          for (let j = 0; j < np; j++) params.push(r.valType());
          const nr = r.u32(); const results: string[] = [];
          for (let j = 0; j < nr; j++) results.push(r.valType());
          typeForms.push([...params, "->", ...results]);
        } else { break; }
      }
    } else if (id === 2) { // import
      const count = r.u32();
      for (let i = 0; i < Math.min(count, 100000) && r.pos < end; i++) {
        const module = r.str(); const field = r.str();
        const kind = r.byte();
        if (kind === 0) {
          const typeIdx = r.u32();
          const form = typeForms[typeIdx] ?? [];
          imports.push({ index: importFnCount++, name: `${module}.${field}`, params: form.filter(x => x !== "->"), results: form.slice(form.indexOf("->") + 1), kind: "import" });
        } else if (kind === 2) { const flags = r.u32(); const min = r.u32(); let max: number | undefined; if (flags & 1) max = r.u32(); memories.push({ min, max }); }
        else if (kind === 1) { r.u32(); /* table */ }
        else if (kind === 3) { r.byte(); r.byte(); /* global */ }
      }
    } else if (id === 3) { // function
      functions = r.u32();
    } else if (id === 5) { // memory
      const count = r.u32();
      for (let i = 0; i < count && r.pos < end; i++) { const flags = r.u32(); const min = r.u32(); let max: number | undefined; if (flags & 1) max = r.u32(); memories.push({ min, max }); }
    } else if (id === 6) { // global
      try { const count = r.u32(); globals = Math.min(count, 1e6); } catch { /* count in vec */ }
    } else if (id === 7) { // export
      const count = r.u32();
      for (let i = 0; i < Math.min(count, 100000) && r.pos < end; i++) {
        const name = r.str(); const kind = r.byte(); const idx = r.u32();
        exports.push({ name, kind: KINDS[kind] ?? `kind(${kind})`, index: idx });
      }
    } else if (id === 10) { // code — size heuristic hints
      if (size > 0 && functions > 0) {
        const perFn = size / functions;
        if (perFn < 40) codeHint.push(`small bodies (~${Math.round(perFn)}B avg) — thin wrappers`);
        else if (perFn > 2000) codeHint.push(`large bodies (~${Math.round(perFn / 1024)}KB avg) — compiled from real source`);
      }
    }
    r.pos = end;
  }
  // Import surface tells what the module touches.
  const importMods = [...new Set(imports.map(i => i.name.split(".")[0] ?? ""))];
  if (importMods.includes("env")) codeHint.push("imports from env — syscall-like boundary (memory access / clocks / random)");
  if (importMods.some(m => /wasi/i.test(m))) codeHint.push("WASI imports — wasi-libc build");
  if (importMods.some(m => /emscripten/i.test(m))) codeHint.push("emscripten runtime");
  if (nameSection && nameSection.functions.length > 0) codeHint.push(`name section present (${nameSection.functions.length} names) — symbol recovery direct`);
  else codeHint.push("no name section — stripped, needs custom tooling");
  const artifacts: WasmAnalysis["artifacts"] = [];
  artifacts.push(await writeArtifact(input.outputRoot, "wasm_analysis.json", JSON.stringify({
    ...base, valid: true, version, sections, imports, exports, functions, memories, globals, customSections, nameSection, codeHint,
  }, null, 2)));
  const md = [
    `# WASM analysis — ${base.file}`, "",
    `- ${base.bytes} bytes, wasm version ${version}`,
    `- sections: ${sections.map(s => `${s.name}(${s.size}B)`).join(" ")}`,
    `- functions: ${functions} local + ${imports.length} imported`,
    `- exports: ${exports.slice(0, 50).map(e => `${e.name}:${e.kind}`).join(", ") || "-"}`,
    `- imports: ${imports.slice(0, 80).map(i => i.name).join(", ") || "-"}`,
    `- memories: ${memories.map(m => `${m.min}${m.max !== undefined ? `..${m.max}` : ""} pages`).join(", ") || "none"}`,
    `- custom: ${customSections.map(c => c.name).join(", ") || "-"}`,
    "", "## Hints", ...codeHint.map(h => `- ${h}`),
    "", "## Exported functions", ...(nameSection?.functions.filter(f => exports.some(e => e.index === f.index)).slice(0, 60).map(f => `- \`${f.name}\` (index ${f.index})`) ?? exports.slice(0, 60).map(e => `- index ${e.index}`)),
  ].join("\n");
  artifacts.push(await writeArtifact(input.outputRoot, "wasm_report.md", md));
  return { ...base, valid: true, version, sections, imports, exports, functions, memories, globals, customSections, nameSection, codeHint, artifacts };
};
