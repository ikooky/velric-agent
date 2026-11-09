import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { writeArtifact } from "../adapters/artifacts.js";

export interface WasmDisasmInput { readonly file: string; readonly outputRoot: string; readonly maxFunctions?: number; }
export interface WasmInstr { readonly offset: number; readonly opcode: number; readonly name: string; readonly imm?: string; }
export interface WasmFuncDisasm { readonly index: number; readonly name: string; readonly size: number; readonly instrs: WasmInstr[]; readonly calls: string[]; readonly branches: number; readonly blocks: number; }
export interface WasmDisasmResult {
  readonly file: string; readonly bytes: number; readonly functions: number; readonly disassembled: number;
  readonly callgraph: { from: string; to: string; count: number }[];
  readonly details: WasmFuncDisasm[];
  readonly artifacts: { path: string; bytes: number }[];
}

class R {
  pos = 0;
  readonly buf: Buffer;
  constructor(buf: Buffer) { this.buf = buf; }
  byte(): number { return this.buf.readUInt8(this.pos++); }
  u32(): number { let r = 0, s = 0; for (;;) { const b = this.byte(); r |= (b & 0x7F) << s; if (!(b & 0x80)) return r >>> 0; s += 7; if (s > 35) throw new Error("leb"); } }
  i32(): number { let r = 0, s = 0; for (;;) { const b = this.byte(); if (s < 32) r |= (b & 0x7F) << s; s += 7; if (!(b & 0x80)) { if (s < 40 && (b & 0x40)) r |= -(1 << s); return r | 0; } } }
  i64(): bigint { let r = 0n, s = 0n; for (;;) { const b = this.byte(); r |= BigInt(b & 0x7F) << s; s += 7n; if (!(b & 0x80)) { if (s < 64n && (b & 0x40)) r |= -(1n << s); return BigInt.asIntN(64, r); } } }
  f32(): number { const v = this.buf.readFloatLE(this.pos); this.pos += 4; return v; }
  f64(): number { const v = this.buf.readDoubleLE(this.pos); this.pos += 8; return v; }
  skip(n: number): void { this.pos += n; }
}

// opcode table: 0x00-0xC4 core + sign-ext + saturated trunc + bulk/memory + SIMD(0xFD prefix)
const OP: Record<number, string> = {
  0x00: "unreachable", 0x01: "nop", 0x02: "block", 0x03: "loop", 0x04: "if", 0x05: "else", 0x0B: "end", 0x0C: "br", 0x0D: "br_if", 0x0E: "br_table", 0x0F: "return",
  0x10: "call", 0x11: "call_indirect", 0x1A: "drop", 0x1B: "select", 0x1C: "select_t",
  0x20: "local.get", 0x21: "local.set", 0x22: "local.tee", 0x23: "global.get", 0x24: "global.set",
  0x25: "table.get", 0x26: "table.set",
  0x28: "i32.load", 0x29: "i64.load", 0x2A: "f32.load", 0x2B: "f64.load", 0x2C: "i32.load8_s", 0x2D: "i32.load8_u", 0x2E: "i32.load16_s", 0x2F: "i32.load16_u",
  0x30: "i64.load8_s", 0x31: "i64.load8_u", 0x32: "i64.load16_s", 0x33: "i64.load16_u", 0x34: "i64.load32_s", 0x35: "i64.load32_u", 0x36: "i32.store", 0x37: "i64.store", 0x38: "f32.store", 0x39: "f64.store",
  0x3A: "i32.store8", 0x3B: "i32.store16", 0x3C: "i64.store8", 0x3D: "i64.store16", 0x3E: "i64.store32",
  0x3F: "memory.size", 0x40: "memory.grow",
  0x41: "i32.const", 0x42: "i64.const", 0x43: "f32.const", 0x44: "f64.const",
  0x45: "i32.eqz", 0x46: "i32.eq", 0x47: "i32.ne", 0x48: "i32.lt_s", 0x49: "i32.lt_u", 0x4A: "i32.gt_s", 0x4B: "i32.gt_u", 0x4C: "i32.le_s", 0x4D: "i32.le_u", 0x4E: "i32.ge_s", 0x4F: "i32.ge_u",
  0x50: "i64.eqz", 0x51: "i64.eq", 0x52: "i64.ne", 0x53: "i64.lt_s", 0x54: "i64.lt_u", 0x55: "i64.gt_s", 0x56: "i64.gt_u", 0x57: "i64.le_s", 0x58: "i64.le_u", 0x59: "i64.ge_s", 0x5A: "i64.ge_u",
  0x5B: "f32.eq", 0x5C: "f32.ne", 0x5D: "f32.lt", 0x5E: "f32.gt", 0x5F: "f32.le", 0x60: "f32.ge", 0x61: "f64.eq", 0x62: "f64.ne", 0x63: "f64.lt", 0x64: "f64.gt", 0x65: "f64.le", 0x66: "f64.ge",
  0x67: "i32.clz", 0x68: "i32.ctz", 0x69: "i32.popcnt", 0x6A: "i32.add", 0x6B: "i32.sub", 0x6C: "i32.mul", 0x6D: "i32.div_s", 0x6E: "i32.div_u", 0x6F: "i32.rem_s", 0x70: "i32.rem_u", 0x71: "i32.and", 0x72: "i32.or", 0x73: "i32.xor", 0x74: "i32.shl", 0x75: "i32.shr_s", 0x76: "i32.shr_u", 0x77: "i32.rotl", 0x78: "i32.rotr",
  0x79: "i64.clz", 0x7A: "i64.ctz", 0x7B: "i64.popcnt", 0x7C: "i64.add", 0x7D: "i64.sub", 0x7E: "i64.mul", 0x7F: "i64.div_s", 0x80: "i64.div_u", 0x81: "i64.rem_s", 0x82: "i64.rem_u", 0x83: "i64.and", 0x84: "i64.or", 0x85: "i64.xor", 0x86: "i64.shl", 0x87: "i64.shr_s", 0x88: "i64.shr_u", 0x89: "i64.rotl", 0x8A: "i64.rotr",
  0x8B: "f32.abs", 0x8C: "f32.neg", 0x8D: "f32.ceil", 0x8E: "f32.floor", 0x8F: "f32.trunc", 0x90: "f32.nearest", 0x91: "f32.sqrt", 0x92: "f32.add", 0x93: "f32.sub", 0x94: "f32.mul", 0x95: "f32.div", 0x96: "f32.min", 0x97: "f32.max", 0x98: "f32.copysign",
  0x99: "f64.abs", 0x9A: "f64.neg", 0x9B: "f64.ceil", 0x9C: "f64.floor", 0x9D: "f64.trunc", 0x9E: "f64.nearest", 0x9F: "f64.sqrt", 0xA0: "f64.add", 0xA1: "f64.sub", 0xA2: "f64.mul", 0xA3: "f64.div", 0xA4: "f64.min", 0xA5: "f64.max", 0xA6: "f64.copysign",
  0xA7: "i32.wrap_i64", 0xA8: "i32.trunc_f32_s", 0xA9: "i32.trunc_f32_u", 0xAA: "i32.trunc_f64_s", 0xAB: "i32.trunc_f64_u", 0xAC: "i64.extend_i32_s", 0xAD: "i64.extend_i32_u", 0xAE: "i64.trunc_f32_s", 0xAF: "i64.trunc_f32_u", 0xB0: "i64.trunc_f64_s", 0xB1: "i64.trunc_f64_u",
  0xB2: "f32.convert_i32_s", 0xB3: "f32.convert_i32_u", 0xB4: "f32.convert_i64_s", 0xB5: "f32.convert_i64_u", 0xB6: "f32.demote_f64", 0xB7: "f64.convert_i32_s", 0xB8: "f64.convert_i32_u", 0xB9: "f64.convert_i64_s", 0xBA: "f64.convert_i64_u", 0xBB: "f64.promote_f32", 0xBC: "i32.reinterpret_f32", 0xBD: "i64.reinterpret_f64", 0xBE: "f32.reinterpret_i32", 0xBF: "f64.reinterpret_i64",
  0xC0: "i32.extend8_s", 0xC1: "i32.extend16_s", 0xC2: "i64.extend8_s", 0xC3: "i64.extend16_s", 0xC4: "i64.extend32_s",
  0xD0: "ref.null", 0xD1: "ref.is_null", 0xD2: "ref.func",
  0xFC00: "i32.trunc_sat_f32_s", 0xFC01: "i32.trunc_sat_f32_u", 0xFC02: "i32.trunc_sat_f64_s", 0xFC03: "i32.trunc_sat_f64_u", 0xFC04: "i64.trunc_sat_f32_s", 0xFC05: "i64.trunc_sat_f32_u", 0xFC06: "i64.trunc_sat_f64_s", 0xFC07: "i64.trunc_sat_f64_u",
  0xFC08: "memory.init", 0xFC09: "data.drop", 0xFC0A: "memory.copy", 0xFC0B: "memory.fill",
  0xFC0C: "table.init", 0xFC0D: "elem.drop", 0xFC0E: "table.copy", 0xFC0F: "table.grow", 0xFC10: "table.size", 0xFC11: "table.fill",
};
const SIMD: Record<number, string> = { 0: "v128.load", 1: "v128.load8x8_s", 2: "v128.load8x8_u", 3: "v128.load16x4_s", 4: "v128.load16x4_u", 5: "v128.load32x2_s", 6: "v128.load32x2_u", 7: "v128.load8_splat", 8: "v128.load16_splat", 9: "v128.load32_splat", 10: "v128.load64_splat", 11: "v128.store", 12: "v128.const", 13: "i8x16.shuffle", 14: "i8x16.swizzle", 15: "i8x16.splat", 16: "i16x8.splat", 17: "i32x4.splat", 18: "i64x2.splat", 19: "f32x4.splat", 20: "f64x2.splat", 21: "i8x16.extract_lane_s", 22: "i8x16.extract_lane_u", 23: "i8x16.replace_lane", /* ... rest lazily named */ 84: "i8x16.eq", 90: "i8x16.add", 97: "i16x8.add", 103: "i32x4.add", 109: "i64x2.add", 115: "f32x4.add", 121: "f64x2.add" };

const memarg = (r: R): string => { const align = r.u32(); const off = r.u32(); return `off=${off} align=${align}`; };

export const disassembleWasm = async (input: WasmDisasmInput): Promise<WasmDisasmResult> => {
  const buf = await readFile(input.file);
  const r = new R(buf);
  r.pos = 8;
  const funcNames = new Map<number, string>();
  const importNames = new Map<number, string>();
  let typeCount = 0;
  const typeForms: { params: number; results: number }[] = [];
  let importFuncCount = 0;
  let localFuncCount = -1;
  let codeOff = -1; let codeSize = 0;
  const funcTypeIdx: number[] = [];
  while (r.pos < buf.length) {
    const id = r.byte(); const size = r.u32(); const start = r.pos; const end = start + size;
    if (id === 1) {
      typeCount = r.u32();
      for (let i = 0; i < typeCount; i++) { const form = r.byte(); const np = r.u32(); r.skip(np); const nr = r.u32(); r.skip(nr); typeForms.push({ params: np, results: nr }); }
    } else if (id === 2) {
      const count = r.u32();
      for (let i = 0; i < count; i++) {
        const mod = (() => { const l = r.u32(); const s = buf.toString("utf8", r.pos, r.pos + l); r.pos += l; return s; })();
        const field = (() => { const l = r.u32(); const s = buf.toString("utf8", r.pos, r.pos + l); r.pos += l; return s; })();
        const kind = r.byte();
        if (kind === 0) { r.u32(); importNames.set(importFuncCount, `${mod}.${field}`); importFuncCount++; }
        else if (kind === 1) { r.u32(); r.byte(); }
        else if (kind === 2) { const fl = r.u32(); r.u32(); if (fl & 1) r.u32(); }
        else if (kind === 3) { r.byte(); r.byte(); }
      }
    } else if (id === 3) {
      const n = r.u32();
      for (let i = 0; i < n; i++) funcTypeIdx.push(r.u32());
      localFuncCount = n;
    } else if (id === 0) {
      const l = r.u32(); const name = buf.toString("utf8", r.pos, r.pos + l); r.pos += l;
      if (name === "name") {
        while (r.pos < end) {
          const sub = r.byte(); const subSize = r.u32(); const subEnd = r.pos + subSize;
          if (sub === 1) {
            const cnt = r.u32();
            for (let i = 0; i < cnt; i++) { const idx = r.u32(); const l2 = r.u32(); const nm = buf.toString("utf8", r.pos, r.pos + l2); r.pos += l2; funcNames.set(idx, nm); }
          }
          r.pos = subEnd;
        }
      }
    } else if (id === 10) { codeOff = start; codeSize = size; }
    r.pos = end;
  }
  if (codeOff < 0 || localFuncCount < 0) return { file: basename(input.file), bytes: buf.length, functions: 0, disassembled: 0, callgraph: [], details: [], artifacts: [await writeArtifact(input.outputRoot, "wasm_disasm.txt", "no code section")] };
  const nameOf = (idx: number): string => funcNames.get(idx) ?? importNames.get(idx) ?? `f${idx}`;
  const maxFn = input.maxFunctions ?? 5000;
  // walk code section
  r.pos = codeOff;
  const funcCount = r.u32();
  const details: WasmFuncDisasm[] = [];
  const callgraph: { from: string; to: string; count: number }[] = [];
  const callMap = new Map<string, Map<string, number>>();
  for (let f = 0; f < Math.min(funcCount, maxFn); f++) {
    const bodySize = r.u32();
    const bodyStart = r.pos;
    const bodyEnd = bodyStart + bodySize;
    const localGroups = r.u32();
    let localCount = 0;
    for (let g = 0; g < localGroups; g++) { const cnt = r.u32(); r.byte(); localCount += cnt; }
    const instrs: WasmInstr[] = [];
    const calls: string[] = [];
    let branches = 0; let blocks = 0;
    while (r.pos < bodyEnd) {
      const off = r.pos - codeOff;
      const op = r.byte();
      if (op === 0xFD) { const simdOp = r.u32(); instrs.push({ offset: off, opcode: op, name: SIMD[simdOp] ?? `simd(${simdOp})` }); r.skip(0); continue; }
      const name = OP[op];
      if (name === undefined) { instrs.push({ offset: off, opcode: op, name: `unknown(0x${op.toString(16)})` }); break; }
      let imm: string | undefined;
      switch (op) {
        case 0x02: case 0x03: case 0x04: { const b = r.byte(); imm = b === 0x40 ? "void" : b === 0x7F ? "i32" : b === 0x7E ? "i64" : b === 0x7D ? "f32" : b === 0x7C ? "f64" : `bt(0x${b.toString(16)})`; blocks++; break; }
        case 0x0C: case 0x0D: imm = String(r.u32()); branches++; break;
        case 0x0E: { const n = r.u32(); const ts: number[] = []; for (let i = 0; i <= n; i++) ts.push(r.u32()); imm = ts.join(","); branches++; break; }
        case 0x10: { const callee = r.u32(); const cname = nameOf(callee); calls.push(cname); imm = `${callee} <${cname}>`; const m = callMap.get(nameOf(f + importFuncCount)) ?? new Map(); m.set(cname, (m.get(cname) ?? 0) + 1); callMap.set(nameOf(f + importFuncCount), m); break; }
        case 0x11: { const t = r.u32(); const tb = r.u32(); imm = `type=${t} table=${tb}`; break; }
        case 0x1C: { const n = r.u32(); for (let i = 0; i < n; i++) r.byte(); break; }
        case 0x20: case 0x21: case 0x22: imm = String(r.u32()); break;
        case 0x23: case 0x24: case 0x25: case 0x26: imm = String(r.u32()); break;
        case 0xD2: imm = String(r.u32()); break;
        case 0xD0: { const ht = r.byte(); imm = ht === 0x70 ? "funcref" : ht === 0x6F ? "externref" : `ht(0x${ht.toString(16)})`; break; }
        case 0x41: imm = String(r.i32()); break;
        case 0x42: imm = r.i64().toString(); break;
        case 0x43: imm = String(r.f32()); break;
        case 0x44: imm = String(r.f64()); break;
        case 0x0B: break;
        default:
          if (op >= 0x28 && op <= 0x3E) imm = memarg(r);
          else if (op === 0x3F || op === 0x40) imm = String(r.u32());
          else if (op === 0xFC) { const sub = r.u32(); const subName = OP[(0xFC00 + sub)] ?? `fc(${sub})`; instrs.push({ offset: off, opcode: op, name: subName }); if (sub === 8 || sub === 12) { r.u32(); r.u32(); } else if (sub === 9 || sub === 13 || sub === 14) { r.u32(); r.u32(); } else if (sub === 15 || sub === 17) { r.u32(); } continue; }
      }
      instrs.push({ offset: off, opcode: op, name, imm });
    }
    details.push({ index: f + importFuncCount, name: nameOf(f + importFuncCount), size: bodySize, instrs, calls, branches, blocks });
    r.pos = bodyEnd;
  }
  for (const [from, targets] of callMap) for (const [to, count] of targets) callgraph.push({ from, to, count });
  callgraph.sort((a, b) => b.count - a.count);
  const artifacts: WasmDisasmResult["artifacts"] = [];
  const lines: string[] = [`; wasm disassembly — ${basename(input.file)}`, `; ${funcCount} functions (${importFuncCount} imported), disassembled ${details.length}`, ""];
  for (const fn of details) {
    lines.push(`func ${fn.index} <${fn.name}> {  ; ${fn.size}B, ${fn.instrs.length} instrs, ${fn.branches} branches`);
    for (const i of fn.instrs) lines.push(`  ${String(i.offset).padStart(6)}  ${i.name}${i.imm !== undefined ? ` ${i.imm}` : ""}`);
    lines.push("}", "");
  }
  artifacts.push(await writeArtifact(input.outputRoot, "wasm_disasm.txt", lines.join("\n")));
  artifacts.push(await writeArtifact(input.outputRoot, "wasm_callgraph.json", JSON.stringify(callgraph.slice(0, 5000), null, 2)));
  return { file: basename(input.file), bytes: buf.length, functions: funcCount + importFuncCount, disassembled: details.length, callgraph: callgraph.slice(0, 5000), details: details.slice(0, 200), artifacts };
};
