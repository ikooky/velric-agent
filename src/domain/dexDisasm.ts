import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { writeArtifact } from "../adapters/artifacts.js";
import type { DexAnalysis } from "./dexAnalyze.js";

export interface DexDisasmInput { readonly file: string; readonly outputRoot: string; readonly maxMethods?: number; readonly classFilter?: string; }
export interface DexMethodDisasm { readonly cls: string; readonly method: string; readonly registers: number; readonly ins: string[]; readonly code: string[]; readonly strings: string[]; readonly calls: string[]; }
export interface DexDisasmResult {
  readonly file: string; readonly bytes: number; readonly methods: number; readonly disassembled: number;
  readonly details: DexMethodDisasm[];
  readonly stringXrefs: { str: string; where: string[] }[];
  readonly artifacts: { path: string; bytes: number }[];
}

// Dalvik opcode names — core set; unknown falls back to op-XX
const N: Record<number, string> = {
  0x00: "nop", 0x01: "move", 0x02: "move/from16", 0x03: "move/16", 0x04: "move-wide", 0x05: "move-wide/from16", 0x06: "move-wide/16", 0x07: "move-object", 0x08: "move-object/from16", 0x09: "move-object/16",
  0x0A: "move-result", 0x0B: "move-result-wide", 0x0C: "move-result-object", 0x0D: "move-exception", 0x0E: "return-void", 0x0F: "return", 0x10: "return-wide", 0x11: "return-object",
  0x12: "const/4", 0x13: "const/16", 0x14: "const", 0x15: "const/high16", 0x16: "const-wide/16", 0x17: "const-wide/32", 0x18: "const-wide", 0x19: "const-wide/high16", 0x1A: "const-string", 0x1B: "const-string/jumbo", 0x1C: "const-class", 0x1D: "monitor-enter", 0x1E: "monitor-exit", 0x1F: "check-cast", 0x20: "instance-of", 0x21: "array-length", 0x22: "new-instance", 0x23: "new-array", 0x24: "filled-new-array", 0x25: "filled-new-array/range", 0x26: "fill-array-data", 0x27: "throw", 0x28: "goto", 0x29: "goto/16", 0x2A: "goto/32", 0x2B: "packed-switch", 0x2C: "sparse-switch",
  0x2D: "cmpl-float", 0x2E: "cmpg-float", 0x2F: "cmpl-double", 0x30: "cmpg-double", 0x31: "cmp-long",
  0x32: "if-eq", 0x33: "if-ne", 0x34: "if-lt", 0x35: "if-ge", 0x36: "if-gt", 0x37: "if-le", 0x38: "if-eqz", 0x39: "if-nez", 0x3A: "if-ltz", 0x3B: "if-gez", 0x3C: "if-gtz", 0x3D: "if-lez",
  0x44: "aget", 0x45: "aget-wide", 0x46: "aget-object", 0x47: "aget-boolean", 0x48: "aget-byte", 0x49: "aget-char", 0x4A: "aget-short", 0x4B: "aput", 0x4C: "aput-wide", 0x4D: "aput-object", 0x4E: "aput-boolean", 0x4F: "aput-byte", 0x50: "aput-char", 0x51: "aput-short",
  0x52: "iget", 0x53: "iget-wide", 0x54: "iget-object", 0x55: "iget-boolean", 0x56: "iget-byte", 0x57: "iget-char", 0x58: "iget-short", 0x59: "iput", 0x5A: "iput-wide", 0x5B: "iput-object", 0x5C: "iput-boolean", 0x5D: "iput-byte", 0x5E: "iput-char", 0x5F: "iput-short",
  0x60: "sget", 0x61: "sget-wide", 0x62: "sget-object", 0x63: "sget-boolean", 0x64: "sget-byte", 0x65: "sget-char", 0x66: "sget-short", 0x67: "sput", 0x68: "sput-wide", 0x69: "sput-object", 0x6A: "sput-boolean", 0x6B: "sput-byte", 0x6C: "sput-char", 0x6D: "sput-short",
  0x6E: "invoke-virtual", 0x6F: "invoke-super", 0x70: "invoke-direct", 0x71: "invoke-static", 0x72: "invoke-interface",
  0x74: "invoke-virtual/range", 0x75: "invoke-super/range", 0x76: "invoke-direct/range", 0x77: "invoke-static/range", 0x78: "invoke-interface/range",
  0x7B: "neg-int", 0x7C: "not-int", 0x7D: "neg-long", 0x7E: "not-long", 0x7F: "neg-float", 0x80: "neg-double", 0x81: "int-to-long", 0x82: "int-to-float", 0x83: "int-to-double", 0x84: "long-to-int", 0x85: "long-to-float", 0x86: "long-to-double", 0x87: "float-to-int", 0x88: "float-to-long", 0x89: "float-to-double", 0x8A: "double-to-int", 0x8B: "double-to-long", 0x8C: "double-to-float", 0x8D: "int-to-byte", 0x8E: "int-to-char", 0x8F: "int-to-short",
  0x90: "add-int", 0x91: "sub-int", 0x92: "mul-int", 0x93: "div-int", 0x94: "rem-int", 0x95: "and-int", 0x96: "or-int", 0x97: "xor-int", 0x98: "shl-int", 0x99: "shr-int", 0x9A: "ushr-int", 0x9B: "add-long", 0x9C: "sub-long", 0x9D: "mul-long", 0x9E: "div-long", 0x9F: "rem-long", 0xA0: "and-long", 0xA1: "or-long", 0xA2: "xor-long", 0xA3: "shl-long", 0xA4: "shr-long", 0xA5: "ushr-long", 0xA6: "add-float", 0xA7: "sub-float", 0xA8: "mul-float", 0xA9: "div-float", 0xAA: "rem-float", 0xAB: "add-double", 0xAC: "sub-double", 0xAD: "mul-double", 0xAE: "div-double", 0xAF: "rem-double",
  0xB0: "add-int/2addr", 0xB1: "sub-int/2addr", 0xB2: "mul-int/2addr", 0xB3: "div-int/2addr", 0xB4: "rem-int/2addr", 0xB5: "and-int/2addr", 0xB6: "or-int/2addr", 0xB7: "xor-int/2addr", 0xB8: "shl-int/2addr", 0xB9: "shr-int/2addr", 0xBA: "ushr-int/2addr", 0xBB: "add-long/2addr", 0xBC: "sub-long/2addr", 0xBD: "mul-long/2addr", 0xBE: "div-long/2addr", 0xBF: "rem-long/2addr", 0xC0: "and-long/2addr", 0xC1: "or-long/2addr", 0xC2: "xor-long/2addr", 0xC3: "shl-long/2addr", 0xC4: "shr-long/2addr", 0xC5: "ushr-long/2addr", 0xC6: "add-float/2addr", 0xC7: "sub-float/2addr", 0xC8: "mul-float/2addr", 0xC9: "div-float/2addr", 0xCA: "rem-float/2addr", 0xCB: "add-double/2addr", 0xCC: "sub-double/2addr", 0xCD: "mul-double/2addr", 0xCE: "div-double/2addr", 0xCF: "rem-double/2addr",
  0xD0: "add-int/lit16", 0xD1: "rsub-int", 0xD2: "mul-int/lit16", 0xD3: "div-int/lit16", 0xD4: "rem-int/lit16", 0xD5: "and-int/lit16", 0xD6: "or-int/lit16", 0xD7: "xor-int/lit16", 0xD8: "add-int/lit8", 0xD9: "rsub-int/lit8", 0xDA: "mul-int/lit8", 0xDB: "div-int/lit8", 0xDC: "rem-int/lit8", 0xDD: "and-int/lit8", 0xDE: "or-int/lit8", 0xDF: "xor-int/lit8", 0xE0: "shl-int/lit8", 0xE1: "shr-int/lit8", 0xE2: "ushr-int/lit8",
};
// instruction formats: opcode → (code units, operand layout)
const FMT: Record<number, string> = {
  0x00: "10x", 0x01: "12x", 0x02: "22x", 0x03: "32x", 0x04: "12x", 0x05: "22x", 0x06: "32x", 0x07: "12x", 0x08: "22x", 0x09: "32x",
  0x0A: "11x", 0x0B: "11x", 0x0C: "11x", 0x0D: "11x", 0x0E: "10x", 0x0F: "11x", 0x10: "11x", 0x11: "11x",
  0x12: "11n", 0x13: "21s", 0x14: "31i", 0x15: "21h", 0x16: "21s", 0x17: "31i", 0x18: "51l", 0x19: "21h", 0x1A: "21c", 0x1B: "31c", 0x1C: "21c", 0x1D: "11x", 0x1E: "11x", 0x1F: "21c", 0x20: "22c", 0x21: "12x", 0x22: "21c", 0x23: "22c", 0x24: "35c", 0x25: "3rc", 0x26: "31t", 0x27: "11x", 0x28: "10t", 0x29: "20t", 0x2A: "30t", 0x2B: "31t", 0x2C: "31t",
  0x2D: "23x", 0x2E: "23x", 0x2F: "23x", 0x30: "23x", 0x31: "23x",
  0x32: "22t", 0x33: "22t", 0x34: "22t", 0x35: "22t", 0x36: "22t", 0x37: "22t", 0x38: "21t", 0x39: "21t", 0x3A: "21t", 0x3B: "21t", 0x3C: "21t", 0x3D: "21t",
  0x44: "23x", 0x45: "23x", 0x46: "23x", 0x47: "23x", 0x48: "23x", 0x49: "23x", 0x4A: "23x", 0x4B: "23x", 0x4C: "23x", 0x4D: "23x", 0x4E: "23x", 0x4F: "23x", 0x50: "23x", 0x51: "23x",
  0x52: "22c", 0x53: "22c", 0x54: "22c", 0x55: "22c", 0x56: "22c", 0x57: "22c", 0x58: "22c", 0x59: "22c", 0x5A: "22c", 0x5B: "22c", 0x5C: "22c", 0x5D: "22c", 0x5E: "22c", 0x5F: "22c",
  0x60: "21c", 0x61: "21c", 0x62: "21c", 0x63: "21c", 0x64: "21c", 0x65: "21c", 0x66: "21c", 0x67: "21c", 0x68: "21c", 0x69: "21c", 0x6A: "21c", 0x6B: "21c", 0x6C: "21c", 0x6D: "21c",
  0x6E: "35c", 0x6F: "35c", 0x70: "35c", 0x71: "35c", 0x72: "35c", 0x74: "3rc", 0x75: "3rc", 0x76: "3rc", 0x77: "3rc", 0x78: "3rc",
  0x7B: "12x", 0x7C: "12x", 0x7D: "12x", 0x7E: "12x", 0x7F: "12x", 0x80: "12x", 0x81: "12x", 0x82: "12x", 0x83: "12x", 0x84: "12x", 0x85: "12x", 0x86: "12x", 0x87: "12x", 0x88: "12x", 0x89: "12x", 0x8A: "12x", 0x8B: "12x", 0x8C: "12x", 0x8D: "12x", 0x8E: "12x", 0x8F: "12x",
  0x90: "23x", 0x91: "23x", 0x92: "23x", 0x93: "23x", 0x94: "23x", 0x95: "23x", 0x96: "23x", 0x97: "23x", 0x98: "23x", 0x99: "23x", 0x9A: "23x", 0x9B: "23x", 0x9C: "23x", 0x9D: "23x", 0x9E: "23x", 0x9F: "23x", 0xA0: "23x", 0xA1: "23x", 0xA2: "23x", 0xA3: "23x", 0xA4: "23x", 0xA5: "23x", 0xA6: "23x", 0xA7: "23x", 0xA8: "23x", 0xA9: "23x", 0xAA: "23x", 0xAB: "23x", 0xAC: "23x", 0xAD: "23x", 0xAE: "23x", 0xAF: "23x",
  0xB0: "12x", 0xB1: "12x", 0xB2: "12x", 0xB3: "12x", 0xB4: "12x", 0xB5: "12x", 0xB6: "12x", 0xB7: "12x", 0xB8: "12x", 0xB9: "12x", 0xBA: "12x", 0xBB: "12x", 0xBC: "12x", 0xBD: "12x", 0xBE: "12x", 0xBF: "12x", 0xC0: "12x", 0xC1: "12x", 0xC2: "12x", 0xC3: "12x", 0xC4: "12x", 0xC5: "12x", 0xC6: "12x", 0xC7: "12x", 0xC8: "12x", 0xC9: "12x", 0xCA: "12x", 0xCB: "12x", 0xCC: "12x", 0xCD: "12x", 0xCE: "12x", 0xCF: "12x",
  0xD0: "22b", 0xD1: "22b", 0xD2: "22b", 0xD3: "22b", 0xD4: "22b", 0xD5: "22b", 0xD6: "22b", 0xD7: "22b", 0xD8: "22b", 0xD9: "22b", 0xDA: "22b", 0xDB: "22b", 0xDC: "22b", 0xDD: "22b", 0xDE: "22b", 0xDF: "22b", 0xE0: "22b", 0xE1: "22b", 0xE2: "22b",
};
const units = (fmt: string): number => ({ "10x": 1, "12x": 1, "11x": 1, "11n": 1, "10t": 1, "20t": 2, "22x": 2, "21s": 2, "21h": 2, "21c": 2, "23x": 2, "22t": 2, "22b": 2, "22c": 2, "21t": 2, "31i": 3, "31t": 3, "31c": 3, "30t": 3, "35c": 3, "3rc": 3, "51l": 5, "32x": 3 }[fmt] ?? 1);

export const disassembleDex = async (input: DexDisasmInput): Promise<DexDisasmResult> => {
  const buf = await readFile(input.file);
  const details: DexMethodDisasm[] = [];
  if (buf.length < 112 || buf.toString("ascii", 0, 3) !== "dex") {
    const artifacts = [await writeArtifact(input.outputRoot, "dex_disasm.smali", "; not a dex file")];
    return { file: basename(input.file), bytes: buf.length, methods: 0, disassembled: 0, details: [], stringXrefs: [], artifacts };
  }
  const strXref = new Map<string, Set<string>>();
  let methods = 0;
  let disassembled = 0;
  // Reuse structure parse from dexAnalyze but we need method→code_off mapping: re-walk header
  // Bounds-guarded readers: a corrupt/hostile header can carry offsets far
  // beyond the file — raw Buffer reads would throw ERR_OUT_OF_RANGE and kill
  // the CLI. Out-of-range reads return 0 so parsing degrades instead of crash.
  let truncated = false;
  const rd32 = (p: number): number => (p >= 0 && p + 4 <= buf.length) ? buf.readUInt32LE(p) : (truncated = true, 0);
  const rd16 = (p: number): number => (p >= 0 && p + 2 <= buf.length) ? buf.readUInt16LE(p) : (truncated = true, 0);
  const rd8 = (p: number): number => (p >= 0 && p < buf.length) ? buf.readUInt8(p) : (truncated = true, 0);
  const stringIdsSize = rd32(56); const stringIdsOff = rd32(60);
  const typeIdsSize = rd32(64); const typeIdsOff = rd32(68);
  const protoIdsOff = rd32(76);
  const fieldIdsSize = rd32(80); const fieldIdsOff = rd32(84);
  const methodIdsSize = rd32(88); const methodIdsOff = rd32(92);
  const classDefsSize = rd32(96); const classDefsOff = rd32(100);
  const readStr = (offset: number): string => {
    let p = offset; let len = 0, shift = 0;
    for (;;) { const b = rd8(p++); len |= (b & 0x7F) << shift; if (!(b & 0x80)) break; shift += 7; }
    return buf.toString("utf8", p, Math.min(p + len, buf.length)).replace(/\0.*$/s, "");
  };
  const str = (idx: number): string => {
    if (idx < 0 || idx >= stringIdsSize) return "?";
    return readStr(rd32(stringIdsOff + idx * 4));
  };
  const typeDesc = (idx: number): string => idx >= 0 && idx < typeIdsSize ? str(rd32(typeIdsOff + idx * 4)) : "?";
  const methodRef = (idx: number): string => {
    if (idx < 0 || idx >= methodIdsSize) return "?";
    const at = methodIdsOff + idx * 8;
    return `${typeDesc(rd16(at))}->${str(rd32(at + 4))}()`;
  };
  const fieldRef = (idx: number): string => {
    if (idx < 0 || idx >= fieldIdsSize) return "?";
    const at = fieldIdsOff + idx * 8;
    return `${typeDesc(rd16(at))}.${str(rd32(at + 4))}`;
  };
  const uleb = (p: number): [number, number] => {
    let r = 0, s = 0;
    for (;;) { const b = rd8(p++); r |= (b & 0x7F) << s; if (!(b & 0x80)) return [r >>> 0, p]; s += 7; }
  };
  const maxMethods = input.maxMethods ?? 3000;
  const filter = input.classFilter ? new RegExp(input.classFilter) : null;
  for (let ci = 0; ci < Math.min(classDefsSize, 50000) && disassembled < maxMethods; ci++) {
    const at = classDefsOff + ci * 32;
    const className = typeDesc(rd32(at));
    if (filter && !filter.test(className)) continue;
    const classDataOff = rd32(at + 24);
    if (!classDataOff || classDataOff >= buf.length) continue;
    let p = classDataOff;
    let staticF: number; [staticF, p] = uleb(p);
    let instF: number; [instF, p] = uleb(p);
    let directM: number; [directM, p] = uleb(p);
    let virtualM: number; [virtualM, p] = uleb(p);
    p = (() => { let q = p; for (let i = 0, idx = 0; i < staticF + instF; i++) { let d: number; [d, q] = uleb(q); idx += d; let a: number; [a, q] = uleb(q); } return q; })();
    let methodIdx = 0;
    for (let mi = 0; mi < directM + virtualM && disassembled < maxMethods; mi++) {
      let midx: number; [midx, p] = uleb(p);
      let acc: number; [acc, p] = uleb(p);
      let codeOff: number; [codeOff, p] = uleb(p);
      methodIdx += midx; // class_data method_idx 是差分编码, 须累加
      methods++;
      if (!codeOff || codeOff + 16 > buf.length) continue;
      // code_item: registers_size(2) ins_size(2) outs_size(2) tries_size(2) debug_info_off(4) insns_size(4) insns...
      const regs = rd16(codeOff);
      const ins = rd16(codeOff + 2);
      const insnsSize = rd32(codeOff + 12);
      const insns = codeOff + 16;
      const ref = methodRef(methodIdx);
      const code: string[] = [];
      const strs: string[] = [];
      const calls: string[] = [];
      const sigByte = (b: number): string => {
        const op = b & 0xFF;
        const hi = b >> 8;
        const name = N[op] ?? `op-${op.toString(16)}`;
        const fmt = FMT[op] ?? "10x";
        let operands = "";
        switch (fmt) {
          case "10x": case "11x": case "10t": operands = ""; break;
          case "12x": case "11n": operands = `v${hi & 0xF}, v${hi >> 4}`; break;
          case "22x": case "21t": case "21s": case "21h": case "23x": case "22t": case "22b": { const u2 = rd16(insns + 0 * 2 + 2); operands = `v${hi & 0xF}, v${hi >> 4}, ${fmt === "22x" ? `v${u2}` : u2}`; break; }
          case "21c": { const idx2 = rd16(insns + 2); const kind = op >= 0x60 && op <= 0x6D ? "field" : op === 0x1C || op === 0x1F ? "type" : "string"; const target = kind === "field" ? fieldRef(idx2) : kind === "type" ? typeDesc(idx2) : str(idx2); if (kind === "string") strs.push(target); operands = `v${hi}, ${target}`; break; }
          case "31i": case "31t": case "30t": { const v = rd32(insns + 2); operands = `v${hi}, ${op >= 0x2A && op <= 0x2C ? `+${v}` : v}`; break; }
          case "31c": { const idx2 = rd32(insns + 2); const sv = str(idx2); strs.push(sv); operands = `v${hi}, "${sv}"`; break; }
          case "22c": { const idx2 = rd16(insns + 2); const kind = (op >= 0x52 && op <= 0x5F) || op === 0x1F ? "field" : (op >= 0x20 && op <= 0x26) ? "type" : "?"; const target = kind === "field" ? fieldRef(idx2) : typeDesc(idx2); operands = `v${hi & 0xF}, v${hi >> 4}, ${target}`; break; }
          case "35c": case "3rc": {
            const u2 = rd16(insns + 2); const u3 = rd16(insns + 4);
            const mref = methodRef(u2);
            calls.push(mref);
            if (fmt === "35c") {
              // format 35c: A|G|op BBBB F|E|D|C
              const count = (hi >> 4) & 0xF; // A = arg count (high nibble of cu>>8)
              const g = hi & 0xF;
              const fedc = u3;
              const regs = [g, fedc & 0xF, (fedc >> 4) & 0xF, (fedc >> 8) & 0xF, (fedc >> 12) & 0xF].slice(0, count);
              operands = `{${regs.map(r2 => `v${r2}`).join(", ")}}, ${mref}`;
            } else {
              // format 3rc: AA BBBB CCCC
              const count = hi & 0xFF;
              const first = u3;
              operands = count === 0 ? `{}, ${mref}` : `{v${first}..v${first + count - 1}}, ${mref}`;
            }
            break;
          }
          case "51l": { const v = Number(buf.readBigUInt64LE(insns + 2)); operands = `v${hi}, ${v}`; break; }
          default: operands = "";
        }
        return `${name}${operands ? ` ${operands}` : ""}`;
      };
      let ip = 0;
      const lines: string[] = [];
      while (ip < insnsSize && lines.length < 5000) {
        const cu = rd16(insns + ip * 2);
        const op = cu & 0xFF;
        const fmt = FMT[op];
        if (!fmt) { lines.push(`nop-padding 0x${cu.toString(16)}`); ip++; continue; }
        // pseudo-instructions (nop + payload) for switch/array-data
        if (op === 0x00 && (cu >> 8) === 0x01) { // packed-switch payload
          const size = rd16(insns + (ip + 1) * 2);
          lines.push(`packed-switch-payload(${size})`);
          ip += 4 + size * 2; continue;
        }
        if (op === 0x00 && (cu >> 8) === 0x02) { // sparse-switch payload
          const size = rd16(insns + (ip + 1) * 2);
          lines.push(`sparse-switch-payload(${size})`);
          ip += 2 + size * 4; continue;
        }
        if (op === 0x00 && (cu >> 8) === 0x03) { // fill-array-data payload
          const width = rd16(insns + (ip + 1) * 2);
          const size = rd32(insns + (ip + 2) * 2);
          lines.push(`array-data(width=${width}, size=${size})`);
          ip += 4 + Math.ceil((width * size) / 2); continue;
        }
        try { lines.push(sigByte(cu)); } catch { lines.push(`decode-error@${ip}`); }
        ip += units(fmt);
      }
      disassembled++;
      for (const s of strs) { const set = strXref.get(s) ?? new Set<string>(); set.add(ref); strXref.set(s, set); }
      details.push({ cls: className, method: ref, registers: regs, ins: [`${ins}`], code: lines, strings: strs, calls });
    }
  }
  const all = [...strXref.entries()].map(([s, where]) => ({ str: s, where: [...where] })).filter(x => x.str.length > 3);
  // URL/密钥样字符串优先排序, 其余保持发现顺序; 上限 8000 防御性截断
  const isUrl = (s: string): boolean => /^https?:\/\//.test(s) || /^[\w.-]+\.[a-z]{2,}(?:\/|$)/i.test(s);
  const stringXrefs = [...all.filter(x => isUrl(x.str)), ...all.filter(x => !isUrl(x.str))].slice(0, 8000);
  const artifacts: DexDisasmResult["artifacts"] = [];
  const out: string[] = [`; dex disassembly — ${basename(input.file)}`, `; ${methods} methods seen, ${disassembled} disassembled`, ""];
  for (const m of details) {
    out.push(`.method ${m.method}  ; regs=${m.registers}`);
    for (const c of m.code) out.push(`  ${c}`);
    out.push(".end method", "");
  }
  artifacts.push(await writeArtifact(input.outputRoot, "dex_disasm.smali", out.join("\n")));
  artifacts.push(await writeArtifact(input.outputRoot, "dex_string_xrefs.json", JSON.stringify(stringXrefs, null, 2)));
  return { file: basename(input.file), bytes: buf.length, methods, disassembled, details: details.slice(0, 100), stringXrefs, artifacts };
};
void (null as unknown as DexAnalysis);
