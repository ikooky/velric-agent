import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { writeArtifact } from "../adapters/artifacts.js";
import type { ElfSection } from "./elfAnalyze.js";

export interface X86DisasmInput {
  readonly file: string;
  readonly outputRoot: string;
  /** disassemble at virtual address */
  readonly vaddr?: number;
  /** max instructions per function */
  readonly maxInstrs?: number;
  /** max functions to disassemble */
  readonly maxFunctions?: number;
}
export interface X86FuncDisasm { readonly name: string; readonly address: string; readonly size: number; readonly instrs: { address: string; mnemonic: string; opStr: string }[]; readonly calls: string[]; }
export interface X86DisasmResult {
  readonly file: string; readonly bytes: number; readonly engine: string;
  readonly arch: string; readonly functions: number; readonly disassembled: number;
  readonly strings: { address: string; text: string }[];
  readonly importsUsed: string[];
  readonly details: X86FuncDisasm[];
  readonly artifacts: { path: string; bytes: number }[];
  readonly degraded: boolean; readonly reason?: string;
}

/** parse ELF sections minimally (raw, independent of analyzeElf output shape) */
const elfSections = (buf: Buffer): { name: string; addr: bigint; offset: number; size: number; exec: boolean }[] => {
  const is64 = buf[4] === 2;
  const le = buf[5] === 1;
  const rd = (p: number | undefined, n: number): bigint => { let v = 0n; for (let i = n - 1; i >= 0; i--) v = (v << 8n) | BigInt((le ? buf[(p ?? 0) + i] : buf[(p ?? 0) + n - 1 - i]) ?? 0); return v; };
  const shoff = Number(rd(is64 ? 0x28 : 0x20, is64 ? 8 : 4));
  const shentsize = Number(rd(is64 ? 0x3A : 0x2E, 2));
  const shnum = Number(rd(is64 ? 0x3C : 0x30, 2));
  const shstrndx = Number(rd(is64 ? 0x3E : 0x32, 2));
  if (!shoff || !shnum || shstrndx >= shnum) return [];
  const strtabOff = Number(rd(shoff + shstrndx * shentsize + (is64 ? 0x18 : 0x10), is64 ? 8 : 4));
  const nameAt = (p: number): string => { const no = Number(rd(p, 4)); const e0 = strtabOff + no; if (e0 < 0 || e0 >= buf.length) return ""; const end = buf.indexOf(0, e0); return buf.toString("utf8", e0, end < 0 ? e0 : end); };
  const out: { name: string; addr: bigint; offset: number; size: number; exec: boolean }[] = [];
  for (let i = 0; i < shnum; i++) {
    const at = shoff + i * shentsize;
    const type = Number(rd(at + 4, 4));
    const addr = rd(at + (is64 ? 0x10 : 0x0C), is64 ? 8 : 4);
    const offset = Number(rd(at + (is64 ? 0x18 : 0x10), is64 ? 8 : 4));
    const size = Number(rd(at + (is64 ? 0x20 : 0x14), is64 ? 8 : 4));
    const flags = rd(at + (is64 ? 0x08 : 0x08), is64 ? 8 : 4);
    out.push({ name: nameAt(at), addr, offset, size, exec: (flags & 0x4n) !== 0n });
  }
  return out;
};

type CapstoneModule = { Capstone: new (arch: number, mode: number) => { disasm(data: number[] | Uint8Array, opts?: { address?: number | bigint; count?: number }): { address: number | bigint; size: number; mnemonic: string; opStr: string }[]; close(): void }; Const: Record<string, number> };
let cached: CapstoneModule | null = null;
const loadCapstone = async (): Promise<CapstoneModule | null> => {
  if (cached) return cached;
  try {
    const m = (await import("capstone-wasm")) as unknown as CapstoneModule & { loadCapstone?: () => Promise<void> };
    if (typeof m.loadCapstone === "function") await m.loadCapstone();
    cached = m;
    return m;
  } catch { return null; }
};

const targetOf = (i: { mnemonic: string; opStr: string }): string => {
  const m = /^0x([0-9a-f]+)$/.exec(i.opStr);
  return m ? (m[1] ?? "") : "";
};

export const disassembleX86 = async (input: X86DisasmInput): Promise<X86DisasmResult> => {
  const buf = await readFile(input.file);
  const base = basename(input.file);
  const sections = elfSections(buf);
  const execSections = sections.filter(s => s.exec && s.size > 0);
  // capstone-wasm missing → degraded mode (strings + sections only)
  const cap = await loadCapstone();
  if (!cap) {
    const strings = extractStrings(buf, 5);
    const artifacts = [await writeArtifact(input.outputRoot, "x86_disasm.txt", "engine unavailable — install capstone-wasm to enable instruction-level disassembly\n\n" + strings.map(s => `${s.address} ${s.text}`).join("\n"))];
    return { file: base, bytes: buf.length, engine: "none", arch: detectArch(buf), functions: 0, disassembled: 0, strings, importsUsed: [], details: [], artifacts, degraded: true, reason: "capstone-wasm not installed" };
  }
  const is64 = buf[4] === 2;
  const archX86 = cap.Const.CS_ARCH_X86 ?? 3; const mode64 = cap.Const.CS_MODE_64 ?? 8; const mode32 = cap.Const.CS_MODE_32 ?? 4;
  let cs = new cap.Capstone(archX86, is64 ? mode64 : mode32);
  const symbols = elfSymbols(buf, sections);
  const nameForAddr = new Map<string, string>(symbols.map(s => [s.value, s.name]));
  const details: X86FuncDisasm[] = [];
  const allCalls: string[] = [];
  const maxFn = input.maxFunctions ?? 40;
  const maxInstrs = input.maxInstrs ?? 4000;
  const lines: string[] = [`; x86 disassembly — ${base}`, ""];
  for (const sec of execSections) {
    if (details.length >= maxFn) break;
    const code = buf.subarray(sec.offset, sec.offset + sec.size);
    // function anchors: symbols first, then entry point, then raw prologues
    type Anchor = { name: string; off: number; addr: bigint };
    const anchors: Anchor[] = [];
    for (const sym of symbols) if (sym.secName === sec.name && sym.size > 0) anchors.push({ name: sym.name, off: Number(BigInt("0x" + sym.value) - sec.addr), addr: BigInt("0x" + sym.value) });

    if (sec.addr <= entryOf(buf) && entryOf(buf) < sec.addr + BigInt(sec.size)) anchors.unshift({ name: "_entry", off: Number(entryOf(buf) - sec.addr), addr: entryOf(buf) });
    if (anchors.length < 8) {
      // raw prologue scan: endbr64 (f3 0f 1e fa), push rbp;mov rbp,rsp (55 48 89 e5), push r15..r8 (41 5x)
      for (let off = 0; off + 4 <= code.length && anchors.length < 24; off++) {
        const b0 = code[off] ?? 0, b1 = code[off + 1] ?? 0, b2 = code[off + 2] ?? 0, b3 = code[off + 3] ?? 0;
        const endbr = b0 === 0xF3 && b1 === 0x0F && b2 === 0x1E && b3 === 0xFA;
        const rbp = b0 === 0x55 && b1 === 0x48 && b2 === 0x89 && b3 === 0xE5;
        const pushR = b0 === 0x41 && b1 >= 0x54 && b1 <= 0x57;
        if (endbr || rbp || pushR) anchors.push({ name: `sub_${(sec.addr + BigInt(off)).toString(16)}`, off, addr: sec.addr + BigInt(off) });
      }
    }
    // 同一 off 只留一个锚点: 符号锚点(有真名)优先于 prologue 启发式锚点
    const byOff = new Map<number, Anchor>();
    for (const a of anchors) {
      const prev = byOff.get(a.off);
      if (prev !== undefined && !prev.name.startsWith("sub_") && a.name.startsWith("sub_")) continue; // 符号锚点已占位, 丢弃同址 prologue 锚点
      byOff.set(a.off, a);
    }
    const sorted = [...byOff.values()].sort((x, y) => x.off - y.off);
    for (let ai = 0; ai < sorted.length; ai++) {
      const a = sorted[ai]!;
      if (details.length >= maxFn) break;
      if (a.off < 0 || a.off >= code.length) continue;
      // capstone-wasm 线性内存限制: 单次调用代码量须 <64KB — 按函数锚点分块; 函数边界=下一锚点, 单函数超限截断到 60KB
      const nextOff = ai + 1 < sorted.length ? sorted[ai + 1]!.off : code.length;
      const fnLen = Math.min(nextOff - a.off, 0xF000);
      if (fnLen <= 0) continue;
      const fnCode = code.subarray(a.off, a.off + fnLen);
      let insns: { address: number | bigint; size: number; mnemonic: string; opStr: string }[] = [];
      try { insns = cs.disasm(fnCode, { address: a.addr, count: maxInstrs }); } catch { try { cs.close(); } catch { /* poisoned */ } cs = new cap.Capstone(archX86, is64 ? mode64 : mode32); continue; }
      if (insns.length === 0) continue;
      const calls: string[] = [];
      const flines: string[] = [];
      for (const i of insns) {
        const addrHex = BigInt(i.address).toString(16);
        const line = `0x${addrHex}  ${i.mnemonic} ${i.opStr}${nameForAddr.get(targetOf(i)) ? ` <${nameForAddr.get(targetOf(i))}>` : ""}`.trimEnd();
        flines.push(line);
        if (i.mnemonic === "call" || i.mnemonic === "jmp") {
          const m = /^0x([0-9a-f]+)$/.exec(i.opStr) ?? /^0x[0-9a-f]+ <(.+)>$/.exec(i.opStr);
          if (m) { const target = m[1]!; calls.push(target); allCalls.push(target); }
        }
      }
      // stop at ret + padding? capstone linear sweep already covers; size = last instr end - first
      const size = Number(BigInt(insns[insns.length - 1]!.address) + BigInt(insns[insns.length - 1]!.size) - a.addr);
      details.push({ name: a.name, address: "0x" + a.addr.toString(16), size, instrs: insns.map(i => ({ address: "0x" + BigInt(i.address).toString(16), mnemonic: i.mnemonic, opStr: i.opStr })), calls });
      lines.push(`${a.name}:`, ...flines, "");
    }
  }
  cs.close();
  const strings = extractStrings(buf, 5);
  const importsUsed = [...new Set(allCalls)].filter(c => nameForAddr.get(c) === undefined).slice(0, 200);
  const artifacts: X86DisasmResult["artifacts"] = [];
  artifacts.push(await writeArtifact(input.outputRoot, "x86_disasm.txt", lines.join("\n")));
  artifacts.push(await writeArtifact(input.outputRoot, "x86_disasm.json", JSON.stringify(details.map(d => ({ ...d, instrs: d.instrs.slice(0, 50) })), null, 2)));
  return { file: base, bytes: buf.length, engine: "capstone-wasm", arch: is64 ? "x86-64" : "x86-32", functions: details.length, disassembled: details.reduce((n, d) => n + d.instrs.length, 0), strings, importsUsed, details: details.slice(0, 50), artifacts, degraded: false };
};
const detectArch = (buf: Buffer): string => !buf || buf.length < 5 ? "?" : buf[4] === 2 ? "x86-64" : "x86-32";
const entryOf = (buf: Buffer): bigint => {
  const is64 = buf[4] === 2; const le = buf[5] === 1;
  const rd = (p: number | undefined, n: number): bigint => { let v = 0n; for (let i = n - 1; i >= 0; i--) v = (v << 8n) | BigInt((le ? buf[(p ?? 0) + i] : buf[(p ?? 0) + n - 1 - i]) ?? 0); return v; };
  return rd(is64 ? 0x18 : 0x18, is64 ? 8 : 4);
};
const extractStrings = (buf: Buffer, min: number): { address: string; text: string }[] => {
  const out: { address: string; text: string }[] = [];
  let start = -1;
  for (let i = 0; i < buf.length; i++) {
    const c = buf[i] ?? 0;
    const printable = c >= 0x20 && c < 0x7F;
    if (printable && start < 0) start = i;
    if (!printable && start >= 0) { if (i - start >= min) out.push({ address: "0x" + start.toString(16), text: buf.toString("utf8", start, i) }); start = -1; }
  }
  (buf.length - start >= min && start >= 0) && out.push({ address: " " + start.toString(16), text: buf.toString("utf8", start) });
  return out.slice(0, 5000);
};
interface RawSym { name: string; value: string; size: number; secName: string; }
const elfSymbols = (buf: Buffer, sections: { name: string; addr: bigint; offset: number; size: number; exec: boolean }[]): RawSym[] => {
  const is64 = buf[4] === 2; const le = buf[5] === 1;
  const rd = (p: number | undefined, n: number): bigint => { let v = 0n; for (let i = n - 1; i >= 0; i--) v = (v << 8n) | BigInt((le ? buf[(p ?? 0) + i] : buf[(p ?? 0) + n - 1 - i]) ?? 0); return v; };
  const find = (name: string) => sections.find(s => s.name === name);
  const out: RawSym[] = [];
  for (const table of [".symtab", ".dynsym"]) {
    const sec = find(table);
    if (!sec) continue;
    const strtabSec = find(table === ".symtab" ? ".strtab" : ".dynstr");
    if (!strtabSec) continue;
    const entsize = is64 ? 24 : 16;
    const count = Math.floor(sec.size / entsize);
    for (let i = 1; i < Math.min(count, 20000); i++) {
      const at = sec.offset + i * entsize;
      if (at + entsize > buf.length) break;
      const nameOff = Number(rd(at, 4));
      const value = rd(at + (is64 ? 8 : 4), is64 ? 8 : 4);
      const size = Number(rd(at + (is64 ? 0x10 : 0x14), is64 ? 8 : 4));
      const shndx = Number(rd(at + (is64 ? 0x6 : 0xE), 2));
      let nm = "";
      const e = buf.indexOf(0, strtabSec.offset + nameOff);
      if (e >= 0) nm = buf.toString("utf8", strtabSec.offset + nameOff, e);
      if (!nm) continue;
      out.push({ name: nm, value: value.toString(16), size, secName: shndx === 0 || shndx === 0xFFFF ? "" : (sections[shndx]?.name ?? "") });
    }
  }
  return out;
};
