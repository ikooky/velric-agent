import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { writeArtifact } from "../adapters/artifacts.js";

export interface ElfAnalyzeInput {
  readonly file: string;
  readonly outputRoot: string;
}
export interface ElfSection { name: string; type: number; flags: number; addr: string; offset: number; size: number; }
interface RawSection { name: string; type: number; flags: number; addr: bigint; offset: number; size: number; }
export interface ElfSymbolRow { name: string; value: string; size: number; bind: string; type: string; shndx: number; }
interface RawSymbol { name: string; value: bigint; size: number; bind: string; type: string; shndx: number }
export interface ElfAnalysis {
  readonly file: string;
  readonly bytes: number;
  readonly valid: boolean;
  readonly reason?: string;
  readonly class: "ELF32" | "ELF64" | "";
  readonly endianness: "LE" | "BE" | "";
  readonly machine: string;
  readonly type: string;
  readonly entry: string;
  readonly interpreter?: string;
  readonly buildId?: string;
  readonly sections: ElfSection[];
  readonly programs: { type: string; flags: string; vaddr: string; filesz: number; memsz: number }[];
  readonly dynamicDependencies: string[];
  readonly soname?: string;
  readonly symbols: { count: number; exported: string[]; imported: string[]; sample: ElfSymbolRow[] };
  readonly hardening: { readonly stripped: boolean; readonly stackCanary: boolean; readonly nx: boolean; readonly pie: boolean; readonly relro: "none" | "partial" | "full"; readonly fortify: boolean; readonly rpath?: string; readonly runpath?: string };
  readonly notes: string[];
  readonly artifacts: { path: string; bytes: number }[];
}

const MACHINES: Record<number, string> = { 0x03: "x86", 0x3E: "x86-64", 0x28: "ARM", 0xB7: "AArch64", 0x08: "MIPS", 0xF3: "RISC-V", 0x14: "PowerPC", 0x15: "PowerPC64", 0x16: "S390", 0x32: "IA-64", 0x12: "SPARC", 0x2A: "M68k", 0x04: "NS32K" };
const ETYPES: Record<number, string> = { 1: "REL", 2: "EXEC", 3: "DYN(PIE/shared)", 4: "CORE" };
const PTYPES: Record<number, string> = { 0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 6: "PHDR", 7: "TLS", 0x6474e550: "GNU_EH_FRAME", 0x6474e551: "GNU_STACK", 0x6474e552: "GNU_RELRO", 0x6474e553: "GNU_PROPERTY" };

class Reader {
  readonly buf: Buffer; pos = 0;
  constructor(buf: Buffer) { this.buf = buf; }
  u8(): number { return this.buf.readUInt8(this.pos++); }
  u16(): number { const v = this.buf.readUInt16LE(this.pos); this.pos += 2; return v; }
  u16be(): number { const v = this.buf.readUInt16BE(this.pos); this.pos += 2; return v; }
  u32(): number { const v = this.buf.readUInt32LE(this.pos); this.pos += 4; return v; }
  u32be(): number { const v = this.buf.readUInt32BE(this.pos); this.pos += 4; return v; }
  u64(): bigint { const v = this.buf.readBigUInt64LE(this.pos); this.pos += 8; return v; }
  u64be(): bigint { const v = this.buf.readBigUInt64BE(this.pos); this.pos += 8; return v; }
  cstr(): string { const end = this.buf.indexOf(0, this.pos); if (end === -1) return ""; const s = this.buf.toString("utf8", this.pos, end); this.pos = end + 1; return s; }
  strAt(offset: number): string { const end = this.buf.indexOf(0, offset); if (end === -1) return ""; return this.buf.toString("utf8", offset, end); }
  skip(n: number): void { this.pos += n; }
}

export const analyzeElf = async (input: ElfAnalyzeInput): Promise<ElfAnalysis> => {
  const buf = await readFile(input.file);
  const base = { file: basename(input.file), bytes: buf.length };
  if (buf.length < 64 || buf.readUInt32BE(0) !== 0x7F454C46) {
    return { ...base, valid: false, reason: "not-elf", class: "", endianness: "", machine: "", type: "", entry: "0x0", sections: [], programs: [], dynamicDependencies: [], symbols: { count: 0, exported: [], imported: [], sample: [] }, hardening: { stripped: false, stackCanary: false, nx: false, pie: false, relro: "none", fortify: false }, notes: [], artifacts: [] };
  }
  const r = new Reader(buf);
  r.pos = 4;
  const eiClass = r.u8(); // 1=32 2=64
  const eiData = r.u8(); // 1=LE 2=BE
  r.skip(10); // version/osabi/abiversion/pad
  const is64 = eiClass === 2;
  const be = eiData === 2;
  const u16 = () => (be ? r.u16be() : r.u16());
  const u32 = () => (be ? r.u32be() : r.u32());
  const u64 = () => (be ? r.u64be() : r.u64());
  const type = ETYPES[u16() & 3] ?? "?";
  const machineNum = u16();
  const machineName = MACHINES[machineNum] ?? `unknown(${machineNum})`;
  if (is64) { r.pos = 24; } else { r.pos = 24; }
  const entry = is64 ? u64() : BigInt(u32());
  const phoff = is64 ? u64() : BigInt(u32());
  const shoff = is64 ? u64() : BigInt(u32());
  r.skip(4); // e_flags
  r.skip(2); // e_ehsize
  const phentsize = u16();
  const phnum = u16();
  const shentsize = u16();
  const shnum = u16();
  const shstrndx = u16();
  // Sections
  const sections: RawSection[] = [];
  let shstrTab = 0;
  if (shoff > 0n && shnum > 0 && shoff < buf.length) {
    for (let i = 0; i < Math.min(shnum, 256); i++) {
      const at = Number(shoff) + i * shentsize;
      if (at + shentsize > buf.length) break;
      r.pos = at;
      const nameOff = u32();
      const secType = u32();
      const flags = is64 ? u64() : BigInt(u32());
      const addr = is64 ? u64() : BigInt(u32());
      r.skip(is64 ? 8 : 4); // offset — read below for accuracy
      r.pos = at + (is64 ? 24 : 16);
      const offset = Number(is64 ? u64() : BigInt(u32()));
      const size = Number(is64 ? u64() : BigInt(u32()));
      sections.push({ name: `#${nameOff}`, type: secType, flags: Number(flags), addr, offset, size });
      if (i === shstrndx) shstrTab = offset;
    }
    if (shstrTab > 0) {
      for (const s of sections) {
        const off = shstrTab + Number(s.name.slice(1));
        if (off < buf.length) s.name = r.strAt(off);
      }
    }
  }
  // Program headers
  const rawPrograms: { type: string; flags: string; vaddr: bigint; filesz: number; memsz: number }[] = [];
  let interpreter: string | undefined;
  let buildId: string | undefined;
  let gnuStackFlags = -1;
  let hasRelro = false;
  let dynamicOffset = -1;
  let dynamicSize = 0;
  if (phoff > 0n && phnum > 0 && phoff < buf.length) {
    for (let i = 0; i < Math.min(phnum, 128); i++) {
      const at = Number(phoff) + i * phentsize;
      if (at + phentsize > buf.length) break;
      // ELF64 Phdr: type(4) flags(4) offset(8) vaddr(8) paddr(8) filesz(8) memsz(8) align(8)
      // ELF32 Phdr: type(4) offset(4) vaddr(4) paddr(4) filesz(4) memsz(4) flags(4) align(4)
      r.pos = at;
      const ptypeNum = u32();
      let offsetNum: number; let vaddr: bigint; let filesz: number; let memsz: number; let pflags: number;
      if (is64) {
        pflags = u32();
        offsetNum = Number(u64());
        vaddr = u64();
        r.skip(8); // paddr
        filesz = Number(u64());
        memsz = Number(u64());
      } else {
        offsetNum = u32();
        vaddr = BigInt(u32());
        r.skip(4); // paddr
        filesz = u32();
        memsz = u32();
        pflags = u32();
      }
      const pname = PTYPES[ptypeNum] ?? `ptype(${ptypeNum})`;
      const flagStr = is64 ? ["", "R", "W", "RW", "E", "RE", "", "RWE"][pflags & 7] ?? "?" : "";
      rawPrograms.push({ type: pname, flags: flagStr, vaddr, filesz, memsz });
      if (ptypeNum === 3 && offsetNum < buf.length) { r.pos = offsetNum; interpreter = r.cstr(); }
      if (ptypeNum === 4) {
        // PT_NOTE: scan for GNU build-id (owner "GNU", type 3)
        let p = offsetNum;
        const end = Math.min(offsetNum + filesz, buf.length);
        while (p + 16 <= end) {
          r.pos = p;
          const namesz = u32(); const descsz = u32(); const ntype = u32();
          const owner = buf.toString("ascii", p + 12, Math.min(p + 12 + namesz, end)).replace(/\0.*$/, "");
          const descAt = p + 12 + namesz + ((4 - (namesz % 4)) % 4);
          if (owner === "GNU" && ntype === 3 && descsz > 0 && descAt + descsz <= buf.length) {
            buildId = buf.toString("hex", descAt, descAt + descsz);
          }
          p = descAt + descsz;
        }
      }
      if (ptypeNum === 0x6474e551) gnuStackFlags = pflags;
      if (ptypeNum === 0x6474e552) hasRelro = true;
      if (ptypeNum === 2) { dynamicOffset = offsetNum; dynamicSize = filesz; }
    }
  }
  // Dynamic section: dependencies / soname / rpath / runpath / BIND_NOW
  const dynamicDependencies: string[] = [];
  let soname: string | undefined;
  let rpath: string | undefined;
  let runpath: string | undefined;
  let bindNow = false;
  let hasSymbolic = false;
  if (dynamicOffset > 0 && dynamicSize > 0) {
    let p = dynamicOffset;
    const end = Math.min(dynamicOffset + dynamicSize, buf.length);
    const tagSize = is64 ? 16 : 8;
    const entries: { tag: bigint; val: bigint }[] = [];
    while (p + tagSize <= end) {
      r.pos = p;
      const tag = is64 ? u64() : BigInt(u32());
      const val = is64 ? u64() : BigInt(u32());
      if (tag === 0n) break;
      entries.push({ tag, val });
      p += tagSize;
    }
    // find strtab addr
    let strtabAddr = entries.find(e => e.tag === 5n)?.val ?? 0n;
    const strtabOffset = addrToOffset(strtabAddr, sections);
    if (strtabOffset > 0) {
      for (const e of entries) {
        const at = strtabOffset + Number(e.val);
        if (e.tag === 1n && at < buf.length) dynamicDependencies.push(r.strAt(at));
        if (e.tag === 14n && at < buf.length) soname = r.strAt(at);
        if (e.tag === 15n && at < buf.length) rpath = r.strAt(at);
        if (e.tag === 29n && at < buf.length) runpath = r.strAt(at);
      }
    }
    // BIND_NOW arrives via DT_BIND_NOW, DT_FLAGS.DF_BIND_NOW (0x8) or DT_FLAGS_1.DF_1_NOW (0x1)
    bindNow = entries.some(e => e.tag === 24n)
      || entries.some(e => e.tag === 30n && (e.val & 0x8n) !== 0n)
      || entries.some(e => e.tag === 0x6FFFFFFBn && (e.val & 0x1n) !== 0n);
    hasSymbolic = entries.some(e => e.tag === 16n);
  }
  // Symbols via .dynsym / .symtab
  const exported: string[] = [];
  const imported: string[] = [];
  const sample: RawSymbol[] = [];
  let symbolCount = 0;
  for (const secName of [".dynsym", ".symtab"]) {
    const symSec = sections.find(s => s.name === secName);
    if (!symSec) continue;
    const strSecName = secName === ".dynsym" ? ".dynstr" : ".strtab";
    const strSec = sections.find(s => s.name === strSecName);
    if (!strSec) continue;
    const entsize = is64 ? 24 : 16;
    const n = Math.floor(symSec.size / entsize);
    for (let i = 0; i < Math.min(n, 200000); i++) {
      const at = symSec.offset + i * entsize;
      if (at + entsize > buf.length) break;
      r.pos = at;
      const nameOff = u32();
      r.pos = at + 4;
      const info = r.u8();
      r.skip(1); // other
      const shndx = u16();
      const value = is64 ? u64() : BigInt(u32());
      const size = is64 ? Number((() => { r.pos = at + 16; return u64(); })()) : u32();
      const bind = info >> 4; const stype = info & 0xF;
      const name = strSec.offset + nameOff < buf.length ? r.strAt(strSec.offset + nameOff) : "";
      symbolCount++;
      const bindName = ["LOCAL", "GLOBAL", "WEAK"][bind] ?? `bind(${bind})`;
      const typeName = ["NOTYPE", "OBJECT", "FUNC", "SECTION", "FILE", "COMMON", "TLS"][stype] ?? `type(${stype})`;
      if (name && bindName !== "LOCAL" && shndx !== 0) exported.push(name);
      else if (name && shndx === 0 && bindName !== "LOCAL") imported.push(name);
      if (name && sample.length < 40 && (bindName !== "LOCAL")) sample.push({ name, value, size, bind: bindName, type: typeName, shndx });
    }
  }
  // Hardening verdicts
  const canarySyms = [...exported, ...imported].some(n => n === "__stack_chk_fail" || n === "__stack_chk_guard");
  const dynstr = buf.toString("latin1");
  const fortify = /_chk@|__chk_fail|_FORTIFY/.test([...imported].join(" "));
  const nx = gnuStackFlags === -1 ? true : (gnuStackFlags & 1) === 0; // PF_X absent
  const relro: ElfAnalysis["hardening"]["relro"] = !hasRelro ? "none" : bindNow ? "full" : "partial";
  const notes: string[] = [];
  if (type.startsWith("DYN")) notes.push("PIE or shared object (ET_DYN)");
  if (interpreter && type.startsWith("DYN")) notes.push("dynamic PIE executable");
  if (canarySyms) notes.push("stack canary present (__stack_chk_*)");
  else notes.push("no stack canary imports — likely no -fstack-protector");
  if (!nx) notes.push("GNU_STACK executable — NX disabled");
  if (relro === "none") notes.push("no RELRO segment");
  else if (relro === "partial") notes.push("partial RELRO (no BIND_NOW)");
  if (hasSymbolic) notes.push("DT_SYMBOLIC set (unusual)");
  const stripped = !sections.some(s => s.name === ".symtab");
  const artifacts: ElfAnalysis["artifacts"] = [];
  const report = {
    ...base, valid: true, class: is64 ? "ELF64" : "ELF32", endianness: be ? "BE" : "LE",
    machine: machineName, type, entry: entry.toString(), interpreter, buildId,
    sections: sections.map(s => ({ name: s.name, type: s.type, addr: s.addr.toString(), offset: s.offset, size: s.size, flags: s.flags })),
    programs: rawPrograms.map(p => ({ ...p, vaddr: `0x${p.vaddr.toString(16)}` })), dynamicDependencies, soname, symbols: { count: symbolCount, exportedCount: exported.length, importedCount: imported.length, exportedTop: exported.slice(0, 500), importedTop: imported.slice(0, 2000), sample: sample.map(sy => ({ ...sy, value: `0x${sy.value.toString(16)}` })) },
    hardening: { stripped, stackCanary: canarySyms, nx, pie: type.startsWith("DYN") && !!interpreter, relro, fortify, rpath, runpath },
    notes,
  };
  artifacts.push(await writeArtifact(input.outputRoot, "elf_analysis.json", JSON.stringify(report, (_, v) => typeof v === "bigint" ? `0x${v.toString(16)}` : v, 2)));
  const md = [
    `# ELF analysis — ${base.file}`, "",
    `- ${report.class} ${report.endianness} ${report.machine}, type=${type}, entry=0x${entry.toString(16)}`,
    `- bytes=${base.bytes} build-id=${buildId ?? "-"} interpreter=${interpreter ?? "-"}`,
    `- sections=${sections.length} programs=${rawPrograms.length} symbols=${symbolCount} (exported ${exported.length}, imported ${imported.length})`,
    `- deps: ${dynamicDependencies.join(", ") || "-"}`,
    `- hardening: stripped=${stripped} canary=${canarySyms} NX=${nx} PIE=${report.hardening.pie} RELRO=${relro} fortify=${fortify}`,
    "", "## Hardening notes", ...notes.map(n => `- ${n}`), "",
    "## Imported (attack surface: libc functions used)", ...imported.slice(0, 120).map(n => `- ${n}`), "",
    "## Exported", ...exported.slice(0, 120).map(n => `- ${n}`),
  ].join("\n");
  artifacts.push(await writeArtifact(input.outputRoot, "elf_report.md", md));
  return {
    ...base, valid: true, class: is64 ? "ELF64" : "ELF32", endianness: be ? "BE" : "LE", machine: machineName, type,
    entry: `0x${entry.toString(16)}`, interpreter, buildId,
    sections: sections.map(s => ({ ...s, addr: `0x${s.addr.toString(16)}` })),
    programs: rawPrograms.map(p => ({ ...p, vaddr: `0x${p.vaddr.toString(16)}` })),
    dynamicDependencies, soname,
    symbols: { count: symbolCount, exported: exported.slice(0, 500), imported: imported.slice(0, 2000), sample: sample.map(sy => ({ ...sy, value: `0x${sy.value.toString(16)}` })) },
    hardening: { stripped, stackCanary: canarySyms, nx, pie: type.startsWith("DYN") && !!interpreter, relro, fortify, rpath, runpath },
    notes, artifacts,
  };
};

const addrToOffset = (addr: bigint, sections: RawSection[]): number => {
  for (const s of sections) if (addr >= s.addr && addr < s.addr + BigInt(s.size) && s.type !== 8) return s.offset + Number(addr - s.addr);
  return 0;
};
