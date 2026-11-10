import { describe, expect, it } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { analyzeElf } from "../src/domain/elfAnalyze.js";
import { analyzeWasm } from "../src/domain/wasmAnalyze.js";
import { analyzeDex } from "../src/domain/dexAnalyze.js";

// Minimal WASM: (module (func (export "add") ...)) with name section — built by hand
function leb(n: number): number[] { const out: number[] = []; do { let b = n & 0x7F; n >>>= 7; if (n) b |= 0x80; out.push(b); } while (n); return out; }
function wstr(s: string): number[] { const b = [...s].map(c => c.charCodeAt(0)); return [...leb(b.length), ...b]; }
function sec(id: number, payload: number[]): number[] { return [id, ...leb(payload.length), ...payload]; }
const miniWasm = new Uint8Array([
  0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
  ...sec(1, [...leb(1), 0x60, ...leb(2), 0x7F, 0x7F, ...leb(1), 0x7F]),
  ...sec(3, [...leb(1), 0]),
  ...sec(7, [...leb(1), ...wstr("add"), 0x00, 0]),
  ...sec(10, [...leb(1), ...leb(7), 0x00, 0x20, 0x00, 0x20, 0x01, 0x6A, 0x0B]),
  ...sec(0, [...wstr("name"), 0x01, ...leb([...leb(1), 0, ...wstr("addfn")].length), ...leb(1), 0, ...wstr("addfn")]),
]);

// Minimal DEX: header + string_ids pointing at "Lfoo;" — validity check only on real structure
describe("binary-analyze", () => {
  it("wasm: parses hand-built module with name section", async () => {
    const dir = await mkdtemp(join(tmpdir(), "wasm-"));
    const f = join(dir, "mini.wasm");
    await writeFile(f, miniWasm);
    const r = await analyzeWasm({ file: f, outputRoot: join(dir, "out") });
    expect(r.valid).toBe(true);
    expect(r.functions).toBe(1);
    expect(r.exports[0]?.name).toBe("add");
    expect(r.nameSection?.functions[0]?.name).toBe("addfn");
  });
  it("wasm: rejects non-wasm bytes", async () => {
    const dir = await mkdtemp(join(tmpdir(), "wasm-"));
    const f = join(dir, "fake.wasm");
    await writeFile(f, Buffer.from("not a wasm at all"));
    const r = await analyzeWasm({ file: f, outputRoot: join(dir, "out") });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("not-wasm-magic");
  });
  it("elf: rejects non-elf file", async () => {
    const dir = await mkdtemp(join(tmpdir(), "elf-"));
    const f = join(dir, "plain.txt");
    await writeFile(f, "hello world not elf");
    const r = await analyzeElf({ file: f, outputRoot: join(dir, "out") });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("not-elf");
  });
  it("dex: rejects non-dex file", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dex-"));
    const f = join(dir, "plain.txt");
    await writeFile(f, Buffer.alloc(200, 0x41)); // 200 bytes, no dex magic
    const r = await analyzeDex({ file: f, outputRoot: join(dir, "out") });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("not-dex-magic");
  });
});

import { disassembleWasm } from "../src/domain/wasmDisasm.js";
import { disassembleDex } from "../src/domain/dexDisasm.js";

describe("instruction-layer disassembly", () => {
  it("wasm-disasm: disassembles hand-built module with resolved call names", async () => {
    const dir = await mkdtemp(join(tmpdir(), "wd-"));
    const f = join(dir, "mini.wasm");
    // (module (import "env" "log" (func)) (func $add (param i32 i32)(result i32) local.get 0 local.get 1 i32.add) (func $main i32.const 7 call $add) (export "add") (name section))
    await writeFile(f, miniWasm);
    const r = await disassembleWasm({ file: f, outputRoot: join(dir, "out") });
    expect(r.disassembled).toBeGreaterThan(0);
    const addFn = r.details.find(d => d.name === "addfn" || d.name === "f1");
    expect(addFn).toBeTruthy();
    expect(addFn!.instrs.some(i => i.name === "i32.add")).toBe(true);
  });
  it("wasm-disasm: rejects garbage", async () => {
    const dir = await mkdtemp(join(tmpdir(), "wd-"));
    const f = join(dir, "g.wasm");
    await writeFile(f, Buffer.from("garbage bytes here for sure"));
    const r = await disassembleWasm({ file: f, outputRoot: join(dir, "out") });
    expect(r.disassembled).toBe(0);
  });
  it("dex-disasm: rejects non-dex", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dd-"));
    const f = join(dir, "x.dex");
    await writeFile(f, Buffer.alloc(200, 1));
    const r = await disassembleDex({ file: f, outputRoot: join(dir, "out") });
    expect(r.disassembled).toBe(0);
  });
});

import { disassembleX86 } from "../src/domain/x86Disasm.js";

describe("x86 instruction-layer disassembly", () => {
  it("degrades gracefully on non-ELF garbage", async () => {
    const dir = await mkdtemp(join(tmpdir(), "x86-"));
    const f = join(dir, "g.bin");
    await writeFile(f, Buffer.from("not an elf at all"));
    const r = await disassembleX86({ file: f, outputRoot: join(dir, "out") });
    // 非ELF: 无exec段 → 0函数; 引擎在则degraded=false但无函数, 引擎不在则degraded=true — 两者都不崩
    expect(r.functions).toBe(0);
    expect(r.disassembled).toBe(0);
  });
  it("disassembles hand-built ELF64 with one exec function", async () => {
    const dir = await mkdtemp(join(tmpdir(), "x86-"));
    const f = join(dir, "t.elf");
    // 最小ELF64: ehdr + .text section(code: push rbp; mov rbp,rsp; mov eax,42; ret) + shstrtab
    const ehsize = 64, shentsize = 64, shnum = 3;
    const shstr = Buffer.from("\0.text\0.shstrtab\0");
    const code = Buffer.from([0x55, 0x48, 0x89, 0xE5, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3]);
    const textOff = ehsize, shstrOff = textOff + code.length;
    const shoff = shstrOff + shstr.length;
    const eh = Buffer.alloc(ehsize);
    eh.write("\x7fELF", 0, "ascii"); eh[4] = 2; eh[5] = 1; eh[6] = 1; // ELF64 LE
    eh.writeUInt16LE(3, 16); // EM_X86_64
    eh.writeUInt32LE(1, 20); // ET_REL? use ET_EXEC
    eh.writeUInt16LE(ehsize, 52); // e_ehsize @ 0x34
    eh.writeUInt16LE(shentsize, 58); // e_shentsize @ 0x3a
    eh.writeUInt16LE(shnum, 60); // e_shnum @ 0x3c
    eh.writeUInt16LE(shnum - 1, 62); // e_shstrndx @ 0x3e
    eh.writeBigUInt64LE(BigInt(shoff), 40); // e_shoff 0x28
    eh.writeBigUInt64LE(0x1000n, 24); // e_entry
    const sh = Buffer.alloc(shentsize * shnum);
    // [0] NULL, [1] .text (PROGBITS|EXEC), [2] .shstrtab
    sh.writeUInt32LE(1, shentsize * 1 + 0); // name off ".text"
    sh.writeUInt32LE(1, shentsize * 1 + 4); // PROGBITS
    sh.writeBigUInt64LE(0x1000n, shentsize * 1 + 0x10); // addr
    sh.writeUInt32LE(textOff, shentsize * 1 + 0x18);
    sh.writeBigUInt64LE(BigInt(code.length), shentsize * 1 + 0x20);
    sh.writeBigUInt64LE(0x4n, shentsize * 1 + 0x08); // SHF_EXECINSTR
    sh.writeUInt32LE(7, shentsize * 2 + 0); // name off ".shstrtab"
    sh.writeUInt32LE(3, shentsize * 2 + 4); // STRTAB
    sh.writeUInt32LE(shstrOff, shentsize * 2 + 0x18);
    sh.writeBigUInt64LE(BigInt(shstr.length), shentsize * 2 + 0x20);
    await writeFile(f, Buffer.concat([eh, code, shstr, sh]));
    const r = await disassembleX86({ file: f, outputRoot: join(dir, "out") });
    if (r.engine === "none") return; // capstone未装的机器上走降级路径
    expect(r.functions).toBeGreaterThanOrEqual(1);
    const all = r.details.flatMap(fn => fn.instrs);
    expect(all.some(i => i.mnemonic === "mov" && i.opStr.includes("0x2a"))).toBe(true);
  });
});
