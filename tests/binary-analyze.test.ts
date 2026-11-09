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
