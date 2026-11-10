import { join } from "node:path";
import type { Ctx } from "../shared.js";

/** 逆向 — 静态与指令层 */
export const ReverseHandlers: Record<string, (ctx: Ctx) => Promise<number>> = {
  "vm-analyze": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [jsDir, dir] = positional;
  if (!jsDir || !dir) {
    console.error("usage: vm-analyze <jsDir> <outdir> [--max-files N] [--min-score N]");
    return 2;
  }
  const { analyzeVmCorpus } = await import("../../domain/vmAnalyze.js");
  out(await analyzeVmCorpus({ jsDir, outputRoot: dir, maxFiles: num(flags["max-files"]), minInterpreterScore: num(flags["min-score"]) }));
  return 0;
  },
  "dom-sinks": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [jsDir, dir] = positional;
  if (!jsDir || !dir) {
    console.error("usage: dom-sinks <jsDir> <outdir>");
    return 2;
  }
  const { scanDomSinks } = await import("../../domain/domSinks.js");
  out(await scanDomSinks({ jsDir, outputRoot: dir }));
  return 0;
  },
  "analyze-gates": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [jsDir, dir] = positional;
  if (!jsDir || !dir) { console.error("usage: analyze-gates <jsDir> <outdir>"); return 2; }
  const { analyzeGates } = await import("../../domain/gates.js");
  out(await analyzeGates({ jsDir, outputRoot: dir }));
  return 0;
  },
  "elf-analyze": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [file, dir] = positional;
  if (!file || !dir) {
    console.error("usage: elf-analyze <binary> <outdir>");
    return 2;
  }
  const { analyzeElf } = await import("../../domain/elfAnalyze.js");
  out(await analyzeElf({ file, outputRoot: dir }));
  return 0;
  },
  "wasm-analyze": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [file, dir] = positional;
  if (!file || !dir) {
    console.error("usage: wasm-analyze <file.wasm> <outdir>");
    return 2;
  }
  const { analyzeWasm } = await import("../../domain/wasmAnalyze.js");
  out(await analyzeWasm({ file, outputRoot: dir }));
  return 0;
  },
  "dex-analyze": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [file, dir] = positional;
  if (!file || !dir) {
    console.error("usage: dex-analyze <file.dex|file.apk> <outdir>");
    return 2;
  }
  const { analyzeDex } = await import("../../domain/dexAnalyze.js");
  let target = file;
  // APK: extract classes.dex in-place to a temp dir next to output
  if (/\.apk$/i.test(file)) {
    const { readFile } = await import("node:fs/promises");
    const { execFile } = await import("node:child_process");
    const { promisify } = await import("node:util");
    const buf = await readFile(file);
    if (buf.readUInt32LE(0) === 0x04034b50) {
      const zipDir = join(dir, "_apk");
      await import("node:fs/promises").then(fs => fs.mkdir(zipDir, { recursive: true }));
      await promisify(execFile)("unzip", ["-o", "-j", file, "classes.dex", "-d", zipDir]);
      target = join(zipDir, "classes.dex");
    }
  }
  out(await analyzeDex({ file: target, outputRoot: dir }));
  return 0;
  },
  "wasm-disasm": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [file, dir] = positional;
  if (!file || !dir) {
    console.error("usage: wasm-disasm <file.wasm> <outdir> [--max-functions N]");
    return 2;
  }
  const { disassembleWasm } = await import("../../domain/wasmDisasm.js");
  const r = await disassembleWasm({ file, outputRoot: dir, maxFunctions: num(flags["max-functions"]) });
  out({ file: r.file, bytes: r.bytes, functions: r.functions, disassembled: r.disassembled, callgraphEdges: r.callgraph.length, topCalls: r.callgraph.slice(0, 20), artifacts: r.artifacts });
  return 0;
  },
  "dex-disasm": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [file, dir] = positional;
  if (!file || !dir) {
    console.error("usage: dex-disasm <file.dex|.apk> <outdir> [--max-methods N] [--class-filter RE]");
    return 2;
  }
  const { disassembleDex } = await import("../../domain/dexDisasm.js");
  let target = file;
  if (/\.apk$/i.test(file)) {
    const { readFile } = await import("node:fs/promises");
    const { execFile } = await import("node:child_process");
    const { promisify } = await import("node:util");
    const buf = await readFile(file);
    if (buf.readUInt32LE(0) === 0x04034b50) {
      const zipDir = join(dir, "_apk");
      const fs = await import("node:fs/promises");
      await fs.mkdir(zipDir, { recursive: true });
      await promisify(execFile)("unzip", ["-o", "-j", file, "classes.dex", "-d", zipDir]);
      target = join(zipDir, "classes.dex");
    }
  }
  const r = await disassembleDex({ file: target, outputRoot: dir, maxMethods: num(flags["max-methods"]), classFilter: typeof flags["class-filter"] === "string" ? flags["class-filter"] : undefined });
  out({ file: r.file, bytes: r.bytes, methods: r.methods, disassembled: r.disassembled, sample: r.details.slice(0, 3), topStringXrefs: r.stringXrefs.filter(x => /^(?:https?:|str )/.test(x.str) || x.str.length > 8).slice(0, 20), artifacts: r.artifacts });
  return 0;
  },
  "x86-disasm": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [file, dir] = positional;
  if (!file || !dir) {
    console.error("usage: x86-disasm <elf-binary> <outdir> [--max-functions N] [--max-instrs N]");
    return 2;
  }
  const { disassembleX86 } = await import("../../domain/x86Disasm.js");
  const r = await disassembleX86({ file, outputRoot: dir, maxFunctions: num(flags["max-functions"]), maxInstrs: num(flags["max-instrs"]) });
  out({ file: r.file, engine: r.engine, arch: r.arch, degraded: r.degraded, reason: r.reason, bytes: r.bytes, functions: r.functions, disassembled: r.disassembled, calls: r.importsUsed.slice(0, 40), topFunctions: r.details.map(f => ({ name: f.name, address: f.address, size: f.size, instrs: f.instrs.length })), artifacts: r.artifacts });
  return 0;
  },
};
