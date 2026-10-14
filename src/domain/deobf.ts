import { writeFile, mkdir, readFile, readdir } from "node:fs/promises";
import { join, basename } from "node:path";

/** JS deobfuscation PRE-PASS for the extraction pipeline (routes, domSinks,
 *  gates, permTree): string-array unpacking (obfuscator.io style) and
 *  control-flow flattening simplification. Not a general decompiler — it
 *  restores the STRING LITERALS the regex extractors need, which obfuscation
 *  destroys by hiding every "/api/..." literal inside an array + decoder.
 *
 *  Deterministic, pure text transforms, zero execution of target code. */

export interface DeobfInput {
  /** directory of harvested .js files (harvest stage js/ dir) */
  readonly jsDir: string;
  readonly outputRoot: string;
  readonly maxFiles?: number;
  readonly maxFileBytes?: number;
}

export interface DeobfResult {
  readonly files: number;
  readonly restored: { file: string; stringsRestored: number; switchSimplified: boolean }[];
  readonly artifacts: { path: string; bytes: number }[];
}

const MAX_FILE = 8 * 1024 * 1024;

/** Find a string-array + decoder pattern and inline it.
 *  obfuscator.io shape:
 *    var _0xabc = ['\x2f\x61\x70\x69', '...'];          (array, hex/unicode escaped)
 *    function _0xdec(i, j) { ... _0xabc ... }            (decoder)
 *    ... _0xdec(0x1, 0x2) ...                            (call sites)
 *  Strategy: locate the largest all-string array literal, then replace
 *  every `decoder(<num>)` / `decoder(<num>, <num>)` call whose decoder name
 *  is used ONLY with that array (cheap heuristic) with the literal. */
const STRING_ARRAY_RE = /(?:var|let|const)\s+(_[0-9a-fA-F]{4,8}|[A-Za-z_$][\w$]*)\s*=\s*\[((?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')(?:\s*,\s*(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')){5,})\]\s*;/g;

const unescapeStr = (raw: string): string => {
  // raw includes quotes
  const inner = raw.slice(1, -1);
  return inner.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\n/g, "\n").replace(/\\r/g, "\r").replace(/\\t/g, "\t")
    .replace(/\\'/g, "'").replace(/\\"/g, '"').replace(/\\\\/g, "\\");
};

/** Replace hex-number call args and index the array. */
const inlineArray = (code: string, arrayName: string, values: string[]): { code: string; count: number } => {
  // call sites: arrayName[0x1] or decoder(...) — we only handle DIRECT indexing
  // (covers obfuscator.io's "string array direct access" mode) and the common
  // decoder form where the decoder body is `return arr[idx - offset]`.
  let count = 0;
  // direct: _0xabc[0x2] / _0xabc[2]
  const direct = new RegExp(`${arrayName.replace(/\$/g, "\\$")}\\s*\\[\\s*(0x[0-9a-fA-F]+|\\d+)\\s*\\]`, "g");
  code = code.replace(direct, (m, num) => {
    const i = Number(num);
    if (i >= 0 && i < values.length) { count += 1; return JSON.stringify(values[i]); }
    return m;
  });
  return { code, count };
};

/** Decoder-form: function _0xf(a,b){ ... return _0xarr[a-0x99]; }
 *  Extract offset from the body, then replace decoder(0xN) calls. */
const inlineDecoder = (code: string, arrayName: string, values: string[], decoderName: string): { code: string; count: number } => {
  const decRe = new RegExp(`function\\s+${decoderName.replace(/\$/g, "\\$")}\\s*\\(([^)]*)\\)\\s*\\{`);
  const m = decRe.exec(code);
  if (!m) return { code, count: 0 };
  const bodyStart = m.index + m[0].length;
  // find the return that indexes the array
  const retRe = new RegExp(`return\\s+${arrayName.replace(/\$/g, "\\$")}\\s*\\[\\s*\\w+\\s*-\\s*(0x[0-9a-fA-F]+|\\d+)\\s*\\]`);
  const body = code.slice(bodyStart, bodyStart + 2000);
  const rm = retRe.exec(body);
  if (!rm) return { code, count: 0 };
  const offset = Number(rm[1]);
  let count = 0;
  const callRe = new RegExp(`${decoderName.replace(/\$/g, "\\$")}\\s*\\(\\s*(0x[0-9a-fA-F]+|\\d+)\\s*(?:,\\s*[^)]*)?\\)`, "g");
  code = code.replace(callRe, (full, num) => {
    const i = Number(num) - offset;
    if (i >= 0 && i < values.length) { count += 1; return JSON.stringify(values[i]); }
    return full;
  });
  return { code, count };
};

/** Control-flow flattening: `while(true){ switch(X[_0xi++]){ case '0': ... continue; } }`
 *  Simplification: drop the dispatcher, keep case bodies in order. This is
 *  the obfuscator.io flat shape; restoring exact order needs the index map —
 *  we approximate by sequencing cases in declaration order, which is right
 *  for straight-line code (the common case for route tables). */
const simplifyFlattened = (code: string): { code: string; simplified: boolean } => {
  // obfuscator.io flat loop: while(!![]){ switch(_0x1a2b[_0x3c++]){ case '0': ... } }
  // and the numeric variant while(0x1)/while(!0x0)
  const flatRe = /while\s*\(\s*(?:!!\[\]|!0x0|0x1|true)\s*\)\s*\{\s*switch\s*\(\s*\w+\s*\[\s*\w+\+\+\s*\]\s*\)\s*\{/;
  if (!flatRe.test(code)) return { code, simplified: false };
  let simplified = false;
  // Replace `case 'n': ... continue;` blocks: strip case labels + continue,
  // keep statements.
  code = code.replace(/case\s*(?:"[^"]*"|'[^']*'|0x[0-9a-fA-F]+|\d+)\s*:\s*/g, () => { simplified = true; return ""; });
  return { code, simplified };
};

export const deobfuscateCorpus = async (input: DeobfInput): Promise<DeobfResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  const outDir = join(input.outputRoot, "js-deobf");
  await mkdir(outDir, { recursive: true });
  const maxBytes = input.maxFileBytes ?? MAX_FILE;

  let names: string[] = [];
  try { names = (await readdir(input.jsDir)).filter((n) => n.endsWith(".js")).slice(0, input.maxFiles ?? 200); } catch { names = []; }

  const restored: DeobfResult["restored"] = [];
  for (const name of names) {
    const src = join(input.jsDir, name);
    let code: string;
    try { code = await readFile(src, "utf8"); } catch { continue; }
    if (code.length > maxBytes) continue;

    let stringsRestored = 0;
    // 1. string arrays (largest first — the main array dominates)
    const arrays: { name: string; values: string[]; matchLen: number }[] = [];
    for (const m of code.matchAll(STRING_ARRAY_RE)) {
      const name = m[1]!;
      const rawList = m[2]!;
      const values = [...rawList.matchAll(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g)].map((x) => unescapeStr(x[0]));
      arrays.push({ name, values, matchLen: m[0].length });
    }
    arrays.sort((a, b) => b.matchLen - a.matchLen);
    for (const arr of arrays.slice(0, 3)) {
      // direct indexing
      const d = inlineArray(code, arr.name, arr.values);
      code = d.code; stringsRestored += d.count;
      // decoder form: find functions that only index this array
      const decRe = /function\s+(_[0-9a-fA-F]{4,8}|[A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{/g;
      for (const dm of code.matchAll(decRe)) {
        const window = code.slice(dm.index ?? 0, (dm.index ?? 0) + 300);
        if (new RegExp(`return\\s+${arr.name.replace(/\$/g, "\\$")}\\s*\\[`).test(window)) {
          const r = inlineDecoder(code, arr.name, arr.values, dm[1]!);
          code = r.code; stringsRestored += r.count;
          break; // one decoder per array in practice
        }
      }
    }

    // 2. control-flow flattening simplification
    const cf = simplifyFlattened(code);
    code = cf.code;

    // 3. unicode escapes anywhere else (obfuscator leaves \x68\x74\x74\x70 in non-array strings)
    const before = code.length;
    code = code.replace(/(?:\\x[0-9a-fA-F]{2}){3,}/g, (m) => {
      const s = m.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
      // only restore when it decodes to printable ASCII (URLs, words)
      return /^[\x20-\x7e]+$/.test(s) ? JSON.stringify(s).slice(1, -1) : m;
    });
    if (code.length !== before) stringsRestored += 1;

    if (stringsRestored > 0 || cf.simplified) {
      await writeFile(join(outDir, name), code, "utf8");
      restored.push({ file: basename(name), stringsRestored, switchSimplified: cf.simplified });
    }
  }

  const bodyStr = JSON.stringify({ files: names.length, restored }, null, 2);
  const path = join(input.outputRoot, "deobf_summary.json");
  await writeFile(path, bodyStr, "utf8");
  return { files: names.length, restored, artifacts: [{ path, bytes: Buffer.byteLength(bodyStr) }] };
};
