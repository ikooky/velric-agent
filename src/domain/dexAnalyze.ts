import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { writeArtifact } from "../adapters/artifacts.js";

export interface DexAnalyzeInput { readonly file: string; readonly outputRoot: string; }
export interface DexClass { readonly name: string; readonly superClass: string; readonly accessFlags: number; readonly methods: { name: string; proto: string }[]; readonly fields: string[]; }
export interface DexAnalysis {
  readonly file: string; readonly bytes: number; readonly valid: boolean; readonly reason?: string;
  readonly version: string;
  readonly strings: number;
  readonly classes: number;
  readonly methods: number;
  readonly fields: number;
  readonly classDefs: DexClass[];
  readonly stringSamples: string[];
  readonly urlLike: string[];
  readonly secretLike: { kind: string; value: string }[];
  readonly artifacts: { path: string; bytes: number }[];
}

class Dx {
  pos = 0;
  readonly buf: Buffer;
  truncated = false;
  constructor(buf: Buffer) { this.buf = buf; }
  // Bounds-guarded: hostile header offsets must degrade, not throw ERR_OUT_OF_RANGE.
  u32(): number { if (this.pos < 0 || this.pos + 4 > this.buf.length) { this.truncated = true; this.pos = this.buf.length; return 0; } const v = this.buf.readUInt32LE(this.pos); this.pos += 4; return v; }
  u16(): number { if (this.pos < 0 || this.pos + 2 > this.buf.length) { this.truncated = true; this.pos = this.buf.length; return 0; } const v = this.buf.readUInt16LE(this.pos); this.pos += 2; return v; }
  u8(): number { if (this.pos < 0 || this.pos >= this.buf.length) { this.truncated = true; return 0; } return this.buf.readUInt8(this.pos++); }
  uleb(): number { let r = 0, s = 0; for (;;) { const b = this.u8(); r |= (b & 0x7F) << s; if (!(b & 0x80)) return r >>> 0; s += 7; } }
  skip(n: number): void { this.pos += n; }
}

const ACC: Record<number, string> = { 0x1: "public", 0x2: "private", 0x4: "protected", 0x8: "static", 0x10: "final", 0x20: "synchronized", 0x200: "interface", 0x400: "abstract", 0x800: "strict", 0x1000: "synthetic", 0x2000: "annotation", 0x4000: "enum" };
const flagsOf = (f: number): string => Object.entries(ACC).filter(([bit]) => (f & Number(bit)) !== 0).map(([, n]) => n).join(" ");

export const analyzeDex = async (input: DexAnalyzeInput): Promise<DexAnalysis> => {
  const buf = await readFile(input.file);
  const base = { file: basename(input.file), bytes: buf.length };
  const empty = (reason: string): DexAnalysis => ({ ...base, valid: false, reason, version: "", strings: 0, classes: 0, methods: 0, fields: 0, classDefs: [], stringSamples: [], urlLike: [], secretLike: [], artifacts: [] });
  if (buf.length < 112) return empty("too-short");
  if (buf.toString("ascii", 0, 3) !== "dex") return empty("not-dex-magic");
  const version = buf.toString("ascii", 4, 7);
  const d = new Dx(buf);
  // header: magic(8) checksum(4) sig(20) file_size(4) header_size(4) endian(4) link_size(4) link_off(4) map_off(4)
  // string_ids_size(4) string_ids_off(4) type_ids_size(4) type_ids_off(4) proto_ids_size(4) proto_ids_off(4) field_ids_size(4) field_ids_off(4)
  d.pos = 56;
  const stringIdsSize = d.u32(); const stringIdsOff = d.u32();
  const typeIdsSize = d.u32(); const typeIdsOff = d.u32();
  d.skip(8); // proto
  const fieldIdsSize = d.u32(); const fieldIdsOff = d.u32();
  const methodIdsSize = d.u32(); const methodIdsOff = d.u32();
  d.skip(4 + 4); // class_defs size/off read below
  d.pos = 96;
  const classDefsSize = d.u32(); const classDefsOff = d.u32();
  // strings: MUTF-8 (≈UTF-8 for BMP without embedded NULs) — read via uleb length + bytes
  const readStringAt = (offset: number): string => {
    if (!Number.isFinite(offset) || offset <= 0 || offset >= buf.length) return "";
    let p = offset; let len = 0, shift = 0;
    for (;;) { if (p >= buf.length) return ""; const b = buf.readUInt8(p++); len |= (b & 0x7F) << shift; if (!(b & 0x80)) break; shift += 7; }
    return buf.toString("utf8", p, Math.min(p + len, buf.length)).replace(/\0.*$/s, "");
  };
  const strings: string[] = [];
  const stringCount = Math.min(stringIdsSize, 3_000_000);
  for (let i = 0; i < stringCount; i++) {
    const idAt = stringIdsOff + i * 4;
    if (idAt < 0 || idAt + 4 > buf.length) break;
    strings.push(readStringAt(buf.readUInt32LE(idAt)));
  }
  // types: descriptor strings via type_ids -> string index
  const typeDesc = (idx: number): string => {
    if (idx < 0 || idx >= typeIdsSize) return "?";
    const at = typeIdsOff + idx * 4;
    if (at < 0 || at + 4 > buf.length) return "?";
    return strings[buf.readUInt32LE(at)] ?? "?";
  };
  // methods: method_ids -> class_idx(2) proto_idx(2) name_idx(4)
  const methodName = (idx: number): { name: string; clazz: string } => {
    if (idx < 0 || idx >= methodIdsSize) return { name: "?", clazz: "?" };
    const at = methodIdsOff + idx * 8;
    if (at < 0 || at + 8 > buf.length) return { name: "?", clazz: "?" };
    const clazz = typeDesc(buf.readUInt16LE(at));
    const name = strings[buf.readUInt32LE(at + 4)] ?? "?";
    return { name, clazz };
  };
  const fieldName = (idx: number): string => {
    if (idx < 0 || idx >= fieldIdsSize) return "?";
    const at = fieldIdsOff + idx * 8;
    if (at < 0 || at + 8 > buf.length) return "?";
    return `${typeDesc(buf.readUInt16LE(at))} ${strings[buf.readUInt32LE(at + 4)] ?? "?"}`;
  };
  // class defs: class_idx(4) access_flags(4) superclass_idx(4) interfaces_off(4) source_file_idx(4) annotations_off(4) class_data_off(4) static_values_off(4)
  const classDefs: DexClass[] = [];
  let methodCount = 0;
  let fieldCount = 0;
  const classLimit = Math.min(classDefsSize, 50000);
  for (let i = 0; i < classLimit; i++) {
    const at = classDefsOff + i * 32;
    if (at < 0 || at + 32 > buf.length) break;
    const classIdx = buf.readUInt32LE(at);
    const accessFlags = buf.readUInt32LE(at + 4);
    const superIdx = buf.readUInt32LE(at + 8);
    const classDataOff = buf.readUInt32LE(at + 24);
    const name = typeDesc(classIdx);
    const superClass = typeDesc(superIdx);
    const methods: { name: string; proto: string }[] = [];
    const fields: string[] = [];
    if (classDataOff > 0 && classDataOff < buf.length) {
      try {
        const cd = new Dx(buf); cd.pos = classDataOff;
        const staticFields = cd.uleb(); const instanceFields = cd.uleb();
        const directMethods = cd.uleb(); const virtualMethods = cd.uleb();
        for (let f = 0, idx = 0; f < staticFields + instanceFields; f++) {
          idx += cd.uleb(); const acc = cd.uleb();
          const fn = fieldName(idx);
          fields.push(`${flagsOf(acc)} ${fn}`.trim());
          fieldCount++;
        }
        for (let m = 0, idx = 0; m < directMethods + virtualMethods; m++) {
          idx += cd.uleb(); const acc = cd.uleb(); cd.uleb(); // code_off
          const mn = methodName(idx);
          methods.push({ name: mn.name, proto: `${flagsOf(acc)}`.trim() });
          methodCount++;
        }
      } catch { /* malformed class_data — keep what we have */ }
    }
    classDefs.push({ name, superClass, accessFlags, methods, fields });
  }
  // String intel: URLs / secrets
  const urlLike = [...new Set(strings.filter(s => /^https?:\/\//.test(s) && s.length < 300))].slice(0, 400);
  const secretLike: { kind: string; value: string }[] = [];
  const seen = new Set<string>();
  for (const s of strings) {
    if (s.length > 160) continue;
    let kind: string | undefined;
    if (/^AIza[0-9A-Za-z_-]{35}/.test(s)) kind = "google-api-key";
    else if (/^sk-[A-Za-z0-9]{20,}/.test(s)) kind = "openai-style-key";
    else if (/^gh[pousr]_[A-Za-z0-9]{36,}/.test(s)) kind = "github-token";
    else if (/^AKIA[0-9A-Z]{16}/.test(s)) kind = "aws-access-key";
    else if (/(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)["'\s:=]{1,4}[A-Za-z0-9+/_-]{16,}/i.test(s)) kind = "generic-assignment";
    if (kind && !seen.has(s)) { seen.add(s); secretLike.push({ kind, value: s.slice(0, 120) }); if (secretLike.length >= 200) break; }
  }
  const artifacts: DexAnalysis["artifacts"] = [];
  artifacts.push(await writeArtifact(input.outputRoot, "dex_analysis.json", JSON.stringify({
    ...base, valid: true, version, strings: stringCount, classes: classDefs.length, methods: methodCount, fields: fieldCount,
    classDefs: classDefs.map(c => ({ name: c.name, superClass: c.superClass, access: flagsOf(c.accessFlags), methods: c.methods.slice(0, 200).map(m => m.name), fields: c.fields.slice(0, 100) })),
    urlCount: urlLike.length, secretCount: secretLike.length,
  }, null, 2)));
  artifacts.push(await writeArtifact(input.outputRoot, "dex_strings.txt", strings.join("\n")));
  artifacts.push(await writeArtifact(input.outputRoot, "dex_urls.txt", urlLike.join("\n")));
  const md = [
    `# DEX analysis — ${base.file}`, "",
    `- ${base.bytes} bytes, dex version ${version}`,
    `- strings: ${stringCount}  classes: ${classDefs.length}  methods: ${methodCount}  fields: ${fieldCount}`,
    `- urls: ${urlLike.length}  secret candidates: ${secretLike.length}`,
    "", "## Classes", ...classDefs.slice(0, 200).map(c => `- ${c.name}${c.superClass !== "?" ? ` extends ${c.superClass}` : ""} (${flagsOf(c.accessFlags)}) — ${c.methods.length} methods, ${c.fields.length} fields`),
    "", "## URL endpoints", ...urlLike.slice(0, 120).map(u => `- ${u}`),
    "", "## Secret candidates", ...secretLike.slice(0, 80).map(s => `- [${s.kind}] ${s.value}`),
  ].join("\n");
  artifacts.push(await writeArtifact(input.outputRoot, "dex_report.md", md));
  return { ...base, valid: true, version, strings: stringCount, classes: classDefs.length, methods: methodCount, fields: fieldCount, classDefs: classDefs.slice(0, 500), stringSamples: strings.slice(0, 40), urlLike, secretLike, artifacts };
};
