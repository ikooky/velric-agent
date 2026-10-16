import { inflateRawSync, gunzipSync } from "node:zlib";
import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";
import { scanSecrets } from "./secrets.js";

export interface BackupUnpackInput {
  readonly urls: string[];
  readonly outputRoot: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxDecompressedBytes?: number;
  readonly maxEntryBytes?: number;
  readonly maxEntries?: number;
}
export interface BackupUnpackResult {
  readonly processed: number;
  readonly unpacked: { url: string; kind: string; entries: string[]; bytes: number }[];
  readonly secrets: { source: string; line: string }[];
  readonly failures: { url: string; reason: string }[];
  readonly decompressedBytes: number;
  readonly artifacts: { path: string; bytes: number }[];
}
interface Budget { remaining: number; consumed: number; entries: number; entryLimit: number }
const limit = (value: number | undefined, fallback: number): number => value === undefined ? fallback : Number.isSafeInteger(value) && value >= 0 ? Math.min(value, fallback) : 0;
const consume = (budget: Budget, bytes: number): void => {
  if (bytes > budget.remaining) throw new Error("decompressed output budget exceeded");
  budget.remaining -= bytes; budget.consumed += bytes;
};
const boundedInflate = (buf: Buffer, budget: Budget, gzip: boolean): Buffer => {
  const cap = gzip ? budget.remaining : Math.min(budget.entryLimit, budget.remaining);
  if (cap <= 0) throw new Error("decompressed output budget exhausted");
  try {
    const out = gzip ? gunzipSync(buf, { maxOutputLength: cap }) : inflateRawSync(buf, { maxOutputLength: cap });
    consume(budget, out.length); return out;
  } catch (error) {
    // A failed native inflater may already have emitted its entire allowance.
    // Charge that allowance too: retries/other archives cannot reset the budget.
    consume(budget, Math.min(cap, budget.remaining)); throw error;
  }
};
const safeName = (name: string): boolean => !!name && !/[\\\x00-\x1f]/.test(name) && !name.startsWith("/") && !/^[a-z]:/i.test(name) && !name.split("/").includes("..");
const crc32 = (data: Uint8Array): number => {
  let crc = 0xffffffff;
  for (const value of data) { crc ^= value; for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0); }
  return (crc ^ 0xffffffff) >>> 0;
};

/** Central sizes locate compressed input only; zlib's actual output is bounded independently. */
const unzip = (buf: Buffer, budget: Budget): Map<string, Buffer> => {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50 && i + 22 + buf.readUInt16LE(i + 20) === buf.length) { eocd = i; break; }
  }
  if (eocd < 0 || buf.readUInt16LE(eocd + 4) !== 0 || buf.readUInt16LE(eocd + 6) !== 0) throw new Error("invalid or multi-disk ZIP");
  const count = buf.readUInt16LE(eocd + 10), size = buf.readUInt32LE(eocd + 12), start = buf.readUInt32LE(eocd + 16);
  if (count !== buf.readUInt16LE(eocd + 8) || start + size !== eocd || count > budget.entries) throw new Error("ZIP directory or entry budget invalid");
  const files = new Map<string, Buffer>(); let cursor = start;
  for (let n = 0; n < count; n++) {
    if (cursor + 46 > eocd || buf.readUInt32LE(cursor) !== 0x02014b50) throw new Error("invalid ZIP central entry");
    const flags = buf.readUInt16LE(cursor + 8), method = buf.readUInt16LE(cursor + 10), crc = buf.readUInt32LE(cursor + 16);
    const compressed = buf.readUInt32LE(cursor + 20), original = buf.readUInt32LE(cursor + 24);
    const nameLength = buf.readUInt16LE(cursor + 28), extra = buf.readUInt16LE(cursor + 30), comment = buf.readUInt16LE(cursor + 32), offset = buf.readUInt32LE(cursor + 42);
    const next = cursor + 46 + nameLength + extra + comment;
    if (next > eocd || offset + 30 > start || buf.readUInt32LE(offset) !== 0x04034b50 || flags & 1 || ![0, 8].includes(method)) throw new Error("unsupported or invalid ZIP entry");
    const localNameLength = buf.readUInt16LE(offset + 26), localExtra = buf.readUInt16LE(offset + 28), dataStart = offset + 30 + localNameLength + localExtra;
    const name = buf.subarray(cursor + 46, cursor + 46 + nameLength).toString("utf8");
    if (dataStart + compressed > start || buf.readUInt16LE(offset + 8) !== method || buf.readUInt16LE(offset + 6) !== flags || !buf.subarray(offset + 30, offset + 30 + localNameLength).equals(buf.subarray(cursor + 46, cursor + 46 + nameLength))) throw new Error("ZIP local metadata mismatch");
    if (!(flags & 8) && (buf.readUInt32LE(offset + 18) !== compressed || buf.readUInt32LE(offset + 22) !== original || buf.readUInt32LE(offset + 14) !== crc)) throw new Error("ZIP size/CRC metadata mismatch");
    if (original > budget.entryLimit || original > budget.remaining) throw new Error("ZIP declared size exceeds budget");
    budget.entries--; cursor = next;
    const input = buf.subarray(dataStart, dataStart + compressed);
    const data = method === 8 ? boundedInflate(input, budget, false) : (() => { if (input.length > budget.entryLimit) throw new Error("ZIP entry too large"); consume(budget, input.length); return input; })();
    if (data.length !== original || crc32(data) !== crc) throw new Error("ZIP actual size/CRC mismatch");
    if (!safeName(name)) throw new Error("unsafe ZIP entry path");
    if (!name.endsWith("/")) { if (files.has(name)) throw new Error("duplicate ZIP entry"); files.set(name, data); }
  }
  if (cursor !== eocd) throw new Error("ZIP directory size mismatch");
  return files;
};

const untar = (plain: Buffer, budget: Budget): Map<string, Buffer> => {
  const entries = new Map<string, Buffer>(); let cursor = 0;
  const field = (start: number, bytes: number): string => plain.subarray(start, start + bytes).toString("utf8").split("\0")[0]!;
  while (cursor + 512 <= plain.length) {
    if (plain.subarray(cursor, cursor + 512).every(v => v === 0)) return entries;
    if (budget.entries-- <= 0) throw new Error("TAR entry budget exhausted");
    const sizeText = field(cursor + 124, 12).trim(), checksumText = field(cursor + 148, 8).trim();
    if (!/^[0-7]+$/.test(sizeText) || !/^[0-7]+$/.test(checksumText)) throw new Error("invalid TAR numeric metadata");
    const bytes = Number.parseInt(sizeText, 8), checksum = Number.parseInt(checksumText, 8);
    let actual = 0; for (let i = 0; i < 512; i++) actual += i >= 148 && i < 156 ? 32 : plain[cursor + i]!;
    if (actual !== checksum || bytes > budget.entryLimit || cursor + 512 + bytes > plain.length) throw new Error("TAR checksum/length or output limit invalid");
    const name = [field(cursor + 345, 155), field(cursor, 100)].filter(Boolean).join("/");
    const type = plain[cursor + 156]!;
    if (!safeName(name)) throw new Error("unsafe TAR entry path");
    if (type === 0 || type === 48) {
      if (entries.has(name)) throw new Error("duplicate TAR entry");
      entries.set(name, plain.subarray(cursor + 512, cursor + 512 + bytes));
    } else if (type !== 53) throw new Error("unsupported TAR link or extension entry");
    cursor += 512 + Math.ceil(bytes / 512) * 512;
  }
  throw new Error("truncated TAR archive");
};

export const unpackBackups = async (input: BackupUnpackInput): Promise<BackupUnpackResult> => {
  const budget: Budget = { remaining: limit(input.maxDecompressedBytes, 256 * 1024 * 1024), consumed: 0, entries: limit(input.maxEntries, 2000), entryLimit: limit(input.maxEntryBytes, 64 * 1024 * 1024) };
  const unpacked: BackupUnpackResult["unpacked"] = [], secrets: BackupUnpackResult["secrets"] = [], failures: BackupUnpackResult["failures"] = [];
  let processed = 0, downloaded = 0;
  for (const raw of input.urls.slice(0, 20)) {
    let url: URL;
    try { url = new URL(raw); if (!/^https?:$/.test(url.protocol) || url.username || url.password) continue; } catch { continue; }
    const r = await fetchUrl(url.href, { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 20000, raw: true, redirect: "manual", maxBytes: Math.min(32 * 1024 * 1024, 128 * 1024 * 1024 - downloaded) });
    downloaded += r.bytes;
    if (r.status !== 200 || r.complete === false || r.truncated || r.error || !r.rawBuffer) { failures.push({ url: raw, reason: r.error ?? "download incomplete or non-200" }); continue; }
    processed++;
    const buf = r.rawBuffer, path = url.pathname.toLowerCase();
    try {
      let entries: Map<string, Buffer>, kind: string;
      if (path.endsWith(".zip") || buf.subarray(0, 2).toString() === "PK") { entries = unzip(buf, budget); kind = "zip"; }
      else if (/\.(?:tgz|tar\.gz)$/.test(path) || buf[0] === 31 && buf[1] === 139) { entries = untar(boundedInflate(buf, budget, true), budget); kind = "tar.gz"; }
      else if (path.endsWith(".tar")) { consume(budget, buf.length); entries = untar(buf, budget); kind = "tar"; }
      else if (/\.(?:sql|json|txt|csv)$/.test(path)) { if (buf.length > budget.entryLimit) throw new Error("dump entry too large"); consume(budget, buf.length); entries = new Map([[url.pathname, buf]]); kind = "text-dump"; }
      else throw new Error("unsupported backup format");
      for (const [name, data] of entries) {
        if (!/\.(?:txt|json|sql|env|ya?ml|toml|ini|conf|cfg|properties|js|py|php|java|xml|md|csv)$/i.test(name) && !/(?:^|\/)\.env/.test(name)) continue;
        for (const hit of scanSecrets([{ path: name, text: data.toString("utf8") }])) secrets.push({ source: `${raw}::${name}`, line: `${hit.name}: ${hit.match.slice(0, 80)}` });
      }
      unpacked.push({ url: raw, kind, entries: [...entries.keys()], bytes: buf.length });
    } catch (error) { failures.push({ url: raw, reason: error instanceof Error ? error.message : String(error) }); }
  }
  const result: BackupUnpackResult = { processed, unpacked, secrets, failures, decompressedBytes: budget.consumed, artifacts: [] };
  result.artifacts.push(await writeArtifact(input.outputRoot, "backup_unpack.json", JSON.stringify(result, null, 2)));
  return result;
};