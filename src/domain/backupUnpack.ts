import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { unzipSync } from "fflate";
import zlib from "node:zlib";
import tarStream from "tar-stream";
import { scanSecrets } from "./secrets.js";

/** Cap-bounded gunzip: the ISIZE trailer is attacker-controlled and
 *  multi-member gzip makes it lie outright. zlib's maxOutputLength aborts
 *  inflation the moment the output would exceed the cap — no full-size
 *  buffer is ever allocated. */
const gunzipCapped = (buf: Buffer): Buffer =>
  zlib.gunzipSync(buf, { maxOutputLength: MAX_DECOMPRESSED });

/** Backup/dump unpack + secret scan: paths-stage discoveries (.zip/.tar.gz/
 *  .sql/.json dumps) are downloaded, unpacked in memory, and every text
 *  entry runs through the secret scanner. */

export interface BackupUnpackInput {
  readonly urls: string[];
  readonly outputRoot: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}

export interface BackupUnpackResult {
  readonly processed: number;
  readonly unpacked: { url: string; kind: string; entries: string[]; bytes: number }[];
  readonly secrets: { source: string; line: string }[];
  readonly artifacts: { path: string; bytes: number }[];
}

const fetchBinary = async (url: string, opts: { proxy?: string; timeoutMs?: number }): Promise<Buffer | null> => {
  const { fetchUrl } = await import("../adapters/http.js");
  const r = await fetchUrl(url, { ...opts, raw: true, maxBytes: 32 * 1024 * 1024 });
  if (r.status !== 200 || !r.rawBuffer) return null;
  return r.rawBuffer;
};

const MAX_DECOMPRESSED = 256 * 1024 * 1024; // 256 MB total decompressed cap

const listZip = (buf: Buffer): { names: string[]; read: (name: string) => Buffer | null } => {
  // Pre-decompression cap: fflate's filter runs BEFORE each entry inflates.
  // The counter accumulates DECLARED sizes and skips entries once the total
  // passes the cap — decompressed bytes stay bounded even for hostile zips.
  let declaredTotal = 0;
  const files = unzipSync(new Uint8Array(buf), {
    filter: (file) => {
      declaredTotal += file.originalSize;
      return declaredTotal <= MAX_DECOMPRESSED;
    },
  });
  const safeNames: string[] = [];
  let total = 0;
  for (const [k, v] of Object.entries(files)) {
    if (/^(?:__proto__|constructor|prototype)$/.test(k)) continue; // hostile archive key guard
    total += v.length;
    if (total > MAX_DECOMPRESSED) throw new Error("decompressed size exceeds cap");
    safeNames.push(k);
  }
  return {
    names: safeNames,
    read: (name: string): Buffer | null => {
      const f = files[name];
      return f ? Buffer.from(f) : null;
    },
  };
};

const MAX_ENTRY = 64 * 1024 * 1024; // per-entry decompressed cap

const listTarGz = async (buf: Buffer): Promise<{ names: string[]; read: (name: string) => Buffer | null }> => {
  // Bomb guard 1: the gzip ISIZE trailer (last 4 bytes, mod 2^32) declares
  // the decompressed size — refuse anything implausibly large BEFORE
  // inflating (fflate gunzipSync grows its output buffer unboundedly).
  if (buf.length < 18) throw new Error("not a gzip stream");
  const isize = buf.readUInt32LE(buf.length - 4);
  if (isize === 0 || isize > MAX_DECOMPRESSED) {
    // ISIZE is mod 2^32 — a >4GiB payload wraps; 0 is also suspicious for a
    // tarball. Stream-decompress with a byte counter instead of trusting it.
    throw new Error("gzip declared size implausible — refusing");
  }
  const plain = gunzipCapped(buf);
  const extract = tarStream.extract();
  const entries = new Map<string, Buffer>();
  let held = 0;
  const done = new Promise<void>((resolve, reject) => {
    extract.on("entry", ((header: { name: string }, stream: { on: (ev: string, fn: (c?: unknown) => void) => void }, next: (err?: Error | null) => void) => {
      const chunks: Buffer[] = [];
      let entryLen = 0;
      let oversize = false;
      stream.on("data", (c?: unknown) => {
        if (!Buffer.isBuffer(c)) return;
        entryLen += c.length;
        // Bomb guard 2: per-entry + total caps while buffering.
        if (entryLen > MAX_ENTRY || held + entryLen > MAX_DECOMPRESSED) { oversize = true; return; }
        chunks.push(c);
      });
      stream.on("end", () => {
        if (!oversize && !header.name.endsWith("/")) {
          entries.set(header.name, Buffer.concat(chunks));
          held += entryLen;
        }
        next();
      });
    }) as unknown as (...a: unknown[]) => void);
    extract.on("finish", () => resolve());
    extract.on("error", (e: Error) => reject(e));
  });
  extract.write(plain);
  extract.end(() => {});
  await done;
  return {
    names: [...entries.keys()],
    read: (name: string): Buffer | null => entries.get(name) ?? null,
  };
};

export const unpackBackups = async (input: BackupUnpackInput): Promise<BackupUnpackResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 20000 };
  const unpacked: BackupUnpackResult["unpacked"] = [];
  const secrets: BackupUnpackResult["secrets"] = [];
  let processed = 0;

  for (const url of input.urls.slice(0, 20)) {
    const buf = await fetchBinary(url, opts);
    if (!buf) continue;
    processed++;

    let archive: { names: string[]; read: (name: string) => Buffer | null } | null = null;
    let kind = "";
    const pathLower = url.toLowerCase();
    if (pathLower.endsWith(".zip") || (buf.length > 4 && buf[0] === 0x50 && buf[1] === 0x4b)) {
      try { archive = listZip(buf); kind = "zip"; } catch { /* not a zip */ }
    } else if (pathLower.endsWith(".tar.gz") || pathLower.endsWith(".tgz") || (buf.length > 2 && buf[0] === 0x1f && buf[1] === 0x8b)) {
      try { archive = await listTarGz(buf); kind = "tar.gz"; } catch { /* not a tgz */ }
    }

    if (archive) {
      const textEntries = archive.names.filter((n) => /\.(?:txt|json|sql|env|ya?ml|toml|ini|conf|cfg|properties|js|py|php|java|xml|md)$/i.test(n) || /(?:^|\/)\.env/.test(n)).slice(0, 200);
      for (const name of textEntries) {
        const data = archive.read(name);
        if (!data) continue;
        const text = data.toString("utf8");
        const hits = scanSecrets([{ path: name, text }]);
        for (const h of hits) secrets.push({ source: `${url}::${name}`, line: `${h.name}: ${h.match.slice(0, 80)}` });
      }
      unpacked.push({ url, kind, entries: archive.names.slice(0, 500), bytes: buf.length });
      continue;
    }

    // Plain text dump (.sql/.json/...): scan directly.
    if (/\.(?:sql|json|txt|csv)$/i.test(pathLower) || buf.subarray(0, 64).toString("latin1").match(/(?:CREATE TABLE|INSERT INTO|password|secret)/i)) {
      const text = buf.toString("utf8");
      const hits = scanSecrets([{ path: url, text }]);
      for (const h of hits) secrets.push({ source: url, line: `${h.name}: ${h.match.slice(0, 80)}` });
      unpacked.push({ url, kind: "text-dump", entries: [], bytes: buf.length });
    }
  }

  const result: BackupUnpackResult = { processed, unpacked, secrets, artifacts: [] };
  const body = JSON.stringify(result, null, 2);
  const path = join(input.outputRoot, "backup_unpack.json");
  await writeFile(path, body);
  result.artifacts.push({ path, bytes: Buffer.byteLength(body) });
  return result;
};
