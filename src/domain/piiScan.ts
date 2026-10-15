import { writeFile, mkdir, readFile, readdir } from "node:fs/promises";
import { join, relative } from "node:path";
import { createHash } from "node:crypto";

/** Sensitive-data-exposure scanner over recorded traffic (Akto-style): reads
 *  every response blob captured by traffic_record, scans for PII movement
 *  (emails/phones/cards/national IDs/JWTs) and credential pairs (jsluice
 *  pairing), then attributes each hit back to the exchange (method+URL) so
 *  the finding says WHICH endpoint leaks WHICH data class.
 *
 *  Pure local batch job over the blob store — no re-firing, no LLM. */

import { scanPii, scanPairedSecrets, scanSecrets, type SecretHit } from "./secrets.js";

export interface PiiScanInput {
  /** traffic outputRoot (contains traffic.ndjson + blobs/). */
  readonly recordRoot: string;
  readonly outputRoot: string;
  /** Skip obviously-binary blobs by content sniffing. Default true. */
  readonly skipBinary?: boolean;
  readonly maxBlobs?: number;
}

export interface EndpointExposure {
  readonly method: string;
  readonly url: string;
  /** data class -> hit count */
  readonly kinds: Record<string, number>;
  readonly sampleMatches: { kind: string; match: string }[];
}

export interface PiiScanResult {
  readonly blobsScanned: number;
  readonly exchanges: number;
  /** endpoint-level rollup, sorted by distinct data classes desc. */
  readonly exposures: EndpointExposure[];
  /** credential PAIRS found (jsluice pairing) — these are findings on their own. */
  readonly credentialPairs: (SecretHit & { url: string; method: string })[];
  readonly artifacts: { path: string; bytes: number }[];
}

interface NdExchange {
  readonly id: string;
  readonly method: string;
  readonly url: string;
  readonly respBodyHash: string | null;
}

const TEXTUAL_RE = /^(?:text\/|application\/(?:json|xml|x-www-form-urlencoded|javascript|sql|yaml|toml|csv)|image\/svg)/i;
const looksTextual = (buf: Buffer): boolean => {
  // quick sniff: no NUL in first 512 bytes and valid UTF-8 round trip on the head
  const head = buf.subarray(0, 512);
  if (head.includes(0)) return false;
  return Buffer.compare(Buffer.from(head.toString("utf8"), "utf8"), head) === 0;
};

export const scanTrafficPii = async (input: PiiScanInput): Promise<PiiScanResult> => {
  await mkdir(input.outputRoot, { recursive: true });

  // exchange index: respBodyHash -> {method,url}
  const hashToExchange = new Map<string, NdExchange>();
  let exchangeCount = 0;
  try {
    const nd = await readFile(join(input.recordRoot, "traffic.ndjson"), "utf8");
    for (const line of nd.split("\n")) {
      if (!line.trim()) continue;
      try {
        const e = JSON.parse(line) as NdExchange;
        if (e.respBodyHash) hashToExchange.set(e.respBodyHash, e);
        exchangeCount++;
      } catch { /* torn line */ }
    }
  } catch {
    return { blobsScanned: 0, exchanges: 0, exposures: [], credentialPairs: [], artifacts: [] };
  }

  // walk blob store
  const blobRoot = join(input.recordRoot, "blobs");
  const blobFiles: string[] = [];
  const shardDirs = await readdir(blobRoot).catch(() => [] as string[]);
  for (const shard of shardDirs) {
    const files = await readdir(join(blobRoot, shard)).catch(() => [] as string[]);
    for (const f of files) if (f.endsWith(".bin")) blobFiles.push(join(blobRoot, shard, f));
  }

  const perEndpoint = new Map<string, { method: string; url: string; _kinds: Map<string, number>; _samples: { kind: string; match: string }[] }>();
  const credentialPairs: PiiScanResult["credentialPairs"] = [];
  let scanned = 0;
  const cap = input.maxBlobs ?? 2000;

  for (const bf of blobFiles) {
    if (scanned >= cap) break;
    const hash = createHash("sha256").update(await readFile(bf)).digest("hex");
    // Only RESPONSE bodies are PII movement; request bodies map via reqBodyHash
    // and are scanned too (client PII submissions matter less, skip to keep
    // signal high — respBodyHash index decides attribution).
    const ex = hashToExchange.get(hash);
    let buf: Buffer;
    try { buf = await readFile(bf); } catch { continue; }
    if (buf.length === 0 || buf.length > 4 * 1024 * 1024) continue;
    if ((input.skipBinary ?? true) && !looksTextual(buf)) continue;
    scanned++;
    const text = buf.toString("utf8");
    const relPath = relative(input.recordRoot, bf);
    const piiHits = scanPii([{ path: relPath, text }]);
    const pairHits = scanPairedSecrets([{ path: relPath, text }]);
    const credHits = scanSecrets([{ path: relPath, text }]).filter((h) => h.name !== "generic_secret_assignment" && h.name !== "internal_ip" && h.name !== "internal_host");

    // attribution: hash found in index = response body of that exchange
    if (ex) {
      const key = `${ex.method} ${ex.url}`;
      const agg = perEndpoint.get(key) ?? { method: ex.method, url: ex.url, _kinds: new Map<string, number>(), _samples: [] as { kind: string; match: string }[] };
      for (const h of piiHits) {
        agg._kinds.set(h.name, (agg._kinds.get(h.name) ?? 0) + 1);
        if (agg._samples.length < 6 && !agg._samples.some((s) => s.kind === h.name)) agg._samples.push({ kind: h.name, match: h.match });
      }
      for (const h of [...pairHits, ...credHits]) {
        agg._kinds.set(h.name, (agg._kinds.get(h.name) ?? 0) + 1);
        if (agg._samples.length < 6 && !agg._samples.some((s) => s.kind === h.name)) agg._samples.push({ kind: h.name, match: h.match });
      }
      perEndpoint.set(key, agg);
    }
    for (const h of pairHits) {
      credentialPairs.push({ ...h, url: ex?.url ?? relPath, method: ex?.method ?? "-" });
    }
  }

  const exposures = [...perEndpoint.values()]
    .filter((e) => e._kinds.size > 0)
    .map((e) => ({ method: e.method, url: e.url, kinds: Object.fromEntries(e._kinds), sampleMatches: e._samples }))
    .sort((a, b) => Object.keys(b.kinds).length - Object.keys(a.kinds).length);

  const bodyStr = JSON.stringify({ blobsScanned: scanned, exchanges: exchangeCount, exposures, credentialPairs }, null, 2);
  const path = join(input.outputRoot, "pii_exposure.json");
  await writeFile(path, bodyStr, "utf8");
  return { blobsScanned: scanned, exchanges: exchangeCount, exposures, credentialPairs, artifacts: [{ path, bytes: Buffer.byteLength(bodyStr) }] };
};
