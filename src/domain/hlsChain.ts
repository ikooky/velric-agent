import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";
import { createHash, createDecipheriv, createHmac } from "node:crypto";

/** HLS capability-chain extractor: given a signed m3u8 gateway, pulls the
 *  playlist, the AES-128 key endpoint, and every segment, then decrypts the
 *  segments into plain TS (0x47 sync verified) — proving the whole path from
 *  API answer to playable file. Also probes whether the gateway signs ARBITRARY
 *  paths (capability-URL discipline check) and whether segments are
 *  per-segment signed (unforgeable) or unsigned (guessable → whole-library
 *  dump). */

export interface HlsChainInput {
  /** Gateway URL template with {PATH} (URL-encoded m3u8 path). */
  readonly gatewayTemplate: string;
  /** The m3u8 path (server-issued capability) or a full URL when the playlist
   *  is directly reachable. */
  readonly playlistPathOrUrl: string;
  /** Key endpoint (absolute or template with {PATH}); IV auto-read from
   *  #EXT-X-KEY, defaults to zero. */
  readonly keyUrl: string;
  readonly outputRoot: string;
  readonly token?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  /** Download + decrypt at most N segments (default 2, proof-level). */
  readonly maxSegments?: number;
  /** Also test whether the gateway signs arbitrary paths. */
  readonly probeArbitrary?: boolean;
}

export interface HlsChainResult {
  readonly playlistStatus: number;
  readonly segments: number;
  readonly durationSec: number;
  readonly keyBytes: number;
  readonly ivHex?: string;
  readonly decrypted: { index: number; bytes: number; syncOk: boolean }[];
  readonly arbitraryPathSigned: boolean | null;
  readonly segmentUrlSigned: boolean;
  readonly artifacts: { path: string; bytes: number }[];
}

const get = async (url: string, input: HlsChainInput, raw = false): Promise<{ status: number; body: string; buf: Buffer }> => {
  const headers = { ...(input.headers ?? {}) };
  if (input.token) headers.authorization = input.token;
  const r = await fetchUrl(url, { headers, maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 20_000, maxBytes: 64 * 1024 * 1024, raw });
  return { status: r.status, body: r.body, buf: r.rawBuffer ?? Buffer.from(r.body, "binary") };
};

export const extractHlsChain = async (input: HlsChainInput): Promise<HlsChainResult> => {
  const plUrl = input.playlistPathOrUrl.startsWith("http")
    ? input.playlistPathOrUrl
    : input.gatewayTemplate.replaceAll("{PATH}", encodeURIComponent(input.playlistPathOrUrl));
  const pl = await get(plUrl, input);
  if (pl.status !== 200) throw new Error(`playlist fetch ${pl.status}`);
  const segUrls = [...pl.body.matchAll(/^(https?:\/\/\S+)$/gm)].map((m) => m[1] ?? "");
  const durations = [...pl.body.matchAll(/#EXTINF:([\d.]+)/g)].map((m) => Number(m[1]));
  const keyMatch = /#EXT-X-KEY:METHOD=AES-128,URI="([^"]+)"(?:,IV=(0x[0-9a-fA-F]+))?/.exec(pl.body);
  const ivHex = keyMatch?.[2];

  let keyBytes = 0;
  let decrypted: HlsChainResult["decrypted"] = [];
  if (keyMatch?.[1]) {
    const keyUrl = keyMatch[1].startsWith("http") ? keyMatch[1] : input.keyUrl.replaceAll("{PATH}", encodeURIComponent(keyMatch[1]).replaceAll("%2F", "/"));
    const kr = await get(keyUrl, input, true);
    keyBytes = kr.buf.length;
    if (kr.status === 200 && keyBytes === 16) {
      const iv = ivHex ? Buffer.from(ivHex.slice(2), "hex") : Buffer.alloc(16);
      const { writeFile, mkdir } = await import("node:fs/promises");
      const { join } = await import("node:path");
      await mkdir(input.outputRoot, { recursive: true });
      const cap = Math.min(input.maxSegments ?? 2, segUrls.length);
      for (let i = 0; i < cap; i++) {
        const sr = await get(segUrls[i]!, input, true);
        if (sr.status !== 200) { decrypted.push({ index: i, bytes: 0, syncOk: false }); continue; }
        try {
          const d = createDecipheriv("aes-128-cbc", kr.buf, iv);
          const out = Buffer.concat([d.update(sr.buf), d.final()]);
          const syncOk = out.length >= 189 && out[0] === 0x47 && out[188] === 0x47;
          if (!syncOk) (await import("node:fs/promises")).writeFile("/tmp/hlsdbg.txt", `segbuf=${sr.buf.length} out=${out.length} first=${out.subarray(0,8).toString("hex")} keylen=${kr.buf.length} keyhex=${kr.buf.toString("hex")} ivhex=${iv.toString("hex")}`);
          await writeFile(join(input.outputRoot, `seg${i}.ts`), out);
          decrypted.push({ index: i, bytes: out.length, syncOk });
        } catch { decrypted.push({ index: i, bytes: sr.buf.length, syncOk: false }); }
      }
    }
  }

  // Gateway discipline: does it sign an arbitrary (bogus) path?
  let arbitraryPathSigned: boolean | null = null;
  if (input.probeArbitrary !== false && input.gatewayTemplate.includes("{PATH}")) {
    const bogus = await get(input.gatewayTemplate.replaceAll("{PATH}", encodeURIComponent(`probe-${Date.now()}/x.m3u8`)), input);
    if (bogus.status === 200 && /#EXTM3U[\s\S]*#EXTINF/.test(bogus.body)) arbitraryPathSigned = true;
    else if (bogus.status > 0) arbitraryPathSigned = false;
  }
  // Segment signature: strip query and refetch.
  let segmentUrlSigned = false;
  if (segUrls[0]?.includes("?")) {
    const bare = segUrls[0].split("?")[0]!;
    const sr = await get(bare, input, true);
    segmentUrlSigned = !(sr.status === 200 && sr.buf.length > 1000);
  }

  const { writeFile, mkdir } = await import("node:fs/promises");
  const { join } = await import("node:path");
  await mkdir(input.outputRoot, { recursive: true });
  await writeFile(join(input.outputRoot, "playlist.m3u8"), pl.body);
  const body = JSON.stringify({ plUrl, segments: segUrls.length, durationSec: durations.reduce((p, c) => p + c, 0), keyBytes, ivHex, decrypted, arbitraryPathSigned, segmentUrlSigned }, null, 2);
  const artifact = await writeArtifact(input.outputRoot, "hls_chain.json", body);
  return {
    playlistStatus: pl.status,
    segments: segUrls.length,
    durationSec: Number(durations.reduce((p, c) => p + c, 0).toFixed(1)),
    keyBytes, ivHex, decrypted, arbitraryPathSigned, segmentUrlSigned,
    artifacts: [artifact],
  };
};

void createHash;
void createHmac;
