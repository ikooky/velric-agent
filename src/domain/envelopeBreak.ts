import { readFile } from "node:fs/promises";
import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";
import { createHash, createDecipheriv } from "node:crypto";

/** Encrypted-response envelope breaker for web fronts whose JS bundle embeds
 *  the cipher. Locates AES key material in harvested bundles (static class
 *  fields, obfuscated const pools), reconstructs the exact key/iv derivation,
 *  and decrypts captured API envelopes so every endpoint answer becomes
 *  readable. Key/iv schemes are derived from the classic dual-SHA256 split
 *  used by several app shells; a custom deriver can be injected. */

export interface EnvelopeInput {
  /** API response (or file with one) shaped {"code":…,"data":"<cipher b64>"}. */
  readonly response: string;
  readonly outputRoot: string;
  /** Candidate interface keys harvested from bundles; each is tried. */
  readonly keys: readonly string[];
  /** Optional custom deriver; default = dual-SHA256 split scheme. */
  readonly deriver?: (key: string, cipher: Buffer) => { key: Buffer; iv: Buffer };
  readonly proxy?: string;
}

export interface EnvelopeResult {
  readonly cracked: boolean;
  readonly keyUsed?: string;
  readonly scheme: string;
  readonly plaintextPrefix?: string;
  readonly parsed?: unknown;
  readonly tried: { key: string; ok: boolean; note: string }[];
  readonly artifacts: { path: string; bytes: number }[];
}

const sha = (b: Buffer): Buffer => createHash("sha256").update(b).digest();

/** k || salt12 → i; l=sha(i)[8:24]; m=l||i[:half]; g=i[half:]||l;
 *  key=sha(m)[0:8]||sha(g)[8:24]||sha(m)[24:]; iv=sha(g)[0:4]||sha(m)[12:20]||sha(g)[28:] */
export const dualShaSplit = (key: string, cipher: Buffer): { key: Buffer; iv: Buffer } => {
  const k = Buffer.from(key, "utf8");
  const i = Buffer.concat([k, cipher.subarray(0, 12)]);
  const half = i.length >> 1;
  const l = sha(i).subarray(8, 24);
  const m = Buffer.concat([l, i.subarray(0, half)]);
  const g = Buffer.concat([i.subarray(half), l]);
  return {
    key: Buffer.concat([sha(m).subarray(0, 8), sha(g).subarray(8, 24), sha(m).subarray(24)]),
    iv: Buffer.concat([sha(g).subarray(0, 4), sha(m).subarray(12, 20), sha(g).subarray(28)]),
  };
};

export const crackEnvelope = async (input: EnvelopeInput): Promise<EnvelopeResult> => {
  const raw = input.response.trim().startsWith("{") || input.response.includes("\"data\"")
    ? input.response
    : await readFile(input.response, "utf8").catch(() => input.response);
  let doc: { code?: number; data?: string };
  try { doc = JSON.parse(raw) as typeof doc; } catch { throw new Error("input is not an envelope document"); }
  const cipher = Buffer.from((doc.data ?? "").trim(), "base64");
  const tried: EnvelopeResult["tried"] = [];
  let cracked = false;
  let keyUsed: string | undefined;
  let plaintext: string | undefined;
  let parsed: unknown;
  if (cipher.length >= 16) {
    for (const key of input.keys) {
      try {
        const { key: k, iv } = (input.deriver ?? dualShaSplit)(key, cipher);
        const d = createDecipheriv("aes-256-cbc", k, iv);
        const out = Buffer.concat([d.update(cipher.subarray(12)), d.final()]).toString("utf8");
        tried.push({ key, ok: true, note: `AES-256-CBC ok, ${out.length} chars` });
        cracked = true;
        keyUsed = key;
        plaintext = out;
        try { parsed = out === "nil" ? null : JSON.parse(out); } catch { parsed = undefined; }
        break;
      } catch (e) {
        tried.push({ key, ok: false, note: (e as Error).message.slice(0, 60) });
      }
    }
  }
  const body = JSON.stringify({ cracked, keyUsed, parsed, tried }, null, 2);
  const artifact = await writeArtifact(input.outputRoot, "envelope.json", body);
  return {
    cracked, keyUsed,
    scheme: input.deriver ? "custom" : "aes-256-cbc dual-sha256-split",
    plaintextPrefix: plaintext?.slice(0, 200),
    parsed, tried, artifacts: [artifact],
  };
};

/** Bundle key harvester: static class-field assignments and hex/base64ish
 *  constants sitting near sign/secret identifiers inside harvested JS. */
export const harvestBundleKeys = (bundleText: string): { keys: string[]; urls: string[] } => {
  const keys = new Set<string>();
  for (const m of bundleText.matchAll(/(?:interfaceKey|imgKey|signKey|secretKey|appSecret|apiKey)["']?\s*[=:]\s*["']([A-Za-z0-9_-]{8,64})["']/g)) keys.add(m[1] ?? "");
  for (const m of bundleText.matchAll(/["']([0-9a-f]{32})["']/g)) keys.add(m[1] ?? "");
  const urls = [...new Set([...bundleText.matchAll(/https?:\/\/[a-z0-9.-]+\.[a-z]{2,}[^"'\s)]*/g)].map((m) => m[0]))].slice(0, 60);
  return { keys: [...keys], urls };
};

void fetchUrl;
