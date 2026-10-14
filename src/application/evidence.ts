import { createHash } from "node:crypto";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

/**
 * 内容寻址证据存储:blob 存储 + sha256 校验。
 * blobs/<hash[:2]>/<hash>.bin + manifest.json(记录来源/长度/哈希)。
 */
export interface EvidenceItem {
  readonly source: string; // e.g. "runtime_api.json#detail[3]" or "curl poc"
  readonly label?: string;
  readonly content: string;
}

export interface EvidenceInput {
  readonly outputRoot: string;
  readonly items: EvidenceItem[];
}

export interface EvidenceResult {
  readonly blobs: { hash: string; bytes: number; path: string; source: string; label?: string }[];
  readonly manifestPath: string;
}

const sha256 = (data: string): string =>
  createHash("sha256").update(data, "utf8").digest("hex");

export const saveEvidence = async (input: EvidenceInput): Promise<EvidenceResult> => {
  const blobDir = join(input.outputRoot, "blobs");
  const blobs: EvidenceResult["blobs"] = [];
  for (const it of input.items) {
    const hash = sha256(it.content);
    const bin = join(blobDir, hash.slice(0, 2), `${hash}.bin`);
    await mkdir(dirname(bin), { recursive: true });
    await writeFile(bin, it.content, "utf8");
    // write-after-verify: reread to confirm durable write
    const written = await readFile(bin, "utf8");
    if (sha256(written) !== hash) {
      throw { code: "io_error", message: `evidence write verify failed for ${hash}` };
    }
    blobs.push({ hash, bytes: Buffer.byteLength(it.content), path: bin, source: it.source, label: it.label });
  }
  // Merge into an existing manifest instead of clobbering: a second save
  // in the same outputRoot previously wiped the first call's blob entries.
  const manifestPath = join(input.outputRoot, "manifest.json");
  let existing: { blobs?: { hash: string }[] } = {};
  try { existing = JSON.parse(await readFile(manifestPath, "utf8")) as { blobs?: { hash: string }[] }; } catch { /* fresh */ }
  const priorHashes = new Set((existing.blobs ?? []).map((b) => b.hash));
  const merged = [...(existing.blobs ?? []).filter((b) => !blobs.some((n) => n.hash === b.hash)), ...blobs];
  void priorHashes;
  await writeFile(manifestPath, JSON.stringify({ generatedAt: new Date().toISOString(), blobs: merged }, null, 2), "utf8");
  return { blobs, manifestPath };
};

/** Verify a blob against its recorded sha256 (velric verifyFile). */
export const verifyEvidence = async (
  outputRoot: string,
  hash: string,
): Promise<{ ok: boolean; bytes: number }> => {
  if (!/^[0-9a-f]{64}$/.test(hash)) return { ok: false, bytes: 0 };
  const bin = join(outputRoot, "blobs", hash.slice(0, 2), `${hash}.bin`);
  let content: string;
  try {
    content = await readFile(bin, "utf8");
    const st = await stat(bin);
    return { ok: sha256(content) === hash, bytes: st.size };
  } catch {
    return { ok: false, bytes: 0 };
  }
};
