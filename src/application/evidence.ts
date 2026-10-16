import { join } from "node:path";
import { readBlob, readJson, safePath, withRootLock, writeJson } from "../core/storage.js";
import { EvidenceStore } from "../domain/graphs.js";

export interface EvidenceItem { readonly source: string; readonly label?: string; readonly content: string }
export interface EvidenceInput { readonly outputRoot: string; readonly items: EvidenceItem[] }
export interface EvidenceResult {
  readonly blobs: { hash: string; bytes: number; path: string; source: string; label?: string }[];
  readonly manifestPath: string;
}
interface Manifest { blobs: EvidenceResult["blobs"]; generatedAt?: string }

/** Publication and manifest merge are one cross-process transaction. */
export const saveEvidence = async (input: EvidenceInput): Promise<EvidenceResult> => withRootLock(input.outputRoot, async () => {
  const root = input.outputRoot;
  const old = await readJson<Manifest>(root, "manifest.json", () => ({blobs:[]}), (value) => {
    const m = value as Manifest;
    return !!m && Array.isArray(m.blobs) && m.blobs.every(b => b && /^[a-f0-9]{64}$/.test(b.hash) &&
      Number.isSafeInteger(b.bytes) && b.bytes >= 0 && typeof b.path === "string" && typeof b.source === "string");
  });
  for (const entry of old.blobs) {
    const path = await safePath(root, `blobs/${entry.hash.slice(0,2)}/${entry.hash}.bin`);
    const bytes = await readBlob(root, entry.hash);
    if (entry.path !== path || !bytes || bytes.length !== entry.bytes) throw Object.assign(new Error("manifest evidence integrity mismatch"),{code:"evidence_integrity"});
  }
  const store = new EvidenceStore(root); await store.load();
  const blobs: EvidenceResult["blobs"] = [];
  for (const item of input.items) {
    const blob = await store.put(Buffer.from(item.content,"utf8"),item.label);
    const path = await safePath(root, `blobs/${blob.hash.slice(0,2)}/${blob.hash}.bin`);
    blobs.push({hash:blob.hash,bytes:blob.bytes,path,source:item.source,label:item.label});
  }
  const merged = new Map(old.blobs.map(b=>[b.hash,b]));
  for (const b of blobs) merged.set(b.hash,b);
  await writeJson(root,"manifest.json",{generatedAt:new Date().toISOString(),blobs:[...merged.values()]});
  return {blobs,manifestPath:join(root,"manifest.json")};
});
