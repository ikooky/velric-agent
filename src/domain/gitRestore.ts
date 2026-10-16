import { fetchUrl } from "../adapters/http.js";
import { join } from "node:path";
import { inflateSync } from "node:zlib";
import { createHash } from "node:crypto";
import { writeArtifact } from "../adapters/artifacts.js";
import { safePath } from "../core/storage.js";
import { discoveryOrigin, discoveryUrl } from "./pathProbe.js";

export interface GitRestoreInput {
  readonly baseUrl: string;
  readonly outputRoot: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxObjects?: number;
  readonly maxObjectBytes?: number;
  readonly maxDecompressedBytes?: number;
  readonly maxFiles?: number;
}
export interface GitRestoreResult {
  readonly baseUrl: string;
  readonly gitFound: boolean;
  readonly objectsRecovered: number;
  readonly commits: string[];
  readonly filesRestored: number;
  readonly workDir: string;
  readonly objectRequests: number;
  readonly decompressedBytes: number;
  readonly failures: string[];
  readonly artifacts: { path: string; bytes: number }[];
}
interface GitObject { type: "blob" | "tree" | "commit" | "tag"; payload: Buffer }
const bounded = (value: number | undefined, fallback: number): number => value === undefined ? fallback : Number.isSafeInteger(value) && value >= 0 ? Math.min(value, fallback) : 0;
const shaPattern = /^[0-9a-f]{40}$/;
const parseLoose = (raw: Buffer, sha: string, max: number): { object: GitObject; bytes: number } => {
  const data = inflateSync(raw, { maxOutputLength: max });
  if (createHash("sha1").update(data).digest("hex") !== sha) throw new Error("Git object hash mismatch");
  const nul = data.indexOf(0);
  if (nul < 0 || nul > 100) throw new Error("invalid Git object header");
  const header = data.subarray(0, nul).toString("ascii").match(/^(blob|tree|commit|tag) (0|[1-9][0-9]*)$/);
  if (!header || Number(header[2]) !== data.length - nul - 1) throw new Error("Git object length mismatch");
  return { object: { type: header[1] as GitObject["type"], payload: data.subarray(nul + 1) }, bytes: data.length };
};
const treeEntries = (data: Buffer): { mode: string; name: string; sha: string }[] => {
  const entries: { mode: string; name: string; sha: string }[] = []; let cursor = 0;
  while (cursor < data.length) {
    const space = data.indexOf(32, cursor), nul = data.indexOf(0, space);
    if (space < cursor || nul < space || nul + 21 > data.length) throw new Error("malformed Git tree");
    const mode = data.subarray(cursor, space).toString("ascii"), name = data.subarray(space + 1, nul).toString("utf8");
    if (!/^(?:100644|100755|40000|040000|120000|160000)$/.test(mode) || !name || name === "." || name === ".." || name.toLowerCase() === ".git" || /[\\/\x00-\x1f:]/.test(name)) throw new Error("unsafe Git tree entry");
    entries.push({ mode, name, sha: data.subarray(nul + 1, nul + 21).toString("hex") }); cursor = nul + 21;
  }
  return entries;
};

export const restoreGit = async (input: GitRestoreInput): Promise<GitRestoreResult> => {
  const base = discoveryOrigin(input.baseUrl), workDir = join(input.outputRoot, "git-restored");
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10000, redirect: "manual" as const };
  const failures: string[] = [], artifacts: GitRestoreResult["artifacts"] = [], commits: string[] = [];
  const maxObjects = bounded(input.maxObjects, 400), objectBytes = bounded(input.maxObjectBytes, 8 * 1024 * 1024), totalBytes = bounded(input.maxDecompressedBytes, 64 * 1024 * 1024), maxFiles = bounded(input.maxFiles, 2000);
  let objectRequests = 0, decompressedBytes = 0, filesRestored = 0, storedBytes = 0;
  const cache = new Map<string, GitObject | null>();
  const snapshot = (gitFound: boolean): GitRestoreResult => ({ baseUrl: base, gitFound, objectsRecovered: [...cache.values()].filter(Boolean).length, commits, filesRestored, workDir, objectRequests, decompressedBytes, failures, artifacts });
  const get = async (path: string, raw = false) => fetchUrl(new URL(`/.git/${path}`, base).href, { ...opts, raw, maxBytes: raw ? 8 * 1024 * 1024 : 1024 * 1024 });
  const cfg = await get("config");
  if (cfg.status !== 200 || cfg.complete === false || cfg.truncated || cfg.error || !cfg.body.includes("[core")) return snapshot(false);
  // Never write target-controlled config/hooks into an executable local repository.
  artifacts.push(await writeArtifact(input.outputRoot, "git-restored-metadata/config.txt", cfg.body));
  const head = await get("HEAD");
  let headSha: string | null = null;
  const headText = head.status === 200 && head.complete !== false && !head.truncated && !head.error ? head.body.trim() : "";
  if (shaPattern.test(headText)) headSha = headText;
  const symref = headText.match(/^ref: (refs\/heads\/[A-Za-z0-9_./-]+)$/)?.[1];
  const safeRef = symref && !symref.includes("..") && !symref.includes("//") && discoveryUrl(base, `/.git/${symref}`) ? symref : null;
  const metadata = new Map<string, string>();
  for (const file of ["index", "packed-refs", "logs/HEAD", "logs/refs/heads/master", "logs/refs/heads/main", "info/refs", "ORIG_HEAD"]) {
    const r = await get(file, true);
    if (r.status !== 200 || r.complete === false || r.truncated || r.error || !r.rawBuffer) continue;
    await writeArtifact(input.outputRoot, `git-restored-metadata/${file}`, r.rawBuffer);
    metadata.set(file, r.rawBuffer.toString("utf8"));
  }
  if (!headSha && safeRef) {
    const r = await get(safeRef);
    if (r.status === 200 && r.complete !== false && !r.truncated && shaPattern.test(r.body.trim())) headSha = r.body.trim();
    if (!headSha) for (const line of (metadata.get("packed-refs") ?? "").split("\n")) {
      const [sha, ref] = line.trim().split(/\s+/);
      if (ref === safeRef && sha && shaPattern.test(sha)) { headSha = sha; break; }
    }
  }
  if (!headSha) {
    const log = (metadata.get("logs/HEAD") ?? "").trim().split("\n").at(-1)?.split(" ")[1];
    if (log && shaPattern.test(log) && !/^0+$/.test(log)) headSha = log;
  }
  const fetchObject = async (sha: string): Promise<GitObject | null> => {
    if (!shaPattern.test(sha)) return null;
    if (cache.has(sha)) return cache.get(sha)!;
    cache.set(sha, null);
    const cap = Math.min(objectBytes, totalBytes - decompressedBytes);
    if (objectRequests >= maxObjects || cap <= 0) { failures.push("object budget exhausted"); return null; }
    objectRequests++;
    const r = await get(`objects/${sha.slice(0, 2)}/${sha.slice(2)}`, true);
    if (r.status !== 200 || r.complete === false || r.truncated || r.error || !r.rawBuffer) return null;
    try {
      const parsed = parseLoose(r.rawBuffer, sha, cap); decompressedBytes += parsed.bytes;
      cache.set(sha, parsed.object); return parsed.object;
    } catch (error) {
      decompressedBytes += cap;
      failures.push(`${sha}: ${error instanceof Error ? error.message : String(error)}`); return null;
    }
  };
  const walkTree = async (sha: string, prefix: string, ancestors: ReadonlySet<string>): Promise<void> => {
    if (ancestors.size >= 32 || ancestors.has(sha) || filesRestored >= maxFiles) return;
    const obj = await fetchObject(sha); if (obj?.type !== "tree") return;
    let entries: ReturnType<typeof treeEntries>;
    try { entries = treeEntries(obj.payload); } catch (error) { failures.push(String(error)); return; }
    const next = new Set(ancestors); next.add(sha);
    for (const entry of entries) {
      if (filesRestored >= maxFiles) break;
      const name = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.mode === "40000" || entry.mode === "040000") await walkTree(entry.sha, name, next);
      else if (entry.mode === "100644" || entry.mode === "100755") {
        const blob = await fetchObject(entry.sha);
        if (blob?.type !== "blob" || storedBytes + blob.payload.length > totalBytes) continue;
        try {
          await safePath(input.outputRoot, `git-restored/${name}`);
          await writeArtifact(input.outputRoot, `git-restored/${name}`, blob.payload);
          filesRestored++; storedBytes += blob.payload.length;
        } catch (error) { failures.push(String(error)); }
      }
    }
  };
  if (headSha) {
    const commit = await fetchObject(headSha);
    if (commit?.type === "commit") {
      commits.push(headSha);
      const tree = commit.payload.toString("utf8").match(/^tree ([0-9a-f]{40})$/m)?.[1];
      if (tree) await walkTree(tree, "", new Set());
    }
  }
  const result = snapshot(true);
  artifacts.push(await writeArtifact(input.outputRoot, "git_restore.json", JSON.stringify(result, null, 2)));
  return result;
};