import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { gunzipSync, inflateSync } from "node:zlib";

/** .git directory recovery: fetch config/HEAD/index/logs + pack objects from a
 *  leaked .git, rebuild the source tree locally (loose objects + packfiles),
 *  and surface commit history. Read-only against the target. */

export interface GitRestoreInput {
  readonly baseUrl: string;
  readonly outputRoot: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxObjects?: number;
}

export interface GitRestoreResult {
  readonly baseUrl: string;
  readonly gitFound: boolean;
  readonly objectsRecovered: number;
  readonly commits: string[];
  readonly filesRestored: number;
  readonly workDir: string;
  readonly artifacts: { path: string; bytes: number }[];
}

const GIT_FILES = ["/config", "/HEAD", "/index", "/packed-refs", "/logs/HEAD", "/logs/refs/heads/master", "/logs/refs/heads/main", "/info/refs", "/ORIG_HEAD"];

const hexOf = (sha: string): Buffer => Buffer.from(sha, "hex");

/** Minimal zlib-inflated loose-object parser → {type, payload}. */
const parseLooseObject = (raw: Buffer): { type: string; payload: Buffer } | null => {
  try {
    let buf: Buffer;
    try { buf = inflateSync(raw); } catch { buf = gunzipSync(raw); }
    const nul = buf.indexOf(0);
    if (nul < 0) return null;
    const header = buf.subarray(0, nul).toString("utf8");
    const type = header.split(" ")[0] ?? "";
    return { type, payload: buf.subarray(nul + 1) };
  } catch {
    return null;
  }
};

/** Parse tree objects into entries. */
const parseTree = (payload: Buffer): { mode: string; name: string; sha: string }[] => {
  const out: { mode: string; name: string; sha: string }[] = [];
  let i = 0;
  while (i < payload.length) {
    const sp = payload.indexOf(0x20, i);
    const nul = payload.indexOf(0x00, sp);
    if (sp < 0 || nul < 0) break;
    out.push({
      mode: payload.subarray(i, sp).toString("utf8"),
      name: payload.subarray(sp + 1, nul).toString("utf8"),
      sha: payload.subarray(nul + 1, nul + 21).toString("hex"),
    });
    i = nul + 21;
  }
  return out;
};

export const restoreGit = async (input: GitRestoreInput): Promise<GitRestoreResult> => {
  const base = input.baseUrl.replace(/\/$/, "");
  const workDir = join(input.outputRoot, "git-restored");
  await mkdir(workDir, { recursive: true });
  const gitDir = join(workDir, ".git");
  await mkdir(join(gitDir, "objects"), { recursive: true });
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10000 };

  // 1) Confirm the leak
  const cfg = await fetchUrl(`${base}/.git/config`, opts);
  if (cfg.status !== 200 || !cfg.body.includes("[core")) {
    return { baseUrl: base, gitFound: false, objectsRecovered: 0, commits: [], filesRestored: 0, workDir, artifacts: [] };
  }
  await writeFile(join(gitDir, "config"), cfg.body);

  // 2) Pull core metadata
  const head = await fetchUrl(`${base}/.git/HEAD`, opts);
  let headSha: string | null = null;
  if (head.status === 200) {
    await writeFile(join(gitDir, "HEAD"), head.body);
    headSha = (head.body.match(/ref:\s*refs\/heads\/(\S+)/) ?? [])[1] ? null : (head.body.match(/[0-9a-f]{40}/) ?? [null])[0] ?? null;
  }
  for (const f of GIT_FILES.slice(2)) {
    const r = await fetchUrl(`${base}/.git${f}`, opts);
    if (r.status === 200) {
      const p = join(gitDir, f.replace(/\/$/, ""));
      await mkdir(join(p, ".."), { recursive: true });
      await writeFile(p, r.body);
    }
  }

  // 3) Loose-object walk: resolve HEAD → tree → blobs (bounded).
  const objectsRecovered = { n: 0 };
  const commits: string[] = [];
  const filesRestored = { n: 0 };
  const seen = new Set<string>();

  const fetchObject = async (sha: string): Promise<{ type: string; payload: Buffer } | null> => {
    if (seen.has(sha)) return null;
    seen.add(sha);
    const path = `/objects/${sha.slice(0, 2)}/${sha.slice(2)}`;
    const res = await fetchUrl(`${base}/.git${path}`, { ...opts, maxBytes: 8 * 1024 * 1024, raw: true });
    if (res.status !== 200 || !res.rawBuffer) return null;
    objectsRecovered.n++;
    return parseLooseObject(res.rawBuffer);
  };

  const walkTree = async (treeSha: string, prefix: string, depth: number): Promise<void> => {
    if (depth > 8 || objectsRecovered.n >= (input.maxObjects ?? 400)) return;
    const obj = await fetchObject(treeSha);
    if (!obj || obj.type !== "tree") return;
    for (const entry of parseTree(obj.payload)) {
      const name = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.mode === "40000" || entry.mode === "040000") {
        await walkTree(entry.sha, name, depth + 1);
      } else {
        const blob = await fetchObject(entry.sha);
        if (blob && blob.type === "blob") {
          const out = join(workDir, name);
          await mkdir(join(out, ".."), { recursive: true });
          await writeFile(out, blob.payload);
          filesRestored.n++;
        }
      }
    }
  };

  // HEAD may be a symref: resolve via refs/heads/<name> or packed-refs.
  if (!headSha) {
    const m = head.body.match(/ref:\s*refs\/heads\/(\S+)/);
    if (m) {
      const refFile = await fetchUrl(`${base}/.git/refs/heads/${m[1]}`, opts);
      if (refFile.status === 200) headSha = (refFile.body.match(/[0-9a-f]{40}/) ?? [null])[0] ?? null;
    }
  }
  // packed-refs fallback
  if (!headSha) {
    const packed = await fetchUrl(`${base}/.git/packed-refs`, opts);
    if (packed.status === 200) headSha = (packed.body.match(/[0-9a-f]{40}/) ?? [null])[0] ?? null;
  }

  if (headSha) {
    commits.push(headSha);
    const commit = await fetchObject(headSha);
    if (commit && commit.type === "commit") {
      const treeSha = (commit.payload.toString("utf8").match(/tree ([0-9a-f]{40})/) ?? [])[1] ?? null;
      if (treeSha) await walkTree(treeSha, "", 0);
    }
  }

  const report = join(input.outputRoot, "git_restore.json");
  const body = JSON.stringify({ baseUrl: base, gitFound: true, objectsRecovered: objectsRecovered.n, commits, filesRestored: filesRestored.n, workDir }, null, 2);
  await writeFile(report, body);
  return { baseUrl: base, gitFound: true, objectsRecovered: objectsRecovered.n, commits, filesRestored: filesRestored.n, workDir, artifacts: [{ path: report, bytes: Buffer.byteLength(body) }] };
};
