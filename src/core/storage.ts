import { AsyncLocalStorage } from "node:async_hooks";
import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";

const error = (code: string, message: string): Error & { code: string } => Object.assign(new Error(message), { code });
const roots = new Map<string, Promise<unknown>>();
const held = new AsyncLocalStorage<ReadonlySet<string>>();
const digest = (data: Uint8Array): string => createHash("sha256").update(data).digest("hex");

/** Refuse links in any existing path component; missing descendants may be created. */
const inspect = async (path: string): Promise<void> => {
  const absolute = resolve(path);
  const parts = absolute.split(sep).filter(Boolean);
  let current: string = sep;
  for (const part of parts) {
    current = resolve(current, part);
    try {
      const st = await lstat(current);
      if (st.isSymbolicLink()) throw error("path_escape", "symbolic links are not valid storage paths");
    } catch (cause) {
      if ((cause as NodeJS.ErrnoException).code === "ENOENT") return;
      throw cause;
    }
  }
};

export const safePath = async (root: string, name: string): Promise<string> => {
  if (!isAbsolute(root)) throw error("invalid_output_root", "storage root must be absolute");
  const base = resolve(root), target = resolve(base, name), rel = relative(base, target);
  if (!rel || rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw error("path_escape", "storage path must remain inside its root");
  await inspect(base); await inspect(target);
  return target;
};

const ensureParent = async (root: string, name: string): Promise<string> => {
  const target = await safePath(root, name);
  await mkdir(dirname(target), { recursive: true });
  await inspect(dirname(target));
  return target;
};

/** Atomic publication; scratch names are unique and created without following links. */
export const writeBytes = async (root: string, name: string, data: string | Uint8Array): Promise<void> => {
  const target = await ensureParent(root, name);
  const temp = `${target}.${process.pid}.${randomUUID()}.tmp`;
  let handle;
  try {
    handle = await open(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    await handle.writeFile(data); await handle.sync(); await handle.close(); handle = undefined;
    await safePath(root, name);
    await rename(temp, target);
  } finally {
    await handle?.close().catch(() => undefined);
    await unlink(temp).catch((cause: NodeJS.ErrnoException) => { if (cause.code !== "ENOENT") throw cause; });
  }
};

export const readBytes = async (root: string, name: string): Promise<Buffer> => {
  const target = await safePath(root, name);
  const handle = await open(target, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { return await handle.readFile(); } finally { await handle.close(); }
};

export const readJson = async <T>(root: string, name: string, initial: () => T, validate?: (value: unknown) => boolean): Promise<T> => {
  let bytes: Buffer;
  try { bytes = await readBytes(root, name); }
  catch (cause) { if ((cause as NodeJS.ErrnoException).code === "ENOENT") return initial(); throw cause; }
  try {
    const value: unknown = JSON.parse(bytes.toString("utf8"));
    if (validate && !validate(value)) throw new Error("state schema rejected");
    return value as T;
  } catch { throw error("corrupt_state", `invalid persisted state: ${name}`); }
};

export const writeJson = async (root: string, name: string, value: unknown): Promise<void> => {
  await writeBytes(root, name, JSON.stringify(value, null, 2));
};

const ownerAlive = (pid: unknown): boolean => {
  if (!Number.isSafeInteger(pid) || Number(pid) < 1) return true;
  try { process.kill(Number(pid), 0); return true; }
  catch (cause) { return (cause as NodeJS.ErrnoException).code !== "ESRCH"; }
};

/** Cross-process single writer. Never steal a live owner's lock on age alone. */
const diskLock = async (root: string): Promise<() => Promise<void>> => {
  const path = await ensureParent(root, ".state.lock");
  const token = randomUUID();
  const deadline = Date.now() + 60000;
  for (;;) {
    try {
      const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      try { await handle.writeFile(JSON.stringify({ pid: process.pid, token })); await handle.sync(); } finally { await handle.close(); }
      return async () => {
        const current = await readFile(path, "utf8").catch(() => "");
        if (current && JSON.parse(current).token === token) await unlink(path);
      };
    } catch (cause) {
      if ((cause as NodeJS.ErrnoException).code !== "EEXIST") throw cause;
      await inspect(path);
      const before = await lstat(path).catch(() => null);
      if (!before) continue;
      let owner: { pid?: number; token?: string } | null = null;
      try { owner = JSON.parse(await readFile(path, "utf8")); } catch { /* creation may still be in progress */ }
      if (owner && !ownerAlive(owner.pid)) {
        const after = await lstat(path).catch(() => null);
        if (after && after.ino === before.ino && after.mtimeMs === before.mtimeMs) await unlink(path).catch(() => undefined);
        continue;
      }
      if (Date.now() >= deadline) throw error("state_busy", "state transaction is owned by another writer");
      await new Promise<void>((done) => setTimeout(done, 10));
    }
  }
};

export const withRootLock = async <T>(root: string, run: () => Promise<T>): Promise<T> => {
  if (!isAbsolute(root)) throw error("invalid_output_root", "storage root must be absolute");
  const key = resolve(root);
  if (held.getStore()?.has(key)) return run();
  const previous = roots.get(key) ?? Promise.resolve();
  const task = previous.catch(() => undefined).then(async () => {
    const release = await diskLock(key);
    const next = new Set(held.getStore() ?? []); next.add(key);
    try { return await held.run(next, run); } finally { await release(); }
  });
  roots.set(key, task);
  try { return await task; } finally { if (roots.get(key) === task) roots.delete(key); }
};

export const assertHash = (hash: string): void => {
  if (!/^[0-9a-f]{64}$/.test(hash)) throw error("invalid_hash", "expected a lowercase SHA-256 digest");
};

export const readBlob = async (root: string, hash: string): Promise<Buffer | null> => {
  assertHash(hash);
  let bytes: Buffer;
  try { bytes = await readBytes(root, `blobs/${hash.slice(0, 2)}/${hash}.bin`); }
  catch (cause) { if ((cause as NodeJS.ErrnoException).code === "ENOENT") return null; throw cause; }
  if (digest(bytes) !== hash) throw error("evidence_integrity", "evidence content does not match its address");
  return bytes;
};

export const putBlob = async (root: string, data: Uint8Array): Promise<{ hash: string; bytes: number; path: string }> => {
  const hash = digest(data), name = `blobs/${hash.slice(0, 2)}/${hash}.bin`;
  const path = await safePath(root, name);
  await withRootLock(root, async () => {
    const previous = await readBlob(root, hash);
    if (!previous) await writeBytes(root, name, data);
  });
  return { hash, bytes: data.byteLength, path };
};
