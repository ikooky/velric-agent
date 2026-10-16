import { writeFile, readFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

/** Global rate limiter: token bucket with min-interval between acquisitions.
 *  Shared process-wide so every recon module slows down together when the
 *  target pushes back. */

interface Waiter { resolve: () => void; reject: (e: Error) => void; cleanup: () => void }
interface Bucket { interval: number; lastAt: number; queue: Waiter[]; timer?: ReturnType<typeof setTimeout> }
const buckets = new Map<string, Bucket>();
export interface RateLimitOptions { rps?: number; signal?: AbortSignal }
const abortError = (): Error => Object.assign(new Error("Rate-limit acquisition cancelled"), { name: "AbortError" });
const schedule = (key: string, b: Bucket): void => {
  if (b.timer) clearTimeout(b.timer);
  b.timer = undefined;
  if (!b.queue.length) return;
  const wait = b.lastAt + b.interval - Date.now();
  if (wait > 0) { b.timer = setTimeout(() => schedule(key, b), wait); return; }
  const next = b.queue.shift()!;
  b.lastAt = Date.now(); next.cleanup(); next.resolve();
  schedule(key, b);
};
export const acquire = (key: string, limit: number | RateLimitOptions): { promise: Promise<void>; cancel: () => void } => {
  const interval = typeof limit === "number" ? Math.max(0, limit) : (limit.rps && limit.rps > 0 ? 1000 / limit.rps : 0);
  let b = buckets.get(key);
  if (!b) {
    for (const [k, idle] of buckets) if (!idle.queue.length && Date.now() - idle.lastAt > 60000) buckets.delete(k);
    b = { interval, lastAt: -Infinity, queue: [] }; buckets.set(key, b);
  }
  b.interval = interval;
  const bucket = b; const signal = typeof limit === "number" ? undefined : limit.signal;
  let waiter: Waiter | undefined;
  const cancel = (): void => {
    if (!waiter) return;
    const i = bucket.queue.indexOf(waiter);
    if (i < 0) return;
    bucket.queue.splice(i, 1); waiter.cleanup(); waiter.reject(abortError()); schedule(key, bucket);
  };
  const promise = new Promise<void>((resolve, reject) => {
    if (signal?.aborted) { reject(abortError()); return; }
    waiter = { resolve, reject, cleanup: () => signal?.removeEventListener("abort", cancel) };
    signal?.addEventListener("abort", cancel, { once: true });
    bucket.queue.push(waiter); schedule(key, bucket);
  });
  return { promise, cancel };
};

export const throttledMap = async <T>(
  tasks: readonly (() => Promise<T>)[],
  options: { concurrency?: number; host?: string } & RateLimitOptions,
): Promise<T[]> => {
  const concurrency = options.concurrency ?? 8;
  const results: T[] = [];
  let cursor = 0;
  const worker = async (): Promise<void> => {
    while (cursor < tasks.length) {
      const idx = cursor++;
      const t = tasks[idx];
      if (!t) continue;
      if (options.host) await acquire(options.host, options).promise;
      results[idx] = await t();
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, tasks.length) }, worker));
  return results;
};

// ---------- Auto pipeline checkpoint ----------

/** Stage-level checkpoint for the auto pipeline: completed stages are skipped
 *  on resume, so a crashed run continues instead of restarting. */

export interface Checkpoint {
  /** Seed the checkpoint was written for — a different seed invalidates it
   *  (stale stage artifacts from a previous target must not be resumed). */
  seed?: string;
  readonly stages: Record<string, { status: string; at: string }>;
}

export const readCheckpoint = async (outputRoot: string, seed?: string): Promise<Checkpoint> => {
  try {
    const cp = JSON.parse(await readFile(join(outputRoot, "checkpoint.json"), "utf8")) as Checkpoint;
    if (seed !== undefined && cp.seed !== undefined && cp.seed !== seed) return { stages: {} };
    return cp;
  } catch {
    return { stages: {} };
  }
};

export const writeStageDone = async (
  outputRoot: string,
  stage: string,
  seed?: string,
): Promise<void> => {
  const cp = await readCheckpoint(outputRoot, seed);
  if (seed !== undefined) (cp as { seed?: string }).seed = seed;
  cp.stages[stage] = { status: "ok", at: new Date().toISOString() };
  await mkdir(outputRoot, { recursive: true });
  await writeFile(join(outputRoot, "checkpoint.json"), JSON.stringify(cp, null, 2));
};
