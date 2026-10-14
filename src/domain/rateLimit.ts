import { writeFile, readFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

/** Global rate limiter: token bucket with min-interval between acquisitions.
 *  Shared process-wide so every recon module slows down together when the
 *  target pushes back. */

const buckets = new Map<string, Bucket>();

interface Bucket {
  readonly interval: number;
  lastAt: number;
  queue: Array<() => void>;
  draining: boolean;
}

/** Per-key min-interval gate. Single scheduled timer per bucket guarantees the
 *  configured interval is enforced even under concurrent acquire() bursts
 *  (previously each acquire scheduled its own drain, letting two waiters
 *  release back-to-back in one tick). */
export interface RateLimitOptions { rps?: number }

export const acquire = (key: string, limit: number | { rps?: number }): { promise: Promise<void>; cancel: () => void } => {
  const intervalMs = typeof limit === "number" ? limit : 1000 / Math.max(limit.rps ?? 0, 0.001);
  let b = buckets.get(key);
  if (!b) { b = { interval: intervalMs, lastAt: 0, queue: [], draining: false }; buckets.set(key, b); }
  const bucket = b;
  let cancelled = false;
  const promise = new Promise<void>((resolve) => {
    const tryRun = (): void => {
      if (cancelled) { resolve(); return; }
      const now = Date.now();
      if (now - bucket.lastAt >= bucket.interval) {
        bucket.lastAt = now;
        resolve();
        return;
      }
      bucket.queue.push(resolve);
      if (!bucket.draining) {
        bucket.draining = true;
        const drain = (): void => {
          bucket.draining = false;
          const next = bucket.queue.shift();
          if (next) {
            bucket.lastAt = Date.now();
            next();
            if (bucket.queue.length > 0) {
              bucket.draining = true;
              setTimeout(drain, bucket.interval);
            }
          }
          if (bucket.queue.length === 0 && Date.now() - bucket.lastAt > 60000) buckets.delete(key); // idle prune
        };
        const wait = bucket.interval - (Date.now() - bucket.lastAt);
        setTimeout(drain, Math.max(wait, 0));
      }
    };
    tryRun();
  });
  return { promise, cancel: () => { cancelled = true; } };
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
      if (options.host) await acquire(options.host, options);
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
  readonly stages: Record<string, { status: string; at: string }>;
}

export const readCheckpoint = async (outputRoot: string): Promise<Checkpoint> => {
  try {
    return JSON.parse(await readFile(join(outputRoot, "checkpoint.json"), "utf8")) as Checkpoint;
  } catch {
    return { stages: {} };
  }
};

export const writeStageDone = async (
  outputRoot: string,
  stage: string,
): Promise<void> => {
  const cp = await readCheckpoint(outputRoot);
  cp.stages[stage] = { status: "ok", at: new Date().toISOString() };
  await mkdir(outputRoot, { recursive: true });
  await writeFile(join(outputRoot, "checkpoint.json"), JSON.stringify(cp, null, 2));
};
