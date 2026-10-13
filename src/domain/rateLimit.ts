import { writeFile, readFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

/** Global rate limiter: token bucket with min-interval between acquisitions.
 *  Shared process-wide so every recon module slows down together when the
 *  target pushes back. */

interface Bucket {
  lastAt: number;
  queue: (() => void)[];
}

const buckets = new Map<string, Bucket>();

export interface RateLimitOptions {
  /** Max acquisitions per second per bucket (0/undefined = unlimited). */
  readonly rps?: number;
  /** Fixed delay between acquisitions in ms (alternative to rps). */
  readonly intervalMs?: number;
}

export const acquire = (bucketKey: string, opts: RateLimitOptions): Promise<void> => {
  const rps = opts.rps ?? 0;
  const interval = opts.intervalMs ?? (rps > 0 ? 1000 / rps : 0);
  if (interval <= 0) return Promise.resolve();
  let b = buckets.get(bucketKey);
  if (!b) {
    b = { lastAt: 0, queue: [] };
    buckets.set(bucketKey, b);
  }
  const bucket = b;
  return new Promise((resolve) => {
    bucket.queue.push(resolve);
    const drain = (): void => {
      if (bucket.queue.length === 0) return;
      const now = Date.now();
      const wait = Math.max(0, bucket.lastAt + interval - now);
      if (wait > 0) {
        setTimeout(drain, wait);
        return;
      }
      bucket.lastAt = now;
      const next = bucket.queue.shift();
      if (next) next();
      if (bucket.queue.length > 0) setImmediate(drain);
    };
    drain();
  });
};

/** Run tasks with bounded concurrency + per-host rate limiting. */
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
