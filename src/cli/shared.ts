import type { ProxyPool } from "../domain/proxyPool.js";

/** Shared CLI context handed to every command handler. */
export interface Ctx {
  readonly positional: readonly string[];
  readonly flags: Record<string, string | boolean>;
  readonly out: (v: unknown) => void;
  readonly num: (v: string | boolean | undefined) => number | undefined;
  readonly jarr: (flags: Record<string, string | boolean | undefined>, key: string) => string[] | undefined;
  readonly jobj: <T>(flags: Record<string, string | boolean | undefined>, key: string) => Promise<T | undefined>;
  readonly jarrObj: <T>(flags: Record<string, string | boolean | undefined>, key: string) => Promise<T[] | undefined>;
  readonly resolveProxy: (flags: Record<string, string | boolean | undefined>) => Promise<string | undefined>;
  readonly poolState: { pool?: ProxyPool };
}

export const num = (v: string | boolean | undefined): number | undefined => {
  if (typeof v !== "string" || v.trim() === "") return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined; // NaN flags silently corrupt timeouts/slices
};

/** Comma-separated flag → string[] (e.g. --urls a,b,c). */
export const jarr = (flags: Record<string, string | boolean | undefined>, key: string): string[] | undefined => {
  const v = flags[key];
  if (typeof v !== "string" || v.trim() === "") return undefined;
  return v.split(",").map((x) => x.trim()).filter(Boolean);
};

/** Structured flag: `--<key>-file FILE` (JSON file) wins, else inline `--<key> JSON`. */
export const jobj = async <T>(flags: Record<string, string | boolean | undefined>, key: string): Promise<T | undefined> => {
  const file = flags[`${key}-file`];
  if (typeof file === "string" && file !== "") {
    const { readFile } = await import("node:fs/promises");
    return JSON.parse(await readFile(file, "utf8")) as T;
  }
  const inline = flags[key];
  if (typeof inline === "string" && inline.trim() !== "") {
    try { return JSON.parse(inline) as T; } catch { return undefined; }
  }
  return undefined;
};

/** Resolve effective proxy: --proxy single URI, or round-robin from --proxy-pool <file>. */
export const poolState: { pool?: ProxyPool } = {};

export const resolveProxy = async (flags: Record<string, string | boolean | undefined>): Promise<string | undefined> => {
  const { setGlobalRateLimit } = await import("../adapters/http.js");
  if (typeof flags.rps === "string" && Number(flags.rps) > 0) setGlobalRateLimit(Number(flags.rps));
  if (typeof flags.proxy === "string") return flags.proxy;
  if (typeof flags["proxy-pool"] === "string") {
    if (!poolState.pool) {
      const { ProxyPool } = await import("../domain/proxyPool.js");
      poolState.pool = await ProxyPool.fromFile(flags["proxy-pool"]);
    }
    return poolState.pool.next() ?? undefined;
  }
  return undefined;
};

/** Array flag via --<key>-file/--<key> JSON, else comma list. */
export const jarrObj = async <T>(flags: Record<string, string | boolean | undefined>, key: string): Promise<T[] | undefined> => {
  const v = await jobj<T[]>(flags, key);
  if (v !== undefined) return v;
  return jarr(flags, key) as unknown as T[] | undefined;
};

/** Minimal argv parser: command-first, --flag value pairs, --bool flags. */
export interface ParsedArgs {
  readonly command: string;
  readonly positional: string[];
  readonly flags: Record<string, string | boolean>;
}

export const parseArgs = (argv: readonly string[]): ParsedArgs => {
  const [command = "help", ...rest] = argv;
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = rest[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(a);
    }
  }
  return { command, positional, flags };
};
