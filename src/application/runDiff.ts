import { readFile } from "node:fs/promises";
import { join } from "node:path";

/** Structured diff between two recon runs of the same target: new endpoints,
 * params, routes, assets — the basis for attack-surface monitoring (cron the
 * CLI, diff consecutive runs, alert on additions). */

export interface RunDiffInput {
  readonly oldRoot: string;
  readonly newRoot: string;
}

export interface RunDiffResult {
  readonly addedApi: string[];
  readonly removedApi: string[];
  readonly addedRoutes: string[];
  readonly addedParams: { method: string; path: string; fields: string[] }[];
  readonly assetsDelta: { type: string; key: string; change: "added" | "removed" }[];
  readonly summary: string;
}

const readLines = async (root: string, name: string): Promise<string[]> => {
  try {
    return (await readFile(join(root, name), "utf8")).split("\n").filter(Boolean);
  } catch (err) {
    // Only "file absent" is an empty baseline; other IO failures (perms,
    // corrupt fs) must surface — silently treating them as empty would report
    // every existing row as newly added (false diff).
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
};

const readJsonFile = async <T,>(root: string, name: string): Promise<T | null> => {
  try {
    return JSON.parse(await readFile(join(root, name), "utf8")) as T;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
};

interface MergedParams {
  method: string;
  path: string;
  fields: { name: string }[];
}

export const runDiff = async (input: RunDiffInput): Promise<RunDiffResult> => {
  const [oldApi, newApi] = await Promise.all([
    readLines(input.oldRoot, "api_merged.txt"),
    readLines(input.newRoot, "api_merged.txt"),
  ]);
  const oldSet = new Set(oldApi);
  const newSet = new Set(newApi);
  const addedApi = [...newSet].filter((x) => !oldSet.has(x)).sort();
  const removedApi = [...oldSet].filter((x) => !newSet.has(x)).sort();

  const [oldRoutes, newRoutes] = await Promise.all([
    readLines(input.oldRoot, "routes.txt"),
    readLines(input.newRoot, "routes.txt"),
  ]);
  const oldRouteSet = new Set(oldRoutes);
  const addedRoutes = [...new Set(newRoutes)].filter((x) => !oldRouteSet.has(x)).sort();

  const oldParams = (await readJsonFile<MergedParams[]>(input.oldRoot, "params_merged.json")) ?? [];
  const newParams = (await readJsonFile<MergedParams[]>(input.newRoot, "params_merged.json")) ?? [];
  const oldFieldSet = new Map(oldParams.map((p) => [`${p.method} ${p.path}`, new Set(p.fields.map((f) => f.name))]));
  const addedParams = newParams
    .map((p) => {
      const key = `${p.method} ${p.path}`;
      const prev = oldFieldSet.get(key) ?? new Set<string>();
      const fields = p.fields.map((f) => f.name).filter((f) => !prev.has(f));
      return fields.length > 0 ? { method: p.method, path: p.path, fields } : null;
    })
    .filter((x): x is { method: string; path: string; fields: string[] } => x !== null);

  const oldAssets = (await readJsonFile<{ type: string; key: string }[]>(input.oldRoot, "assets.json")) ?? [];
  const newAssets = (await readJsonFile<{ type: string; key: string }[]>(input.newRoot, "assets.json")) ?? [];
  const oa = new Map(oldAssets.map((a) => [`${a.type}:${a.key}`, a]));
  const na = new Map(newAssets.map((a) => [`${a.type}:${a.key}`, a]));
  const assetsDelta = [
    ...[...na.keys()].filter((k) => !oa.has(k)).map((k) => ({ type: na.get(k)!.type, key: na.get(k)!.key, change: "added" as const })),
    ...[...oa.keys()].filter((k) => !na.has(k)).map((k) => ({ type: oa.get(k)!.type, key: oa.get(k)!.key, change: "removed" as const })),
  ];

  const parts = [
    `+${addedApi.length} API`,
    `-${removedApi.length} API`,
    `+${addedRoutes.length} routes`,
    `+${addedParams.length} param-sets`,
    `±${assetsDelta.length} assets`,
  ];
  return {
    addedApi,
    removedApi,
    addedRoutes,
    addedParams,
    assetsDelta,
    summary: parts.join("  "),
  };
};
