import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

/** Structured site map (api-recon Phase 5 deliverable): one JSON artifact
 *  aggregating routes, APIs, params, feature trigger points, and honest
 *  coverage limitations — the machine-readable contract downstream tools
 *  (asset ingestion, report gen) consume. */

export interface SiteMapInput {
  readonly baseUrl: string;
  readonly outputRoot: string;
  readonly runtimeMode?: "depth" | "coverage" | "both" | "static-only";
  readonly appType?: string;
  readonly routesFile?: string;
  readonly apiMergedFile?: string;
  readonly paramsFile?: string;
  readonly coverageFile?: string;
  readonly limitations?: string;
}

export interface SiteMap {
  readonly site: string;
  readonly runtimeMode: string;
  readonly appType: string;
  /** Gate-defeat strategy in effect during capture (from hook config facts). */
  readonly routeGuardStrategy: string[];
  readonly frontendRoutes: string[];
  readonly apis: string[];
  readonly apisFromStatic: string[];
  readonly apisFromRuntime: string[];
  readonly routesVerifiedByClick: string[];
  readonly params: { method: string; path: string; transport: string; fields: string[]; confidence: string }[];
  readonly featuresTriggered: { route: string; kind: string; label: string }[];
  readonly limitations: string;
}

const readLines = async (p: string): Promise<string[]> => {
  try { return (await readFile(p, "utf8")).split("\n").map((l) => l.trim()).filter(Boolean); }
  catch { return []; }
};

const readJson = async <T>(p: string): Promise<T | null> => {
  try { return JSON.parse(await readFile(p, "utf8")) as T; }
  catch { return null; }
};

export const buildSiteMap = async (input: SiteMapInput): Promise<SiteMap> => {
  await mkdir(input.outputRoot, { recursive: true });
  const root = input.outputRoot;

  const routes = await readLines(join(root, "routes.txt"));
  const apis = await readLines(join(root, "api_merged.txt"));
  const staticApis = await readLines(join(root, "api_static.txt"));
  const runtimeRaw = await readJson<{ uniqueCalls?: string[] }>(join(root, "runtime_api.json"));
  const runtimeApis = [...new Set((runtimeRaw?.uniqueCalls ?? []).map((c) => c.split(" ").slice(1).join(" ")))];
  // merged = static ∪ runtime; attribute each merged api to its source(s).
  const staticSet = new Set(staticApis);
  const runtimeSet = new Set(runtimeApis);
  const apisFromStatic = apis.filter((a) => staticSet.has(a));
  const apisFromRuntime = apis.filter((a) => runtimeSet.has(a));
  const coverageRaw = await readJson<{ interactions?: { route: string }[] }>(join(root, "coverage.json"));
  const routesVerifiedByClick = [...new Set((coverageRaw?.interactions ?? []).map((i) => i.route))].filter(Boolean);
  // Guard strategy facts recorded by the runtime hook (best effort).
  const gatesRaw = await readJson<{ suggestedConfig?: unknown }>(join(root, "gates_report.json"));
  const routeGuardStrategy = gatesRaw ? ["gates-analyzed"] : [];
  // params_merged.json shape: paramMerge writes a TOP-LEVEL ARRAY of
  // endpoints (accept that first); tolerate a legacy {endpoints:[...]} wrapper.
  type ParamEntry = { method: string; path: string; fields: { name: string; in: string; confidence: string }[] };
  const paramsRaw = (await readJson<ParamEntry[] | { endpoints?: ParamEntry[] }>(join(root, "params_merged.json"))) ?? [];
  const paramEntries: ParamEntry[] = Array.isArray(paramsRaw) ? paramsRaw : paramsRaw.endpoints ?? [];
  const coverage = await readJson<{ interactions?: { route: string; kind: string; label: string }[] }>(join(root, "coverage.json"));

  const params: SiteMap["params"] = paramEntries.map((e) => ({
    method: e.method,
    path: e.path,
    transport: e.fields.some((f) => f.in === "body") ? "body" : "query",
    fields: e.fields.map((f) => f.name),
    confidence: e.fields[0]?.confidence ?? "low",
  }));

  const sitemap: SiteMap = {
    site: input.baseUrl,
    runtimeMode: input.runtimeMode ?? "static-only",
    appType: input.appType ?? "unknown",
    routeGuardStrategy,
    frontendRoutes: routes,
    apis,
    apisFromStatic,
    apisFromRuntime,
    routesVerifiedByClick,
    params,
    featuresTriggered: (coverage?.interactions ?? []).map((i) => ({ route: i.route, kind: i.kind, label: i.label })),
    limitations: input.limitations ?? "static harvest only; runtime/coverage stages not run",
  };
  await writeFile(join(root, "site_map.json"), JSON.stringify(sitemap, null, 2));
  return sitemap;
};
