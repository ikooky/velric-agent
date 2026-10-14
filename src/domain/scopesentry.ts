import { fetchUrl } from "../adapters/http.js";

/** ScopeSentry sync client (deterministic thin client over the platform's
 *  documented MCP/HTTP API — skills/scopesentry/SKILL.md). Zero state: the
 *  operator supplies endpoint + API key; every call maps 1:1 to a documented
 *  API route. Used to push discovered subdomains/URLs into a scan platform
 *  and read asset lists back. */

export interface ScopeSentryConfig {
  readonly baseUrl: string; // e.g. http://host:8082
  readonly apiKey: string; // ssk_...
  readonly proxy?: string;
  readonly timeoutMs?: number;
}

const call = async <T>(cfg: ScopeSentryConfig, path: string, body?: unknown): Promise<T> => {
  const r = await fetchUrl(`${cfg.baseUrl.replace(/\/$/, "")}${path}`, {
    method: body ? "POST" : "GET",
    headers: { "x-api-key": cfg.apiKey, "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
    proxy: cfg.proxy,
    timeoutMs: cfg.timeoutMs ?? 20000,
  });
  if (r.status !== 200) throw new Error(`scopesentry ${path} -> ${r.status}: ${r.body.slice(0, 200)}`);
  return JSON.parse(r.body) as T;
};

export const listProjects = (cfg: ScopeSentryConfig) => call<unknown>(cfg, "/api/project");

export const listAssets = (cfg: ScopeSentryConfig, input: {
  asset_type: string;
  pageIndex?: number;
  pageSize?: number;
  search?: string;
  filter?: Record<string, unknown>;
}) => call<unknown>(cfg, `/api/assets/${input.asset_type}?page=${input.pageIndex ?? 1}&pageSize=${input.pageSize ?? 20}${input.search ? `&search=${encodeURIComponent(input.search)}` : ""}`);

export const createScanTask = (cfg: ScopeSentryConfig, input: {
  name: string;
  node: string[];
  template: string;
  targetSource: "general" | "project" | "asset" | "RootDomain" | "subdomain" | "UrlScan";
  target?: string;
  project?: string[];
}) => call<unknown>(cfg, "/api/task", input);

/** Push recon output (subdomains.txt / api list) as a scan task on the platform. */
export const pushSubdomains = (cfg: ScopeSentryConfig, input: { name: string; node: string[]; template: string; subdomains: string[]; project?: string[] }) =>
  createScanTask(cfg, { name: input.name, node: input.node, template: input.template, targetSource: "general", target: input.subdomains.join("\n"), project: input.project });
