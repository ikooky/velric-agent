import { z } from "zod";

import type { ToolContract } from "./toolContract.js";
import { readOnlyAnnotations, writingAnnotations } from "./toolContract.js";

const outputRoot = z
  .string()
  .describe("absolute directory for artifacts (created if missing)");

// ---- net ----

export const dnsResolveContract: ToolContract = {
  name: "dns_resolve",
  title: "DNS resolve",
  description:
    "Resolve A/AAAA/CNAME records for one or more hosts. Stateless lookup; no caching.",
  kind: "net",
  inputSchema: z.object({
    hosts: z.array(z.string().min(1)).min(1).max(50),
  }),
  outputSchema: z.object({ results: z.array(z.object({ host: z.string(), answers: z.array(z.object({ type: z.string(), value: z.string() })), error: z.string().optional() })) }),
  annotations: readOnlyAnnotations(),
  examples: [{ title: "one host", input: { hosts: ["example.com"] } }],
};

export const httpProbeContract: ToolContract = {
  name: "http_probe",
  title: "HTTP probe",
  description:
    "GET one URL: status, title, server/x-powered-by, size, sha256. TLS verification disabled (recon targets are often self-signed).",
  kind: "net",
  inputSchema: z.object({
    url: z.string().url(),
    cookie: z.string().optional(),
    proxy: z.string().optional(),
    timeoutMs: z.number().int().min(1000).max(120000).optional(),
    headers: z.record(z.string(), z.string()).optional(),
  }),
  outputSchema: z.object({ url: z.string(), status: z.number() }),
  annotations: readOnlyAnnotations(),
  examples: [{ title: "probe", input: { url: "https://example.com" } }],
};

// ---- static ----

export const harvestStaticContract: ToolContract = {
  name: "harvest_static",
  title: "Harvest static bundles",
  description:
    "Fetch the SPA entry, download every script, expand webpack/Vite chunk manifests to fixpoint, extract API endpoints and frontend routes into api_static.txt / routes.txt / paths_other.txt / chunkmap.txt under output_root.",
  kind: "static",
  inputSchema: z.object({
    baseUrl: z.string().describe("entry URL, e.g. https://target/"),
    outputRoot,
    timeoutMs: z.number().int().min(1000).max(120000).optional(),
    maxRounds: z.number().int().min(1).max(20).optional(),
    concurrency: z.number().int().min(1).max(48).optional(),
    proxy: z.string().optional(),
    cookie: z.string().optional(),
  }),
  outputSchema: z.object({ apiEndpoints: z.number(), routes: z.number() }),
  annotations: writingAnnotations(),
  examples: [
    { title: "full harvest", input: { baseUrl: "https://target/", outputRoot: "/tmp/recon" } },
  ],
};

export const extractRoutesContract: ToolContract = {
  name: "extract_routes",
  title: "Extract routes from JS",
  description:
    "Run endpoint/route extraction over a directory of already-downloaded JS chunks (the js/ dir produced by harvest_static).",
  kind: "static",
  inputSchema: z.object({
    jsDir: z.string().describe("absolute path to a directory of .js files"),
    outputRoot,
  }),
  outputSchema: z.object({ api: z.number(), routes: z.number() }),
  annotations: writingAnnotations(),
  examples: [{ title: "re-extract", input: { jsDir: "/tmp/recon/js", outputRoot: "/tmp/recon" } }],
};

// ---- runtime ----

export const captureRuntimeContract: ToolContract = {
  name: "capture_runtime",
  title: "Capture runtime surface",
  description:
    "Drive a headless Chromium through an authorized SPA: inject the api-recon preload hook (three-gate defeat), walk routes, record live XHR/fetch/WS endpoints with methods and bodies into runtime_api.json.",
  kind: "runtime",
  inputSchema: z.object({
    baseUrl: z.string(),
    outputRoot,
    routes: z.array(z.string()).optional(),
    cookies: z.array(z.object({ name: z.string(), value: z.string(), path: z.string().optional() })).optional(),
    localStorage: z.record(z.string(), z.string()).optional(),
    stubs: z.array(z.object({ match: z.string(), body: z.unknown() })).optional(),
    chromiumPath: z.string().optional(),
    headless: z.boolean().optional(),
    proxy: z.string().optional(),
    waitMs: z.number().int().optional(),
    perRouteMs: z.number().int().optional(),
    routeTimeoutMs: z.number().int().optional(),
    recordWs: z.boolean().optional(),
  }),
  outputSchema: z.object({ uniqueCalls: z.array(z.string()) }),
  annotations: writingAnnotations(),
  examples: [
    { title: "depth capture", input: { baseUrl: "https://target/", outputRoot: "/tmp/recon" } },
  ],
};

// ---- structure ----

export const buildPermTreeContract: ToolContract = {
  name: "build_perm_tree",
  title: "Rebuild permission tree",
  description:
    "Parse userRouteAuth from downloaded JS, resolve webpack aliases via routeMap, infer hierarchy from code prefixes, and write permissive menu/permission stubs (permissions_all_stub.json / role_permissions_stub.json).",
  kind: "structure",
  inputSchema: z.object({
    jsDir: z.string(),
    outputRoot,
    role: z.string().optional(),
    roots: z.array(z.string()).optional(),
    prefixParent: z.record(z.string(), z.string()).optional(),
    extraParent: z.record(z.string(), z.string()).optional(),
  }),
  outputSchema: z.object({ entries: z.number(), codes: z.number() }),
  annotations: writingAnnotations(),
  examples: [{ title: "default heuristics", input: { jsDir: "/tmp/recon/js", outputRoot: "/tmp/recon" } }],
};

export const mergeParamsContract: ToolContract = {
  name: "merge_params",
  title: "Merge parameter samples",
  description:
    "Merge recorded param samples (param_samples.json: [{method,url,body,query}]) into per-endpoint field sets with confidence. A field seen in every sample is high; seen once is medium; nothing implies required/optional from one sample.",
  kind: "structure",
  inputSchema: z.object({
    samplesFile: z.string().describe("absolute path to param_samples.json"),
    outputRoot,
  }),
  outputSchema: z.object({ samples: z.number(), endpoints: z.number() }),
  annotations: writingAnnotations(),
  examples: [
    { title: "merge", input: { samplesFile: "/tmp/recon/param_samples.json", outputRoot: "/tmp/recon" } },
  ],
};

// ---- policy ----

export const spiderMpaContract: ToolContract = {
  name: "spider_mpa",
  title: "Spider MPA",
  description:
    "Same-origin bounded BFS crawl for non-SPA targets: extract <form> endpoints with params, inline ajax URLs, and the reached link set into forms.txt / links.txt / api_inline.txt.",
  kind: "static",
  inputSchema: z.object({
    baseUrl: z.string(),
    outputRoot,
    cookie: z.string().optional(),
    proxy: z.string().optional(),
    maxPages: z.number().int().min(1).max(2000).optional(),
    depth: z.number().int().min(0).max(10).optional(),
    delayMs: z.number().int().min(0).max(5000).optional(),
    include: z.string().optional(),
    exclude: z.string().optional(),
  }),
  outputSchema: z.object({ crawled: z.number(), forms: z.number() }),
  annotations: writingAnnotations(),
  examples: [{ title: "crawl", input: { baseUrl: "https://target/", outputRoot: "/tmp/recon" } }],
};

export const ALL_CONTRACTS: readonly ToolContract[] = [
  dnsResolveContract,
  httpProbeContract,
  harvestStaticContract,
  extractRoutesContract,
  spiderMpaContract,
  captureRuntimeContract,
  buildPermTreeContract,
  mergeParamsContract,
];