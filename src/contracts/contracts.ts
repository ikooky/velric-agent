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
    apiPattern: z.string().optional(),
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

// ---- enrich / report / evidence (velric engine capabilities) ----

export const enrichAssetsContract: ToolContract = {
  name: "enrich_assets",
  title: "Enrich asset graph",
  description:
    "Asset graph auto-completion: resolve seeds (A/AAAA/CNAME), upsert root_domain/domain/subdomain/ip/service nodes, HTTP-probe web services (status+title). Writes assets.json.",
  kind: "net",
  inputSchema: z.object({
    seeds: z.array(z.string()).min(1).describe("domains or URLs"),
    outputRoot,
    proxy: z.string().optional(),
    cookie: z.string().optional(),
    timeoutMs: z.number().int().min(1000).max(120000).optional(),
    http: z.boolean().optional().describe("probe web services (default true)"),
  }),
  outputSchema: z.object({ assets: z.number() }),
  annotations: writingAnnotations(),
  examples: [{ title: "enrich", input: { seeds: ["example.com"], outputRoot: "/tmp/recon" } }],
};

export const genReportContract: ToolContract = {
  name: "gen_report",
  title: "Render markdown report",
  description:
    "Render a deliverable pentest report (findings sorted by severity, PoC evidence) from report.json.",
  kind: "structure",
  inputSchema: z.object({
    reportFile: z.string().describe("path to report.json {title,goal,assetCounts,findings[]}"),
    outputRoot,
  }),
  outputSchema: z.object({ findings: z.number() }),
  annotations: writingAnnotations(),
  examples: [{ title: "report", input: { reportFile: "/tmp/recon/report.json", outputRoot: "/tmp/recon" } }],
};

export const autoPipelineContract: ToolContract = {
  name: "auto_recon",
  title: "Autonomous recon pipeline",
  description:
    "Full recon pipeline in one command: enrich asset graph → classify SPA/MPA → static recon (harvest/spider) → runtime capture → perm tree + param matrix → findings/report/evidence. State lives in outputRoot only.",
  kind: "runtime",
  inputSchema: z.object({
    seed: z.string().describe("domain or URL"),
    outputRoot,
    chromiumPath: z.string().optional(),
    proxy: z.string().optional(),
    cookie: z.string().optional(),
    timeoutMs: z.number().int().min(1000).max(120000).optional(),
    skipRuntime: z.boolean().optional(),
    maxPages: z.number().int().min(1).max(200).optional(),
  }),
  outputSchema: z.object({ stages: z.number() }),
  annotations: writingAnnotations(),
  examples: [{ title: "auto", input: { seed: "example.com", outputRoot: "/tmp/recon" } }],
};

export const huntContract: ToolContract = {
  name: "hunt",
  title: "LLM-orchestrated hunt",
  description:
    "Multi-agent LLM orchestration: goals decomposer (goal+constraints) → planner loop (situation→judge→dispatch intents) → worker execution (JSON-action tool loop) → anti-hallucination gates (system-digest evidence channel) → report.md + evidence + graph.json. Async: returns immediately with a statusFile; poll hunt_status(outputRoot) until state=done. Resumable: state lives in outputRoot/graph.json.",
  kind: "runtime",
  inputSchema: z.object({
    goal: z.string().describe("natural-language recon goal"),
    outputRoot,
    chromiumPath: z.string().optional(),
    proxy: z.string().optional(),
    model: z.string().optional().describe("LLM model (default deepseek-v4.1-flash; needs LLM_BASE_URL/LLM_API_KEY or z-api default)"),
    maxRounds: z.number().int().min(1).max(20).optional(),
    maxSteps: z.number().int().min(1).max(30).optional(),
  }),
  outputSchema: z.object({ facts: z.number(), findings: z.number() }),
  annotations: writingAnnotations(),
  examples: [{ title: "hunt", input: { goal: "对 example.com 做 API 面侦察", outputRoot: "/tmp/recon" } }],
};

export const huntStatusContract: ToolContract = {
  name: "hunt_status",
  title: "Poll hunt progress",
  description:
    "Poll the status of a hunt started via the hunt tool. Returns state=running|done|error plus the full result (rounds, goalsMet, facts, findings, reportPath) when done.",
  kind: "runtime",
  inputSchema: z.object({ outputRoot: z.string().describe("outputRoot given to hunt") }),
  outputSchema: z.object({ state: z.string() }),
  annotations: readOnlyAnnotations(),
  examples: [{ title: "poll", input: { outputRoot: "/tmp/recon" } }],
};

export const workflowGuideContract: ToolContract = {
  name: "workflow_guide",
  title: "Recon workflow guide",
  description:
    "Returns the full recon methodology (Phase 0-5: classify → static → auth gates → runtime → perm tree → merge/report) plus execution disciplines (observed/inferred, no-CVE-matching-as-finding, serial chains step-by-step, route diversity). READ THIS FIRST before calling other tools.",
  kind: "policy",
  inputSchema: z.object({}),
  outputSchema: z.object({ phases: z.number() }),
  annotations: readOnlyAnnotations(),
  examples: [{ title: "read guide", input: {} }],
};

export const saveEvidenceContract: ToolContract = {
  name: "save_evidence",
  title: "Save evidence blobs",
  description:
    "Content-addressed (sha256) evidence store: writes blobs/<h2>/<hash>.bin + manifest.json, verifies each write.",
  kind: "structure",
  inputSchema: z.object({
    itemsFile: z.string().describe("path to items.json [{source,label?,content}]"),
    outputRoot,
  }),
  outputSchema: z.object({ blobs: z.number() }),
  annotations: writingAnnotations(),
  examples: [{ title: "evidence", input: { itemsFile: "/tmp/recon/evidence_items.json", outputRoot: "/tmp/recon" } }],
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
  enrichAssetsContract,
  genReportContract,
  saveEvidenceContract,
  autoPipelineContract,
  huntContract,
  huntStatusContract,
  workflowGuideContract,
];