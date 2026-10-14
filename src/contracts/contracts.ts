import { z } from "zod";

import type { ToolContract } from "./toolContract.js";
import { readOnlyAnnotations, writingAnnotations } from "./toolContract.js";

const outputRoot = z
  .string()
  .describe("absolute directory for artifacts (created if missing)");

// ---- net ----

const LEDGER = z.string().optional().describe("auto-record touched URLs into the hunt observation ledger");

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
    observationLedgerRoot: z.string().optional().describe("auto-record touched URLs into the hunt observation ledger"),
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
    observationLedgerRoot: z.string().optional().describe("auto-record touched URLs into the hunt observation ledger"),
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
    observationLedgerRoot: z.string().optional().describe("auto-record touched URLs into the hunt observation ledger"),
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
    observationLedgerRoot: z.string().optional().describe("auto-record touched URLs into the hunt observation ledger"),
    maxRoutes: z.number().int().min(1).max(200).optional(),
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
    observationLedgerRoot: z.string().optional().describe("auto-record touched URLs into the hunt observation ledger"),
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
    observationLedgerRoot: z.string().optional().describe("auto-record touched URLs into the hunt observation ledger"),
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
    observationLedgerRoot: z.string().optional().describe("auto-record touched URLs into the hunt observation ledger"),
    seeds: z.array(z.string()).min(1).describe("domains or URLs"),
    outputRoot,
    proxy: z.string().optional(),
    cookie: z.string().optional(),
    timeoutMs: z.number().int().min(1000).max(120000).optional(),
    http: z.boolean().optional().describe("probe web services (default true)"),
  }),
  outputSchema: z.object({ assets: z.array(z.unknown()) }),
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
    observationLedgerRoot: z.string().optional().describe("auto-record touched URLs into the hunt observation ledger"),
  }),
  outputSchema: z.object({ findings: z.number() }),
  annotations: writingAnnotations(),
  examples: [{ title: "report", input: { reportFile: "/tmp/recon/report.json", outputRoot: "/tmp/recon" } }],
};

export const autoPipelineContract: ToolContract = {
  name: "auto_recon",
  title: "Autonomous recon pipeline",
  description:
    "Starts the full recon pipeline asynchronously (returns immediately; poll auto_status until state=done): fingerprint → subdomains → enrich → classify → harvest/spider → runtime → perm tree + params → sensitive paths → CORS → sourcemaps → auth surface → dom sinks → JWT → findings/report/evidence. Stage-level checkpoint (resume by default, --fresh to rerun). State lives in outputRoot only.",
  kind: "runtime",
  inputSchema: z.object({
    observationLedgerRoot: z.string().optional().describe("auto-record touched URLs into the hunt observation ledger"),
    seed: z.string().describe("domain or URL"),
    outputRoot,
    chromiumPath: z.string().optional(),
    proxy: z.string().optional(),
    cookie: z.string().optional(),
    timeoutMs: z.number().int().min(1000).max(120000).optional(),
    skipRuntime: z.boolean().optional(),
    maxPages: z.number().int().min(1).max(200).optional(),
  }),
  outputSchema: z.object({ started: z.boolean(), statusFile: z.string() }),
  annotations: writingAnnotations(),
  examples: [{ title: "auto", input: { seed: "example.com", outputRoot: "/tmp/recon" } }],
};

export const autoStatusContract: ToolContract = {
  name: "auto_status",
  title: "Poll auto_recon progress",
  description:
    "Poll the async auto_recon pipeline: returns {state: running|done|error, result?} from outputRoot/auto_status.json.",
  kind: "runtime",
  inputSchema: z.object({ outputRoot }),
  outputSchema: z.object({ state: z.string() }),
  annotations: readOnlyAnnotations(),
  examples: [{ title: "poll", input: { outputRoot: "/tmp/recon" } }],
};

export const huntContract = {
  name: "hunt_begin",
  title: "Begin host-driven hunt",
  description:
    "Initialize the hunt workspace: creates/resets graph.json for the goal and returns the DRIVER PLAYBOOK (planner/worker disciplines: goal decomposition rules, hard-floor planning, quantified acceptance, evidence gates, worker red lines). The HOST agent is the brain — read the playbook, then drive tools + hunt_record/hunt_overview in a loop.",
  kind: "runtime",
  inputSchema: z.object({ goal: z.string(), outputRoot: z.string() }),
  outputSchema: z.object({ goal: z.string() }),
  annotations: writingAnnotations(),
  examples: [{ title: "begin", input: { goal: "对 example.com 做 API 面侦察", outputRoot: "/tmp/recon" } }],
} as unknown as ToolContract;

export const huntRecordContract = {
  name: "hunt_record",
  title: "Record gated results",
  description:
    "Write intents/goals/facts/findings/assets back into the graph. Anti-hallucination gates run automatically: every http(s) URL cited in evidence/poc must exist in the observation ledger (URLs tools actually requested when observationLedgerRoot was set); observed facts must cite a ledger entry; inferred facts pass with confidence=inferred. Returns accepted/dropped counts.",
  kind: "runtime",
  inputSchema: z.object({
    outputRoot,
    intentId: z.number().optional(),
    intentSummary: z.string().optional(),
    goals: z.array(z.object({ summary: z.string(), vulnclass: z.string().optional() })).optional(),
    intents: z.array(z.object({ summary: z.string(), state: z.string().optional() })).optional(),
    facts: z.array(z.object({
      summary: z.string().optional(),
      detail: z.string().optional(),
      evidence: z.string().optional(),
      confidence: z.string().optional().describe("observed|inferred"),
    })).optional(),
    findings: z.array(z.object({
      name: z.string().optional(),
      vulnclass: z.string().optional(),
      severity: z.string().optional(),
      summary: z.string().optional(),
      poc: z.string().optional(),
    })).optional(),
    assets: z.array(z.object({
      type: z.string().optional(),
      key: z.string().optional(),
      props: z.record(z.string(), z.unknown()).optional(),
    })).optional(),
    goalsMet: z.array(z.object({ id: z.number(), reason: z.string().optional() })).optional(),
  }),
  outputSchema: z.object({ accepted: z.number(), dropped: z.number() }),
  annotations: writingAnnotations(),
  examples: [{ title: "record", input: { outputRoot: "/tmp/recon", facts: [{ summary: "GET /x → 200", evidence: "GET https://t/x → 200", confidence: "observed" }] } }],
} as unknown as ToolContract;

export const huntOverviewContract = {
  name: "hunt_overview",
  title: "Read hunt situation",
  description:
    "Return the full situation (goal, goals+met, open/running/recent intents, recent facts with evidence, findings, asset counts) for the host's next planning decision.",
  kind: "runtime",
  inputSchema: z.object({ outputRoot }),
  outputSchema: z.object({ overview: z.string() }),
  annotations: readOnlyAnnotations(),
  examples: [{ title: "overview", input: { outputRoot: "/tmp/recon" } }],
} as unknown as ToolContract;

export const workflowGuideContract: ToolContract = {
  name: "workflow_guide",
  title: "Recon workflow guide",
  description:
    "Returns the full recon methodology (Phase 0-5: classify → static → auth gates → runtime → perm tree → merge/report) plus execution disciplines (observed/inferred, no-CVE-matching-as-finding, serial chains step-by-step, route diversity). READ THIS FIRST before calling other tools.",
  kind: "policy",
  inputSchema: z.object({}),
  outputSchema: z.string(),
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
    observationLedgerRoot: z.string().optional().describe("auto-record touched URLs into the hunt observation ledger"),
  }),
  outputSchema: z.object({ blobs: z.array(z.object({ hash: z.string(), bytes: z.number() })) }),
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
    observationLedgerRoot: z.string().optional().describe("auto-record touched URLs into the hunt observation ledger"),
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


export const runDiffContract: ToolContract = {
  name: "run_diff",
  title: "Diff two recon runs",
  description:
    "Structured diff between two recon outputRoots of the same target: added/removed API endpoints, new routes, new param sets, asset delta. Basis for attack-surface monitoring (cron the CLI auto + run-diff consecutive runs).",
  kind: "runtime",
  inputSchema: z.object({
    oldRoot: z.string(),
    newRoot: z.string(),
  }),
  outputSchema: z.object({ summary: z.string() }),
  annotations: readOnlyAnnotations(),
  examples: [{ title: "diff", input: { oldRoot: "/tmp/recon-old", newRoot: "/tmp/recon-new" } }],
};

export const probeParamsContract: ToolContract = {
  name: "probe_params",
  title: "Per-param differential probe",
  description:
    "For each merged endpoint: baseline request, then remove one query param at a time and diff status/body. Reveals required params (removal → 4xx) and behavior-switch params without guessing. GET endpoints only.",
  kind: "runtime",
  inputSchema: z.object({
    mergedFile: z.string().describe("path to params_merged.json"),
    baseUrl: z.string().optional().describe("origin for relative-path endpoints (paramMerge strips hosts); without it relative endpoints are skipped and counted"),
    outputRoot,
    observationLedgerRoot: z.string().optional().describe("auto-record touched URLs into the hunt observation ledger"),
    cookie: z.string().optional(),
    proxy: z.string().optional(),
    timeoutMs: z.number().optional(),
    maxEndpoints: z.number().optional(),
  }),
  outputSchema: z.object({ probed: z.number() }),
  annotations: writingAnnotations(),
  examples: [{ title: "probe", input: { mergedFile: "/tmp/recon/params_merged.json", outputRoot: "/tmp/recon" } }],
};


export const subdomainsContract: ToolContract = {
  name: "subdomain_enum",
  title: "Subdomain enumeration",
  description:
    "crt.sh certificate transparency + CNAME chain walking + high-frequency wordlist DNS brute (142 prefixes: api/dev/admin/uat/gray/jenkins/k8s/grafana...). Writes subdomains.txt.",
  kind: "runtime",
  inputSchema: z.object({ domain: z.string(), outputRoot, observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ total: z.array(z.string()), crtSh: z.array(z.string()), bruteFound: z.array(z.object({ host: z.string(), ips: z.array(z.string()) })), wildcardDns: z.boolean() }),
  annotations: writingAnnotations(),
  examples: [{ title: "enum", input: { domain: "example.com", outputRoot: "/tmp/recon" } }],
};

export const portScanContract: ToolContract = {
  name: "port_scan",
  title: "TCP port scan",
  description:
    "TCP connect scan of top 67 ports (web/db/middleware/admin). Non-web open ports (redis/mongodb/es...) are direct findings. Writes ports_open.txt.",
  kind: "runtime",
  inputSchema: z.object({ host: z.string(), outputRoot, ports: z.array(z.number()).optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ open: z.array(z.object({ port: z.number(), service: z.string() })), scanned: z.number() }),
  annotations: writingAnnotations(),
  examples: [{ title: "scan", input: { host: "1.2.3.4", outputRoot: "/tmp/recon" } }],
};

export const pathsContract: ToolContract = {
  name: "probe_paths",
  title: "Sensitive path probing",
  description:
    "Built-in 65 high-signal paths (.git/config, .env, swagger, actuator, druid, phpinfo, backup dumps...) with soft-404 calibration (random-path baseline; isomorphic responses are not findings). Writes sensitive_paths.txt.",
  kind: "runtime",
  inputSchema: z.object({ baseUrl: z.string(), outputRoot, paths: z.array(z.string()).optional(), cookie: z.string().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ found: z.array(z.unknown()) }),
  annotations: writingAnnotations(),
  examples: [{ title: "probe", input: { baseUrl: "https://target/", outputRoot: "/tmp/recon" } }],
};

export const corsContract: ToolContract = {
  name: "probe_cors",
  title: "CORS misconfiguration probe",
  description:
    "Origin variants (evil / suffix-reflection / null / localhost) via OPTIONS; flags ACAO reflection + ACAC true. Writes cors_probe.json.",
  kind: "runtime",
  inputSchema: z.object({ baseUrl: z.string(), outputRoot, origins: z.array(z.string()).optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ misconfigured: z.boolean() }),
  annotations: writingAnnotations(),
  examples: [{ title: "cors", input: { baseUrl: "https://api.target/", outputRoot: "/tmp/recon" } }],
};

export const fingerprintContract: ToolContract = {
  name: "fingerprint",
  title: "WAF/CDN + methods + cookies",
  description:
    "WAF/CDN identification from header signatures (cloudflare/aliyun/qcloud/safedog/baota...), HTTP method enumeration (OPTIONS Allow + PUT/TRACE), Set-Cookie security audit (Secure/HttpOnly/SameSite). Writes fingerprint.json.",
  kind: "runtime",
  inputSchema: z.object({ baseUrl: z.string(), outputRoot, cookie: z.string().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ waf: z.array(z.string()) }),
  annotations: writingAnnotations(),
  examples: [{ title: "fp", input: { baseUrl: "https://target/", outputRoot: "/tmp/recon" } }],
};

export const waybackContract: ToolContract = {
  name: "wayback_urls",
  title: "Historical URLs from Wayback",
  description:
    "web.archive.org CDX API: historical 200-URLs for the domain — dead admin panels, old API versions. Feeds the endpoint pool. Writes wayback_urls.txt.",
  kind: "runtime",
  inputSchema: z.object({ target: z.string(), outputRoot, maxUrls: z.number().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ urls: z.array(z.string()) }),
  annotations: writingAnnotations(),
  examples: [{ title: "wb", input: { target: "example.com", outputRoot: "/tmp/recon" } }],
};

export const sourcemapsContract: ToolContract = {
  name: "detect_sourcemaps",
  title: "Source-map leak detection",
  description:
    "Checks every harvested JS for sourceMappingURL + probes <file>.map (local then remote via baseUrl). Leaked maps = recoverable original sources. Writes sourcemaps.txt.",
  kind: "runtime",
  inputSchema: z.object({ outputRoot, jsDir: z.string().optional(), baseUrl: z.string().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ leaked: z.array(z.unknown()) }),
  annotations: writingAnnotations(),
  examples: [{ title: "sm", input: { outputRoot: "/tmp/recon" } }],
};

export const batchContract: ToolContract = {
  name: "auto_batch",
  title: "Batch pipeline",
  description:
    "Runs the auto pipeline for every seed in seeds.txt (one dir per target) + comparison summary (batch_summary.md). Optional webhook notify on completion. Long-running: returns started; poll each target's pipeline.json.",
  kind: "runtime",
  inputSchema: z.object({ seedsFile: z.string(), outputRoot, chromiumPath: z.string().optional(), skipRuntime: z.boolean().optional(), notifyWebhook: z.string().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ started: z.boolean(), statusFile: z.string() }),
  annotations: writingAnnotations(),
  examples: [{ title: "batch", input: { seedsFile: "/tmp/seeds.txt", outputRoot: "/tmp/batch" } }],
};


export const authProbeContract: ToolContract = {
  name: "auth_probe",
  title: "Auth-surface mapping",
  description:
    "Every discovered endpoint probed anonymous vs authenticated (cookie). Classifies the API surface into anonymous-reachable / auth-required / ambiguous — the core deliverable of API recon. Writes auth_surface.json.",
  kind: "runtime",
  inputSchema: z.object({ endpointsFile: z.string(), outputRoot, cookie: z.string().optional(), proxy: z.string().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ probed: z.number() }),
  annotations: writingAnnotations(),
  examples: [{ title: "auth", input: { endpointsFile: "/tmp/recon/api_merged.txt", outputRoot: "/tmp/recon" } }],
};

export const idorContract: ToolContract = {
  name: "idor_prescreen",
  title: "IDOR candidate prescreen",
  description:
    "From the param matrix: GET endpoints with id-like params, numeric-neighbor variants (original vs shifted), response fingerprint diff. Read-only. Candidates go to host_review. Writes idor_prescreen.json.",
  kind: "runtime",
  inputSchema: z.object({ mergedFile: z.string(), outputRoot, cookie: z.string().optional(), proxy: z.string().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ screened: z.number() }),
  annotations: writingAnnotations(),
  examples: [{ title: "idor", input: { mergedFile: "/tmp/recon/params_merged.json", outputRoot: "/tmp/recon" } }],
};

export const gitRestoreContract: ToolContract = {
  name: "git_restore",
  title: "Leaked .git source recovery",
  description:
    "Fetches .git config/HEAD/refs + walks loose objects (tree→blob) from a leaked .git directory and rebuilds the source tree locally. Read-only against the target. Writes git-restored/ + git_restore.json.",
  kind: "runtime",
  inputSchema: z.object({ baseUrl: z.string(), outputRoot, proxy: z.string().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ gitFound: z.boolean() }),
  annotations: writingAnnotations(),
  examples: [{ title: "git", input: { baseUrl: "https://target/", outputRoot: "/tmp/recon" } }],
};

export const domSinksContract: ToolContract = {
  name: "dom_sinks",
  title: "DOM-XSS taint chain scan",
  description:
    "Static taint analysis over harvested JS: location.hash/search/referrer/name → innerHTML/eval/document.write/insertAdjacentHTML/jQuery chains. Outputs candidate sinks + trigger context. Writes dom_sinks.json.",
  kind: "runtime",
  inputSchema: z.object({ jsDir: z.string(), outputRoot, observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ chains: z.array(z.object({ file: z.string(), source: z.string(), sink: z.string(), excerpt: z.string() })) }),
  annotations: writingAnnotations(),
  examples: [{ title: "dom", input: { jsDir: "/tmp/recon/js", outputRoot: "/tmp/recon" } }],
};

export const jwtContract: ToolContract = {
  name: "jwt_inspect",
  title: "JWT analysis",
  description:
    "Collects JWTs (secrets.txt / js corpus / raw token), decodes header+payload (alg/exp/claims), flags alg=none, cracks HS256 against a weak-secret dictionary. Writes jwt_analysis.json.",
  kind: "runtime",
  inputSchema: z.object({ outputRoot, secretsFile: z.string().optional(), jsDir: z.string().optional(), token: z.string().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ tokens: z.number() }),
  annotations: writingAnnotations(),
  examples: [{ title: "jwt", input: { outputRoot: "/tmp/recon", jsDir: "/tmp/recon/js" } }],
};

export const wsSchemaContract: ToolContract = {
  name: "ws_schema",
  title: "WS message schema",
  description:
    "Parses recorded WebSocket frames (runtime_api.json wsFrames) into per-endpoint field tables (dotted paths, types, samples) — private-protocol interface docs from real traffic. Writes ws_schema.json.",
  kind: "runtime",
  inputSchema: z.object({ runtimeFile: z.string(), outputRoot, observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ endpoints: z.number() }),
  annotations: writingAnnotations(),
  examples: [{ title: "ws", input: { runtimeFile: "/tmp/recon/runtime_api.json", outputRoot: "/tmp/recon" } }],
};


export const oidcContract: ToolContract = {
  name: "probe_oidc",
  title: "OAuth/OIDC/SAML config probe",
  description:
    "Discovers /.well-known/openid-configuration, oauth-authorization-server, SAML metadata; static weakness checks (implicit flow, fragment response, missing PKCE). Writes oidc_probe.json.",
  kind: "runtime",
  inputSchema: z.object({ baseUrl: z.string(), outputRoot, proxy: z.string().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ found: z.array(z.unknown()) }),
  annotations: writingAnnotations(),
  examples: [{ title: "oidc", input: { baseUrl: "https://target/", outputRoot: "/tmp/recon" } }],
};

export const smuggleContract: ToolContract = {
  name: "probe_smuggle",
  title: "Request-smuggling differential",
  description:
    "Paired GETs differing in one canonicalization dimension (dot-segment, double-slash, encoded-slash, case, semicolon) + CL+TE POST. Status divergence across variants = parser disagreement. Read-only. Writes smuggle_probe.json.",
  kind: "runtime",
  inputSchema: z.object({ baseUrl: z.string(), outputRoot, proxy: z.string().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ differentials: z.array(z.object({ dimension: z.string(), variantStatus: z.number() })) }),
  annotations: writingAnnotations(),
  examples: [{ title: "smuggle", input: { baseUrl: "https://target/", outputRoot: "/tmp/recon" } }],
};

export const archiveContract: ToolContract = {
  name: "archive_recover",
  title: "Blocked-page archive recovery",
  description:
    "When a URL is blocked (403/429/WAF interstitial): Wayback availability API then archive.today mirror rotation to recover the content. Writes recovered.html.",
  kind: "runtime",
  inputSchema: z.object({ url: z.string(), outputRoot, proxy: z.string().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ recoveredFrom: z.string().nullable() }),
  annotations: writingAnnotations(),
  examples: [{ title: "recover", input: { url: "https://target/page", outputRoot: "/tmp/recon" } }],
};

export const wsOriginContract: ToolContract = {
  name: "ws_origin_check",
  title: "WS origin validation (CSWSH)",
  description:
    "Attempts the WebSocket upgrade with a hostile Origin and with no Origin; accepted cross-origin upgrade = missing origin validation (CSWSH prescreen). Notes auth material location from the URL. Writes ws_origin.json.",
  kind: "runtime",
  inputSchema: z.object({ url: z.string(), outputRoot, headers: z.record(z.string(), z.string()).optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ vulnerable: z.boolean() }),
  annotations: writingAnnotations(),
  examples: [{ title: "ws", input: { url: "wss://target/ws", outputRoot: "/tmp/recon" } }],
};


export const graphqlDeepContract: ToolContract = {
  name: "graphql_deep",
  title: "GraphQL deep introspection",
  description:
    "Full introspection with minimal-query fallback, schema parse (types/queries/mutations/subscriptions), SDL export, optional diff vs previous schema. Writes graphql_schema.txt + graphql_deep.json.",
  kind: "runtime",
  inputSchema: z.object({ endpoint: z.string(), outputRoot, previousSchemaFile: z.string().optional(), headers: z.record(z.string(), z.string()).optional(), proxy: z.string().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ introspected: z.boolean() }),
  annotations: writingAnnotations(),
  examples: [{ title: "gql", input: { endpoint: "https://target/graphql", outputRoot: "/tmp/recon" } }],
};

export const protoDecodeContract: ToolContract = {
  name: "proto_decode",
  title: "Protobuf heuristic decode",
  description:
    "Wire-format walk over binary WS frames (varint/tag pairs, wire types 0-5) producing a field-number/type table — candidate schema for private protocols without a .proto file. Writes proto_decode.json.",
  kind: "runtime",
  inputSchema: z.object({ data: z.string(), encoding: z.enum(["hex", "base64"]).optional(), outputRoot, observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ looksLikeProtobuf: z.boolean() }),
  annotations: writingAnnotations(),
  examples: [{ title: "proto", input: { data: "CgR0ZXN0", outputRoot: "/tmp/recon" } }],
};

export const nucleiLiteContract: ToolContract = {
  name: "nuclei_lite",
  title: "Template matcher",
  description:
    "nuclei-style template engine (status/word/regex matchers) with a curated built-in set: exposed panels (kibana/grafana/jenkins/nacos), actuator env, swagger, git/env leaks, directory listing. Read-only GETs. Writes nuclei_lite.json.",
  kind: "runtime",
  inputSchema: z.object({ baseUrl: z.string(), outputRoot, proxy: z.string().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ matched: z.array(z.object({ id: z.string(), severity: z.string() })) }),
  annotations: writingAnnotations(),
  examples: [{ title: "scan", input: { baseUrl: "https://target/", outputRoot: "/tmp/recon" } }],
};

export const loginReplayContract: ToolContract = {
  name: "login_replay",
  title: "Login auto-replay",
  description:
    "Detects a login form, fills credentials via headless Chromium, submits, and exports the authenticated cookie header for use by runtime capture / auth probes. Writes login_replay.json.",
  kind: "runtime",
  inputSchema: z.object({ baseUrl: z.string(), username: z.string(), password: z.string(), outputRoot, chromiumPath: z.string().optional(), proxy: z.string().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ submitted: z.boolean() }),
  annotations: writingAnnotations(),
  examples: [{ title: "login", input: { baseUrl: "https://target/login", username: "u", password: "p", outputRoot: "/tmp/recon" } }],
};

export const backupUnpackContract: ToolContract = {
  name: "backup_unpack",
  title: "Backup/dump unpack + secret scan",
  description:
    "Downloads .zip/.tar.gz/.sql/.json dump URLs found by paths probing, unpacks in memory (fflate), scans every text entry with the secret scanner. Writes backup_unpack.json.",
  kind: "runtime",
  inputSchema: z.object({ urls: z.array(z.string()), outputRoot, proxy: z.string().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ processed: z.number() }),
  annotations: writingAnnotations(),
  examples: [{ title: "unpack", input: { urls: ["https://target/backup.zip"], outputRoot: "/tmp/recon" } }],
};

export const sqliteReadContract: ToolContract = {
  name: "sqlite_read",
  title: "SQLite leak reader",
  description:
    "Parses a leaked .db file (WASM sqlite, no native deps): tables + row counts, sensitive table/column flags, row samples from password/token/user tables. Writes sqlite_read.json.",
  kind: "runtime",
  inputSchema: z.object({ file: z.string(), outputRoot, observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ opened: z.boolean() }),
  annotations: writingAnnotations(),
  examples: [{ title: "db", input: { file: "/tmp/recon/leak.db", outputRoot: "/tmp/recon" } }],
};


export const gatesContract: ToolContract = {
  name: "analyze_gates",
  title: "Auth-gate static analysis",
  description:
    "api-recon Phase 2: grep recipes over harvested JS locating the render/interceptor/content gates (storage keys, code fields, permission APIs) with suggested HookConfig patches. Writes gates_report.json.",
  kind: "runtime",
  inputSchema: z.object({ jsDir: z.string(), outputRoot, observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ renderGate: z.object({ storageKeys: z.array(z.string()) }) }),
  annotations: writingAnnotations(),
  examples: [{ title: "gates", input: { jsDir: "/tmp/recon/js", outputRoot: "/tmp/recon" } }],
};

export const coverageContract: ToolContract = {
  name: "run_coverage",
  title: "Interactive coverage enumeration",
  description:
    "api-recon Phase 3b: drives headless Chromium through sidebar/tabs/table-actions/toolbar, records outbound API calls per interaction, builds the parameter trigger matrix. Writes coverage.json.",
  kind: "runtime",
  inputSchema: z.object({ baseUrl: z.string(), outputRoot, hook: z.record(z.string(), z.unknown()).optional(), cookie: z.string().optional(), chromiumPath: z.string().optional(), maxClicksPerCategory: z.number().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ interactions: z.number() }),
  annotations: writingAnnotations(),
  examples: [{ title: "cov", input: { baseUrl: "https://target/", outputRoot: "/tmp/recon" } }],
};

export const siteMapContract: ToolContract = {
  name: "build_site_map",
  title: "Structured site map",
  description:
    "api-recon Phase 5 deliverable: aggregates routes.txt/api_merged.txt/params_merged.json/coverage.json into one structured site_map.json (apis/params/features/limitations).",
  kind: "runtime",
  inputSchema: z.object({ baseUrl: z.string(), outputRoot, runtimeMode: z.enum(["depth", "coverage", "both", "static-only"]).optional(), appType: z.string().optional(), limitations: z.string().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ apis: z.array(z.string()) }),
  annotations: writingAnnotations(),
  examples: [{ title: "map", input: { baseUrl: "https://target/", outputRoot: "/blobs/recon" } }],
};

export const trafficRecContract: ToolContract = {
  name: "traffic_record",
  title: "Traffic recording proxy",
  description:
    "velric platform: forward proxy recording every exchange (full req/resp for HTTP, tunnel metadata for HTTPS) to traffic.ndjson + sha256 blob store. Long-running; returns bound port.",
  kind: "runtime",
  inputSchema: z.object({ outputRoot, port: z.number().optional(), upstreamProxy: z.string().optional(), maxExchanges: z.number().optional(), mitm: z.boolean().optional(), stop: z.boolean().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ port: z.number() }),
  annotations: writingAnnotations(),
  examples: [{ title: "rec", input: { outputRoot: "/tmp/recon" } }],
};

export const assetGraphContract: ToolContract = {
  name: "asset_graph",
  title: "Asset graph store",
  description:
    "velric dual-graph (asset side): global shared asset truth store — upsert root_domain/subdomain/ip/service/endpoint with computed dedup keys and host-chain linking; URL upsert auto-creates the chain. Persists asset_graph.json.",
  kind: "runtime",
  inputSchema: z.object({ outputRoot, action: z.enum(["upsert", "upsert_url", "counts", "query"]), type: z.enum(["root_domain", "subdomain", "ip", "service", "app", "endpoint"]).optional(), value: z.string().optional(), parent: z.string().optional(), meta: z.record(z.string(), z.unknown()).optional(), taskTag: z.string().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ ok: z.boolean() }),
  annotations: writingAnnotations(),
  examples: [{ title: "asset", input: { outputRoot: "/tmp/recon", action: "counts" } }],
};

export const expGraphContract: ToolContract = {
  name: "exploration_graph",
  title: "Exploration lineage graph",
  description:
    "velric dual-graph (exploration side): per-run goal→intent→fact→finding lineage with spawns/derived_from/yields/proves edges and asset anchors; lineage/overview queries. Persists exploration_graph.json.",
  kind: "runtime",
  inputSchema: z.object({ outputRoot, action: z.enum(["add_node", "add_edge", "anchor", "set_state", "lineage", "overview"]), kind: z.enum(["goal", "intent", "fact", "finding", "hint"]).optional(), summary: z.string().optional(), payload: z.record(z.string(), z.unknown()).optional(), from: z.string().optional(), rel: z.enum(["spawns", "derived_from", "yields", "proves"]).optional(), to: z.string().optional(), nodeId: z.string().optional(), assetKey: z.string().optional(), state: z.enum(["open", "met", "dead", "pending"]).optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ ok: z.boolean() }),
  annotations: writingAnnotations(),
  examples: [{ title: "node", input: { outputRoot: "/tmp/recon", action: "add_node", kind: "goal", summary: "map target" } }],
};

export const evidenceContract: ToolContract = {
  name: "evidence_store",
  title: "Finding evidence store",
  description:
    "velric evidence: sha256-addressed blob store for finding evidence (request/response/command output), deduped across findings, indexed in evidence_index.json.",
  kind: "runtime",
  inputSchema: z.object({ outputRoot, action: z.enum(["put", "get", "list"]), file: z.string().optional(), hash: z.string().optional(), tag: z.string().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({}).passthrough(), // put:{hash,bytes} get:{hash,bytes,found} list:{entries:[]}
  annotations: writingAnnotations(),
  examples: [{ title: "put", input: { outputRoot: "/tmp/recon", action: "put", file: "/tmp/poc.txt" } }],
};


export const coldGraphContract: ToolContract = {
  name: "cold_graph",
  title: "Exploration graph compaction",
  description:
    "Fold cold exploration regions (untouched for N rounds) into content-hashed digest nodes with member snapshots; expand on demand. Persists cold_stamps.json.",
  kind: "runtime",
  inputSchema: z.object({ outputRoot, action: z.enum(["compact", "expand"]), digestId: z.string().optional(), round: z.number().optional(), coldAfterRounds: z.number().optional(), maxDigestSize: z.number().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ digests: z.array(z.string()) }),
  annotations: writingAnnotations(),
  examples: [{ title: "compact", input: { outputRoot: "/tmp/recon", action: "compact" } }],
};

export const retestContract: ToolContract = {
  name: "finding_retest",
  title: "Finding retest",
  description:
    "Register findings with PoC + status/body predicates; replay PoC and classify reproduced/fixed/inconclusive; disposition flips on verdicts. Persists retest_store.json.",
  kind: "runtime",
  inputSchema: z.object({ outputRoot, action: z.enum(["register", "run", "list"]), id: z.string().optional(), name: z.string().optional(), severity: z.enum(["low", "medium", "high", "critical"]).optional(), poc: z.object({ method: z.string(), url: z.string(), headers: z.record(z.string(), z.string()).optional(), body: z.string().optional() }).optional(), predicates: z.object({ fixedStatuses: z.array(z.number()).optional(), fixedBodyAny: z.array(z.string()).optional(), vulnerableBodyAny: z.array(z.string()).optional() }).optional(), proxy: z.string().optional(), note: z.string().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ ok: z.boolean() }),
  annotations: writingAnnotations(),
  examples: [{ title: "run", input: { outputRoot: "/tmp/recon", action: "run", id: "f1" } }],
};

export const trafficQueryContract: ToolContract = {
  name: "traffic_query",
  title: "Traffic search/get",
  description:
    "Query the recorded traffic log (host/status/method/text filters, paginated) and fetch one exchange with its stored bodies.",
  kind: "runtime",
  inputSchema: z.object({ outputRoot, action: z.enum(["search", "get"]), id: z.string().optional(), host: z.string().optional(), status: z.number().optional(), method: z.string().optional(), text: z.string().optional(), page: z.number().optional(), pageSize: z.number().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ total: z.number() }),
  annotations: readOnlyAnnotations(),
  examples: [{ title: "search", input: { outputRoot: "/tmp/recon", action: "search", host: "api.example.com" } }],
};

export const reportExportContract: ToolContract = {
  name: "export_findings",
  title: "Findings export (csv/json/md)",
  description:
    "Export a findings batch as CSV, per-finding Markdown, or JSON from report json. Writes findings.csv / findings.json / finding_<id>.md.",
  kind: "runtime",
  inputSchema: z.object({ reportJsonFile: z.string(), outputRoot, format: z.enum(["csv", "json", "md-all"]), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({ files: z.number() }),
  annotations: writingAnnotations(),
  examples: [{ title: "csv", input: { reportJsonFile: "/tmp/recon/report.json", outputRoot: "/tmp/recon", format: "csv" } }],
};

export const evidenceBindContract: ToolContract = {
  name: "evidence_bind",
  title: "Finding↔evidence binding lifecycle",
  description:
    "Ordered evidence bindings per finding with roles (baseline/proof/verification/supporting), optimistic-version conflict rejection, update/unbind/reorder, and md-zip export. Persists evidence_bindings.json.",
  kind: "runtime",
  inputSchema: z.object({ outputRoot, action: z.enum(["bind", "update", "unbind", "reorder", "get", "export"]), findingId: z.string().optional(), expectedVersion: z.number().optional(), refs: z.array(z.object({ hash: z.string(), role: z.enum(["baseline", "proof", "verification", "supporting"]), note: z.string().optional() })).optional(), bindingId: z.string().optional(), role: z.enum(["baseline", "proof", "verification", "supporting"]).optional(), note: z.string().optional(), order: z.array(z.string()).optional(), zipPath: z.string().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({}).passthrough(), // bind/get:{findingId,version,bindings[]} others:{version}
  annotations: writingAnnotations(),
  examples: [{ title: "bind", input: { outputRoot: "/tmp/recon", action: "bind", findingId: "f1", expectedVersion: 0, refs: [{ hash: "a".repeat(64), role: "proof" }] } }],
};


export const scanPlatformContract: ToolContract = {
  name: "scan_platform",
  title: "Native scan platform (in-process, zero external service)",
  description:
    "ScopeSentry functional equivalent built in-process: projects -> tasks (ordered module pipeline: subdomain_scan/port_scan/fingerprint/dir_scan/web_crawler/nuclei_lite/web_probes) -> shared AssetStore with task provenance + local list/count retrieval. Two-phase chaining via sourceTask (targets resolved from a done task's subdomain assets). No external platform, no credentials.",
  kind: "runtime",
  inputSchema: z.object({ outputRoot, action: z.enum(["create_project", "create_task", "run_task", "get_task", "list_tasks", "list_projects", "list_assets", "count_assets"]), name: z.string().optional(), targets: z.array(z.string()).optional(), projectId: z.string().optional(), taskId: z.string().optional(), modules: z.array(z.string()).optional(), sourceTask: z.string().optional(), query: z.object({ type: z.string().optional(), taskTag: z.string().optional(), valuePrefix: z.string().optional(), valueRegex: z.string().optional() }).optional(), page: z.number().optional(), pageSize: z.number().optional(), proxy: z.string().optional(), cookie: z.string().optional(), timeoutMs: z.number().optional(), observationLedgerRoot: LEDGER }),
  outputSchema: z.object({}).passthrough(), // per-action shapes: Project/Task records, arrays, {total,page,items}
  annotations: writingAnnotations(),
  examples: [{ title: "two-phase chain", input: { outputRoot: "/tmp/recon", action: "create_task", projectId: "p1", name: "phase2", modules: ["port_scan", "fingerprint"], sourceTask: "t1" } }],
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
  autoStatusContract,
  runDiffContract,
  probeParamsContract,
  subdomainsContract,
  portScanContract,
  pathsContract,
  corsContract,
  fingerprintContract,
  waybackContract,
  sourcemapsContract,
  batchContract,
  authProbeContract,
  idorContract,
  gitRestoreContract,
  domSinksContract,
  jwtContract,
  wsSchemaContract,
  oidcContract,
  smuggleContract,
  archiveContract,
  wsOriginContract,
  graphqlDeepContract,
  protoDecodeContract,
  nucleiLiteContract,
  loginReplayContract,
  backupUnpackContract,
  sqliteReadContract,
  gatesContract,
  coverageContract,
  siteMapContract,
  trafficRecContract,
  assetGraphContract,
  expGraphContract,
  evidenceContract,
  coldGraphContract,
  retestContract,
  trafficQueryContract,
  reportExportContract,
  evidenceBindContract,
  scanPlatformContract,
  huntContract,
  huntRecordContract,
  huntOverviewContract,
  workflowGuideContract,
];