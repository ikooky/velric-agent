#!/usr/bin/env node
/** Generate golden output samples by REALLY invoking every handler against a
 *  local mock server. Samples must never be hand-written (self-deception) —
 *  this script is the only sanctioned source of tests/golden_samples.json.
 *
 *  Inputs come from each contract's own examples (the advertised surface).
 *  Outputs are real handler returns, normalized for volatile fields
 *  (timestamps, durations, tmp paths). Network-bound tools that cannot run
 *  against a local mock (external corpora / OOB) are EXCLUDED with a reason —
 *  the schema test asserts every exclusion is justified, nothing silently
 *  missing. Rerun: node scripts/generate-golden-samples.mjs */
import { createServer } from "node:http";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { handlers } from "../dist/server/registerTools.js";
import { ALL_CONTRACTS } from "../dist/contracts/contracts.js";

/** Tools that REQUIRE external networks/corpora — cannot be sampled against a
 *  local mock. Every entry needs a reason; the test enforces this list stays
 *  honest (no free-pass dumping ground). */
const EXCLUDED = {
  subdomain_enum: "external corpora (crt.sh dns brute) — needs real DNS",
  subdomain_alter: "needs real DNS resolution of public names",
  wayback_urls: "external archive.org/wayback corpus",
  oob_confirm: "external interactsh servers (oast.live)",
  dns_resolve: "localhost works but resolver-dependent; covered by own unit test",
  hunt_begin: "covered by pipeline.test budget tests (real invocations)",
  hunt_record: "covered by pipeline.test budget tests",
  hunt_overview: "stateful hunt graph — covered by pipeline.test",
};

// ---- local mock: deterministic behaviors on 127.0.0.1 ----
const MIME = { html: "text/html", js: "application/javascript", json: "application/json" };
const pages = {
  "/": [200, "html", "<html><body>ok <a href='/api/v1/users'>u</a></body></html>"],
  "/login": [200, "html", "<html><body><form action='/dologin'><input name=user><input name=pass></form></body></html>"],
  "/dologin": [200, "json", '{"ok":true}', { "set-cookie": "sid=abc; Path=/" }],
  "/api/v1/users": [200, "json", JSON.stringify([{ id: 1, name: "a", email: "a@x.com" }])],
  "/app.js": [200, "js", "var k='AKIAIOSFODNN7EXAMPLE';fetch('/api/v1/users?x=1')"],
  "/admin": [200, "html", "<html><body>admin</body></html>"],
  "/login": [200, "html", "<html><body><form action='/login'><input name=user><input name=pass></form></body></html>"],
  "/.well-known/openid-configuration": [200, "json", JSON.stringify({ issuer: "http://127.0.0.1", jwks_uri: "http://127.0.0.1/jwks" })],
};
const srv = createServer((req, res) => {
  const u = new URL(req.url, "http://127.0.0.1");
  const hit = pages[u.pathname];
  if (hit) { res.writeHead(hit[0], { "content-type": MIME[hit[1]], ...(hit[3] ?? {}) }); res.end(hit[2]); }
  else { res.writeHead(404, { "content-type": "text/plain" }); res.end("nope"); }
});
await new Promise((r) => srv.listen(0, "127.0.0.1", r));
const port = srv.address().port;
const base = `http://127.0.0.1:${port}`;
const root = mkdtempSync(join(tmpdir(), "golden-"));

// deterministic JWT (header.payload.sig shape only — no real secret)
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwtTok = `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ sub: "u1", role: "user", iat: 1 })}.${"a".repeat(43)}`;

/** Per-tool input overrides where contract examples point at external hosts. */
const overrides = {
  extract_routes: { jsDir: join(root, "js"), outputRoot: root },
  build_perm_tree: { jsDir: join(root, "js"), outputRoot: root },
  deobfuscate_js: { jsDir: join(root, "js"), outputRoot: root },
  dom_sinks: { jsDir: join(root, "js"), outputRoot: root },
  gen_report: { reportFile: join(root, "report.json"), outputRoot: root },
  export_findings: { reportJsonFile: join(root, "report.json"), outputRoot: root, format: "csv" },
  save_evidence: { action: "save", itemsFile: join(root, "evidence_items.json"), outputRoot: root },
  replay_tamper: { recordRoot: root, outputRoot: root },
  authz_replay: { recordRoot: root, outputRoot: root, roles: { guest: "" } },
  mass_assign: { recordRoot: root, outputRoot: root },
  pii_scan: { recordRoot: root, outputRoot: root },
  finding_retest: { outputRoot: root, action: "list" },
  evidence_bind: { outputRoot: root, action: "get" },
  scan_platform: { outputRoot: root, action: "list_projects" },
  graphql_authz: { schemaFile: join(root, "schema.graphql"), endpoint: `${base}/api/v1/users`, outputRoot: root },
  fingerprint: { baseUrl: base, outputRoot: root },
  http_probe: { urls: [`${base}/`, `${base}/nope`], outputRoot: root },
  path_probe: { baseUrl: base, outputRoot: root },
  dir_fuzz: { url: base, outputRoot: root, words: ["admin", "zz"], maxWords: 2 },
  header_bypass: { url: `${base}/api/v1/users`, outputRoot: root },
  verb_matrix: { url: `${base}/api/v1/users`, outputRoot: root },
  cors_probe: { baseUrl: base, outputRoot: root },
  probe_smuggle: { url: base, outputRoot: root },
  ws_origin_check: { url: `ws://127.0.0.1:${port}`, outputRoot: root },
  login_replay: { baseUrl: `${base}/login`, username: "a", password: "b", outputRoot: root },
  session_crawl: { baseUrl: `${base}/`, loginUrl: `${base}/dologin`, username: "a", password: "b", outputRoot: root, maxPages: 2, loggedInRegex: "ok" },
  harvest_static: { baseUrl: base, outputRoot: root },
  detect_sourcemaps: { baseUrl: base, outputRoot: root },
  extract_routes: { jsDir: root, outputRoot: root },
  deobfuscate_js: { jsDir: root, outputRoot: root },
  dom_sinks: { jsDir: root, outputRoot: root },
  probe_oidc: { baseUrl: base, outputRoot: root },
  jwt: { action: "attack", token: jwtTok, endpoint: `${base}/api/v1/users`, outputRoot: root },
  mine_hidden_params: { url: `${base}/api/v1/users?x=1`, outputRoot: root, maxWords: 3, timeoutMs: 2000 },
  pii_scan: { recordRoot: root, outputRoot: root },
  rate_limit_probe: { url: `${base}/api/v1/users`, outputRoot: root, maxRequests: 3 },
  admin_surface: { baseUrl: base, outputRoot: root },
  nuclei_lite: { baseUrl: base, outputRoot: root },
  waf_adapt: { url: `${base}/`, outputRoot: root },
  tls_audit: { host: "127.0.0.1", port, outputRoot: root },
  url_refine: { action: "dedupe", urls: [`${base}/a?id=1`, `${base}/a?id=2`], outputRoot: root },
  screenshot: { urls: [`${base}/`], outputRoot: root },
};

const volatile = (k) => /At$|^(tookMs|ms|durationMs|elapsed|probedAt|generatedAt|capturedAt|startedAt|checkedAt|scannedAt)/.test(k);
const norm = (v, depth = 0) => {
  if (depth > 6) return "…";
  if (Array.isArray(v)) return v.slice(0, 5).map((x) => norm(x, depth + 1));
  if (v && typeof v === "object") {
    const o = {};
    for (const [k, val] of Object.entries(v)) {
      if (volatile(k)) continue;
      o[k] = typeof val === "string" && val.startsWith(root) ? val.replace(root, "/ROOT") : norm(val, depth + 1);
    }
    return o;
  }
  if (typeof v === "string" && v.startsWith(root)) return v.replace(root, "/ROOT");
  return v;
};

// ---- phase 0: seed prerequisites (files + recorded traffic) ----
const { writeFile: wf, mkdir: mk } = await import("node:fs/promises");
await mk(join(root, "js"), { recursive: true });
await wf(join(root, "js", "app.js"), "fetch('/api/v1/users?debug=1'); var k='AKIAIOSFODNN7EXAMPLE';");
await wf(join(root, "js", "rbac.js"), "router.beforeEach((to)=>{ if(to.meta.requiresAuth && !user.role) redirect('/login'); }); const perms=['user:edit','admin:imp']; if(user.hasRole('admin')) allow('/admin'); });");
const gqlSchema = "type Query { users: [User] } type User { id: ID name: String } type Mutation { deleteUser(id: ID): Boolean }";
await wf(join(root, "schema.graphql"), gqlSchema);
await wf(join(root, "api_static.txt"), "GET /api/v1/users\nPOST /api/v1/users\n");
await wf(join(root, "api_merged.txt"), "GET /api/v1/users\nPOST /api/v1/users\n");
await wf(join(root, "param_samples.json"), JSON.stringify([{ url: `${base}/api/v1/users`, method: "GET", params: [{ name: "x", in: "query", values: ["1"] }] }]));
await wf(join(root, "evidence_items.json"), JSON.stringify([{ label: "poc", content: "proof" }]));
await wf(join(root, "report.json"), JSON.stringify({ title: "t", goal: "g", generatedAt: "t", assetCounts: {}, findings: [{ id: "f1", name: "n", severity: "high", summary: "s", vulnClass: "c" }] }));
// evidence hash for evidence_bind: reuse the seeded report finding's own hash later — bind needs a REAL stored hash
// traffic.ndjson 录制: 直接起 recorder? 简化 — 写最小合法 ndjson (exchange 格式从 trafficRecorder spill 格式)
const h64 = (s0) => Buffer.from(s0).toString("base64");
// 真实 blob 文件: blobs/xx/<sha256> — 用 node crypto 算
const { createHash } = await import("node:crypto");
const blobHash = (b) => createHash("sha256").update(b).digest("hex");
const reqBody = JSON.stringify({ user: "u1", role: "user" });
const rbh = blobHash(reqBody);
await mk(join(root, "blobs", rbh.slice(0, 2)), { recursive: true });
await wf(join(root, "blobs", rbh.slice(0, 2), rbh), reqBody);
const respBody = JSON.stringify({ ok: true, rows: [1] });
const rspbh = blobHash(respBody);
await mk(join(root, "blobs", rspbh.slice(0, 2)), { recursive: true });
await wf(join(root, "blobs", rspbh.slice(0, 2), rspbh), respBody);
const ex = { id: "ex1", ts: "2026-01-01T00:00:00Z", client: "127.0.0.1", method: "POST", url: `${base}/api/v1/users`, status: 200, reqHeaders: { "content-type": "application/json", cookie: "sid=admin" }, reqBodyHash: rbh, respBodyHash: rspbh, respContentType: "application/json" };
await wf(join(root, "traffic.ndjson"), JSON.stringify(ex) + "\n");

const samples = {};
const failed = [];
for (const c of ALL_CONTRACTS) {
  if (EXCLUDED[c.name]) continue;
  const h = handlers[c.name];
  if (!h) { failed.push([c.name, "NO HANDLER"]); continue; }
  const input = { ...(c.examples?.[0]?.input ?? {}), ...(overrides[c.name] ?? {}) };
  if (input.outputRoot === undefined) input.outputRoot = root;
  if (typeof input.baseUrl === "string" && input.baseUrl.includes("example.com")) input.baseUrl = base;
  if (typeof input.url === "string" && input.url.includes("example.com")) input.url = `${base}/`;
  if (typeof input.seed === "string" && input.seed.includes("example.com")) input.seed = base;
  if (typeof input.baseUrl === "string" && input.baseUrl.includes("target")) input.baseUrl = base;
  if (typeof input.url === "string" && input.url.includes("target")) input.url = `${base}/`;
  if (Array.isArray(input.urls)) input.urls = input.urls.map((u) => (typeof u === "string" && u.includes("example.com") ? `${base}/` : u));
  if (typeof input.host === "string" && input.host.includes("example.com")) input.host = "127.0.0.1";
  if (typeof input.jsDir === "string") input.jsDir = join(root, "js");
  if (typeof input.schemaFile === "string") input.schemaFile = join(root, "schema.graphql");
  if (typeof input.samplesFile === "string") input.samplesFile = join(root, "param_samples.json");
  if (typeof input.domain === "string" && input.domain.includes("example.com")) continue; // DNS tools stay excluded
  try {
    const out = await Promise.race([
      h(input),
      new Promise((_, rej) => setTimeout(() => rej(new Error("sample timeout 25s")), 25000).unref?.()),
    ]);
    samples[c.name] = norm(out);
  } catch (e) {
    failed.push([c.name, String(e.message).slice(0, 90)]);
  }
}
srv.close();
writeFileSync(new URL("../tests/golden_samples.json", import.meta.url), JSON.stringify({ generatedAt: new Date().toISOString(), excluded: EXCLUDED, samples }, null, 2));
console.log(`sampled: ${Object.keys(samples).length}/${ALL_CONTRACTS.length}, excluded: ${Object.keys(EXCLUDED).length}, failed: ${failed.length}`);
for (const [n, m] of failed) console.log(`  FAIL ${n}: ${m}`);
