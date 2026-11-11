import { PRODUCT_IDENTITY } from "../identity.js";
import { ReconHandlers } from "./groups/recon.js";
import { ContentHandlers } from "./groups/content.js";
import { RuntimeHandlers } from "./groups/runtime.js";
import { ReverseHandlers } from "./groups/reverse.js";
import { InjectHandlers } from "./groups/inject.js";
import { AuthnHandlers } from "./groups/authn.js";
import { AuthzHandlers } from "./groups/authz.js";
import { LogicHandlers } from "./groups/logic.js";
import { PlatformHandlers } from "./groups/platform.js";
import type { Ctx } from "./shared.js";

export interface GroupSpec {
  readonly id: string;
  readonly title: string;
  readonly summary: string;
  readonly handlers: Record<string, (ctx: Ctx) => Promise<number>>;
}

export const GROUPS: readonly GroupSpec[] = [
  { id: "recon", title: "侦察", summary: "资产与面测绘", handlers: ReconHandlers },
  { id: "content", title: "内容", summary: "抓取与语料", handlers: ContentHandlers },
  { id: "runtime", title: "运行时", summary: "浏览器与协议", handlers: RuntimeHandlers },
  { id: "reverse", title: "逆向", summary: "静态与指令层", handlers: ReverseHandlers },
  { id: "inject", title: "注入", summary: "语法与参数", handlers: InjectHandlers },
  { id: "authn", title: "认证", summary: "凭证与令牌", handlers: AuthnHandlers },
  { id: "authz", title: "授权", summary: "越权与访问控制", handlers: AuthzHandlers },
  { id: "logic", title: "业务逻辑", summary: "值域与竞争", handlers: LogicHandlers },
  { id: "platform", title: "平台", summary: "管道/证据/hunt", handlers: PlatformHandlers },
];

/** command → group id (for usage rendering and dispatch). */
export const COMMAND_INDEX: ReadonlyMap<string, (ctx: Ctx) => Promise<number>> = new Map(
  GROUPS.flatMap((g) => Object.entries(g.handlers)),
);

/** Per-command one-line usage, grouped. Rendered by `help`. */
export const usageText = (): string => {
  const lines: string[] = [`velric-agent ${PRODUCT_IDENTITY.packageVersion} — stateless recon toolset (CLI)`, "", "Usage:"];
  for (const g of GROUPS) {
    lines.push(`  # ${g.title} — ${g.summary}`);
    for (const [cmd, fn] of Object.entries(g.handlers)) {
      const doc = fnDoc(cmd);
      lines.push(`  velric-agent ${doc.usage ?? cmd}${doc.desc ? `   ${doc.desc}` : ""}`);
    }
    lines.push("");
  }
  lines.push("Common flags: --proxy URL | --proxy-pool FILE, --rps N (global rate limit), --cookie STR, --timeout MS");
  lines.push("Hunt binding: --run-id ID [--observation-ledger-root DIR] — record every request into the observation ledger for hunt-record verification");
  return lines.join("\n");
};

/** Hand-maintained usage strings (arg shape per command), rendered into help. */
export interface CmdDoc { readonly usage?: string; readonly desc?: string; }
const DOCS: Record<string, CmdDoc> = {
  // recon
  "subdomains": { usage: "subdomains <domain> <outdir>", desc: "subdomain enum (crt.sh + CNAME + wordlist)" },
  "subdomain-alter": { usage: "subdomain-alter <domain> <outdir> --hosts a,b", desc: "alteration-based subdomain generation (+ --resolve)" },
  "port-scan": { usage: "port-scan <host> <outdir>", desc: "TCP top-ports scan (--ports/--timeout)" },
  "dns-resolve": { usage: "dns-resolve <host> [...]", desc: "resolve A/AAAA/CNAME" },
  "http-probe": { usage: "http-probe <url>", desc: "probe one URL (status/title/hash)" },
  "enrich": { usage: "enrich <seed...> --out DIR", desc: "asset graph from seeds (DNS+HTTP)" },
  "wayback": { usage: "wayback <domain> <outdir>", desc: "historical URLs from web.archive.org" },
  "fingerprint": { usage: "fingerprint <baseUrl> <outdir>", desc: "WAF/CDN id + method enum + cookie audit" },
  "paths": { usage: "paths <baseUrl> <outdir>", desc: "sensitive paths w/ soft-404 calibration" },
  "dir-fuzz": { usage: "dir-fuzz <outdir> (--url URL [--wordlist-file F] | --preset sensitive|backups --base URL)", desc: "wordlist fuzzing" },
  "nuclei-lite": { usage: "nuclei-lite <baseUrl> <outdir>", desc: "template matcher (panels/leaks)" },
  "cloud-storage": { usage: "cloud-storage <buckets> <outdir> [--provider p] [--write]", desc: "anonymous S3/GCS/Azure bucket list/read/write" },
  "runtime-config-leak": { usage: "runtime-config-leak <baseUrl> <outdir>", desc: "SPA runtime config leakage (config.js/.env, 20 paths, secret classes)" },
  "admin-surface": { usage: "admin-surface <baseUrl> <outdir>", desc: "admin/panel surface map" },
  "info-leak": { usage: "info-leak <baseUrl> <outdir>", desc: "information disclosure (paths/stack/banners/secrets)" },
  "coverage": { usage: "coverage <baseUrl> <outdir>", desc: "interactive coverage enumeration" },
  "site-map": { usage: "site-map <baseUrl> <outdir>", desc: "structured site map" },
  "asset-graph": { usage: "asset-graph <dir> <action>", desc: "asset graph store" },
  // content
  "harvest": { usage: "harvest <url> <outdir>", desc: "static SPA bundle harvest" },
  "spider": { usage: "spider <url> <outdir>", desc: "MPA crawl (--cookie/--max/--depth/--exclude)" },
  "extract-routes": { usage: "extract-routes <jsdir> <outdir>", desc: "routes from JS corpus" },
  "sourcemaps": { usage: "sourcemaps <jsDir> <outdir>", desc: "source-map leak detection (--base URL)" },
  "deobfuscate": { usage: "deobfuscate <jsDir> <outdir>", desc: "JS corpus deobfuscation (--action analyze)" },
  "git-restore": { usage: "git-restore <baseUrl> <outdir>", desc: "rebuild source from leaked .git" },
  "backup-unpack": { usage: "backup-unpack <urls.txt> <outdir>", desc: "dump unpack + secret scan" },
  "sqlite-read": { usage: "sqlite-read <file.db> <outdir>", desc: "SQLite leak reader" },
  "archive-recover": { usage: "archive-recover <url> <outdir>", desc: "blocked-page archive recovery" },
  "url-refine": { usage: "url-refine <outdir> --urls a,b", desc: "URL dedupe/classify (--action classify, --fuzzy)" },
  "screenshot": { usage: "screenshot <outdir> --urls a,b", desc: "headless screenshot capture (--cluster)" },
  "traffic-recorder": { usage: "traffic-recorder <outdir>", desc: "traffic recording proxy" },
  "traffic-query": { usage: "traffic-query <dir> <action>", desc: "traffic search/get" },
  // runtime
  "runtime": { usage: "runtime <url> <outdir>", desc: "headless runtime capture (--chromium/--routes/--wait/--per-route/--api-pattern)" },
  "session-crawl": { usage: "session-crawl <baseUrl> <loginUrl> <user> <pass> <outdir>", desc: "authenticated crawl w/ relogin" },
  "perm-tree": { usage: "perm-tree <jsdir> <outdir>", desc: "permission tree rebuild (--role NAME)" },
  "merge-params": { usage: "merge-params <samples.json> <outdir>", desc: "param matrix merge" },
  "ws-schema": { usage: "ws-schema <runtime_api.json> <outdir>", desc: "WS message field schemas" },
  "proto-decode": { usage: "proto-decode <hex|base64> <outdir>", desc: "protobuf heuristic decode" },
  "ws-origin-check": { usage: "ws-origin-check <wsUrl> <outdir>", desc: "WS cross-origin check (CSWSH)" },
  // reverse
  "vm-analyze": { usage: "vm-analyze <jsDir> <outdir>", desc: "JS VM interpreter static reverse (opcode table, dispatch, state slots)" },
  "dom-sinks": { usage: "dom-sinks <jsDir> <outdir>", desc: "DOM-XSS taint chain scan" },
  "analyze-gates": { usage: "analyze-gates <jsDir> <outdir>", desc: "auth-gate static analysis" },
  "elf-analyze": { usage: "elf-analyze <binary> <outdir>", desc: "ELF static analysis (sections/symbols/hardening/imports)" },
  "wasm-analyze": { usage: "wasm-analyze <file.wasm> <outdir>", desc: "WASM static analysis (imports/exports/symbol recovery)" },
  "dex-analyze": { usage: "dex-analyze <file.dex|.apk> <outdir>", desc: "DEX static analysis (strings/classes/methods/URLs)" },
  "wasm-disasm": { usage: "wasm-disasm <file.wasm> <outdir>", desc: "full WASM disassembly (all opcodes, callgraph)" },
  "dex-disasm": { usage: "dex-disasm <file.dex|.apk> <outdir>", desc: "Dalvik bytecode disassembly (smali-level, string xrefs)" },
  "asar-unpack": { usage: "asar-unpack <app.asar> <outdir> [--list-only]", desc: "Electron asar extract + license-check localization" },
  "asar-patch": { usage: "asar-patch <app.asar> <out.asar> --patches-file F", desc: "asar text patch + repack (license-check crack)" },
  "x86-disasm": { usage: "x86-disasm <elf> <outdir>", desc: "x86 ELF instruction-level disassembly (capstone-wasm optional)" },
  // inject
  "sqli-probe": { usage: "sqli-probe <url> <outdir> --param q", desc: "SQL injection differential (error/boolean/time blind/auth-bypass)" },
  "nosqli-probe": { usage: "nosqli-probe <url> <outdir> --param id", desc: "NoSQL operator injection ($ne/$gt/$regex/$where, type juggling)" },
  "ldap-probe": { usage: "ldap-probe <url> <outdir> --param uid", desc: "LDAP injection (wildcard/filter-widening/boolean-OR, row divergence)" },
  "deser-surface": { usage: "deser-surface <url> <outdir> [--params a,b] [--cookie-name C]", desc: "deserialization surface (Java/PHP/pickle/YAML, ViewState MAC)" },
  "ssti-probe": { usage: "ssti-probe <url> <outdir> --param q", desc: "SSTI canary arithmetic (11 engine grammars, 49-reflection verdict)" },
  "proto-pollute": { usage: "proto-pollute <url> <outdir>", desc: "prototype pollution vectors (__proto__/constructor, JSON body)" },
  "hpp-probe": { usage: "hpp-probe <url> <outdir> --params a,b", desc: "HTTP parameter pollution (duplicate/array/comma strategies)" },
  "redirect-traverse": { usage: "redirect-traverse <url> <outdir> --params a,b", desc: "open redirect + path traversal encodings (Location analysis, passwd oracle)" },
  // authn
  "user-enum": { usage: "user-enum <url> <outdir> --mode login|register|reset --body-template T --known-user U --candidates a,b", desc: "account enumeration oracle (dual baseline)" },
  "spray": { usage: "spray <url> <outdir> --body-template T --users a,b --passwords p1,p2", desc: "lockout-aware password spray (per-user budget)" },
  "hash-crack": { usage: "hash-crack <hash[,hash]|file> <outdir> [--wordlist-file F]", desc: "identify + dictionary/rule crack (md5/sha/scrypt/pbkdf2)" },
  "cred-brute": { usage: "cred-brute <url> <outdir> --pairs-file F", desc: "credential spray (semantic classification)" },
  "otp-brute": { usage: "otp-brute <url> <outdir> --body-template T", desc: "OTP/2FA rate-limit & lockout measurement (+2FA secret leak detection)" },
  "pass-policy": { usage: "pass-policy <url> <outdir> --body-template T", desc: "password policy surface (10-tier weak acceptance)" },
  "2fa-bypass": { usage: "2fa-bypass <loginUrl> <verifyUrl> <protectedUrl> <outdir> --body-template T --user U --pass P", desc: "2FA step skip / OTP replay" },
  "reset-deep": { usage: "reset-deep <requestUrl> <outdir> --body-template T --email E [--token T]", desc: "reset token shape/reuse/host-poison/alias depth" },
  "reset-abuse": { usage: "reset-abuse <resetUrl> <loginUrl> <outdir>", desc: "static security-answer takeover (spray → reset → login proof)" },
  "admin-creds": { usage: "admin-creds <baseUrl> <outdir> [--panels ids]", desc: "vendor default-credential takeover on admin panels (10 panels, marker-verified)" },
  "oauth-bypass": { usage: "oauth-bypass <authzUrl-{REDIRECT}> <legitRedirect> <outdir>", desc: "OAuth redirect_uri matrix + PKCE downgrade (takeover)" },
  "jwt-inspect": { usage: "jwt-inspect <outdir>", desc: "JWT decode + weak-secret crack" },
  "jwt-attack": { usage: "jwt-attack <token> <endpoint> <outdir>", desc: "JWT attack suite (alg confusion/weak key/kid, --public-key-file)" },
  "jwks-forge": { usage: "jwks-forge <token> <oracleUrl> <outdir> --jwks-url U", desc: "JWT jku/x5u header forgery (attacker JWKS + claim elevation)" },
  "login-replay": { usage: "login-replay <url> <u> <p> <outdir>", desc: "login + cookie export" },
  // authz
  "path-auth-bypass": { usage: "path-auth-bypass <protectedUrl> <outdir>", desc: "path-confusion filter bypass (20 vector matrix, soft-404 calibrated)" },
  "signed-url": { usage: "signed-url <signedUrl> <outdir>", desc: "signed-URL enforcement (signature/expiry strip, key case, dot-segment)" },
  "auth-probe": { usage: "auth-probe <api_merged.txt> <outdir>", desc: "anonymous vs auth access mapping" },
  "idor-prescreen": { usage: "idor-prescreen <params_merged.json> <outdir>", desc: "IDOR candidate prescreen" },
  "idor-deep": { usage: "idor-deep <outdir> --endpoints[-file] JSON", desc: "three-reference IDOR oracle probing (--write for write-IDOR)" },
  "authz-replay": { usage: "authz-replay <recordRoot> <outdir> --roles[-file] JSON", desc: "authz differential replay (live-baseline verdicts)" },
  "role-matrix": { usage: "role-matrix <reconRoot> <outdir> --roles[-file] JSON", desc: "cross-role access matrix" },
  "role-escalate": { usage: "role-escalate <url> <outdir> --body-template {}", desc: "privilege escalation params (role field injection differential)" },
  "mass-assign": { usage: "mass-assign <recordRoot> <outdir>", desc: "mass-assignment sink probe (--fields a,b)" },
  "api-version": { usage: "api-version <versioned-api-url> <outdir>", desc: "API version authz drift (v0..v4 downgrade leaks)" },
  "header-bypass": { usage: "header-bypass <outdir> --urls a,b", desc: "auth-header bypass variants (X-Original-URL etc.)" },
  "verb-matrix": { usage: "verb-matrix <outdir> --urls a,b", desc: "HTTP verb override matrix probe" },
  "graphql-authz": { usage: "graphql-authz <endpoint> <schemaFile> <outdir>", desc: "GraphQL per-field authz differential" },
  // logic
  "entitlement-bypass": { usage: "entitlement-bypass <premiumUrl> <accountUrl> <outdir>", desc: "paywall enforcement test (anon/free/claim forgery)" },
  "billing-tamper": { usage: "billing-tamper <checkoutUrl> <outdir> --body-template T --amount N [--order-url U/{ID}]", desc: "price/currency/qty/coupon tampering with order read-back" },
  "value-abuse": { usage: "value-abuse <url> <outdir> --body-template T", desc: "business-logic value abuse (negative/overflow, read-back persistence)" },
  "race-probe": { usage: "race-probe <url> <outdir>", desc: "TOCTOU race (concurrent mutation + read-back divergence)" },
  "cache-deceive": { usage: "cache-deceive <baseUrl> <outdir> --private-path /api/me", desc: "web cache deception + unkeyed header poisoning" },
  "host-poison": { usage: "host-poison <url> <outdir>", desc: "Host-header/reset poisoning (9-vector canary reflection)" },
  "upload-probe": { usage: "upload-probe <url> <outdir>", desc: "file-upload surface (11 vectors, exec-risk + stored URL)" },
  "graphql-batch": { usage: "graphql-batch <endpoint> <outdir>", desc: "GraphQL depth/alias-bombing limit measurement" },
  // platform
  "auto": { usage: "auto <seed> <outdir>", desc: "deterministic pipeline (checkpoint resume, --fresh)" },
  "auto-batch": { usage: "auto-batch <seeds.txt> <outdir>", desc: "batch pipeline + summary (--notify URL)" },
  "run-diff": { usage: "run-diff <oldDir> <newDir>", desc: "diff two recon runs (attack-surface monitoring)" },
  "gen-report": { usage: "gen-report <report.json> <outdir>", desc: "findings markdown report" },
  "save-evidence": { usage: "save-evidence <items.json> <outdir>", desc: "content-addressed evidence blobs" },
  "evidence": { usage: "evidence <dir> <action>", desc: "evidence blob store" },
  "evidence-bind": { usage: "evidence-bind <dir> <action>", desc: "evidence binding lifecycle" },
  "exploration-graph": { usage: "exploration-graph <dir> <action>", desc: "exploration lineage graph" },
  "cold-graph": { usage: "cold-graph <dir> <action>", desc: "exploration graph compaction" },
  "retest": { usage: "retest <dir> <action>", desc: "finding retest lifecycle" },
  "export-findings": { usage: "export-findings <f> <dir> <fmt>", desc: "findings csv/json/md/sarif export" },
  "service-unauth": { usage: "service-unauth <host> <outdir> [--services ids] [--ports redis=N]", desc: "unauthenticated infra sweep (Redis/Docker/etcd/k8s/ES/prom/Nacos...)" },
  "actuator-exploit": { usage: "actuator-exploit <baseUrl> <outdir> [--no-rce]", desc: "Spring Actuator: env/heapdump secret mining + gateway SpEL RCE" },
  "admin-rce": { usage: "admin-rce <baseUrl> <panel> <user> <pass> <outdir> [--command id]", desc: "post-login exploit (Tomcat WAR shell/Jenkins console/loot)" },
  "actuator-rce": { usage: "actuator-rce <baseUrl> <outdir> [--shutdown]", desc: "Jolokia sysprops/env-write/sessions/heap tokens" },
  "scan-platform": { usage: "scan-platform <dir> <action>", desc: "native scan platform (projects/tasks/pipeline/assets)" },
  "hunt-begin": { usage: "hunt-begin <goal> <outdir>", desc: "open hunt loop (--max-rounds/--max-cost/--max-duration-min)" },
  "hunt-record": { usage: "hunt-record <outdir> --record[-file] F", desc: "write host observations back (goals/facts/findings/assets)" },
  "hunt-overview": { usage: "hunt-overview <outdir>", desc: "read hunt state + snapshot ledger evidence" },
  "waf-adapt": { usage: "waf-adapt <url> <payload> <outdir>", desc: "payload transport adaptation vs WAF (--in query|body|header|path)" },
  "oob-confirm": { usage: "oob-confirm <url> <outdir> --payloads a,b", desc: "OOB callback confirmation (interactsh)" },
  "smuggle-exploit": { usage: "smuggle-exploit <httpBaseUrl> <protectedPath> <outdir>", desc: "CL.TE/TE.CL smuggling into an admin bypass + h2c upgrade" },
  "smuggle-probe": { usage: "smuggle-probe <baseUrl> <outdir>", desc: "request-smuggling differential" },
  "oidc-probe": { usage: "oidc-probe <baseUrl> <outdir>", desc: "OAuth/OIDC/SAML config probe" },
  "cors": { usage: "cors <baseUrl> <outdir>", desc: "CORS misconfiguration probe" },
  "cors-deep": { usage: "cors-deep <url> <outdir>", desc: "CORS exploitability matrix (reflection × credentials, preflight)" },
  "ws-auth": { usage: "ws-auth <wsUrl> <outdir>", desc: "WebSocket auth gap (anonymous upgrade, cross-origin, push; raw RFC6455)" },
  "graphql-deep": { usage: "graphql-deep <endpoint> <outdir>", desc: "GraphQL introspection + schema" },
  "mine-params": { usage: "mine-params <outdir> (--url URL | --remove-diff --merged F --base URL)", desc: "hidden param mining (bucket bisection / remove-diff)" },
  "probe-params": { usage: "probe-params <params_merged.json> <outdir>", desc: "per-param differential probe (--max N)" },
  "pii-scan": { usage: "pii-scan <recordRoot> <outdir>", desc: "PII/credential exposure scan over recorded traffic" },
  "replay-tamper": { usage: "replay-tamper <recordRoot> <outdir>", desc: "replay recorded exchanges with tamper rules (--rules-file, --apply)" },
};

const fnDoc = (cmd: string): CmdDoc => DOCS[cmd] ?? {};
