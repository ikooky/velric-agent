---
name: velric
description: |
  Web 应用攻击面测绘与越权检测工具链（velric-agent CLI）。覆盖子域/端口/敏感路径/CORS/WAF 指纹侦察、
  SPA/MPA 接口枚举、无头运行时流量录制、前端权限树重建、鉴权面差分（authz-replay/role-matrix/IDOR/mass-assign）、
  JWT/GraphQL/Header/Verb 绕过、PII 与凭据泄漏扫描。纯 Node 本地执行，无 LLM 依赖。
  触发关键词：攻击面测绘、接口枚举、越权、IDOR、未授权访问、水平垂直越权、参数探测、隐藏参数、
  权限树、流量录制、CORS、敏感路径、WAF 指纹、sourcemap 泄漏、JWT 攻击、GraphQL 鉴权、mass assignment、PII 扫描。
---

# velric-agent — Web 攻击面测绘工具链

## ACTION REQUIRED（读完后立刻执行）

1. `NOW`: 确认目标在授权测试范围内（本工具链仅用于已授权的安全测试）
2. `NOW`: 校验工具可用 —— `bash <repo>/bootstrap.sh --verify` 通过即就绪；未安装则 `git clone` 仓库后 `bash bootstrap.sh`（一条命令装完并自验，之后 skill 直接调用）
3. `NEXT`: 侦察从 `references/workflow.md` 的 Phase 0 开始，工具不是孤立的——有阶段依赖与门禁
4. `ACT`: 每个命令产物落各自的 `<outdir>/`（JSON+txt 工件），结论必须引用产物文件与真实状态码
5. `ACT`: 需要出网代理时所有命令共用 `--proxy URL` / `--proxy-pool FILE` / `--rps N` 全局限速

工具根目录 = velric-agent 仓库路径（记为 `$VELRIC`，下文命令里替换为 `node $VELRIC/scripts/velric-agent.mjs`）。

## 命令矩阵

命令一律形如 `node $VELRIC/scripts/velric-agent.mjs <subcommand>`，下表省略前缀。首次使用先 `bash $VELRIC/bootstrap.sh`。命令注册表与分组 = `src/cli/registry.ts`（CLI `help` 输出同源渲染）。

### 侦察 — 资产与面测绘

先跑 fingerprint 判 WAF/类型；subdomains/port-scan/wayback 圈资产；paths/dir-fuzz/info-leak 摸面。

| 命令 | 用途 |
|------|------|
| `velric-agent subdomains <domain> <outdir>` | subdomain enum (crt.sh + CNAME + wordlist) |
| `velric-agent subdomain-alter <domain> <outdir> --hosts a,b` | alteration-based subdomain generation (+ --resolve) |
| `velric-agent port-scan <host> <outdir>` | TCP top-ports scan (--ports/--timeout) |
| `velric-agent dns-resolve <host> [...]` | resolve A/AAAA/CNAME |
| `velric-agent http-probe <url>` | probe one URL (status/title/hash) |
| `velric-agent enrich <seed...> --out DIR` | asset graph from seeds (DNS+HTTP) |
| `velric-agent wayback <domain> <outdir>` | historical URLs from web.archive.org |
| `velric-agent fingerprint <baseUrl> <outdir>` | WAF/CDN id + method enum + cookie audit |
| `velric-agent paths <baseUrl> <outdir>` | sensitive paths w/ soft-404 calibration |
| `velric-agent dir-fuzz <outdir> (--url URL [--wordlist-file F] | --preset sensitive|backups --base URL)` | wordlist fuzzing |
| `velric-agent nuclei-lite <baseUrl> <outdir>` | template matcher (panels/leaks) |
| `velric-agent admin-surface <baseUrl> <outdir>` | admin/panel surface map |
| `velric-agent info-leak <baseUrl> <outdir>` | information disclosure (paths/stack/banners/secrets) |
| `velric-agent coverage <baseUrl> <outdir>` | interactive coverage enumeration |
| `velric-agent site-map <baseUrl> <outdir>` | structured site map |
| `velric-agent asset-graph <dir> <action>` | asset graph store |

### 内容 — 抓取与语料

SPA 走 harvest、MPA 走 spider；deobfuscate 还原后做后续分析；泄漏语料 git-restore/backup-unpack/sqlite-read。

| 命令 | 用途 |
|------|------|
| `velric-agent harvest <url> <outdir>` | static SPA bundle harvest |
| `velric-agent spider <url> <outdir>` | MPA crawl (--cookie/--max/--depth/--exclude) |
| `velric-agent extract-routes <jsdir> <outdir>` | routes from JS corpus |
| `velric-agent sourcemaps <jsDir> <outdir>` | source-map leak detection (--base URL) |
| `velric-agent deobfuscate <jsDir> <outdir>` | JS corpus deobfuscation (--action analyze) |
| `velric-agent git-restore <baseUrl> <outdir>` | rebuild source from leaked .git |
| `velric-agent backup-unpack <urls.txt> <outdir>` | dump unpack + secret scan |
| `velric-agent sqlite-read <file.db> <outdir>` | SQLite leak reader |
| `velric-agent archive-recover <url> <outdir>` | blocked-page archive recovery |
| `velric-agent url-refine <outdir> --urls a,b` | URL dedupe/classify (--action classify, --fuzzy) |
| `velric-agent screenshot <outdir> --urls a,b` | headless screenshot capture (--cluster) |
| `velric-agent traffic-recorder <outdir>` | traffic recording proxy |
| `velric-agent traffic-query <dir> <action>` | traffic search/get |

### 运行时 — 浏览器与协议

runtime 抓真实 XHR/WS；merge-params 汇参数矩阵；ws-schema/proto-decode 解私有协议。

| 命令 | 用途 |
|------|------|
| `velric-agent runtime <url> <outdir>` | headless runtime capture (--chromium/--routes/--wait/--per-route/--api-pattern) |
| `velric-agent session-crawl <baseUrl> <loginUrl> <user> <pass> <outdir>` | authenticated crawl w/ relogin |
| `velric-agent perm-tree <jsdir> <outdir>` | permission tree rebuild (--role NAME) |
| `velric-agent merge-params <samples.json> <outdir>` | param matrix merge |
| `velric-agent ws-schema <runtime_api.json> <outdir>` | WS message field schemas |
| `velric-agent proto-decode <hex|base64> <outdir>` | protobuf heuristic decode |
| `velric-agent ws-origin-check <wsUrl> <outdir>` | WS cross-origin check (CSWSH) |

### 逆向 — 静态与指令层

JS: vm-analyze（自定义 VM opcode）→ dom-sinks/analyze-gates；二进制: elf/wasm/dex-analyze 定性 → wasm/dex/x86-disasm 指令级 + xref。

| 命令 | 用途 |
|------|------|
| `velric-agent vm-analyze <jsDir> <outdir>` | JS VM interpreter static reverse (opcode table, dispatch, state slots) |
| `velric-agent dom-sinks <jsDir> <outdir>` | DOM-XSS taint chain scan |
| `velric-agent analyze-gates <jsDir> <outdir>` | auth-gate static analysis |
| `velric-agent elf-analyze <binary> <outdir>` | ELF static analysis (sections/symbols/hardening/imports) |
| `velric-agent wasm-analyze <file.wasm> <outdir>` | WASM static analysis (imports/exports/symbol recovery) |
| `velric-agent dex-analyze <file.dex|.apk> <outdir>` | DEX static analysis (strings/classes/methods/URLs) |
| `velric-agent wasm-disasm <file.wasm> <outdir>` | full WASM disassembly (all opcodes, callgraph) |
| `velric-agent dex-disasm <file.dex|.apk> <outdir>` | Dalvik bytecode disassembly (smali-level, string xrefs) |
| `velric-agent x86-disasm <elf> <outdir>` | x86 ELF instruction-level disassembly (capstone-wasm optional) |

### 注入 — 语法与参数

逐差分探针：SQL/NoSQL/LDAP/SSTI 语法面 + 原型污染/HPP/重定向遍历；全部带基线差分与错误签名，findings 需复核语义。

| 命令 | 用途 |
|------|------|
| `velric-agent sqli-probe <url> <outdir> --param q` | SQL injection differential (error/boolean/time blind/auth-bypass) |
| `velric-agent nosqli-probe <url> <outdir> --param id` | NoSQL operator injection ($ne/$gt/$regex/$where, type juggling) |
| `velric-agent ldap-probe <url> <outdir> --param uid` | LDAP injection (wildcard/filter-widening/boolean-OR, row divergence) |
| `velric-agent ssti-probe <url> <outdir> --param q` | SSTI canary arithmetic (11 engine grammars, 49-reflection verdict) |
| `velric-agent proto-pollute <url> <outdir>` | prototype pollution vectors (__proto__/constructor, JSON body) |
| `velric-agent hpp-probe <url> <outdir> --params a,b` | HTTP parameter pollution (duplicate/array/comma strategies) |
| `velric-agent redirect-traverse <url> <outdir> --params a,b` | open redirect + path traversal encodings (Location analysis, passwd oracle) |

### 认证 — 凭证与令牌

cred-brute 语义分类喷洒；pass-policy/reset-abuse 弱密码与重置接管；jwt-inspect/jwt-attack/jwks-forge 三层 JWT 面。

| 命令 | 用途 |
|------|------|
| `velric-agent cred-brute <url> <outdir> --pairs-file F` | credential spray (semantic classification) |
| `velric-agent otp-brute <url> <outdir> --body-template T` | OTP/2FA rate-limit & lockout measurement (+2FA secret leak detection) |
| `velric-agent pass-policy <url> <outdir> --body-template T` | password policy surface (10-tier weak acceptance) |
| `velric-agent reset-abuse <resetUrl> <loginUrl> <outdir>` | static security-answer takeover (spray → reset → login proof) |
| `velric-agent jwt-inspect <outdir>` | JWT decode + weak-secret crack |
| `velric-agent jwt-attack <token> <endpoint> <outdir>` | JWT attack suite (alg confusion/weak key/kid, --public-key-file) |
| `velric-agent jwks-forge <token> <oracleUrl> <outdir> --jwks-url U` | JWT jku/x5u header forgery (attacker JWKS + claim elevation) |
| `velric-agent login-replay <url> <u> <p> <outdir>` | login + cookie export |

### 授权 — 越权与访问控制

auth-probe 画鉴权面 → idor-prescreen/idor-deep（读写 IDOR）→ authz-replay/role-matrix 多角色差分 → role-escalate/mass-assign/api-version 提权面。

| 命令 | 用途 |
|------|------|
| `velric-agent auth-probe <api_merged.txt> <outdir>` | anonymous vs auth access mapping |
| `velric-agent idor-prescreen <params_merged.json> <outdir>` | IDOR candidate prescreen |
| `velric-agent idor-deep <outdir> --endpoints[-file] JSON` | three-reference IDOR oracle probing (--write for write-IDOR) |
| `velric-agent authz-replay <recordRoot> <outdir> --roles[-file] JSON` | authz differential replay (live-baseline verdicts) |
| `velric-agent role-matrix <reconRoot> <outdir> --roles[-file] JSON` | cross-role access matrix |
| `velric-agent role-escalate <url> <outdir> --body-template {}` | privilege escalation params (role field injection differential) |
| `velric-agent mass-assign <recordRoot> <outdir>` | mass-assignment sink probe (--fields a,b) |
| `velric-agent api-version <versioned-api-url> <outdir>` | API version authz drift (v0..v4 downgrade leaks) |
| `velric-agent header-bypass <outdir> --urls a,b` | auth-header bypass variants (X-Original-URL etc.) |
| `velric-agent verb-matrix <outdir> --urls a,b` | HTTP verb override matrix probe |
| `velric-agent graphql-authz <endpoint> <schemaFile> <outdir>` | GraphQL per-field authz differential |

### 业务逻辑 — 值域与竞争

value-abuse 负数/溢出注入 + 回读持久化；race-probe TOCTOU 并发自证；cache-deceive/host-poison/upload-probe/graphql-batch 基础设施逻辑面。

| 命令 | 用途 |
|------|------|
| `velric-agent value-abuse <url> <outdir> --body-template T` | business-logic value abuse (negative/overflow, read-back persistence) |
| `velric-agent race-probe <url> <outdir>` | TOCTOU race (concurrent mutation + read-back divergence) |
| `velric-agent cache-deceive <baseUrl> <outdir> --private-path /api/me` | web cache deception + unkeyed header poisoning |
| `velric-agent host-poison <url> <outdir>` | Host-header/reset poisoning (9-vector canary reflection) |
| `velric-agent upload-probe <url> <outdir>` | file-upload surface (11 vectors, exec-risk + stored URL) |
| `velric-agent graphql-batch <endpoint> <outdir>` | GraphQL depth/alias-bombing limit measurement |

### 平台 — 管道与证据

auto/auto-batch 确定性管道；hunt 循环台账；waf-adapt/oob-confirm/smuggle/oidc/cors 深化工具；gen-report/save-evidence 收尾。

| 命令 | 用途 |
|------|------|
| `velric-agent auto <seed> <outdir>` | deterministic pipeline (checkpoint resume, --fresh) |
| `velric-agent auto-batch <seeds.txt> <outdir>` | batch pipeline + summary (--notify URL) |
| `velric-agent run-diff <oldDir> <newDir>` | diff two recon runs (attack-surface monitoring) |
| `velric-agent gen-report <report.json> <outdir>` | findings markdown report |
| `velric-agent save-evidence <items.json> <outdir>` | content-addressed evidence blobs |
| `velric-agent evidence <dir> <action>` | evidence blob store |
| `velric-agent evidence-bind <dir> <action>` | evidence binding lifecycle |
| `velric-agent exploration-graph <dir> <action>` | exploration lineage graph |
| `velric-agent cold-graph <dir> <action>` | exploration graph compaction |
| `velric-agent retest <dir> <action>` | finding retest lifecycle |
| `velric-agent export-findings <f> <dir> <fmt>` | findings csv/json/md/sarif export |
| `velric-agent scan-platform <dir> <action>` | native scan platform (projects/tasks/pipeline/assets) |
| `velric-agent waf-adapt <url> <payload> <outdir>` | payload transport adaptation vs WAF (--in query|body|header|path) |
| `velric-agent oob-confirm <url> <outdir> --payloads a,b` | OOB callback confirmation (interactsh) |
| `velric-agent smuggle-probe <baseUrl> <outdir>` | request-smuggling differential |
| `velric-agent oidc-probe <baseUrl> <outdir>` | OAuth/OIDC/SAML config probe |
| `velric-agent cors <baseUrl> <outdir>` | CORS misconfiguration probe |
| `velric-agent cors-deep <url> <outdir>` | CORS exploitability matrix (reflection × credentials, preflight) |
| `velric-agent ws-auth <wsUrl> <outdir>` | WebSocket auth gap (anonymous upgrade, cross-origin, push; raw RFC6455) |
| `velric-agent graphql-deep <endpoint> <outdir>` | GraphQL introspection + schema |
| `velric-agent mine-params <outdir> (--url URL | --remove-diff --merged F --base URL)` | hidden param mining (bucket bisection / remove-diff) |
| `velric-agent probe-params <params_merged.json> <outdir>` | per-param differential probe (--max N) |
| `velric-agent pii-scan <recordRoot> <outdir>` | PII/credential exposure scan over recorded traffic |
| `velric-agent replay-tamper <recordRoot> <outdir>` | replay recorded exchanges with tamper rules (--rules-file, --apply) |


### hunt 循环（宿主 agent 自主驱动）
| 命令 | 用途 |
|------|------|
| `velric-agent hunt-begin <goal> <outdir>` | 开 hunt（预算 --max-rounds/--max-cost） |
| `velric-agent hunt-record <outdir> --record-file F` | 写回观察（goals/facts/findings/assets；facts/findings 须有台账回执支撑——侦察命令加 `--run-id <hunt runId> --observation-ledger-root <outdir>` 才产生回执） |
| `velric-agent hunt-overview <outdir>` | 读态势 + 台账证据快照 |

## 门禁（不可绕过）

1. 观察台账反幻觉闸门：叙述的事实/PoC URL 必须来自台账真实记录，状态码一致，否则 drop
2. 响应状态码必须真实可见才可写入结论；软 404 页面不得当作命中
3. 所有输出到 report 的条目须带证据（文件/URL/状态码）
4. 诚实报告：各阶段数量、未覆盖模块、每条结论的来源（静态/运行时/合并）
5. secrets/dom-sinks/idor 类预筛结果 = 候选，不是实锤，须复核后才可升级结论

## 任务完成自检（声称完成前 MUST 通过）

- [ ] 每条结论都有产物文件 + 真实状态码支撑（不是"应该存在"）
- [ ] soft-404 校准后的命中才算命中；401/403 = 存在但受保护，不是漏洞
- [ ] 预筛类（secrets/idor/dom-sinks）结论标注"候选"，未当实锤
- [ ] WAF 在位时已降速降并发（fingerprint 命中 → --rps 全局限速）
