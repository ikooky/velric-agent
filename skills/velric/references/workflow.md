# velric-agent 侦察工作流

宿主 agent 请先通读本指南再调工具。工具不是孤立的——它们有明确的阶段依赖与门禁。命令分组与 `velric-agent help` 输出一致：侦察 / 内容 / 运行时 / 逆向 / 注入 / 认证 / 授权 / 业务逻辑 / 平台。

## Phase 0 — 指纹与分类（侦察组）
- `fingerprint` 先行：WAF/CDN 在位识别（命中则全局限速降并发）、HTTP 方法枚举、Cookie 安全审计
- 判断目标类型：SPA（重 script bundle、__NUXT__/__NEXT_DATA__ 标记）→ Phase 2 harvest；MPA（服务端渲染多页）→ spider

## Phase 1 — 资产面（侦察组）
- 域名种子 → `subdomains`（crt.sh + CNAME 链 + 词表）+ `subdomain-alter`
- IP/主机 → `port-scan`（非 Web 开放端口直出 finding）
- 历史面 → `wayback`（死接口/老管理面回收）；`enrich` 建资产图
- 面测绘：`runtime-config-leak`（config.js/.env）→ `cloud-storage`（桶列举）→ `paths`（soft-404 校准）/ `dir-fuzz` / `info-leak`（敏感路径+堆栈+banner 三档）/ `admin-surface` / `nuclei-lite`

## Phase 2 — 内容与静态（内容+逆向组）
- SPA → `harvest`（bundle 提取 API/路由 + secrets 扫描）；MPA → `spider` + `extract-routes`
- `deobfuscate` 还原混淆后：`vm-analyze`（自定义 VM opcode 表）、`dom-sinks`（DOM-XSS 污点候选）、`analyze-gates`（鉴权门）、`perm-tree`（权限树）
- 泄漏语料：`git-restore`（.git 源码还原）、`backup-unpack`、`sqlite-read`、`sourcemaps`（.map 泄漏）
- 二进制目标：ELF→`elf-analyze`、WASM→`wasm-analyze`、APK/DEX→`dex-analyze` 定性；Electron 目标先 `asar-unpack` 定位授权校验点；深挖走指令层 `wasm-disasm`（全量反汇编+调用图）/ `dex-disasm`（smali 级+字符串 xref）/ `x86-disasm`（符号/序言锚定）

## Phase 3 — 运行时（运行时组）
- `runtime`（需 Chromium）抓真实 XHR/fetch/WS 帧；无浏览器时静态面兜底
- `session-crawl` 带登录态爬行；`merge-params` 汇参数矩阵
- 私有协议：`ws-schema`（WS 帧字段表）、`proto-decode`（protobuf 启发解码）

## Phase 3.5 — 进入（无凭据）
先拿门，再谈越权。顺序：
- 枚举：`user-enum`（login/register/reset 三模式）拿到有效账号清单
- 拿凭证：`admin-creds`（默认口令）→ `spray`（每用户 3 发，锁定感知）→ `cred-brute`（已知单用户深爆破）
- 从 dump 反推：`hash-crack` 破哈希（md5/sha/scrypt/pbkdf2，字典+规则）
- 前置代理挡路：`smuggle-exploit`（CL.TE/TE.CL 走私 /admin + h2c 升级）
- 签名资源：`signed-url`（剥签名/过期、键大小写、点段）
- 反序列化入口：`deser-surface`（Java/PHP/pickle/YAML 差分 + ViewState MAC 缺失）

## Phase 4 — 攻击面（注入+认证+授权+业务逻辑组）
对带凭据的目标按角色逐个跑，findings 均需独立复核语义：
- **注入组**：`sqli-probe`（error/boolean/time-blind/--auth-bypass）→ `nosqli-probe`（$ne 行数发散）→ `ldap-probe`（通配符加宽）→ `ssti-probe`（11 引擎 49 回显）→ `proto-pollute` / `hpp-probe` / `redirect-traverse`
- **认证组**：`admin-creds`（默认口令打后台）→ `2fa-bypass`/`reset-deep`（第二因子与重置深度）→ `oauth-bypass`（重定向劫持/PKCE）→ `cred-brute`（语义分类喷洒）→ `otp-brute`（2FA 节流+secret 泄漏）→ `pass-policy`（弱密码接受度）→ `reset-abuse`（答案喷洒→重置→登录三段自证）→ `jwt-inspect`/`jwt-attack`（oracle 选匿名 401 鉴权 200 的资源型路由）/`jwks-forge`（jku/x5u 伪造）
- **授权组**：`auth-probe` 画鉴权面 → `idor-prescreen` → `idor-deep`（含 `--write` 写 IDOR，服务器 modified 计数自证）→ `path-auth-bypass`（路径混淆）→ `authz-replay`/`role-matrix` 多角色差分 → `role-escalate`（回显型只信状态码变化）/ `mass-assign` / `api-version` / `header-bypass` / `verb-matrix` / `graphql-authz`
- **业务逻辑组**：`entitlement-bypass`（付费墙服务端强制？）→ `billing-tamper`（计价篡改+回读）→ `value-abuse`（负数/溢出+回读持久化）→ `race-probe`（TOCTOU 并发自证）→ `cache-deceive`（先带 cookie 定私有路径再匿名复核）→ `host-poison`（重置投毒）→ `upload-probe`（exec-risk+落地 URL）→ `graphql-batch`（深度/别名限额）
- **后场与传输**（平台组内）：`service-unauth`（Redis/Docker/etcd/k8s 未授权直取）→ `actuator-exploit`/`actuator-rce`（env/heapdump/Jolokia/session）→ `admin-rce`（登录后拿 shell 或全量 dump）→ `cors`/`cors-deep`、`smuggle-probe`、`oidc-probe`、`ws-auth`/`ws-origin-check`、`waf-adapt`（过 WAF 变形）、`oob-confirm`（interactsh 回调）、`mine-params`/`probe-params`（隐藏参数）

## 收尾（平台组）
- `gen-report` + `save-evidence`（sha256 寻址证据 blob）；`export-findings`（csv/json/md/sarif）；`run-diff` 对比两次 run
- 多目标 → `auto-batch`；全链一条龙 → `auto`（checkpoint 断点续跑）
- hunt 循环：`hunt-begin` 开循环 → 侦察命令带 `--run-id` 产生台账回执 → `hunt-record` 写回观察（反幻觉闸门校验）→ `hunt-overview` 读态势

## 门禁（不可绕过）
1. 观察台账反幻觉闸门：叙述的事实/PoC URL 必须来自台账真实记录，状态码一致，否则 drop
2. 响应状态码必须真实可见才可写入结论；软 404 页面不得当作命中
3. 所有输出到 report 的条目须带证据（文件/URL/状态码）
4. 诚实报告：各阶段数量、未覆盖模块、每条结论的来源（静态/运行时/合并）
5. 预筛类（secrets/dom-sinks/idor）结论 = 候选，不是实锤，须宿主复核后才可升级
