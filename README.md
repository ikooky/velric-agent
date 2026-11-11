<p align="center">
  <img src="assets/velric-lockup-horizontal.png" alt="velric" width="420">
</p>

Agent 自主渗透测试工具包 —— Web 应用攻击面测绘。覆盖子域/端口/敏感路径/CORS/WAF 指纹的纵深侦察，SPA/MPA 接口枚举，无头浏览器运行时流量录制，前端权限树重建，鉴权面测绘与凭据分析。提供纯 CLI 形态与 agent skill 包（skills/velric/）。仅用于已授权的安全测试。

## 功能

命令分组与 `velric-agent help` 同源（`src/cli/registry.ts`）。

**侦察 — 资产与面测绘**
- `subdomains` — 证书透明(ct.sh + CertSpotter 兜底) + CNAME 链 + 词表 DNS 爆破 + 26 服务子域接管指纹(github/heroku/s3/cloudfront/azure…)
- `subdomain-alter` — 子域排列变形引擎(dev→dev2/dev-qa/pre.dev…)，发现 CT/词表都覆盖不到的资产
- `port-scan` — TCP connect top 67 端口，非 Web 开放端口直出 finding
- `fingerprint` — WAF/CDN 识别、HTTP 方法枚举、Cookie 安全审计、安全 header 审计(HSTS/XFO/nosniff/Referrer-Policy/CSP 弱指令评估)、TLS 配置审计
- `dns-resolve` / `http-probe` — 解析/单点探测
- `enrich` — 资产图(DNS+HTTP)
- `wayback` — 历史端点回收
- `paths` — 68 条敏感路径字典，soft-404 校准 + 通配路由识别 + catch-all 聚簇；`paths preset=backups` 衔接 backup-unpack 成完整链
- `dir-fuzz` — 词表内容发现(FUZZ 关键字+soft-404 自动校准+扩展名变异+递归)
- `cloud-storage` — 匿名云桶(S3/GCS/Azure 列举+对象读+可选写探针)
- `runtime-config-leak` — SPA 运行时配置泄漏(config.js/.env 等 20 路径,Stripe/Firebase/Supabase 等密钥类别)
- `info-leak` — 信息泄漏面(22 敏感路径/堆栈/banner/inline secret，三档严重度，SPA fallback 校准)
- `admin-surface` — 管理面板面测绘(29 条路径探测+指纹)
- `nuclei-lite` — 模板匹配(暴露面板/泄漏特征)
- `coverage` / `site-map` — 交互覆盖枚举 / 结构化站点地图

**内容 — 抓取与语料**
- `harvest` — SPA bundle 全量收割(chunk manifest 迭代下载)，提取 API/路由，内置 secrets 扫描与 robots/sitemap 合并
- `spider` — MPA 爬虫，抽表单与内联接口
- `extract-routes` — JS 语料路由提取
- `sourcemaps` — 生产 .map 泄漏检测
- `deobfuscate` — JS 语料反混淆(字符串数组/控制流平坦化还原,--action analyze 只统计)
- `git-restore` — 泄漏 .git 源码树还原
- `backup-unpack` — 备份/转储解包+秘密扫描
- `sqlite-read` — SQLite 泄漏文件解析
- `archive-recover` — 被墙页面归档恢复
- `url-refine` — URL 池零请求精炼(dedupe/classify 攻击候选分流)
- `screenshot` — 无头截图取证(PNG+sha256+同模板聚类)
- `traffic-recorder` — 流量录制代理(全交换记录+sha256 blob;--mitm HTTPS 解密:内置 CA 签发+明文镜像录制)
- `traffic-query` — 流量检索(host/status/method/文本+单体取回)

**运行时 — 浏览器与协议**
- `runtime` — 无头 Chromium 注入 hook(fetch/XHR/WS 全录制)，遍历路由记录真实 METHOD/URL/body
- `session-crawl` — 会话活性正则探测(loggedIn/OutRegex，200-登录页失效场景)
- `login-replay` — 登录自动重放,导出会话 cookie
- `perm-tree` — 前端权限码解析与 stub 生成
- `merge-params` — 多样本参数矩阵聚合(置信度标注)
- `ws-schema` — WS 帧字段结构提取
- `proto-decode` — 二进制 WS 帧 protobuf 猜测解码
- `ws-origin-check` — WS 跨域校验(CSWSH 预筛)

**逆向 — 静态与指令层**
- `vm-analyze` — JS 自定义 VM 解释器静态逆向(opcode 表提取/分类、dispatch 位解码、常量表、报告输出)
- `dom-sinks` — DOM-XSS 污点链静态分析(候选，非实锤)
- `analyze-gates` — 客户端鉴权门静态逆向
- `elf-analyze` — ELF 静态逆向(节区/段/符号/动态依赖,加固判定 PIE/RELRO/NX/栈保护/stripped)
- `wasm-analyze` — WASM 静态逆向(导入导出/内存布局/name-section 符号恢复,emscripten/WASI 识别)
- `dex-analyze` — DEX/APK 静态逆向(类/方法/字段全量,字符串表 URL/密钥提取)
- `wasm-disasm` — WASM 完整反汇编(全 opcode 含 SIMD/饱和截断/批量内存,call 目标名解析,全模块调用图)
- `dex-disasm` — Dalvik 字节码反汇编(smali 级,字符串交叉引用,类过滤,直接吃 APK)
- `x86-disasm` — x86 ELF 指令级反汇编(符号/序言锚定,call 目标标注,可选 capstone-wasm 引擎,缺失自动降级)
- `asar-patch` — asar 文本替换+重打包(改授权比较/激活地址,偏移重算)
- `asar-unpack` — Electron asar 解包(边界校验+去重跳过)与授权校验点定位(local/remote 分类、更新源、混淆度)

**注入 — 语法与参数**
- `sqli-probe` — SQL 注入差分(error-oracle/boolean-blind/有界 time-blind/--auth-bypass 认证绕过)
- `nosqli-probe` — NoSQL 注入($ne/$gt/$regex/$where 运算符+类型混淆,计数发散判定)
- `ldap-probe` — LDAP 注入(通配符/过滤器加宽/布尔语法,行数发散+错误签名)
- `deser-surface` — 反序列化面(Java/PHP/pickle/YAML 差分注入,ViewState MAC)
- `ssti-probe` — SSTI 金丝雀(11 引擎语法,49 回显判定,排除字面回显)
- `proto-pollute` — 原型污染面(__proto__/constructor 向量,反射+差分)
- `hpp-probe` — HTTP 参数污染(duplicate/array/comma/semicolon/percent-dot 差分)
- `redirect-traverse` — 开放重定向(10 变体)+路径遍历(7 编码,passwd 特征判定)

**认证 — 凭证与令牌**
- `user-enum` — 账号枚举(登录/注册/重置三模式,双基线判定)
- `spray` — 锁定感知密码喷洒(每用户预算+延迟)
- `hash-crack` — 哈希识别+字典/规则破解(md5/sha/scrypt/pbkdf2)
- `cred-brute` — 凭证爆破(语义分类:auth-ok/bad-cred/429/锁定/captcha)
- `otp-brute` — OTP/2FA 爆破面(节流/锁定缺失测量)+totpSecret 泄漏检测(RFC6238 伪造素材)
- `pass-policy` — 密码策略面(空/单字符/top 常用 10 档弱密码接受度)
- `2fa-bypass` — 2FA 步骤跳过/OTP 重放(预 OTP 会话直取+信任 cookie 属性)
- `reset-deep` — 重置 token 深度(形态/熵/时间戳、复用、Host 投毒、别名、Referer 泄漏面)
- `reset-abuse` — 密码重置接管(答案喷洒→重置→新凭证登录三段自证+hash 回显)
- `jwt-inspect` — JWT 解码 + HS256 弱密钥爆破
- `jwt-attack` — JWT 攻击套件(alg 混淆/RS-HS/弱 HMAC 密钥/kid 注入/claim 篡改,--public-key-file)
- `jwks-forge` — JWT jku/x5u 伪造(攻击者 JWKS+RSA 签名提权 claims)
- `admin-creds` — 管理面板默认口令接管(10 类面板,标记请求验真,不信裸 200)
- `oauth-bypass` — OAuth redirect_uri 劫持矩阵(11 变体)+PKCE 降级,IdP 自动 302 才算 accepted

**授权 — 越权与访问控制**
- `signed-url` — 签名 URL 强制校验(签名/过期剥离、键大小写、点段)
- `path-auth-bypass` — 路径混淆鉴权绕过(20 向量:点段/矩阵参/编码分隔/NUL/X-Original-URL,soft-404 校准)
- `auth-probe` — 匿名 vs 带 cookie 双探，产出鉴权面清单(含边缘阻断识别)
- `idor-prescreen` — id 类参数数值邻域差分预筛(只读)
- `idor-deep` — 三参照 IDOR 判定(A/B/无关对象,身份字段确认+编码 ID 变体;`--write` 写 IDOR 模式,服务器写计数自证)
- `authz-replay` — 录制流量按低权凭据逐条重放,三态判定(enforced/bypassed/unknown),覆盖 POST/PUT/PATCH/DELETE 越权
- `role-matrix` — 跨角色访问矩阵(reconRoot 内端点 × 多角色凭据,行=端点列=角色)
- `role-escalate` — 提权参数面(role/isAdmin 注入差分,回显型只信状态码变化)
- `mass-assign` — 向录制变更请求注入特权字段(role/isAdmin/user_id/tenant_id…),CWE-915 sink,默认 dry-run
- `api-version` — API 版本鉴权降级泄漏(v0..v4 匿名 vs 鉴权对照)
- `header-bypass` — 认证头绕过变体(X-Original-URL/X-Rewrite-URL/X-Forwarded-For…)
- `verb-matrix` — HTTP 动词覆盖矩阵(GET/POST/PUT/DELETE/PATCH/OVERRIDE 头)
- `graphql-authz` — GraphQL 逐字段鉴权差分(schema 驱动,匿名 pass 剥凭据)

**业务逻辑 — 值域与竞争**
- `value-abuse` — 业务逻辑值域滥用(负数/零/溢出/精度注入,--verify-url 回读持久化验证)
- `race-probe` — TOCTOU 竞争(并发变异 admitted+回读发散)
- `cache-deceive` — Web 缓存欺骗+unkeyed header 投毒面
- `host-poison` — Host 头/重置投毒面(9 向量金丝雀反射)
- `upload-probe` — 文件上传面(类型混淆/双扩展/polyglot/.htaccess,11 向量,exec-risk+落地 URL)
- `graphql-batch` — GraphQL 深度/别名轰炸限额测量
- `entitlement-bypass` — 付费墙服务端强制判定(匿名/免费号/plan 声明头伪造,同构回包=纯 UI 门)
- `billing-tamper` — 计价篡改(0/1分/负数/巨值/浮点/币种/数量/优惠券)+订单回读判 accepted

**平台 — 管道/证据/hunt**
- `auto` — 一键管道 18 阶段，stage 级 checkpoint 断点续跑
- `auto-batch` — 多目标批量 + 汇总对比 + webhook 通知
- `run-diff` — 两次 run 的攻击面变更对比(可配 cron 做监控)
- `gen-report` / `save-evidence` — 报告渲染 + sha256 证据存储；`export-findings` 导出 csv/json/md/SARIF 2.1.0(GitHub code scanning 兼容)
- `hunt-begin` / `hunt-record` / `hunt-overview` — 宿主 agent 驱动的 hunt 循环，观察台账反幻觉闸门，预算硬停
- `asset-graph` / `exploration-graph` / `cold-graph` — 资产图 / 探索血缘图(goal→intent→fact→finding) / 冷压缩
- `evidence` / `evidence-bind` — 证据存储(sha256 寻址+跨漏洞去重) / 绑定生命周期(角色/版本冲突拒绝/md-zip 导出)
- `service-unauth` — 未授权基础设施直取(Redis INFO/Docker API/etcd/Consul/K8s/ES/Prometheus/Nacos/RabbitMQ/CouchDB/MinIO)
- `actuator-exploit` — Spring Actuator 深打:env/configprops/heapdump 挖凭据 + gateway SpEL 路由注入 RCE(自动清理)
- `admin-rce` — 登录后利用(Tomcat WAR 部署 JSP shell+清理/Jenkins script console/面板数据 dump)
- `actuator-rce` — Jolokia MBean 读系统属性、env 写+refresh 实证、session id、heapdump token 提取
- `scan-platform` — 原生扫描平台(进程内:项目/任务/模块流水线/资产检索,零外部服务零凭据)
- `retest` — 漏洞复测(PoC 重放+reproduced/fixed/inconclusive+状态流转)
- `replay-tamper` — 录制流量篡改重放(字段替换规则,默认 dry-run)
- `pii-scan` — 录制流量响应体敏感数据运动分析(邮箱/手机号/银行卡/身份证/JWT),凭据配对验证
- `mine-params` — 隐藏参数挖掘(成对差分+cache-buster+响应词汇自学习)
- `probe-params` — 参数差分(必填/开关参数识别)
- `waf-adapt` — payload 传输变形过 WAF(query/body/header/path 四位置×大小写/编码/分块变体)
- `oob-confirm` — OOB 带外回调确认(interactsh 轮询,盲 SSRF/RCE 实锤)
- `smuggle-exploit` — CL.TE/TE.CL 走私打进后台路径 + h2c 升级
- `smuggle-probe` — 请求走私差分(路径规范化变体+CL/TE)
- `oidc-probe` — OAuth/OIDC/SAML 配置发现与弱配置检查
- `cors` / `cors-deep` — CORS 配置缺陷 / 可利用性矩阵(反射×credentials×preflight)
- `ws-auth` — WebSocket 认证缺口(裸 RFC6455:匿名升级/跨 Origin/无认证推送)
- `graphql-deep` — GraphQL 全量内省+schema diff

**网络设施**
- `--proxy`(http/socks5)/ `--proxy-pool FILE`(轮换+失败剔除)/ `--rps N`(全局限速)
- 外部请求默认 3 次重试

## 命令面

所有命令经 `velric-agent help` 列出；`auto` 管道与 hunt 循环在进程内消费簿记子命令(asset-graph/exploration-graph/traffic-query/retest)。方法论全文见 `skills/velric/references/workflow.md`。


## 安装

要求 Node ≥ 22;`runtime` 需要系统 Chromium(`--chromium` 或 `VELRIC_CHROMIUM`)。

```bash
git clone https://github.com/ikooky/velric-agent.git
cd velric-agent
bash bootstrap.sh
node scripts/velric-agent.mjs <command>
```

`bootstrap.sh` 一条命令完成：Node ≥ 22.13 检查（缺则给出安装指引）→ 运行时依赖安装 → 自验证（`help` 命令矩阵完整性）。零构建：CLI 直接从 TypeScript 源码运行（Node 原生类型剥离）。`--verify` 只验不装。

## CLI

```bash
velric-agent auto <target> <outdir> --chromium /usr/bin/chromium
velric-agent subdomains <domain> <outdir>
velric-agent port-scan <host> <outdir>
velric-agent paths <baseUrl> <outdir>
velric-agent auth-probe <api_merged.txt> <outdir> [--cookie STR]
velric-agent authz-replay <recordRoot> <outdir> --roles-file roles.json
velric-agent pii-scan <recordRoot> <outdir>
velric-agent harvest <baseUrl> <outdir>
velric-agent runtime <baseUrl> <outdir> --chromium <path>
velric-agent help
```

## Skill 接入（agent 宿主）

`skills/velric/` 是给 agent 宿主（Claude Code / Codex / 其它）的技能包：

- `SKILL.md` — 触发关键词 + ACTION REQUIRED + 命令矩阵（Phase 0-4 → 收尾）+ 门禁与自检
- `references/workflow.md` — Phase 0-5 侦察方法论（阶段依赖与门禁）

把 `skills/velric/` 拷进宿主的技能目录即可；工具面全部是 `velric-agent <subcommand>` CLI 命令，无协议层依赖。

## 免责声明

本项目仅供安全研究与**已获得书面授权**的安全测试使用。使用者必须：

- 在测试前确保已获得目标系统所有者的明确授权；
- 遵守所在地的法律法规，不得用于任何非法用途；
- 自行承担使用本工具产生的一切后果。

作者不对任何因滥用、误用或未经授权使用本工具造成的损失负责。下载或使用本工具即视为已阅读并同意本声明。

## License

MIT
