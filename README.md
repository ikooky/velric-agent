<p align="center">
  <img src="assets/velric-lockup-horizontal.png" alt="velric" width="420">
</p>

Agent 自主渗透测试工具包 —— Web 应用攻击面测绘。覆盖子域/端口/敏感路径/CORS/WAF 指纹的纵深侦察，SPA/MPA 接口枚举，无头浏览器运行时流量录制，前端权限树重建，鉴权面测绘与凭据分析。提供纯 CLI 形态与 agent skill 包（skills/velric/）。仅用于已授权的安全测试。

## 功能

**资产与指纹**
- `subdomains` — 证书透明(ct.sh + CertSpotter 兜底) + CNAME 链 + 词表 DNS 爆破 + 26 服务子域接管指纹(github/heroku/s3/cloudfront/azure…)
- `subdomain-alter` — 子域排列变形引擎(dev→dev2/dev-qa/pre.dev…，ops 词表交叉+数字递增)，DNS 解析验证，发现 CT/词表都覆盖不到的资产
- `port-scan` — TCP connect top 67 端口，非 Web 开放端口直出 finding
- `fingerprint` — WAF/CDN 识别、HTTP 方法枚举、Cookie 安全审计、技术栈 header、安全 header 审计(HSTS/XFO/nosniff/Referrer-Policy/CSP 弱指令评估)、TLS 配置审计(协议/套件/证书过期/旧协议接受)
- `dns-resolve` / `http-probe` — 解析/单点探测

**静态侦察**
- `harvest` — SPA bundle 全量收割(chunk manifest 迭代下载)，提取 API/路由，内置 secrets 扫描与 robots/sitemap 合并
- `spider` — MPA 爬虫，抽表单与内联接口
- `paths` — 68 条敏感路径字典，soft-404 校准 + 通配路由识别 + catch-all 聚簇
- `sourcemaps` — 生产 .map 泄漏检测
- `wayback` — 历史端点回收
- `url-refine` — URL 池零请求精炼: action=dedupe(uro 式清洗) / classify(gf 式攻击候选分流)
- `dir-fuzz` — 词表内容发现(FUZZ 关键字+soft-404 自动校准+扩展名变异+递归)
- `screenshot` — gowitness 式截图取证(PNG+sha256+同模板聚类)

**运行时捕获**
- `runtime` — 无头 Chromium 注入 hook(fetch/XHR/WS 全录制)，遍历路由记录真实 METHOD/URL/body
- `perm-tree` — 前端权限码解析与 stub 生成
- `merge-params` — 多样本参数矩阵聚合(置信度标注)
- `ws-schema` — WS 帧字段结构提取

**运行时与交互**
- `analyze-gates` — 三道门静态逆向(渲染门/拦截器门/内容门)+HookConfig 建议
- `coverage` — 交互枚举:菜单/Tab/表格/工具栏点击+参数触发矩阵
- `site-map` — 结构化站点地图(API/参数/功能点/局限)
**平台层**
- `session-crawl` 会话活性正则探测(loggedIn/OutRegex，200-登录页失效场景)
- `traffic-recorder` — 流量录制代理(全交换记录+sha256 blob;--mitm HTTPS 解密:内置 CA 签发+明文镜像录制)
- `asset-graph` — 资产图(六型资产+host 链+去重)
- `exploration-graph` — 探索图(goal→intent→fact→finding 血缘)
- `evidence` — 证据存储(sha256 寻址+跨漏洞去重)
- `evidence-bind` — 证据绑定生命周期(角色/版本冲突拒绝/重排/md-zip 导出)
- `scan-platform` — 原生扫描平台(进程内:项目/任务/模块流水线/资产检索,sourceTask 两阶段链,零外部服务零凭据)
- `cold-graph` — 探索图冷压缩(digest 折叠/按需展开)
- `retest` — 漏洞复测(PoC 重放+reproduced/fixed/inconclusive+状态流转)
- `traffic-query` — 流量检索(host/status/method/文本+单体取回)
- `export-findings` — findings 导出(csv/json/单条 md)
**验证**
- `auth-probe` — 匿名 vs 带 cookie 双探，产出鉴权面清单(含边缘阻断识别)
- `oidc-probe` — OAuth/OIDC/SAML 配置发现与弱配置检查
- `smuggle-probe` — 请求走私差分(路径规范化变体+CL/TE)
- `ws-origin-check` — WS 跨域校验(CSWSH 预筛)
- `graphql-deep` — GraphQL 全量内省+schema diff
- `proto-decode` — 二进制 WS 帧 protobuf 猜测解码
- `nuclei-lite` — 模板匹配(暴露面板/泄漏特征)
- `login-replay` — 登录自动重放,导出会话 cookie
- `backup-unpack` — 备份/转储解包+秘密扫描
- `paths preset=backups` — 备份文件发现(.bak/.old/.swp/tar.gz/sql 后缀+根转储名，soft-404 校准)，衔接 backup-unpack 成完整链
- `sqlite-read` — SQLite 泄漏文件解析
- `idor-prescreen` — id 类参数数值邻域差分预筛(只读)
- `git-restore` — 泄漏 .git 源码树还原
- `dom-sinks` — DOM-XSS 污点链静态分析
- `jwt-inspect` — JWT 解码 + HS256 弱密钥爆破
- `cors` — Origin 变体(反射/null/localhost/后缀匹配)
- `probe-params` — 参数差分(必填/开关参数识别)
- `authz-replay` — 录制流量按低权凭据逐条重放,Autorize 式三态判定(enforced/bypassed/unknown),覆盖 GET-only 矩阵看不到的 POST/PUT/PATCH/DELETE 越权
- `mass-assign` — 向录制变更请求注入客户端从未发送的特权/归属字段(role/isAdmin/user_id/tenant_id/plan…),响应绑定即 CWE-915 sink,默认 dry-run
- `pii-scan` — 录制流量响应体敏感数据运动分析(邮箱/手机号/银行卡/身份证/JWT),按端点归因;凭据配对验证(AWS key+secret 共现才告警)
- `mine-params` — 隐藏参数挖掘(成对差分+cache-buster+响应词汇自学习),发现应用从未暴露的参数名

- `role-matrix` — 跨角色访问矩阵(reconRoot 内端点 × 多角色凭据,行=端点列=角色)
- `idor-deep` — 三参照 IDOR 判定(A/B/无关对象,身份字段确认+编码 ID 变体)
- `graphql-authz` — GraphQL 逐字段鉴权差分(schema 驱动,匿名 pass 剥凭据)
- `header-bypass` — 认证头绕过变体(X-Original-URL/X-Rewrite-URL/X-Forwarded-For…)
- `verb-matrix` — HTTP 动词覆盖矩阵(GET/POST/PUT/DELETE/PATCH/OVERRIDE 头)
- `admin-surface` — 管理面板面测绘(29 条路径探测+指纹)
- `jwt-attack` — JWT 攻击套件(alg 混淆/弱 HMAC 密钥/kid 注入/claim 篡改)
- `waf-adapt` — payload 传输变形过 WAF(query/body/header/path 四位置×大小写/编码/分块变体)
- `oob-confirm` — OOB 带外回调确认(interactsh 轮询,盲 SSRF/RCE 实锤)
- `replay-tamper` — 录制流量篡改重放(字段替换规则,默认 dry-run)
- `deobfuscate` — JS 语料反混淆(字符串数组/控制流平坦化还原,--action analyze 只统计)
- `screenshot` — 无头截图取证(PNG+sha256+聚类)

**编排与交付**
- `auto` — 一键管道 18 阶段(指纹→子域→静态→运行时→验证→报告)，stage 级 checkpoint 断点续跑
- `auto-batch` — 多目标批量 + 汇总对比 + webhook 通知
- `run-diff` — 两次 run 的攻击面变更对比(可配 cron 做监控)
- `gen-report` / `save-evidence` — 报告渲染 + sha256 证据存储；findings 导出含 SARIF 2.1.0(GitHub code scanning 兼容)
- `hunt-begin` / `hunt-record` / `hunt-overview` — 宿主 agent 驱动的 hunt 循环，观察台账反幻觉闸门，maxRounds/maxCost/maxDurationMin 预算硬停

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
