<p align="center">
  <img src="assets/velric-lockup-horizontal.png" alt="velric" width="420">
</p>

Agent 自主渗透测试工具包 —— 让 Agent 独立完成 Web 应用的攻击面测绘。覆盖 SPA/MPA 的后端接口枚举、无头浏览器运行时流量录制、前端权限树重建与多样本参数矩阵聚合，提供 CLI 与 MCP server 双形态，可被任何 MCP 客户端直接驱动。仅用于已授权的安全测试。

## 功能

### 静态分析

- `harvest_static` — SPA bundle 全量收割：抓取入口页 → 解析 webpack/Vite chunk manifest → 迭代下载全部 lazy chunk（不只 HTML 里引用的）→ 提取 API 路径、前端路由、其他路径。产出 `api_static.txt` / `routes.txt` / `paths_other.txt` / `chunkmap.txt` / `js/`。
- `extract_routes` — 对已下载的 `js/` 目录重新执行接口/路由提取（改了正则策略后重跑用）。
- `spider_mpa` — MPA 爬虫：同源受限 BFS，抽取 `<form>` 表单（真实端点+参数名）、内联 ajax URL、可达页面清单。产出 `forms.txt` / `links.txt` / `api_inline.txt`。

### 运行时捕获

- `capture_runtime` — 无头 Chromium 驱动 SPA，document-start 注入 hook（fetch/XHR/WS 全录制），过三道客户端门禁（渲染门/拦截器门/内容门），遍历路由记录真实 METHOD + URL + body + 响应样本。产出 `runtime_api.json` / `api_merged.txt`。

### 结构还原

- `build_perm_tree` — 从收割的 JS 里解析 `userRouteAuth` 权限模块，解析 webpack 别名（`x=o.KEY`），按 code 前缀推断层级，生成全量放行的菜单/权限 stub。产出 `permissions_all_stub.json` / `role_permissions_stub.json` / `permissions_tree.json` 等。

### 参数合并

- `merge_params` — 合并多份运行时录制样本，按端点聚合字段（body/query 区分），标注置信度（≥2 样本一致=high，单样本=medium）。单一样本永远不会被当成必填/可选的结论。

### 网络探测

- `dns_resolve` — A/AAAA/CNAME 解析（≤50 hosts）。
- `http_probe` — 单 URL 探测：状态码/标题/Server/尺寸/sha256，支持自定义 header、cookie、代理。

### 资产与报告

- `enrich_assets` — 资产图自动补全：种子域名/URL → DNS 解析（A/AAAA/CNAME）→ `root_domain`/`domain`/`subdomain`/`ip`/`service` 节点 → HTTP 探测（状态码+标题）。产出 `assets.json`。
- `gen_report` — 从 `report.json` 渲染可交付渗透测试报告（findings 按严重等级排序、含 PoC 证据），输出 `report.md`。
- `save_evidence` — 内容寻址证据存储（sha256）：`blobs/<h2>/<hash>.bin` + `manifest.json`，每次写入校验，独立于易失流量留存证据。

### 攻击面纵深

- **子域枚举** `subdomains` — crt.sh 证书透明 + CNAME 链追踪 + ~142 高频前缀 DNS 爆破(api/dev/admin/uat/gray/jenkins/k8s/grafana...)
- **端口扫描** `port-scan` — TCP connect top 67 端口;公网 redis/mongodb/es 等直接升 high finding
- **敏感路径** `paths` — 65 条高信号字典(.git/.env/swagger/actuator/druid/backup...) + **soft-404 校准**(随机路径基线,同构响应不算发现) + **通配路由识别**(`/{owner}` 类路由撞用户名时 title 回显探测段,自动标注 wildcard-suspect) + **catch-all 聚簇**(同签名多路径聚为一条,429 限流站实测 17→1)
- **CORS 探测** `cors` — Origin 变体(evil/反射/null),ACAO 反射 + ACAC true 判配置缺陷
- **WAF/CDN 识别** `fingerprint` — header 指纹库(cloudflare/aliyun/qcloud/safedog/baota...) + HTTP 方法枚举(OPTIONS/Allow/PUT/TRACE) + Cookie 安全审计(Secure/HttpOnly/SameSite); 附带 Server/X-Powered-By/Via 等技术栈 header
- **Source map 泄漏** `sourcemaps` — harvested JS 逐个探 .map(本地+远程),生产泄漏 = 源码可恢复
- **Wayback 历史** `wayback` — web.archive.org CDX,死接口/老管理面回收
- **批量模式** `auto-batch` — N 目标管道 + 汇总对比报告 + webhook 通知(--notify URL)
- **断点续跑** — auto 管道 stage 级 checkpoint.json,中断后 skip 已完成阶段(--fresh 强制重跑)

### 从测绘到验证

- **鉴权面测绘** `auth-probe` — 每个端点匿名 vs 带 cookie 双探,产出匿名可达/需鉴权/歧义三类清单(API 面核心交付物)
- **IDOR 预筛** `idor-prescreen` — 参数矩阵筛 id 类参数,数值邻域差分(原值/邻值/不存在),响应指纹对比,候选交宿主深挖(只读)
- **.git 源码还原** `git-restore` — 泄漏 .git 的 config/HEAD/refs + loose objects 逐层拉取,本地重建完整源码树(tree→blob 真实解析,zlib+raw 模式)
- **DOM-XSS 污点链** `dom-sinks` — location.*/window.name/postMessage → innerHTML/eval/document.write/insertAdjacentHTML 静态污点分析,fixture 5/5 链全中
- **JWT 分析** `jwt-inspect` — secrets/js 语料/token 三源收集,header/payload 解码,exp/alg=none 检测,HS256 弱密钥字典爆破(实测 "secret" 秒破)
- **WS 消息 schema** `ws-schema` — 录制的 WS 帧解析成字段表(点路径+类型+样本)= 私有协议接口文档

### 基础设施

- **SOCKS5 透传** — undici 原生 Socks5ProxyAgent,--proxy socks5:// 直用
- **代理池轮换** `--proxy-pool FILE` — 轮换+失败计数+自动剔除
- **全局限速** `--rps N` — per-host token bucket,批量目标保持礼貌
- **断点续跑** — stage 级 checkpoint(本轮已含)

### 内建情报能力

- **秘密扫描** — harvest 对 JS bundle 做 regex 扫描(AWS key/GH token/JWT/DB URL/内网 IP/内部主机名),命中写 `secrets.txt`,auto 管道自动升级为 high finding
- **运行时降噪** — capture_runtime 过滤统计信标(GA/sentry)与静态资源(SVG 图标包/字体/图片),只留真实 API 流量
- **指纹增强** — http_probe 返回 TLS 证书 SAN(顺带子域发现)、安全响应头、技术栈签名(vue/vite/nginx 等)
- **robots/sitemap 并入** — harvest 自动抓取 robots.txt + sitemap.xml 路径进路由池
- **GraphQL 探测** — auto 管道对 /graphql 做轻量 introspection 探测
- **HTTP 重试** — 全部外部请求默认 3 次重试(间隔 1s,网络错/超时/5xx)

### 宿主驱动 hunt（零 key）

- `hunt_begin` / `hunt_record` / `hunt_overview` — 宿主 agent（你接入的 MCP 客户端）就是 planner+worker 大脑：`hunt_begin(goal)` 建图并返回驱动手册（目标分解规则、规划纪律：硬底线/不重派/材料性新机理才重开/串行链分步派/路线多样、量化验收、执行红线）；循环 = `hunt_overview` 读态势 → 调侦察工具（带 `observationLedgerRoot`，系统自动把工具真实请求过的 URL+状态记入观察台账）→ `hunt_record` 写回（防幻觉闸门自动执行：evidence 引用的 URL 必须在台账里、observed 事实必须引用系统记录，编造整条丢弃）→ `gen_report` + `save_evidence` 交付。状态全落 graph.json，可重入。无需任何 API key。

### 自主流水线

- `run_diff` / `probe_params` — 攻击面深化与监控:两次 run 的结构化 diff(新端点/新参数/资产变更,配 cron 即攻击面监控);参数差分探测(逐参数剔除对比响应,识别必填/开关参数)
- **MCP 工具矩阵(33 个,按工作流阶段分组)** — `fingerprint` `subdomain_enum` `port_scan` `dns_resolve` `http_probe` `enrich_assets` / `harvest_static` `extract_routes` `spider_mpa` `probe_paths` `detect_sourcemaps` `wayback_urls` / `capture_runtime` `merge_params` `ws_schema` / `probe_params` `auth_probe` `idor_prescreen` `git_restore` `dom_sinks` `jwt_inspect` `probe_cors` / `gen_report` `save_evidence` `run_diff` `auto_recon` `auto_status` `auto_batch` / `hunt_begin` `hunt_record` `hunt_overview` `workflow_guide`
- `auto_recon` / `auto_status` — 一条命令异步跑完侦察全链路- `auto_recon` / `auto_status` — 一条命令异步跑完侦察全链路(规避 MCP 客户端 60s 超时,auto_status 轮询进度):`fingerprint → subdomains → enrich → classify → harvest/spider → runtime → params → paths → cors → sourcemaps → auth_probe → dom_sinks → jwt → findings/report/evidence`(17 阶段)，直接产出 `report.md` + 证据 blob + `pipeline.json` 运行台账。任一非关键阶段失败只记录不中断，产物全落 `outputRoot`；stage 级 checkpoint 断点续跑，`--fresh` 强制重跑。

## 安装

要求 Node ≥ 22；`capture_runtime` 需要系统 Chromium（`--chromium` 或 `VELRIC_CHROMIUM` 指定）。

```bash
npm install -g velric-agent
# 或免安装运行
npx -y velric-agent <command>
```

## CLI 用法

```bash
velric-agent dns-resolve example.com
velric-agent http-probe https://target/
velric-agent harvest https://target/ /tmp/recon
velric-agent extract-routes /tmp/recon/js /tmp/recon
velric-agent spider https://target/ /tmp/recon --cookie "session=..."
velric-agent runtime https://target/ /tmp/recon --chromium /usr/bin/chromium --wait 6000 --per-route 4000
velric-agent perm-tree /tmp/recon/js /tmp/recon
velric-agent merge-params /tmp/recon/param_samples.json /tmp/recon
velric-agent enrich example.com --out /tmp/recon
velric-agent gen-report /tmp/recon/report.json /tmp/recon
velric-agent save-evidence /tmp/recon/items.json /tmp/recon
velric-agent auto https://target/ /tmp/recon --chromium /usr/bin/chromium
velric-agent help
```

## MCP 接入

`velric-agent mcp` 启动 stdio MCP server，暴露全部 33 个工具 + 2 个 resources(driver-playbook/workflow-guide) + 1 个 prompt(hunt-driver)。

Hermes（`config.yaml`）：

```yaml
mcp_servers:
  velric-agent:
    command: npx
    args:
      - -y
      - velric-agent@latest
      - mcp
    enabled: true
```

Claude Code / Cursor 等 JSON 客户端：

```json
{
  "mcpServers": {
    "velric-agent": {
      "command": "npx",
      "args": ["-y", "velric-agent@latest", "mcp"]
    }
  }
}
```

## 典型工作流

一条命令（推荐）：

```bash
velric-agent auto juejin.cn /tmp/recon --chromium /usr/bin/chromium
```

分步（需要精细控制时）：

1. `http_probe` 入口页 → 判断 SPA（空壳+chunk）还是 MPA（服务端渲染+表单）。
2. 静态先行：SPA 用 `harvest_static`，MPA 用 `spider_mpa`。
3. `capture_runtime` 带上 `routes.txt` 的路由，补回静态看不到的 METHOD/body。
4. 模块空白（权限门未过）→ `build_perm_tree` 生成 stub → 作为 `capture_runtime` 的 `stubs` 参数重跑。
5. 运行时 detail 导出 `param_samples.json` → `merge_params` 出参数矩阵。
6. 诚实报告：各阶段数量、未覆盖模块、每条结论的来源（静态/运行时/合并）。

## 边界

- 仅做侦察：枚举路径、方法、参数、路由。不含漏洞利用与破坏性操作。
- 客户端门禁用 stub/mock 拟真通过；outbound 请求按原样录制。
- 仅用于已授权的测试目标。

## 免责声明

本项目仅供安全研究与**已获得书面授权**的安全测试使用。使用者必须：

- 在测试前确保已获得目标系统所有者的明确授权；
- 遵守所在地的法律法规，不得用于任何非法用途；
- 自行承担使用本工具产生的一切后果。

作者不对任何因滥用、误用或未经授权使用本工具造成的损失负责。下载或使用本工具即视为已阅读并同意本声明。

## License

MIT
