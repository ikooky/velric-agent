<p align="center">
  <img src="assets/velric-lockup-horizontal.png" alt="velric" width="420">
</p>

Agent 自主渗透测试工具包 —— Web 应用攻击面测绘。覆盖子域/端口/敏感路径/CORS/WAF 指纹的纵深侦察，SPA/MPA 接口枚举，无头浏览器运行时流量录制，前端权限树重建，鉴权面测绘与凭据分析。提供 CLI 与 MCP server 双形态。仅用于已授权的安全测试。

## 功能

**资产与指纹**
- `subdomains` — 证书透明(ct.sh + CertSpotter 兜底) + CNAME 链 + 词表 DNS 爆破
- `port-scan` — TCP connect top 67 端口，非 Web 开放端口直出 finding
- `fingerprint` — WAF/CDN 识别、HTTP 方法枚举、Cookie 安全审计、技术栈 header
- `dns_resolve` / `http_probe` / `enrich_assets` — 解析/单点探测/资产图

**静态侦察**
- `harvest` — SPA bundle 全量收割(chunk manifest 迭代下载)，提取 API/路由，内置 secrets 扫描与 robots/sitemap 合并
- `spider` — MPA 爬虫，抽表单与内联接口
- `paths` — 68 条敏感路径字典，soft-404 校准 + 通配路由识别 + catch-all 聚簇
- `sourcemaps` — 生产 .map 泄漏检测
- `wayback` — 历史端点回收

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
- `sqlite-read` — SQLite 泄漏文件解析
- `idor-prescreen` — id 类参数数值邻域差分预筛(只读)
- `git-restore` — 泄漏 .git 源码树还原
- `dom-sinks` — DOM-XSS 污点链静态分析
- `jwt-inspect` — JWT 解码 + HS256 弱密钥爆破
- `cors` — Origin 变体(反射/null/localhost/后缀匹配)
- `probe-params` — 参数差分(必填/开关参数识别)

**编排与交付**
- `auto` — 一键管道 17 阶段(指纹→子域→静态→运行时→验证→报告)，stage 级 checkpoint 断点续跑
- `auto-batch` — 多目标批量 + 汇总对比 + webhook 通知
- `run-diff` — 两次 run 的攻击面变更对比(可配 cron 做监控)
- `gen-report` / `save-evidence` — 报告渲染 + sha256 证据存储
- `hunt_begin` / `hunt_record` / `hunt_overview` — 宿主 agent 驱动的 hunt 循环，观察台账反幻觉闸门

**网络设施**
- `--proxy`(http/socks5)/ `--proxy-pool FILE`(轮换+失败剔除)/ `--rps N`(全局限速)
- 外部请求默认 3 次重试

## 安装

要求 Node ≥ 22;`runtime` 需要系统 Chromium(`--chromium` 或 `VELRIC_CHROMIUM`)。

```bash
npm install -g velric-agent
npx -y velric-agent <command>
```

## CLI

```bash
velric-agent auto <target> <outdir> --chromium /usr/bin/chromium
velric-agent subdomains <domain> <outdir>
velric-agent port-scan <host> <outdir>
velric-agent paths <baseUrl> <outdir>
velric-agent auth-probe <api_merged.txt> <outdir> [--cookie STR]
velric-agent harvest <baseUrl> <outdir>
velric-agent runtime <baseUrl> <outdir> --chromium <path>
velric-agent help
```

## MCP 接入

`velric-agent mcp` 启动 stdio MCP server:56 个工具 + 2 个 resources(`velric://driver-playbook`、`velric://workflow-guide`)+ 1 个 prompt(`hunt-driver`)。

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

## 免责声明

本项目仅供安全研究与**已获得书面授权**的安全测试使用。使用者必须：

- 在测试前确保已获得目标系统所有者的明确授权；
- 遵守所在地的法律法规，不得用于任何非法用途；
- 自行承担使用本工具产生的一切后果。

作者不对任何因滥用、误用或未经授权使用本工具造成的损失负责。下载或使用本工具即视为已阅读并同意本声明。

## License

MIT
