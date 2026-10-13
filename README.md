Web 应用 API 面侦察工具集 —— 一个 CLI 和一个 MCP server，共享同一核心。适用于已授权的安全测试：枚举 SPA/MPA 的后端接口、前端路由、请求参数与运行时行为。

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
velric-agent runtime https://target/ /tmp/recon --chromium /usr/bin/chromium
velric-agent perm-tree /tmp/recon/js /tmp/recon
velric-agent merge-params /tmp/recon/param_samples.json /tmp/recon
velric-agent help
```

## MCP 接入

`velric-agent mcp` 启动 stdio MCP server，暴露全部 8 个工具。

Hermes（`config.yaml`）：

```yaml
mcp_servers:
  velric-agent:
    command: npx
    args:
      - -y
      - velric-agent@0.1.0
      - mcp
    enabled: true
```

Claude Code / Cursor 等 JSON 客户端：

```json
{
  "mcpServers": {
    "velric-agent": {
      "command": "npx",
      "args": ["-y", "velric-agent@0.1.0", "mcp"]
    }
  }
}
```
velric-agent setup
velric-agent setup --dry-run   # 只看计划不落盘
```

## 典型工作流

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

## License

MIT
