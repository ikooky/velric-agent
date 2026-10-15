/**
 * Workflow guide — the recon methodology (Phase 0-5) exposed as an MCP tool
 * result, plus the server-level instructions block. A host agent that only
 * sees the tool list has no idea about phase order, gates, or planner
 * disciplines; this file is how it learns them.
 */

export const WORKFLOW_GUIDE = `# velric-agent 侦察工作流

宿主 agent 请先通读本指南再调工具。工具不是孤立的——它们有明确的阶段依赖与门禁。

## Phase 0 — 指纹与分类
- \`fingerprint\` 先行:WAF/CDN 在位识别(命中则全局限速降并发)、HTTP 方法枚举、Cookie 安全审计
- 判断目标类型:SPA(重 script bundle、__NUXT__/__NEXT_DATA__/data-v-app 标记) → 走 Phase 1 harvest;MPA(服务端渲染多页) → 走 spider

## Phase 1 — 资产面
- 域名种子 → \`subdomain_enum\`(crt.sh + CNAME 链 + 词表爆破)
- IP/主机 → \`port_scan\`(非 Web 开放端口直出 finding)
- 历史面 → \`wayback_urls\`(死接口/老管理面回收)
- \`enrich_assets\` 建资产图,后续工具以它为轴

## Phase 2 — 静态侦察
- SPA → \`harvest_static\`(bundle 提取 API/路由,内置 robots/sitemap 合并 + secrets 正则扫描)
- MPA → \`spider_mpa\` + \`extract_routes\`
- \`probe_paths\` 敏感路径(soft-404 校准后仍 200 才算命中;401/403 = 存在但受保护)
- \`detect_sourcemaps\` 生产 .map 泄漏检测

## Phase 3 — 运行时
- \`capture_runtime\`(需 Chromium)抓真实 XHR/fetch/WS 帧;无浏览器时静态面兜底
- \`merge_params\` 汇参数矩阵
- \`ws_schema\` 把 WS 帧解析成字段表(私有协议接口文档)

## Phase 4 — 深化验证
- \`probe_params\` 参数差分(必填/开关参数识别)
- \`auth_probe\` 鉴权面测绘(匿名可达 vs 需鉴权清单)
- \`idor_prescreen\` IDOR 候选预筛(只读差分,候选交宿主复核)
- \`git_restore\` 泄漏 .git 源码还原
- \`dom_sinks\` DOM-XSS 污点链静态扫描
- \`jwt_inspect\` JWT 解码 + 弱密钥爆破
- \`probe_cors\` CORS 配置缺陷

## 收尾
- \`gen_report\` + \`save_evidence\`(sha256 寻址证据 blob);\`run_diff\` 对比两次 run 的面变更
- 多目标 → \`auto_batch\`(每目标一目录 + 汇总对比)
- 全链一条龙 → \`auto_recon\`(异步)+ \`auto_status\` 轮询;stage 级 checkpoint 断点续跑

## 门禁(不可绕过)
1. 观察台账反幻觉闸门:宿主叙述的事实/PoC URL 必须来自台账真实记录,状态码一致,否则 drop
2. 响应状态码必须真实可见才可写入结论;软 404 页面不得当作命中
3. 所有输出到 report 的条目须带证据(文件/URL/状态码)
4. 诚实报告:各阶段数量、未覆盖模块、每条结论的来源(静态/运行时/合并)
5. secrets/dom-sinks/idor 类预筛结果 = 候选,不是实锤,须宿主复核后才可升级结论
`;


/** Server-level instructions (shown in initialize handshake). */
export const SERVER_INSTRUCTIONS = `velric-agent — Agent 自主渗透测试工具包(API 面侦察)。

工作流: 宿主驱动模式——hunt_begin 拿驱动手册(目标分解/规划纪律/闸门规则)→循环{hunt_overview 读态势→调侦察工具(带 observationLedgerRoot 自动记台账)→hunt_record 写回}→gen_report 交付;或 auto_recon 一键确定性管道。无需任何 LLM key。
典型顺序: hunt_begin 驱动循环,或 Phase 0-5 手动: harvest/spider → runtime → perm_tree → merge_params → gen_report。
所有工具无状态,产物落 outputRoot。授权测试范围内使用。`;

/** Tool-call guidance appended to each tool description (phase + deps). */
export const PHASE_TAGS: Record<string, string> = {
  dns_resolve: "[Phase 0 侦察] 独立可用",
  http_probe: "[Phase 0 侦察] 独立可用",
  harvest_static: "[Phase 1 静态] SPA 入口;产出 js/ 供 extract_routes/perm_tree 消费",
  extract_routes: "[Phase 1 静态] 依赖 harvest_static 的 jsDir",
  spider_mpa: "[Phase 1 静态] MPA 入口(与 harvest 二选一)",
  capture_runtime: "[Phase 3 运行时] 建议 Phase 1 的 routes 喂 --routes;重 SPA 加 --wait 5000+",
  build_perm_tree: "[Phase 4 结构] 依赖 harvest_static 的 jsDir",
  merge_params: "[Phase 5 合并] 消费 capture_runtime 产出的 param_samples.json",
  gen_report: "[Phase 5 报告] 消费 findings JSON;收尾用",
  save_evidence: "[Phase 5 存证] 任意阶段产物均可存证",
  auto_recon: "[Phase 0-5 全链路] 确定性管道,一条命令;新手起点",
  hunt_begin: "[Phase 0-5 全链路·宿主驱动] 开局必调:建图+返回驱动手册(planner/worker 纪律)",
  hunt_record: "[Phase 0-5 写回] 带防幻觉闸门:URL 必须在台账、observed 须引系统记录",
  hunt_overview: "[Phase 0-5 态势] 每轮先读:目标/意图/事实/发现全貌",
  run_diff: "[监控] 同目标两次 run 的攻击面 diff:新端点/新参数/资产变更",
  subdomain_enum: "[Phase 1 资产] 子域枚举:crt.sh + CNAME 链 + 词表爆破",
  port_scan: "[Phase 1 资产] TCP top-端口扫描:非 Web 开放端口直出 finding",
  probe_cors: "[Phase 4 深化] CORS 配置缺陷:Origin 反射/null + credentials",
  fingerprint: "[Phase 0 指纹] WAF/CDN 识别 + 方法枚举 + Cookie 安全审计",
  wayback_urls: "[Phase 1 资产] Wayback 历史 URL:死接口/老管理面回收",
  detect_sourcemaps: "[Phase 2 探测] Source map 泄漏:原始源码可恢复",
  auto_batch: "[批量] N 目标管道 + 汇总对比报告(监控场景)",
  auth_probe: "[Phase 4 深化] 鉴权面测绘:匿名可达 vs 需鉴权端点清单",
  idor_prescreen: "[Phase 4 深化] IDOR 预筛:id 类参数数值邻域差分(只读)",
  git_restore: "[Phase 4 深化] .git 泄漏源码还原(tree/blob 对象重建)",
  dom_sinks: "[Phase 4 深化] DOM-XSS 污点链:source→sink 静态分析",
  ws_schema: "[Phase 4 深化] WS 帧字段 schema:私有协议接口文档",
  probe_oidc: "[Phase 4 深化] OAuth/OIDC/SAML 配置发现与弱配置检查",
  probe_smuggle: "[Phase 4 深化] 请求走私差分:规范化变体+CL/TE 组合",
  ws_origin_check: "[Phase 4 深化] WS 跨域校验(CSWSH 预筛)+认证位置标注",
  analyze_gates: "[Phase 0 准备] 三道门静态逆向:渲染门/拦截器门/内容门定位",
  run_coverage: "[Phase 3 运行时] coverage 交互枚举:菜单/Tab/表格/工具栏+参数矩阵",
  build_site_map: "[Phase 5 交付] 结构化站点地图:API/参数/功能点/局限",
  traffic_record: "[平台层] 流量录制代理:全交换记录+sha256 blob",
  asset_graph: "[平台层] 资产图:六型资产+host 链+去重",
  exploration_graph: "[平台层] 探索图:goal→intent→fact→finding 血缘",
  finding_retest: "[平台层] 漏洞复测:PoC 重放+三态判定+状态流转",
  traffic_query: "[平台层] 流量检索:host/status/method/文本过滤+单体取回",
  export_findings: "[Phase 5 交付] findings 导出:csv/json/单条 md",
  evidence_bind: "[平台层] 证据绑定:角色/版本冲突拒绝/重排/md-zip 导出",
  scan_platform: "[平台层] 原生扫描平台:项目/任务/模块流水线+资产检索(sourceTask 两阶段链)",
  graphql_deep: "[Phase 4 深化] GraphQL 全量内省+schema 解析+diff",
  proto_decode: "[Phase 4 深化] 二进制 WS 帧 protobuf 猜测解码",
  nuclei_lite: "[Phase 2 探测] 模板化匹配:暴露面板/泄漏特征",
  login_replay: "[Phase 3 运行时] 登录自动重放,导出会话 cookie",
  backup_unpack: "[Phase 4 深化] 备份/转储解包+秘密扫描",
  sqlite_read: "[Phase 4 深化] SQLite 泄漏文件解析",
};
