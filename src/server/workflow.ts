/**
 * Workflow guide — the recon methodology (Phase 0-5) exposed as an MCP tool
 * result, plus the server-level instructions block. A host agent that only
 * sees the tool list has no idea about phase order, gates, or planner
 * disciplines; this file is how it learns them.
 */

export const WORKFLOW_GUIDE = `# velric-agent 侦察工作流

宿主 agent 请先通读本指南再调工具。工具不是孤立的——它们有明确的阶段依赖与门禁。

## Phase 0 — 分类
先判断目标类型:
- SPA(重 script bundle、__NUXT__/__NEXT_DATA__/data-v-app 标记) → 走 Phase 1 harvest
- MPA(服务端表单、少量脚本) → 走 Phase 1 spider
- 拿不准 → auto_recon 自动分类分流(推荐起点)

## Phase 1 — 静态
SPA: harvest_static 下载 JS bundle → extract_routes 提路由 → api_static.txt 端点清单
MPA: spider_mpa 爬页面 → forms.txt 表单参数 + api_inline.txt 内联接口
产出: 端点清单、路由表、chunkmap。

### Phase 1b — 参数逆向
以 path 为锚扩窗找组包对象: grep '(params|data|body)\\\\s*:\\\\s*\\\\{' 。候选字段 → param_candidates。
传输形态标注: query|json|form|graphql|multipart|encrypted。
必填/可选的结论必须等 Phase 3 多样本 + Phase 5 合并。

## Phase 2 — 鉴权三道门
在收割的 JS 里 grep:
- 渲染门: isLogin/getToken/cookie/localStorage → 怎么判断已登录
- 拦截器门: response_code/errno/axios interceptor → 什么触发跳 /login
- 内容门: menu/permission/role/acl/routes → 菜单权限从哪来

## Phase 3 — 运行时(须已过 Phase 1,有 routes 喂给 --routes)
capture_runtime 无头浏览器录制真实流量 → runtime_api.json + param_samples.json。
重 SPA 建议 --wait 5000-8000 --per-route 2500+。非标准 API 风格用 --api-pattern(如 Discourse 的 .json 后缀)。
参数触发矩阵: 列表首屏/搜索/高级筛选/新建编辑各录一次,diff 出 optional。

## Phase 4 — 权限树
build_perm_tree 从 JS 权限模块重建权限层级(userRouteAuth 或通用 RBAC: hasPermi/roles 守卫)。
产出 permissions_tree.json + 放行 stub。

## Phase 5 — 合并与报告
- merge_params: param_samples.json 多样本合并 → 端点参数矩阵(置信度标注)
- enrich_assets: 种子 → 资产图(DNS+HTTP)
- gen_report: findings → report.md
- save_evidence: sha256 证据留存
- auto_recon: 一条命令走完 0→5(deterministic 管道)
- hunt: LLM 编排版(planner/worker 循环,自主派意图+反幻觉闸门) — 宿主只需给 goal

## 纪律
- 初次受阻(404/被过滤/无回显)≠此路不通:换编码/方法/参数/路径走完再判死路。
- 观察分 observed(直接看到)/inferred(推断)。证伪与证实同等有价值。
- 发现只记增量;换措辞重记已有结论=污染。
- 确认漏洞必须真实触发过+可复现证据;版本号/CVE 匹配、"看起来可注入"严禁当 finding。
- 串行利用链分步推进:后一步依赖前一步的实际产出,前置不存在就别假想后续。
- 路线多样:2-3 条机理不同的路线并存,某条交出逼近目标的实证再聚焦。
- 封锁路线不无理由重试:只有材料性新机理(新入口/新参数/明显不同构造)才重开。
`;

/** Server-level instructions (shown in initialize handshake). */
export const SERVER_INSTRUCTIONS = `velric-agent — Agent 自主渗透测试工具包(API 面侦察)。

工作流: 先调 workflow_guide 读方法论,或直接 auto_recon(确定性管道)/hunt(LLM 编排: 目标分解→planner 派意图→worker 执行→反幻觉闸门→报告)。
典型顺序: hunt(自主) 或 Phase 0-5 手动: harvest/spider → runtime → perm_tree → merge_params → gen_report。
所有工具无状态,产物落 outputRoot。授权测试范围内使用。`;

/** Tool-call guidance appended to each tool description (phase + deps). */
export const PHASE_TAGS: Record<string, string> = {
  dns_resolve: "[Phase 0 侦察] 独立可用",
  http_probe: "[Phase 0 侦察] 独立可用",
  enrich_assets: "[Phase 0→5 资产] 种子→DNS/HTTP 资产图;独立可用",
  harvest_static: "[Phase 1 静态] SPA 入口;产出 js/ 供 extract_routes/perm_tree 消费",
  extract_routes: "[Phase 1 静态] 依赖 harvest_static 的 jsDir",
  spider_mpa: "[Phase 1 静态] MPA 入口(与 harvest 二选一)",
  capture_runtime: "[Phase 3 运行时] 建议 Phase 1 的 routes 喂 --routes;重 SPA 加 --wait 5000+",
  build_perm_tree: "[Phase 4 结构] 依赖 harvest_static 的 jsDir",
  merge_params: "[Phase 5 合并] 消费 capture_runtime 产出的 param_samples.json",
  gen_report: "[Phase 5 报告] 消费 findings JSON;收尾用",
  save_evidence: "[Phase 5 存证] 任意阶段产物均可存证",
  auto_recon: "[Phase 0-5 全链路] 确定性管道,一条命令;新手起点",
  hunt: "[Phase 0-5 全链路·LLM 编排] planner/worker 循环;宿主只给 goal",
  workflow_guide: "[必读] 返回完整方法论(Phase 0-5+纪律);开局先调这个",
};
