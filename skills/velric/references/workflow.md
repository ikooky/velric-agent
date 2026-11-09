# velric-agent 侦察工作流

宿主 agent 请先通读本指南再调工具。工具不是孤立的——它们有明确的阶段依赖与门禁。

## Phase 0 — 指纹与分类
- `fingerprint` 先行:WAF/CDN 在位识别(命中则全局限速降并发)、HTTP 方法枚举、Cookie 安全审计
- 判断目标类型:SPA(重 script bundle、__NUXT__/__NEXT_DATA__/data-v-app 标记) → 走 Phase 1 harvest;MPA(服务端渲染多页) → 走 spider

## Phase 1 — 资产面
- 域名种子 → `subdomains`(crt.sh + CNAME 链 + 词表爆破)
- IP/主机 → `port-scan`(非 Web 开放端口直出 finding)
- 历史面 → `wayback`(死接口/老管理面回收)
- `enrich` 建资产图,后续工具以它为轴

## Phase 2 — 静态侦察
- SPA → `harvest`(bundle 提取 API/路由,内置 robots/sitemap 合并 + secrets 正则扫描)
- MPA → `spider` + `extract-routes`
- `paths` 敏感路径(soft-404 校准后仍 200 才算命中;401/403 = 存在但受保护)
- `sourcemaps` 生产 .map 泄漏检测
- `deobfuscate` 字符串数组/控制流平坦化还原后再做后续分析
- `vm-analyze` 语料命中风控/自定义 VM（IIFE+状态数组+位解码 opcode 分发）时：先跑它拿 opcode 表/常量表/dispatch 语义，再定位导出函数注册点；opcode 表是后续人工追踪调用链的底图
- 二进制目标直接进静态逆向：ELF→`elf-analyze`（加固判定+导入面），WASM→`wasm-analyze`（符号恢复），APK/DEX→`dex-analyze`（类清单+字符串情报）；三者都是纯解析零外部依赖，产出 json+md 双格式

## Phase 3 — 运行时
- `runtime`(需 Chromium)抓真实 XHR/fetch/WS 帧;无浏览器时静态面兜底
- `merge-params` 汇参数矩阵
- `ws-schema` 把 WS 帧解析成字段表(私有协议接口文档)

## Phase 4 — 深化验证
- `probe-params` 参数差分(必填/开关参数识别)
- `auth-probe` 鉴权面测绘(匿名可达 vs 需鉴权清单)
- `idor-prescreen` IDOR 候选预筛(只读差分,候选交宿主复核)
- `git-restore` 泄漏 .git 源码还原
- `dom-sinks` DOM-XSS 污点链静态扫描
- `jwt-inspect` JWT 解码 + 弱密钥爆破
- `cors` CORS 配置缺陷

## 收尾
- `gen-report` + `save-evidence`(sha256 寻址证据 blob);`run-diff` 对比两次 run 的面变更
- 多目标 → `auto-batch`(每目标一目录 + 汇总对比)
- 全链一条龙 → `auto`(异步)+ `auto --status` 轮询;stage 级 checkpoint 断点续跑

## 门禁(不可绕过)
1. 观察台账反幻觉闸门:宿主叙述的事实/PoC URL 必须来自台账真实记录,状态码一致,否则 drop
2. 响应状态码必须真实可见才可写入结论;软 404 页面不得当作命中
3. 所有输出到 report 的条目须带证据(文件/URL/状态码)
4. 诚实报告:各阶段数量、未覆盖模块、每条结论的来源(静态/运行时/合并)
5. secrets/dom-sinks/idor 类预筛结果 = 候选,不是实锤,须宿主复核后才可升级结论
