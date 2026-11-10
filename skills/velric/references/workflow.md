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
- 二进制目标直接进静态逆向：ELF→`elf-analyze`（加固判定+导入面），WASM→`wasm-analyze`（符号恢复），APK/DEX→`dex-analyze`（类清单+字符串情报）；三者都是纯解析零外部依赖，产出 json+md 双格式；指令层深挖：WASM→`wasm-disasm`（全量反汇编+调用图），DEX→`dex-disasm`（smali 级方法体+字符串 xref，--class-filter 聚焦目标类），x86 ELF→`x86-disasm`（符号/序言锚定函数级反汇编，call 目标符号标注；无 capstone-wasm 时自动降级）

攻击面/权限面差分探针（对带凭据的目标按角色逐个跑，findings 均需人工复核语义）：
- 参数面：`hpp-probe`（污染解析器）→ `mine-params`（隐藏参数）→ `mass-assign`（越权字段）
- 注入面：`proto-pollute`（原型污染 gadget）、`redirect-traverse`（重定向+遍历）
- 缓存面：`cache-deceive`（欺骗+投毒，先带 cookie 定私有路径再匿名复核）
- 权限面：`role-escalate`（注册/改资料端点的 role 字段注入；回显型 API 只信状态码变化）
- 业务逻辑面：`value-abuse`（数量/价格负数与溢出注入，--verify-url 回读确认持久化）
- JWT 面：`jwt-attack`（alg=none / RS-HS 公钥混淆 / kid 穿越 / 弱密钥；oracle 端点选"匿名 401、鉴权 200"的资源型路由，公开 whoami 类端点无法作证）
- 注入面：`sqli-probe`（error-oracle/boolean-blind/有界 time-blind/--auth-bypass 认证绕过；body 型配 --body-template）
- 写 IDOR：`idor-deep --write`（变异他人资源，服务器 modified 计数自证；body-ID 门禁在显式 --write 时放开）
- 2FA 面：`otp-brute`（节流/锁定缺失测量；高限额节流器需拉高 --samples 才可见）
- 竞争面：`race-probe`（TOCTOU：并发单次语义请求全 admitted + 回读状态发散；juice-shop 钱包并发充值 30/30 全入账实测）
- GraphQL 限额：`graphql-batch`（深度阶梯 + 别名扇出 512；countries.trevorblades 无别名限制实测）
- SSTI：`ssti-probe`（11 引擎语法金丝雀；49 回显且排除字面回显）
- 投毒面：`host-poison`（Host/XFH 金丝雀反射到服务端生成的绝对 URL — 重置投毒核心）
- 上传面：`upload-probe`（multipart 11 向量；accepted+exec-risk 双判定，落地 URL 提取）
- NoSQL 面：`nosqli-probe`（$ne 全命中语义：行数/modified 计数 vs 基线发散；$where 报错签名作 lead）
- 凭证面：`cred-brute`（语义分类喷洒；安全问题答案爆破用 body-template 适配 reset 端点）
- 2FA secret 泄漏：`otp-brute` 自动附带检测 status/setup 端点明文 totpSecret（命中后 base32 secret + RFC6238 即可伪造 TOTP）

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
