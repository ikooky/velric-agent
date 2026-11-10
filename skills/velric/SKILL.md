---
name: velric
description: |
  Web 应用攻击面测绘与越权检测工具链（velric-agent CLI）。覆盖子域/端口/敏感路径/CORS/WAF 指纹侦察、
  SPA/MPA 接口枚举、无头运行时流量录制、前端权限树重建、鉴权面差分（authz-replay/role-matrix/IDOR/mass-assign）、
  JWT/GraphQL/Header/Verb 绕过、PII 与凭据泄漏扫描。纯 Node 本地执行，无 LLM 依赖。
  触发关键词：攻击面测绘、接口枚举、越权、IDOR、未授权访问、水平垂直越权、参数探测、隐藏参数、
  权限树、流量录制、CORS、敏感路径、WAF 指纹、sourcemap 泄漏、JWT 攻击、GraphQL 鉴权、mass assignment、PII 扫描。
---

# velric-agent — Web 攻击面测绘工具链

## ACTION REQUIRED（读完后立刻执行）

1. `NOW`: 确认目标在授权测试范围内（本工具链仅用于已授权的安全测试）
2. `NOW`: 校验工具可用 —— `bash <repo>/bootstrap.sh --verify` 通过即就绪；未安装则 `git clone` 仓库后 `bash bootstrap.sh`（一条命令装完并自验，之后 skill 直接调用）
3. `NEXT`: 侦察从 `references/workflow.md` 的 Phase 0 开始，工具不是孤立的——有阶段依赖与门禁
4. `ACT`: 每个命令产物落各自的 `<outdir>/`（JSON+txt 工件），结论必须引用产物文件与真实状态码
5. `ACT`: 需要出网代理时所有命令共用 `--proxy URL` / `--proxy-pool FILE` / `--rps N` 全局限速

工具根目录 = velric-agent 仓库路径（记为 `$VELRIC`，下文命令里替换为 `node $VELRIC/scripts/velric-agent.mjs`）。

## 命令矩阵

命令一律形如 `node $VELRIC/scripts/velric-agent.mjs <subcommand>`，下表省略前缀。首次使用先 `bash $VELRIC/bootstrap.sh`。

### Phase 0 — 指纹与分类
| 命令 | 用途 |
|------|------|
| `velric-agent fingerprint <baseUrl> <outdir>` | WAF/CDN 识别、HTTP 方法枚举、Cookie 安全审计 |
| `velric-agent http-probe <url>` | 单 URL 探测（状态/标题/哈希） |

### Phase 1 — 资产面
| 命令 | 用途 |
|------|------|
| `velric-agent subdomains <domain> <outdir>` | 子域枚举（crt.sh + CNAME + 词表） |
| `velric-agent subdomain-alter <domain> <outdir> --hosts a,b` | 改写式子域生成（+`--resolve`） |
| `velric-agent port-scan <host> <outdir>` | TCP top-ports 扫描 |
| `velric-agent wayback <domain> <outdir>` | 历史 URL（web.archive.org） |
| `velric-agent enrich <seed...> --out DIR` | 资产图（DNS+HTTP） |

### Phase 2 — 静态侦察
| 命令 | 用途 |
|------|------|
| `velric-agent harvest <url> <outdir>` | SPA bundle 提取 API/路由 + secrets 扫描 |
| `velric-agent spider <url> <outdir>` | MPA 爬行（--max/--depth/--cookie） |
| `velric-agent extract-routes <jsdir> <outdir>` | 从 JS 语料提取路由 |
| `velric-agent deobfuscate <jsDir> <outdir>` | JS 反混淆（--action analyze 只做统计） |
| `velric-agent vm-analyze <jsDir> <outdir>` | JS 自定义 VM 解释器静态逆向：opcode 表提取/分类（CALL/BRANCH/STORE/RETURN/DOM/ALLOC/REGEX）、dispatch 位解码（&31 / >>5&31）、状态槽位、常量表引用、常量前奏映射。产出 vm_analysis.json + vm_report.md（--max-files/--min-score 调阈值） |
| `velric-agent elf-analyze <binary> <outdir>` | ELF 静态逆向：节区/段/符号表/动态依赖/入口，加固判定（PIE/RELRO/NX/栈保护/stripped/build-id），导入面=攻击面。产出 elf_analysis.json + elf_report.md |
| `velric-agent wasm-analyze <file.wasm> <outdir>` | WASM 静态逆向：节区/导入导出函数/内存布局/name-section 符号恢复（emscripten/WASI 识别）。产出 wasm_analysis.json + wasm_report.md |
| `velric-agent dex-analyze <file.dex或.apk> <outdir>` | DEX 静态逆向：类/方法/字段全量、字符串表 URL/密钥提取（直接吃 APK 自动解 classes.dex）。产出 dex_analysis.json + dex_strings.txt + dex_urls.txt + dex_report.md |
| `velric-agent wasm-disasm <file.wasm> <outdir>` | WASM 完整反汇编：全 opcode（含 SIMD/饱和截断/批量内存）、函数内偏移、call 目标按 name 解析、全模块调用图。产出 wasm_disasm.txt + wasm_callgraph.json（--max-functions 钳制） |
| `velric-agent dex-disasm <file.dex或.apk> <outdir>` | Dalvik 字节码反汇编（smali 级）：每方法指令流+寄存器+调用解析、字符串交叉引用（哪个方法引用哪个字符串）、类过滤。产出 dex_disasm.smali + dex_string_xrefs.json（--class-filter RE / --max-methods N） |
| `velric-agent x86-disasm <elf> <outdir>` | x86 ELF 指令级反汇编：符号表锚定函数（stripped 二进制走 entry+endbr64/push-rbp 序言启发式）、call 目标符号标注、字符串表。产出 x86_disasm.txt + x86_disasm.json（--max-functions N / --max-instrs N）。引擎为 capstone-wasm（可选依赖，缺失时降级输出字符串表并明示） |
| `velric-agent nosqli-probe <url> <outdir> --param id` | NoSQL 注入差分：$ne/$gt/$regex/$exists/$where 运算符 + 类型混淆（[]/null/0/{}），行数/modified 计数发散判定 + Mongo 错误签名。产出 nosqli_cases.json + findings.md（--in body --method PATCH --body-template） |
| `velric-agent race-probe <url> <outdir>` | TOCTOU 竞争面：并发单次语义请求（券/转账/扣款）N×rounds 全发，admitted vs 服务端自证状态发散判定 check-then-act 窗口。产出 race_cases.json + findings.md（--concurrency/--rounds/--verify-url） |
| `velric-agent graphql-batch <endpoint> <outdir>` | GraphQL 深度/别名轰炸限额测量：depth 阶梯（1..9）+ 别名扇出阶梯（2/8/32/128/512），服务端拒绝语义分类。产出 graphql_batch.json/md（--query-template） |
| `velric-agent ldap-probe <url> <outdir> --param uid` | LDAP 注入差分：通配符（\*/前缀\*）/过滤器闭合（\*)）/加宽（\*)(objectClass=\*)）/布尔 OR/AND/null/DN 注入 8 向量，行数发散 + LDAP 错误签名。产出 ldap_cases.json + findings.md |
| `velric-agent api-version <versioned-api-url> <outdir>` | API 版本鉴权降级：v0..v4 姊妹版本匿名 vs 鉴权对照，旧版丢失鉴权层的数据泄漏。产出 api_version_cases.json + api_version.md |
| `velric-agent reset-abuse <resetUrl> <loginUrl> <outdir>` | 密码重置滥用：静态安全问题答案喷洒→重置接受→新凭证登录自证完整接管链+hash 回显检测。产出 reset_cases.json + reset_abuse.md |
| `velric-agent host-poison <url> <outdir>` | Host 头/密码重置投毒面：Host/X-Forwarded-Host/X-Forwarded-Proto/X-Original-Host/Forwarded 等 9 向量金丝雀，检测服务端用攻击者输入构造绝对 URL（重置链接/canonical/跳转）。产出 host_poison.json/md |
| `velric-agent upload-probe <url> <outdir>` | 文件上传面：内容类型混淆、双扩展名、null 截断、SVG/HTML/JS 载体、polyglot GIF、.htaccess、JSP/SHTML 等 11 向量 multipart 上传，接受语义+exec-risk 判定+存储 URL 提取。产出 upload_cases.json + findings.md |
| `velric-agent ssti-probe <url> <outdir> --param q` | SSTI 面：11 种引擎语法的 7\*7 金丝雀算术（jinja/twig/freemarker/velocity/smarty/erb/es6/mvel/pebble），49 回显且非字面回显才 confirmed。产出 ssti_cases.json + findings.md |
| `velric-agent cred-brute <url> <outdir> --pairs-file F` | 凭证爆破：有界字典喷洒 + 逐响应语义分类（auth-ok/bad-cred/429/锁定/CAPTCHA），节流存在性汇总。产出 cred_cases.json + cred_brute.md（--body-template '{USER}/{PASS}' --delay-ms） |
| `velric-agent otp-brute`（增强） | 附带 2FA secret 泄漏检测：探 verify 端点同时检查 setup/status 姐妹端点明文回显 totpSecret（base32 特征），命中即输出可伪造 TOTP 的绕过素材 |
| `velric-agent value-abuse <url> <outdir> --body-template '{"quantity":1}'` | 业务逻辑值域滥用：负数/零/小数/溢出/字符串数值/科学计数法 7 变体注入，接受+回显+**回读持久化验证**三段确认。产出 value_abuse_cases.json + value_abuse.md（--verify-url 回读 / --bearer T） |
| `velric-agent sqli-probe <url> <outdir> --param q` | SQL 注入差分：error-oracle（5 种引号破坏）+ boolean-blind（AND 1=1/1=2 三组对）+ 有界 time-blind（sqlite/pgsql/mysql/mssql）+ 认证绕过语法（--auth-bypass）。产出 sqli_cases.json + sqli_findings.md（--in body 配 --body-template） |
| `velric-agent otp-brute <url> <outdir> --body-template T` | OTP/2FA 爆破面：有界错误码样本测 verify 端点节流/锁定/CAPTCHA 升级缺失，全空间串行时间估算。产出 otp_brute.json/md（T 含 {CODE} 占位符） |
| `velric-agent idor-deep --write` | 写 IDOR 模式：变异目标对象（PATCH/PUT）+ 服务器写计数自证（modified/matched>0），--write-payload/--write-method/--ids |
| `velric-agent hpp-probe <url> <outdir> --params a,b` | HTTP 参数污染：duplicate/array-cast/comma/semicolon/percent-dot 五策略差分，识别 last-wins/first-wins/拼接型解析器。产出 hpp_cases.json + hpp_findings.md |
| `velric-agent proto-pollute <url> <outdir>` | 原型污染面：`__proto__`/`constructor.prototype`/dot-path/数组下标向量（JSON body），反射+差分判定。产出 proto_cases.json + proto_findings.md |
| `velric-agent redirect-traverse <url> <outdir> --params a,b` | 开放重定向（绝对/协议相对/反斜杠/@符号/percent 编码 10 变体，Location 头分析）+ 路径遍历（7 编码变体，/etc/passwd 内容特征判定）。产出 redirect_cases.json + traversal_cases.json + findings.md |
| `velric-agent cache-deceive <baseUrl> <outdir> --private-path /api/me` | Web 缓存欺骗（路径后缀技巧 + 匿名复核确认污染）+ unkeyed header 投毒面（X-Forwarded-Host 等 6 头反射检测）。产出 cache_cases.json + cache_findings.md |
| `velric-agent role-escalate <url> <outdir> --body-template '{}'` | 提权参数面：role/isAdmin/userType 等 20 字段 × 8 值注入差分；回显型 API 自动对照降误报（状态码变化才报）。产出 role_cases.json + role_findings.md |
| `velric-agent paths <baseUrl> <outdir>` | 敏感路径（soft-404 校准） |
| `velric-agent sourcemaps <jsDir> <outdir> --base URL` | 生产 .map 泄漏检测 |

### Phase 3 — 运行时
| 命令 | 用途 |
|------|------|
| `velric-agent runtime <url> <outdir>` | 无头浏览器 XHR/fetch/WS 帧捕获（--chromium） |
| `velric-agent merge-params <samples.json> <outdir>` | 参数矩阵汇总 |
| `velric-agent ws-schema <wsUrl> <outdir>` | WS 帧字段表 |
| `velric-agent session-crawl <baseUrl> <loginUrl> <user> <pass> <outdir>` | 带登录态爬行（自动重登） |
| `velric-agent traffic-recorder <outdir>` | MITM 流量录制代理 |
| `velric-agent screenshot <outdir> --urls a,b` | 无头截图（--cluster） |

### Phase 4 — 鉴权与越权
| 命令 | 用途 |
|------|------|
| `velric-agent auth-probe <api_merged.txt> <outdir>` | 匿名可达 vs 需鉴权测绘 |
| `velric-agent authz-replay <recordRoot> <outdir> --roles-file JSON` | 录制流量多角色差分重放（live-baseline 判定） |
| `velric-agent role-matrix <reconRoot> <outdir> --roles-file JSON` | 跨角色访问矩阵 |
| `velric-agent idor-prescreen <params_merged.json> <outdir>` | IDOR 候选预筛（只读差分） |
| `velric-agent idor-deep <outdir> --endpoints-file JSON` | 三参照 IDOR 真实判定 |
| `velric-agent mass-assign <recordRoot> <outdir>` | mass-assignment 污点探测（--fields） |
| `velric-agent jwt-inspect <outdir>` / `jwt-attack <token> <endpoint> <outdir>` | JWT 解码/弱密钥/攻击套件 |
| `velric-agent graphql-authz <endpoint> <schemaFile> <outdir>` | GraphQL 逐字段鉴权差分 |
| `velric-agent header-bypass <outdir> --urls a,b` | 认证头绕过变体 |
| `velric-agent verb-matrix <outdir> --urls a,b` | HTTP 动词覆盖矩阵 |
| `velric-agent admin-surface <baseUrl> <outdir>` | 管理面测绘 |

### 深化与参数
| 命令 | 用途 |
|------|------|
| `velric-agent mine-params <outdir> (--url URL \| --remove-diff --merged F --base URL)` | 隐藏参数挖掘（桶二分/remove-diff） |
| `velric-agent probe-params <params_merged.json> <outdir>` | 参数差分（必填/开关识别） |
| `velric-agent waf-adapt <url> <payload> <outdir>` | payload 传输变形过 WAF |
| `velric-agent oob-confirm <url> <outdir> --payloads a,b` | OOB 回调确认（interactsh） |
| `velric-agent cors <baseUrl> <outdir>` | CORS 配置缺陷 |
| `velric-agent dom-sinks` / `analyze-gates` / `perm-tree` | DOM 污点 / 鉴权门静态分析 / 权限树重建 |
| `velric-agent pii-scan <recordRoot> <outdir>` | 录制流量 PII/凭据暴露扫描 |
| `velric-agent graphql-deep <endpoint> <outdir>` | GraphQL 内省 + schema |
| `velric-agent oidc-probe` / `smuggle-probe` / `ws-origin-check` | OIDC 配置 / 请求走私 / CSWSH |
| `velric-agent nuclei-lite <baseUrl> <outdir>` | 模板匹配（面板/泄漏） |
| `velric-agent backup-unpack` / `git-restore` / `sqlite-read` / `archive-recover` | 备份还原 / .git 源码还原 / SQLite 读取 / 归档恢复 |
| `velric-agent url-refine <outdir> --urls a,b` | URL 去重/漏洞模式分类（--action classify） |
| `velric-agent replay-tamper <recordRoot> <outdir> --rules-file JSON` | 录制流量篡改重放 |
| `velric-agent login-replay <url> <u> <p> <outdir>` | 登录 + cookie 导出 |

### 收尾
| 命令 | 用途 |
|------|------|
| `velric-agent gen-report <report.json> <outdir>` | findings 报告（markdown/CSV/SARIF） |
| `velric-agent save-evidence <items.json> <outdir>` | sha256 寻址证据 blob |
| `velric-agent run-diff <oldDir> <newDir>` | 两次 run 的面变更对比 |
| `velric-agent auto <seed> <outdir>` | 确定性全链管道（checkpoint 断点续跑） |
| `velric-agent auto-batch <seeds.txt> <outdir>` | 批量 + 汇总 |

### hunt 循环（宿主 agent 自主驱动）
| 命令 | 用途 |
|------|------|
| `velric-agent hunt-begin <goal> <outdir>` | 开 hunt（预算 --max-rounds/--max-cost） |
| `velric-agent hunt-record <outdir> --record-file F` | 写回观察（goals/facts/findings/assets；facts/findings 须有台账回执支撑——侦察命令加 `--run-id <hunt runId> --observation-ledger-root <outdir>` 才产生回执） |
| `velric-agent hunt-overview <outdir>` | 读态势 + 台账证据快照 |

## 门禁（不可绕过）

1. 观察台账反幻觉闸门：叙述的事实/PoC URL 必须来自台账真实记录，状态码一致，否则 drop
2. 响应状态码必须真实可见才可写入结论；软 404 页面不得当作命中
3. 所有输出到 report 的条目须带证据（文件/URL/状态码）
4. 诚实报告：各阶段数量、未覆盖模块、每条结论的来源（静态/运行时/合并）
5. secrets/dom-sinks/idor 类预筛结果 = 候选，不是实锤，须复核后才可升级结论

## 任务完成自检（声称完成前 MUST 通过）

- [ ] 每条结论都有产物文件 + 真实状态码支撑（不是"应该存在"）
- [ ] soft-404 校准后的命中才算命中；401/403 = 存在但受保护，不是漏洞
- [ ] 预筛类（secrets/idor/dom-sinks）结论标注"候选"，未当实锤
- [ ] WAF 在位时已降速降并发（fingerprint 命中 → --rps 全局限速）
