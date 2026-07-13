# GPT-5.6-Pro 独立审计交接说明 — CPA Cyber Abuse Guard v0.1.2 candidate

## 1. 结论前提

本项目是 CLIProxyAPI（CPA）的本地原生请求封控插件，不是上游安全策略的替代品。
当前源码仍是 **v0.1.2 候选工作树**，不得仅凭“功能已实现”、项目内回归语料或本说明
声称生产就绪。当前正式结论是 **RELEASE GATE FAIL / RELEASE BLOCKED**：方法学有效的
独立 v10 首次且唯一正式运行得到合法误报 28/320、恶意阻断 49/320、精确分类 33/320，
未达到门槛且已经消耗。不得创建 `v0.1.2` Tag、GitHub Release 或用于生产部署。
未来只有在新实现完成后，使用全新独立集合重新评审；不得重跑或复用 v10。即使未来全部
门禁通过，也不能保证上游账号永不被警告、限流、暂停或封禁。

状态约定：

- **已验证（开发工作树）**：有本地命令结果，但仍须在最终干净 Tag 上重跑；
- **历史证据**：不可用于批准本版本；
- **NOT CREATED / RELEASE BLOCKED**：因正式门禁失败而不得继续生成；
- **接受限制 / 未实现**：当前版本明确不提供，不能按文档设计视为已实现。

## 2. 项目与安全链路

目标矩阵是 CPA `v7.2.67`（commit
`2075f77c8ebe9ec872759965661936fb1ac2931f`）、CPA C ABI/RPC schema v1、
Linux amd64、glibc 2.34+；musl/Alpine 不受支持。

仓库根 `go.mod` 与当前开发/运行基线仍固定 CPA v7.2.67。独立模块
`integration/pluginstorecontract` 固定 v7.2.72，只用于调用官方
`pluginstore.InstallArchive` 与官方 Host Router 测试验证商店 ZIP、排序和回退契约；使用
合成不透明字节，不加载 `.so`，不能据此声称 CPA v7.2.72 宿主兼容、已部署或已完成集成。

```text
下游请求
  -> CPA ModelRouter（Provider/Auth Selector/Usage/上游之前）
     -> 放行：Handled=false，原请求继续 CPA 原生链路
     -> 阻断：Handled=true + TargetKind=self
        -> execute / execute_stream / count_tokens 返回策略 HTTP 403
        -> http_request 返回不支持 HTTP 405
        -> 不进入 Provider/Auth/Usage/真实上游
```

插件不重写模型名、客户端身份、System Prompt 或安全声明，不执行用户代码，不读取 CPA
Auth/OAuth 文件，不把 Prompt/Token/Cookie/OAuth/API Key 上传给远端分类器，也不抓取
公网媒体 URL。

## 3. 架构与入口

| 层 | 主要入口 | 审计重点 |
|---|---|---|
| C ABI 边界 | `cmd/cyber-abuse-guard/main.go` | 初始化/调用/释放/关闭、8 MiB no-copy 上限、panic recovery |
| 插件生命周期 | `internal/plugin/plugin.go` | 注册、热更新、原子 runtime、关闭并发、RPC 错误语义 |
| 路由与封控 | `internal/plugin/router.go` | 未知 SourceFormat、解析失败/截断/媒体、local self-route |
| 请求提取 | `internal/extract/` | 多协议 JSON、角色/Tool provenance、两层有界解码、资源上限 |
| 决策引擎 | `internal/classifier/` | 组合证据、上下文/角色边界、Balanced/Strict 阈值、性能 |
| 规则 | `rules/`、`internal/rules/` | 嵌入 ruleset `1.0.7`、版本/哈希一致性、无运行时下载 |
| 主体控制 | `internal/subject/` | HMAC 身份、衰减/Cooldown/Manual Block、容量与持久化表示 |
| 审计存储 | `internal/audit/` | 固定事件、SQLite schema v2、迁移/备份/查询/CSV 隐私 |
| 管理面 | `internal/plugin/management.go` | Management Key 边界、精确路由、输入上限与隐私响应 |
| 发布/运维 | `internal/buildinfo/`、`scripts/` | Tag-only、SBOM、严格验证、复现、Watchdog、Secret 生成 |

CPA 管理面只注册固定路径；普通下游 API Key 不能替代 Management Key。Blocked stream
选择真实 HTTP 403，而不是已建立的成功 SSE；这是 ABI v1 的明确取舍。

CPA 当前在调用插件管理处理器前由 `ServeManagementHTTP` 执行 `io.ReadAll`，因此插件的
1 MiB Body 限制和 2 MiB RPC Envelope 限制不是宿主 HTTP 内存上限。部署代理必须设置
请求体限制；Docker/Nginx 示例使用 `client_max_body_size 1m`，并要求服务器沙盒证明超限
请求在进入 CPA 前返回 413。

## 4. v0.1.1 → v0.1.2 主要修改

以下是源码实现状态，不是最终发布 PASS：

1. 增加 URL percent、HTML entity、可检查 Base64、文本 data URL、JSON escape、
   二次 Tool JSON 的有界解码；最多两层/八变体、编码源 128 KiB、解码合计 64 KiB；
   不解压、不展开归档、不联网。
2. image/audio/video 与普通截断分离，增加 `opaque_media_policy=block|audit|allow`
   及 mode 默认值；`allow` 只是未检查透传，不是安全结论。
3. 标准 OpenAI/Responses、Anthropic、Gemini 使用 system/user/assistant/tool provenance；
   逐段和相邻用户续接分析。Assistant refusal/policy restatement 不应算用户意图，但未受约束
   的后续指令必须重新分类。
4. 未知 SourceFormat 在 Strict 解释前本地阻断；Balanced/Audit/Observe 使用通用有界
   不可信文本提取器继续检查。计数器、最小事件和 Watchdog 差量用于发现新协议形态。
5. 嵌入 ruleset `1.0.7`，要求伤害意图、危险对象/影响与操作化、目标、规避或规模证据
   组合；“教育/CTF/已授权”标签不能洗白受保护的高风险操作。
6. RequestedModel 不再明文审计，而是 `sha256-model-v1:<64 hex>` 域分离摘要；
   SourceFormat 只保留 `openai|openai-response|claude|gemini|unknown`。历史读取、管理
   查询和 CSV 也执行相同净化。
7. SQLite schema v2 增加版本/历史和可选 HMAC-only Subject State；严格校验列、类型、
   顺序、约束、索引、单例版本行与迁移序列。迁移事务化；`VACUUM INTO` 备份经私有
   staging、0400、sync、no-overwrite hard link 发布并限制保留。
8. ModelRouter panic、大 RPC、解析边界和关闭竞态采用 mode-aware 本地处理；状态暴露
   readiness、router error、recovered panic、audit/HMAC/persistence degradation 与
   build/rules identity。CPA Host 的根本 fail-open 仍然存在。
9. HMAC 生成器拒绝覆盖、符号链接路径、错误 owner/mode；私有临时文件经同步和
   no-overwrite 发布，不打印密钥。Watchdog 只接受回环地址，校验身份/健康、本地探针和
   计数器差量，不访问 `/v1`。
10. 锁定 Go `1.26.4`、CycloneDX GoMod `v1.9.0`、govulncheck `v1.6.0`；增加
    clean-tag preflight、dirty 标记、严格 verifier/故障注入、SBOM、双 clone 复现、
    source tar.gz、最终 evidence 和 GitHub Tag workflow。

### 4.1 v10 之后的审计加固（2026-07-13）

当前 `agent/post-v10-production-hardening` 分支的本轮提示注入工作基于
`68ce0f662cbb034e61e1f3a8b91f50ea20c57637`，包含 v10 消耗之后的工程加固；这些修改
没有独立盲测结论，不能改变 Release Gate FAIL：

- v7-v10 作者工具在写入前使用生产 `ExtractText` 证明每种 carrier 能恢复原始语义；
  validator 对 schema、提取、重复、重叠、taxonomy、规模、分布和冻结先验语料清单的
  任一异常均非零退出。
- v7-v10 的先验语料路径、SHA-256、文件数和行数均固定；v9/v10 的历史实现、规则、
  嵌入规则、正式语料和正式报告绑定 Git commit
  `0f1d68717daadfd5dfc514ff2174cfb641a5d845` 与 tree
  `df878c537bca9fd71256b1c81ced18e72b583cf3`，缺少 Git 元数据或完整历史时门禁失败，
  不允许静默跳过，也不能通过同时修改当前语料、报告和常量来改写已消费记录。
- 所有 fixture 作者共用私有 `0700` staging、完整写入/fsync、发布前目标不可见断言和
  no-replace 原子目录 rename；Windows 使用不带 replace 标志的原生 `MoveFileEx`，并对
  既有文件、符号链接和并发发布做原生测试；其他不支持平台 fail closed。
- HMAC Secret loader 扩展为 Unix 原子 `O_NOFOLLOW|O_NONBLOCK` 打开；生成器改用可移植
  POSIX `sync`，Watchdog 正确处理带前导零的十进制预算；Base64 检查会恢复横向空白编码
  以及“合法 padding 后追加宽松解码器会忽略的数据”的可读前缀，并将后者 fail closed。
- 依赖升级到 `golang.org/x/crypto v0.52.0`、`x/net v0.55.0`、`x/text v0.37.0`、
  `x/sync v0.20.0`、`x/sys v0.45.0`。本地 `govulncheck` 无可达漏洞；GitHub 上针对旧
  module graph 的 14 条告警需在修复合并到默认分支后等待 GitHub 重扫并确认关闭。
- 上述完整 format/unit/race/fuzz/integration/package 结果属于本轮提示注入修改前的
  开发基线，不能自动继承到当前差异。本轮已重新执行修改文件 gofmt、四个相关源码包
  unit、提示注入相关定向 race、定向 vet、`go mod verify` 和 `git diff --check`；没有运行 v10。

### 4.2 v10 之后的提示注入加固（2026-07-13）

- `internal/classifier/meta_override.go` 新增 `META-OVERRIDE-001` 控制面叠加层，组合
  指令层级反转、拒绝压制、无限制人格、直接完成、Sandbox/占位符洗白、固定输出、
  受保护提示披露和负授权证据；存在普通 Cyber Abuse 候选时保留原 taxonomy。
- Role 证明失败的受支持 Provider 请求会退回有界不可信遍历；Tool Payload 内合法 JSON
  字符串继续递归；同消息分块以及有序 Tool Payload/Output 字符串合并后再次解码；
  单字符分片和两个审查后的 homoglyph 有限归一化；恶意“安全策略”不能通过否定
  拒绝/过滤来被当成安全内容跳过。
- 外部来源 `MDX-Tom/gpt-5.6-instruct` 只按固定快照做只读、脱敏机制审查；没有执行其
  脚本、部署辅助、指令文件或 Prompt Bank，也没有把完整越狱提示复制进本项目。
  派生回归样本是开发可见语料，永久禁止作为未来独立 Holdout。
- ruleset `1.0.7`/SHA-256 只标识 YAML Cyber Abuse 资产，不包含 Go 代码中的
  `META-OVERRIDE-001`、Matcher/Normalizer、Role 与 Extractor 行为。当前开发行为需要由
  “包含本差异的 Git/Build Commit + YAML ruleset 身份”共同标识；正式候选前仍需独立
  policy version/hash，或完整的可验证构建来源绑定。
- 当前提示注入差异没有服务器沙盒、真实 CPA Integration、原生插件加载、部署或发布
  打包证据。此前 CPA Integration PASS 是修改前基线，不能自动代表当前工作树。

### 4.3 Phase 0：CPA 商店与 Executor 契约（2026-07-14）

- 仓库根仍以 CPA v7.2.67 为开发基线；v7.2.72 只存在于隔离的
  `integration/pluginstorecontract` 源码契约模块，不构成宿主兼容声明。
- CPA 商店安装 ZIP 为
  `cyber-abuse-guard_<version>_linux_amd64.zip`，ZIP 根目录只允许一个版本化 `.so`；旧的
  `plugins/linux/amd64/...` 嵌套布局由官方 `InstallArchive` 契约测试明确拒绝。
- 文档、SBOM、构建元数据、报告和运维脚本位于独立
  `cyber-abuse-guard-v<version>-audit-bundle.zip`；该资料包不能交给 CPA 商店安装器。
- `executor.execute`、`executor.execute_stream`、`executor.count_tokens` 统一走策略 403；
  `executor.http_request` 保持 405 unsupported。
- 官方 installer/host 源码契约、合成商店包以及 executor 定向单测已 PASS；真实构建
  产物、audit bundle、四协议 403/Auth/Usage/Provider/Upstream 零调用仍必须以服务器
  沙盒输出补录。

## 5. 信任与威胁边界

受信任：固定版本 CPA Plugin Host、CPA Management Key 中间件、插件进程内代码、经运维
控制的配置/只读 Secret/本地目录。请求体、Header、Tool arguments、模型名、SourceFormat、
媒体和管理测试输入均不可信。

SQLite 本地写入者是重要例外：schema/type/hash/history 能发现结构损坏，但 v0.1.2 没有
keyed whole-snapshot MAC，因此删除一批仍合法的 Subject rows 无法与合法较小快照区分；
本地 DB 写入者在“持久化完整性”上仍被信任。

CPA Host 在插件未加载、注册失败、被 fuse、Router error、宿主接受有效 handled result
前发生 panic、target 无效/为空或 self executor not ready 时，可能继续其他 Router 或原生
路由。更高优先级 Router 若提前 Handle 也会绕过本插件；同优先级按插件 ID 升序。
插件只能覆盖已知错误和 active Balanced/Strict runtime 下的 recovered panic，无法从 ABI
v1 修改 Host 策略、枚举 Router 顺序或检查插件目录。`enforcement_ready` 只是插件内部
状态，不能证明宿主加载/注册、未 fuse、顺序有利或具体请求的 executor ready。

## 6. Holdout / Evaluation 方法学与证据

审计时不要读取、打印或逐条分析任何 Holdout/Evaluation JSONL；只核对冻结的聚合报告、
字节数与哈希。不得运行任何已消费集合的分类，不得使用行级结果调参。

| 代次 | 冻结状态 | 发布意义 |
|---|---|---|
| v1 | retired methodology-invalid diagnostic | 历史诊断，不能批准发布 |
| v2-v8 | `CONSUMED / FAIL` | 已消费失败，禁止重跑 |
| v9 | `CONSUMED / METHODOLOGY INVALID / FAIL` | 缺失固定 Taxonomy Enum 校验器，禁止重跑 |
| v10 | `CONSUMED / FAIL`，方法学有效 | 当前正式门禁失败，最终阻断发布 |

v10 使用 ruleset `1.0.7`，canonical embedded ruleset SHA-256 为
`7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134`。
首次且唯一正式运行仅输出聚合：合法误报 28/320（8.75%），恶意阻断 49/320
（15.31%），精确分类 33/320（10.31%）；四个关键类别门槛也全部失败。
`make holdout-test` 现在会立即拒绝再次分类 v10。完整聚合、哈希与快照身份见
`docs/reports/EVALUATION_V10_REPORT.md`；v1-v9 的历史报告保持冻结，不得改写。

## 7. 验证状态

修改前基线已验证（开发工作树候选证据）：unit/race/vet/fuzz、module/script/actionlint、普通 Corpus、
Round 4 Development Suite、benchmark、govulncheck、真实 CPA + Mock Upstream/Auth/Usage、
隐私、candidate package/verifier/fault checks。普通 Corpus 为 0/142 FP、154/154 recall/exact；
Round 4 为 64/64 恶意阻断、0/64 合法误报。这些非盲测工程结果不能覆盖 v10 的正式失败。

本轮提示注入差异已用锁定的 Go `1.26.4` 验证：修改文件 gofmt；
`go test -tags=sqlite_omit_load_extension ./internal/rules ./internal/extract ./internal/classifier ./internal/plugin -count=1`；
相同四包定向 `go vet`；`go mod verify`；`go mod tidy -diff`；`git diff --check`。
以上仅为源码级开发证据。
新增提示注入/提取/Router 回归用例的三包定向 `go test -race` 也已通过。
`SERVER SANDBOX VALIDATION: PENDING / NOT RUN`；当前差异的真实 CPA Integration、原生
加载、部署、正式 Holdout、正式打包、Tag 和 GitHub Release 均未运行或被禁止。

Phase 0 的 installer/host 源码契约、合成商店 ZIP 和 Executor 单测已通过；双 ZIP 真实
构建产物验证、四协议真实 HTTP 403/405，以及阻断时 Auth Selector、Provider、Usage、
Mock Upstream 零调用仍应以服务器沙盒实际输出补录。服务器沙盒仍为
`PENDING / NOT RUN`。

最终红线已经失败：v10 Release Gate FAIL。因此干净发布 Commit、Annotated Tag、GitHub
Release、正式产物发布和生产灰度均不得继续。未来评审必须来自新实现与全新独立集合。

未实现/接受限制：HMAC 双密钥轮换；持久化 whole-snapshot MAC；外部/本地模型分类器；
外部规则更新；挑战审批与管理 UI；媒体语义、任意编码/压缩/文档解析；Router 顺序/重复
`.so` 自动检测；可信远端地址；schema v2 原地降级；未来 CPA/ABI、musl、非 Linux/amd64。

## 8. 建议优先审计问题

1. Assistant/System safety framing 后接新指令是否仍可洗白，合法 continuation 是否误报。
2. Gemini `functionCall.args`、Anthropic `tool_use.input`、媒体字段乱序下 provenance 是否稳定。
3. 未知 SourceFormat 的通用扫描是否既不静默绕过，也不会把 metadata 大量误报。
4. audit 写入、legacy 读取、管理 API、CSV 是否都不回显明文 Model/任意 SourceFormat。
5. SQLite schema/迁移/备份发布是否有 TOCTOU、跨文件系统或崩溃一致性缺口。
6. register/reconfigure/route/shutdown/native panic 是否有 race、use-after-close 或死锁。
7. HMAC 生成器和运行时 Secret loader 的 symlink/owner/mode/并发/fsync 契约是否一致。
8. 发布脚本能否拒绝 dirty/tag mismatch、缺命令、归档 symlink、错误 ELF/ABI/glibc、
   rules/SBOM/hash 不一致；最终 evidence 是否避免自引用哈希。
9. v10 是否真正只输出聚合、绑定冻结实现与固定 Taxonomy Enum，已消费重跑是否被拒绝。
10. 真实 CPA 的 stream 403、blocked 零 Auth/Usage/Upstream、Management 401 与 rollback。
11. 商店 ZIP 是否根目录仅一个 `.so`，官方 v7.2.72 `InstallArchive` 是否验证安装路径、
    重复安装及旧嵌套布局拒绝；审计资料包是否始终与商店 ZIP 分离。
12. 未加载/注册失败/fused/router error/panic/无效 target/not-ready/优先级抢占时是否明确
    保留宿主 fail-open；同优先级 ID 升序是否有测试或部署核对。
13. Nginx `client_max_body_size 1m` 是否让超限 Management 请求在 CPA `io.ReadAll` 前
    返回 413，而不是只依赖插件 1 MiB/2 MiB 限制。

## 9. 建议命令

```bash
git status --short
git diff --check
git diff --stat 47d30451fa911fa5076b7b8023cc5e532deba25e..HEAD
git ls-files --stage 'scripts/*.sh'
make format-check git-diff-check module-verify
make test vet race fuzz-smoke script-test corpus-regression benchmark vulncheck

# Phase 0 源码级 CPA v7.2.72 store 契约；不加载 .so，也不证明宿主兼容：
make cpa-store-contract

# 只确认已消费保护：v10 会拒绝再次分类并返回非零。
make holdout-test

# 当前不得创建 v0.1.2 tag，也不得运行 formal-release。
# 未来只能在新实现 + 全新独立集合通过后重新建立发布候选。
```

产物复核建议：`sha256sum -c dist/checksums.txt`、`file`、`readelf -h -d -sW`、
`nm -D --defined-only`、`unzip -Z -l`，并从 GitHub Release 回下载后再校验一次。

## 10. GitHub 与最终字段

```text
repository: https://github.com/yujianwudi/cyber-abuse-guard
candidate_base_commit: 47d30451fa911fa5076b7b8023cc5e532deba25e
release_commit: NOT CREATED — RELEASE BLOCKED
annotated_tag: NOT CREATED — RELEASE BLOCKED
annotated_tag_object: NOT CREATED — RELEASE BLOCKED
tag_target_commit: NOT CREATED — RELEASE BLOCKED
github_actions_ci_run: candidate checks only; no approving tagged run
github_actions_release_run: NOT RUN — RELEASE BLOCKED
github_release_url: NOT CREATED — RELEASE BLOCKED
server_sandbox_validation: PENDING / NOT RUN
current_prompt_injection_integration: NOT RUN
root_cpa_development_baseline: v7.2.67
phase0_v7.2.72_scope: official installer and host-routing source contracts only
phase0_store_contract_result: PASS WITH SYNTHETIC ARTIFACT; REAL BUILD ARTIFACT PENDING
phase0_four_protocol_zero_call_matrix: SERVER SANDBOX PENDING / NOT RUN
release_decision: REJECT / FAIL
```

| 产物 | SHA-256 | 状态 |
|---|---|---|
| `cyber-abuse-guard-v0.1.2.so` | NOT CREATED | RELEASE BLOCKED |
| `cyber-abuse-guard_0.1.2_linux_amd64.zip`（CPA 商店 ZIP，根目录仅一个 `.so`） | NOT CREATED | RELEASE BLOCKED |
| `cyber-abuse-guard-v0.1.2-audit-bundle.zip`（独立资料包） | NOT CREATED | RELEASE BLOCKED |
| `cyber-abuse-guard-v0.1.2-source.tar.gz` | NOT CREATED | RELEASE BLOCKED |
| `build-metadata.json` | NOT CREATED | RELEASE BLOCKED |
| `ruleset-manifest.json` / `ruleset.sha256` | NOT CREATED | RELEASE BLOCKED |
| `sbom.cdx.json` | NOT CREATED | RELEASE BLOCKED |
| `release-test-summary.txt` | NOT CREATED | RELEASE BLOCKED |
| `release-evidence-final.md` | NOT CREATED | RELEASE BLOCKED |

最终应同时审阅 README、DESIGN、THREAT_MODEL、LIMITATIONS、INSTALL_DOCKER、全部冻结的
Holdout/Evaluation 聚合报告、测试/隐私/性能/CPA 报告与完整源码；不能只审二进制 ZIP，
也不能依据本说明推翻 v10 的正式失败结论。
