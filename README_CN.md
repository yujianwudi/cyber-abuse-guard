# CPA Cyber Abuse Guard

[![CI](https://github.com/yujianwudi/cyber-abuse-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/yujianwudi/cyber-abuse-guard/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.26.4-00ADD8?logo=go&logoColor=white)](go.mod)
[![Platform](https://img.shields.io/badge/platform-Linux%20amd64-lightgrey)](docs/ROUND6_LIMITATIONS.md)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Prerelease](https://img.shields.io/badge/prerelease-v0.15--rc.2-orange)](https://github.com/yujianwudi/cyber-abuse-guard/releases/tag/v0.15-rc.2)
[![Formal release](https://img.shields.io/badge/formal_v0.15-BLOCKED-critical)](docs/ROUND6_RELEASE_GATE.md)

**面向 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)（CPA）的本地、
确定性、前置 Cyber Abuse 请求风控插件。**

[English](README.md) | 简体中文

带资产的 [`v0.15-rc.2`](https://github.com/yujianwudi/cyber-abuse-guard/releases/tag/v0.15-rc.2)
已作为公开 Linux amd64 prerelease 发布，仅供所有者服务器沙盒验证。该版本通过直接
所有者覆盖发布，并明确标记 `TESTS_SKIPPED_BY_REQUEST`；它不是私有 Round 6
candidate、正式 `v0.15` 证据、CPA Host 兼容证明或生产部署授权。

> [!WARNING]
> 精确项目版本 `0.15` 与正式标签 `v0.15` 仍为
> **BLOCKED / PENDING HOST AND INDEPENDENT AUDIT**。`v0.15-rc.2` 的自动化测试套件和
> CPA Host 集成没有作为发行门禁。RC 源码提交的精确 main CI
> [29644688551](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29644688551)
> 在 CPA 最新源码兼容检查收到 HTTP 403 后失败，后续回归、单元测试、race、vet、构建与
> 可复现性步骤未执行。因此该 RC 必须视为 **SANDBOX ONLY**，真实 CPA Host 验证仍需在
> 所有者 Linux 服务器沙盒完成；Windows、macOS 构建与测试不在范围内。

当 CPA 已加载并注册插件、Router 顺序能够到达本插件且本地 Executor 已就绪时，
Guard 会在 Provider 选择、账号认证调度、用量记账和上游请求之前检查受支持的模型
请求。请求内容只在进程内判断，不发送给公网分类器。

## Round 6 当前状态

| 项目 | 状态 |
|---|---|
| 项目版本 / 预期正式标签 | `0.15` / 精确 `v0.15`（绝不使用 `v0.15.0`） |
| 当前公开 RC 源码 | `main@965c9bdef68a5ddcc954d5f86fae12a8854ec0e5`，tree `03ef0288998df799d620c6310d6f8c2e0351c2e8` |
| 清理前最后一个完整验证的 main 基线 | `6782dfaffd4da3f09604113c7d38675f331dc759`，tree `a8edbe2e6d19fa725fb962cdd6aaad5b416d4b85`；main CI [29630844605](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29630844605) 与标签 CI [29630926354](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29630926354) 已通过 |
| 发布结论 | **BLOCKED / PENDING HOST AND INDEPENDENT AUDIT** |
| 候选字节 | 必须由私有、无标签的 Actions 候选工作流从干净精确源码生成；干净不等于已发布 |
| 合并与发布 | Round 6 与后续发布工作流修复已合并；公开 `v0.15-rc.2` 已发布十项 Linux 沙盒资产，正式 `v0.15` 仍不存在且被阻断 |
| RC 发布模式 | `DIRECT_OWNER_OVERRIDE / TESTS_SKIPPED_BY_REQUEST`；精确 main CI 与 CPA Host 集成未作为发行门禁 |
| RC 源码提交 CI | [29644688551](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29644688551) 在 CPA 最新源码兼容请求收到 HTTP 403 后 **失败**；后续回归、测试、构建和可复现性步骤被跳过 |
| 验证平台 | 仅 Linux amd64；产物引用的数值型 GLIBC ABI 版本必须 `<= 2.34` |
| 不在范围 | Windows、macOS、musl/Alpine、本地部署、生产验证 |
| CPA Host 矩阵 | 当前验证与支持的发行目标固定为 CPA v7.2.88（`93d74a890a44802f656d7f39a573916b2611896e`）；所有者运行的隔离 Host + Mock-upstream 证据为 **NOT RUN / PENDING** |
| 生产环境 | 未登录、未修改；未读取生产请求、审计库、凭证、HMAC key，未连接真实账号池或 Provider |
| Scanner identity | `streaming-scanner-v1` |
| Classifier policy | `classifier-policy-v5` / `42d48af7a854b19d29c956a6f99b9027189ce4ae7b19a1d92a83955639d0916e` |
| 内嵌 YAML ruleset | `1.0.7` / `7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134` |
| 审计 schema | v3 |
| 代码复核 | 自动化审查仅作建议；不声称已获得独立批准 |

历史 v10 评估仍为 `CONSUMED / FAIL`，不得重跑或用于调参。工程检查通过不能
覆盖该方法学结论，也不能授权生产阻断。

## Round 6 做了什么

- 移除生产路径中的 `body[:max_scan_bytes]`；受支持的 JSON 会遍历完整
  CPA 可见结构。
- 将旧 `max_scan_bytes` 迁移为 classifier 保留窗口的兼容别名，不再表示
  “只检查前 256 KiB”。
- 新增有界 `max_total_text_bytes` 与
  `max_classification_chunks`，把累计覆盖量和峰值保留内存分开控制。
- 将 JSON 字符串、multipart 文本、role、provenance 和逻辑字段边界流式送入
  有界 classifier session。
- 在提交分类文本前事务式处理媒体、metadata、tool schema 与 role；未知或歧义
  role 不能冒充可信 user。
- 支持跨窗口匹配和有界 role-aware 组合，同时不保留完整 prompt。
- 审计 schema v3 新增 `decision`、`coverage`、
  `incomplete_reason`、`scanner`，并增加固定低基数 counters。
- envelope 或文本 coverage 一旦 incomplete，会清空所有 partial category、
  score、rule、evidence 和 behavior。

本轮没有启用“incomplete 下 verified local hard finding”窄例外。兼容 counter
仍保留，但预期始终为 0。

## 检查与处置契约

Envelope 完整性和文本 coverage 分开记录：

- `complete`：完整验证可见结构，并检查全部模型可见解码文本；
- `budget_exhausted`：达到累计文本或分类工作预算；
- `unavailable`：malformed、未知 schema/encoding、role 歧义或 RPC 边界导致
  无法证明完整覆盖。

| 模式 | 完整且有害的请求 | Incomplete inspection |
|---|---|---|
| `off` | 放行 | 放行 |
| `observe` | 仅观测 | 放行 + observe |
| `audit` | 仅审计 | 放行 + audit |
| `balanced` | 达到阈值时本地阻断 | 放行 + audit |
| `strict` | 达到 strict 阈值时本地阻断 | 本地阻断 + audit |

安全启动默认值为 `mode: observe` 和 `subject_control.enabled: false`。
Observe 只更新有界 counters：不阻断、不累计主体风险、不持久化逐请求 SQLite
event，也不会为审计关联而扫描完整请求 Body 计算哈希。

Incomplete 请求不进入 subject risk。半截 prefix 不能在 `balanced` 下产生策略阻断。
主体累计还要求显式的可信用户归因证明；未知/未来字段以及 system、assistant、tool
来源文本保留直接请求处置，但不能污染滚动主体风险状态。
嵌套 history/content 数组、provider content 数组中的标量成员，以及 Responses 未知或
非字符串 `type` 仍会接受扫描，但不能获得可信 user attribution；精确 Responses `type`
是传输层判别字段，不作为模型可见 prompt 文本。

启用 audit 后，来自非用户或不可信 wrapper 流量、完整且无 Cyber Abuse category 的
wrapper-only finding 默认只更新有界 `audited` 与 `control_plane_meta_override` counters，不写逐请求 SQLite event，也不计算
request/subject 关联哈希。只有需要逐请求关联时才设置 `audit.persist_wrapper_only: true`。
可信用户 wrapper finding、Cyber Abuse 基础行为、阻断、incomplete inspection 与
opaque-media 处置仍保留完整审计路径。

来自四个公开破限项目的仓库中性回归覆盖 Chat/Responses 的 system、developer、
assistant、tool、function/custom description、tool-call/output，以及 CPA v7.2.88
Codex Desktop 的 `additional_tools`。测试不加入仓库名签名，不复制完整第三方提示词，
并同时验证 1,397–17,166 解码字节长模板、16 KiB 边界、普通双用途安全请求与同身份干净后续请求。

## 默认有效上限

| 控制项 | 默认值 / 边界 |
|---|---|
| 运行模式 | `observe` |
| Subject control | 默认关闭，需显式启用 |
| CPA 可见 RPC envelope | 8 MiB |
| Classifier 保留窗口 | 旧别名默认 256 KiB；合法范围 16 KiB–1 MiB |
| 模型可见文本累计量 | 8 MiB |
| 逻辑文本字段 | 512 |
| 分类工作量 | 自动计算，最小 2048 chunks |
| JSON depth | 32 |
| 派生解码 | 最多 2 层、8 个 variants、128 KiB encoded source、64 KiB 累计保留 decoded text |

`text_bytes_scanned_total` 是累计量，可以大于 `max_scan_bytes`。峰值文本保留量
由有效窗口和固定 classifier state 控制。

如果密集 encoded 文本的派生 decoded view 超过 128 KiB encoded-source 上限，
检查仍会标记为 incomplete。这是明确保留的边界：长 plain text 可以流式扫描，但实现
不会对超限派生视图声称完整 coverage。

压缩后的 shadow planner 只保留封闭语义代表、短 marker 和有界 span metadata，
不再复制调用方可控的长 key 或长语义值。剩余分配仍会随 JSON token/node 与逻辑字段
数量增长，但受显式硬上限控制。alloc、RSS 与并发结果只以最终 Linux CI 和沙盒证据为准。

旧 `ExtractText` API 为源码兼容继续保留，并维持物化 `Parts` 的旧分段语义。
生产 Router 使用 streaming request API，不物化完整 prompt。

相关文档：

- [Streaming scanner 设计](docs/ROUND6_STREAMING_SCANNER_DESIGN.md)
- [配置迁移](docs/ROUND6_CONFIG_MIGRATION.md)
- [已知限制](docs/ROUND6_LIMITATIONS.md)
- [CI、候选构建与发行门禁](docs/ROUND6_RELEASE_GATE.md)
- [文档与工作流索引](docs/README.md)
- [开发交接](docs/ROUND6_DEVELOPMENT_HANDOFF.md)

## 支持的请求面

请求路径覆盖 OpenAI Chat、OpenAI Responses、Interactions、Anthropic Claude、
Google Gemini、OpenAI image/video profile、有界 `multipart/form-data`、
tool definition/payload、metadata 排除和 opaque media 分类。

图片、音频、视频和文档内容保持 opaque，不会解码、远程抓取或发送到其他服务。
Opaque media 的 `allow` 表示“未检查”，不表示“安全”。

确定性策略覆盖 credential theft、phishing、malware、ransomware、exploitation、
data exfiltration、service disruption 和 defense evasion。它不是通用内容审核器，
也不能替代上游 Provider 策略。

## 安全与隐私边界

- Guard 不持久化原始 prompt、tool payload、Authorization header、明文凭证、
  上传代码或 Provider 账号身份。
- 这只是 Guard 本地边界，不是端到端 Host 保证。CPA 可能临时 spool 非 multipart
  请求体，并可能在 Host HTTP 错误日志中持久化原始 body；见
  [决策输出与隐私](docs/RULES.md#decision-output-and-privacy)。
- 审计、metrics 和 management status 只暴露固定字段、counter 与 identity，
  不暴露 prompt 片段或 offset。
- 永不抓取媒体 URL，也不执行请求携带的代码。
- Round 6 未连接真实 Provider 或账号池，未读取生产请求和生产审计数据。
- 未执行四个公开对抗仓库，也未重放其原始 payload。
- CPA 在插件未加载、Router fuse/error、更高优先级 Router、invalid target 或
  Host 不认可 Executor ready 等情况下仍可能 fail-open，因此真实 Host 验证不可省略。

Round 6 的受限数据事实披露见
[开发交接](docs/ROUND6_DEVELOPMENT_HANDOFF.md)。文档不会在发生过宽源码搜索和机械
build-tag 修改的前提下声称“完全零触及”，但没有使用受限 corpus payload 或生产数据
进行实现、调参或得出结论。

## 验证与发布门禁

| 门禁 | 当前状态 |
|---|---|
| Round 6 实现 PR | [PR #9](https://github.com/yujianwudi/cyber-abuse-guard/pull/9) 已合并；其 PR runner 因已记录的 GitHub Billing 限制没有启动，因此不声称 PR CI PASS |
| 清理前最后一个完整验证的 `main` Push CI | [29630844605](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29630844605) 对 `6782dfa` / tree `a8edbe2` **SUCCESS** |
| RC 源码精确 main CI | [29644688551](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29644688551) 在 CPA 最新源码检查遇到 HTTP 403 后 **FAILED**；明确未作为 RC 发行门禁 |
| 源码预发行 `v0.15-rc.1` 标签 CI | [29630926354](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29630926354) 对 `6782dfa` / tree `a8edbe2` **SUCCESS** |
| 私有无标签干净候选 Actions 产物 | **NOT CREATED / PENDING**；必须绑定最终 commit/tree 并生成 `candidate-manifest.json` |
| CPA v7.2.88 Host + Mock upstream | **NOT RUN / PENDING** |
| 独立源码、产物和 Host 审计 | **NOT RUN / PENDING** |
| 与候选绑定的外部 evaluation-v11 或更高 | **NOT RUN / PENDING**；必须是该精确候选首次且唯一的 `CONSUMED / PASS` |
| 注解标签 `v0.15-dev.round6[.N]` 预发行 | 可选；Host、独立审计、候选级评估通过前阻断，且永远不是正式发行 |
| 公开源码预发行 `v0.15-rc.1` | 已存在但没有附加资产；不是私有候选、Host 证据或正式发行 |
| 带资产预发行 `v0.15-rc.2` | **PUBLIC / PRERELEASE / SANDBOX ONLY**；通过直接所有者覆盖发布十项 Linux amd64 资产并按要求跳过测试；不是候选、Host、正式或生产证据 |
| 注解标签 `v0.15` 与已验证 draft | 阻断 |
| 受保护地发布未变化 draft | 阻断 |

Windows 和 macOS 有意不出现在本轮矩阵中。缺少它们不是 Linux-only 任务的失败，
也不得被描述成已有测试覆盖。

安全 Round 6 入口见
[ROUND6_RELEASE_GATE.md](docs/ROUND6_RELEASE_GATE.md)。不要用宽泛
`go test ./...` 或 `go vet ./...` 替换 allowlist 门禁，以免编译或打开已消费的
evaluation 包。

不得创建 `v0.15`、运行正式发行路径、重跑已消费 v10，或把历史资产当作当前证据。
Candidate workflow 必须先存在于默认分支，因此只能在最终 PR 合并到 `main` 且精确
main Push CI 通过后，从 `main` 手动 dispatch。

## 产物契约

v0.15 证据链刻意拆分：

1. 冻结最终 PR head、通过 PR CI、合并到 `main`，并让合并后精确 main commit/tree
   的 Push CI 通过。合并只是 candidate 前置条件，不是部署或发行批准。
2. 从 `main` 手动 dispatch 私有、**无标签**的 GitHub Actions 运行，从干净精确源码生成 Linux amd64
   候选字节；该 Actions artifact 不是 GitHub Release，且会过期。
3. CPA v7.2.88 Host + Mock 记录、独立审计，以及与候选
   绑定的外部 `evaluation-v11` 或更高 `CONSUMED / PASS` 报告，必须绑定同一候选身份。
   Host 身份和证据哈希通过 attestation schema v2 的 `cpa_version`、
   `cpa_commit`、`cpa_host_sha256` 字段传递。
4. 如需持久开发交接，上述门禁通过后，可使用既有注解标签
   `v0.15-dev.round6`（或数字后缀）创建 draft prerelease；它仍是
   `BLOCKED / NOT A FORMAL RELEASE`。
5. 只有该候选级外部评估 attestation 才能准入注解正式标签 `v0.15`。正式工作流
   重建并逐字节比对 Host 已测候选，生成
   `formal-release-attestation.json` 并创建 draft 正式 Release；另一个受保护 promotion
   步骤才发布这份未变化的 draft。

私有候选包含 `cyber-abuse-guard-v0.15.so`、sidecar、
`cyber-abuse-guard_0.15_linux_amd64.zip`、metadata、checksums、ruleset identity、
SBOM 与 `candidate-manifest.json`。Store ZIP 根目录恰好一个 `.so`。Audit bundle 与
source archive 只属于后续正式发行路径。候选字节即使干净，也仍未发布且不授权部署。
正式 source / audit bundle 必须排除 evaluation、Holdout、private、blind、retired
资料，只携带允许公开的低敏 attestation 身份与哈希。

源码树刻意不自我回填未来 Host/审计 PASS 哈希、Merge 身份或 Release 状态。稳定版
v0.15 是否具备资格，只能由外部 Round 6 / formal attestation 资产判定；这些资产必须绑定
最终源码、候选工作流运行、候选字节、Host 记录、独立审计与发行评估。

当前发行与 Host 验证固定为 CPA v7.2.88 / `93d74a890a44802f656d7f39a573916b2611896e`。
后续上游 CPA 版本不会自动改变受支持、已验证或可准入发行的目标。
旧版本专用测试 profile 与 Make 别名已经删除；
更早的观察仅作为不可执行的历史记录保留，不属于当前发行或 Host 证据。

历史 evaluation-v10 始终为 `CONSUMED / FAIL`，不得重跑，也不得作为 formal build 输入。

中立源码策略见 [RELEASE_POLICY.md](docs/RELEASE_POLICY.md)。外部决策记录为
`round6-prerelease-attestation.json` 与 `formal-release-attestation.json`；源码树不会预先
把它们写成未来 PASS。

## 仓库结构

| 路径 | 用途 |
|---|---|
| `cmd/cyber-abuse-guard/` | 原生插件入口和 CPA ABI bridge |
| `internal/classifier/` | 确定性策略和 streaming classifier |
| `internal/extract/` | 事务式请求遍历、流式文本回放、解码、role、multipart 与媒体处理 |
| `internal/plugin/` | Router、Executor、disposition、management、health 与 reconfigure |
| `internal/audit/` | 隐私最小化 SQLite event、schema migration、retention 与 subject state |
| `integration/` | CPA 源码/编译与 Host 契约模块 |
| `scripts/` | 安全门禁、Linux 构建、打包、验证和可复现工具 |
| [`docs/README.md`](docs/README.md) | 架构、运维、策略、当前发行交接与历史报告的文档索引 |

历史 Round 5.2 证据仍保留在
[AUDIT_HANDOFF.md](docs/AUDIT_HANDOFF.md)、
[TEST_REPORT.md](docs/reports/TEST_REPORT.md) 和
[RELEASE_EVIDENCE.md](docs/reports/RELEASE_EVIDENCE.md)，但不能验证 Round 6 候选。

## 安全问题报告

请遵循 [SECURITY.md](SECURITY.md)。Issue 中不得包含真实凭证、私有 prompt、
OAuth 材料、生产请求内容或账号标识。

## 许可证

[MIT](LICENSE)
