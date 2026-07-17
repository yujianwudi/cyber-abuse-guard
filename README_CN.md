# CPA Cyber Abuse Guard

[![CI](https://github.com/yujianwudi/cyber-abuse-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/yujianwudi/cyber-abuse-guard/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.26.4-00ADD8?logo=go&logoColor=white)](go.mod)
[![Platform](https://img.shields.io/badge/platform-Linux%20amd64-lightgrey)](docs/ROUND6_LIMITATIONS.md)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-BLOCKED-critical)](docs/ROUND6_DEVELOPMENT_HANDOFF.md)

**面向 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)（CPA）的本地、
确定性、前置 Cyber Abuse 请求风控插件。**

[English](README.md) | 简体中文

> [!WARNING]
> Round 6 目前只是开发候选，状态始终为
> **BLOCKED / PENDING HOST AND INDEPENDENT AUDIT**。它尚未合并到 `main`，
> 尚未创建 Round 6 Release，也不得部署到生产。本轮只接受 Linux amd64 CI
> 和授权 Linux 沙盒证据；Windows、macOS 构建与测试不在范围内。

当 CPA 已加载并注册插件、Router 顺序能够到达本插件且本地 Executor 已就绪时，
Guard 会在 Provider 选择、账号认证调度、用量记账和上游请求之前检查受支持的模型
请求。请求内容只在进程内判断，不发送给公网分类器。

## Round 6 当前状态

| 项目 | 状态 |
|---|---|
| 开发分支 | `agent/round6-long-text-streaming` |
| Round 5.2 基线 | `main@7a416df66a79218d73214084d4bf8a733268d894`，tree `63db7b7cb14a636f5ba9ff4453be4ebeef170b68` |
| 候选 commit/tree | 必须以最终 PR head 和 Linux CI `build-metadata.json` 为准；README 不自我声明尚未形成的未来身份 |
| 发布结论 | **BLOCKED / PENDING HOST AND INDEPENDENT AUDIT** |
| 合并与发布 | 未合并 `main`；没有 Round 6 Tag 或 Release |
| 验证平台 | 仅 Linux amd64；文档化构建目标为 glibc 2.34 或更高 |
| 不在范围 | Windows、macOS、musl/Alpine、本地部署、生产验证 |
| CPA Host 矩阵 | v7.2.81、v7.2.80 与 v7.2.79 真实 Host + Mock-upstream 均为 **NOT RUN / PENDING** |
| 生产环境 | 未登录、未修改；未读取生产请求、审计库、凭证、HMAC key，未连接真实账号池或 Provider |
| Scanner identity | `streaming-scanner-v1` |
| Classifier policy | `classifier-policy-v3` / `e67ca47a8f9c03b9ba42a417503e7969ee29421471454aa26c4306c8e7d4a97c` |
| 内嵌 YAML ruleset | `1.0.7` / `7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134` |
| 审计 schema | v3 |

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

Incomplete 请求不进入 subject risk。半截 prefix 不能在 `balanced` 下产生策略阻断。

## 默认有效上限

| 控制项 | 默认值 / 边界 |
|---|---|
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
- [CI 与阻断预发布门禁](docs/ROUND6_RELEASE_GATE.md)
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
- 审计、metrics 和 management status 只暴露固定字段、counter 与 identity，
  不暴露 prompt 片段或 offset。
- 永不抓取媒体 URL，也不执行请求携带的代码。
- Round 6 未连接真实 Provider 或账号池，未读取生产请求和生产审计数据。
- 未执行三个公开对抗仓库，也未重放其原始 payload。
- CPA 在插件未加载、Router fuse/error、更高优先级 Router、invalid target 或
  Host 不认可 Executor ready 等情况下仍可能 fail-open，因此真实 Host 验证不可省略。

Round 6 的受限数据事实披露见
[开发交接](docs/ROUND6_DEVELOPMENT_HANDOFF.md)。文档不会在发生过宽源码搜索和机械
build-tag 修改的前提下声称“完全零触及”，但没有使用受限 corpus payload 或生产数据
进行实现、调参或得出结论。

## 验证与发布门禁

| 门禁 | 当前状态 |
|---|---|
| Round 6 源码与回归实现 | 已在开发工作树中；最终结果取决于 exact-source Linux CI |
| Linux amd64 format/module/vet/vulnerability/script | 等待最终 Linux CI |
| Linux amd64 unit/race/fuzz/benchmark | 等待最终 Linux CI |
| 64 KiB 到接近 RPC 上限的长文本阶梯 | 已有测试覆盖；权威 Linux 结果待补 |
| CPA v7.2.81 Host + Mock upstream | **NOT RUN / PENDING** |
| CPA v7.2.80 Host + Mock upstream | **NOT RUN / PENDING** |
| CPA v7.2.79 Host + Mock upstream | **NOT RUN / PENDING** |
| 独立源码、产物和 Host 审计 | **NOT RUN / PENDING** |
| 合并 `main` | 阻断 |
| Round 6 Release | 阻断 |

Windows 和 macOS 有意不出现在本轮矩阵中。缺少它们不是 Linux-only 任务的失败，
也不得被描述成已有测试覆盖。

安全 Round 6 入口见
[ROUND6_RELEASE_GATE.md](docs/ROUND6_RELEASE_GATE.md)。不要用宽泛
`go test ./...` 或 `go vet ./...` 替换 allowlist 门禁，以免编译或打开已消费的
evaluation 包。

当前候选不得运行 `make formal-release`、`make release`、
`make holdout-test`、`make consumed-boundary-test` 或历史 release /
reproducibility 打包路径。

## 产物契约

未来即使获准生成开发产物，也只能是 Linux amd64 且保持阻断：

| 产物 | 契约 |
|---|---|
| `cyber-abuse-guard_<version>_linux_amd64.zip` | CPA Store ZIP；根目录恰好一个可执行 `.so` |
| `cyber-abuse-guard-v<version>-audit-bundle.zip` | 文档、metadata、SBOM、验证和运维证据；不可交给 Store 安装 |
| `cyber-abuse-guard-v<version>-source.tar.gz` | 源码审查包；不能单独证明 Git provenance |

Round 6 手动工作流必须保持 draft、prerelease、not latest，名称必须包含
`BLOCKED / PENDING HOST AND INDEPENDENT AUDIT`。只有 CPA 三个 Host 版本和独立审计都
提供明确 PASS，且仓库所有者另行授权 blocked prerelease 后，工作流才可进入发布步骤。
三份 Host 记录和独立审计必须引用同一个候选 Linux SO SHA-256；工作流会在附加重建产物
前立即重新计算并精确比对该哈希。

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
| `docs/` | 设计、迁移、限制、发布门禁、审计与运维资料 |

历史 Round 5.2 证据仍保留在
[AUDIT_HANDOFF.md](docs/AUDIT_HANDOFF.md)、
[TEST_REPORT.md](docs/reports/TEST_REPORT.md) 和
[RELEASE_EVIDENCE.md](docs/reports/RELEASE_EVIDENCE.md)，但不能验证 Round 6 候选。

## 安全问题报告

请遵循 [SECURITY.md](SECURITY.md)。Issue 中不得包含真实凭证、私有 prompt、
OAuth 材料、生产请求内容或账号标识。

## 许可证

[MIT](LICENSE)
