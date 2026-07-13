# CPA Cyber Abuse Guard

[![CI](https://github.com/yujianwudi/cyber-abuse-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/yujianwudi/cyber-abuse-guard/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.26.4-00ADD8?logo=go&logoColor=white)](go.mod)
[![Platform](https://img.shields.io/badge/platform-Linux%20amd64-lightgrey)](docs/LIMITATIONS.md)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-BLOCKED-critical)](docs/reports/RELEASE_EVIDENCE.md)

**面向 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)（CPA）的本地、
确定性、前置 Cyber Abuse 请求风控插件。**

[English](README.md) | 简体中文

> [!WARNING]
> 本仓库当前是**未发布的开发候选版本**。v0.1.2 的发布结论仍为
> **BLOCKED**；唯一方法学有效的 v10 正式评估为
> `CONSUMED / FAIL`；当前代码尚未完成服务器沙盒验证。不得创建 v0.1.2
> Tag 或 GitHub Release，也不得把当前候选部署到生产环境。

当 CPA 已加载并注册插件、Router 顺序能够到达本插件且自路由 Executor 已就绪时，
CPA Cyber Abuse Guard 会在 Provider 解析和账号认证调度之前检查受支持的模型请求。
它的目标是在本地拒绝明确的操作性 Cyber Abuse，同时尽量保留防御分析、漏洞修复、
事件响应、CTF/靶场和明确授权测试。请求内容只在进程内分析，不会发送到公网分类器。

## 当前状态

| 项目 | 当前状态 |
|---|---|
| 仓库状态 | v10 之后的未发布开发工作树；候选版本谱系为 v0.1.2 |
| 发布结论 | **BLOCKED / NOT PRODUCTION-READY** |
| 正式评估 | v10 `CONSUMED / FAIL`：合法误报 28/320、恶意阻断 49/320、精确分类 33/320 |
| 运行基线 | CPA `v7.2.67`，commit `2075f77c8ebe9ec872759965661936fb1ac2931f` |
| CPA v7.2.72 用途 | 仅用于隔离的源码契约测试；不声明宿主兼容 |
| 文档化构建目标 | Linux amd64、glibc 2.34 或更高、CPA C ABI/RPC schema v1 |
| 不支持平台 | musl/Alpine |
| 内置 YAML 规则集 | `1.0.7`，SHA-256 `7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134` |
| 当前验证 | 已有源码、CI 和 Phase 0 契约证据；仍需项目所有者执行服务器沙盒验证 |

仓库根 `go.mod` 仍固定在 CPA v7.2.67。
`integration/pluginstorecontract` 隔离模块单独固定 CPA v7.2.72，仅用于验证官方
源码契约。归档测试把不透明的合成插件字节交给 `pluginstore.InstallArchive`；
Host Router 测试运行 CPA 官方内存 Fake。两类测试都不加载本插件，也不能证明本项目
可运行在 CPA v7.2.72 宿主上。

## 这个项目是什么

- CPA 原生 `ModelRouter` 与本地自路由 Executor。
- 面向操作性 Cyber Abuse 证据的确定性、中英文规则分类器。
- 当 CPA 接受自路由且 Executor 已就绪时，可在 Provider、认证、Usage 和真实上游
  之前停止拒绝请求的前置控制。
- 带有有界 SQLite 持久化的隐私最小化审计与管理能力。
- 对测试证据、打包契约和可复现性保持明确边界的工程与审计项目。

## 这个项目不是什么

- 不是通用内容、NSFW、版权或软件许可审核器。
- 不是账号调度、额度管理、OAuth 管理、Provider 代理或 429 恢复组件。
- 不能替代上游平台自己的安全策略。
- 不能保证上游账号永不警告、永不限流、永不暂停或永不封禁。
- 不是远程 AI 分类器、遥测收集器、URL 抓取器、媒体扫描器或用户代码执行环境。
- 当前状态不是可投入生产的正式版本。

v10 之后的开发代码包含一个范围较窄的 `META-OVERRIDE-001` 控制面叠加层，用于
识别恶意指令层级反转和安全策略压制。强烈的独立控制面攻击当前可能被记录为
`defense_evasion`；这是开发态的已知范围扩展，不代表本插件已经成为完整的通用
模型安全过滤器。

## 工作链路

```text
下游请求
  -> CPA ModelRouter
    -> 放行：Handled=false
       -> 原始 CPA Provider/Auth/上游链路不变
    -> 阻断：Handled=true, TargetKind=self
       -> 如果 CPA 接受自路由且 Executor 就绪：
          -> execute / execute_stream / count_tokens 返回请求 HTTP 403 的
             RPC Error Envelope
          -> http_request 返回请求 HTTP 405 的 Unsupported Method Envelope
          -> 不进入 Provider 解析、Auth Selector、Usage 或真实上游
```

插件不改写请求模型、客户端身份、System Prompt、安全声明或被放行的请求内容；
不读取 CPA Auth/OAuth 文件；不伪装恶意意图；不执行请求携带的代码；也不把 Prompt
发送到辅助公网分类器。

## 检测范围

内置策略覆盖八类操作性 Cyber Abuse：

- 凭证窃取；
- 钓鱼；
- 恶意软件；
- 勒索软件；
- 漏洞利用；
- 数据外传；
- 服务破坏；
- 防御规避。

单个关键词不足以触发阻断。分类器会组合伤害意图、危险对象或影响，以及操作化、
真实目标、规避或规模证据。“教育”“CTF”“Benchmark”“已授权”等标签不能自动洗白
部署型滥用；明确的防御分析目的和非执行意图则可以保留合法安全工作。

源码提取器覆盖 OpenAI Chat、OpenAI Responses、Anthropic Claude 和 Google Gemini
请求结构。当前仓库具备这些路径的源码测试，但四协议真实 HTTP 行为和阻断后的零下游
调用矩阵仍需项目所有者在服务器沙盒验证。

文本处理有明确上限：

- 最多两层解码、八个唯一变体；
- 编码源最多 128 KiB，解码文本合计最多 64 KiB；
- 支持 URL Percent、HTML Entity、可检查 Base64、文本型 Data URL、JSON Escape
  和有界嵌套 Tool JSON；
- 不解压、不展开归档、不联网抓取，也没有跨请求语义记忆。

图片、音频、视频和文档附件属于不透明内容，可配置为 `block`、`audit` 或
`allow`。`allow` 只表示“未检查后放行”，不代表安全批准。

## 运行模式

| 模式 | 请求行为 | 事件行为 |
|---|---|---|
| `off` | 不提取、不分类、不阻断 | 不保存事件 |
| `observe` | 分类但永不阻断 | 只保留内存聚合 |
| `audit` | 分类但永不阻断 | SQLite 保存隐私最小化事件 |
| `balanced` | 阻断明确的操作性滥用 | 最小事件和主体控制 |
| `strict` | 使用更低的执行阈值 | 最保守；没有 Challenge 流程 |

这些模式只描述已经实现的行为，不构成部署授权。当前候选不得安装到生产环境。
[INSTALL_DOCKER.md](docs/INSTALL_DOCKER.md) 中的灰度、回滚与清理资料仅供未来
满足发布门禁的构建和受控服务器沙盒使用。

## 安全与隐私不变量

- 原始 Prompt、Messages、Tool Payload、Authorization Header、明文 API Key/IP、
  Cookie、OAuth Token、上传代码和上游账号身份不会写入审计库，也不会由管理接口返回。
- `audit.log_original_text: true` 会被拒绝，不存在 Debug 绕过开关。
- 稳定主体身份使用 HMAC；主体持久化可选、有容量上限，并要求稳定 Secret File。
- 永不抓取媒体 URL，也不把请求内容发送到公网分类服务。
- 审计、主体、查询、请求体、解码和 RPC 路径均有明确大小或容量限制。

CPA Host 边界仍存在插件无法消除的 Fail Open 条件：插件未加载、被 Fuse、Router
报错、在有效 Handled 结果被接收前 Panic、返回无效 Target，或自路由到宿主认为未就绪
的 Executor 时，CPA 可能继续其他 Router 或原生路由。更高优先级 Router 也可能先处理
请求；相同优先级按插件 ID 升序执行。

`loaded` 与 `enforcement_ready` 只表示 CPA 已经分派的管理回调所读取到的插件
内部状态，不能独立证明宿主发现并注册了插件、Router 顺序有利、插件未被 Fuse、
目录中不存在重复动态库，或某种请求格式的 Executor 已被宿主接受。运维人员必须单独
确认这些宿主条件。详见 [LIMITATIONS.md](docs/LIMITATIONS.md) 与
[THREAT_MODEL.md](docs/THREAT_MODEL.md)。

审计到的 CPA v7.2.72 Management 源码会在调用插件 Handler 前执行 `io.ReadAll`，
因此面向部署的反向代理必须自行限制 Body；服务器沙盒需证明超限请求在到达 CPA 前
收到 HTTP 413。

## 验证状态

| 证据 | 状态 |
|---|---|
| 根模块 Unit、Race、Vet、Fuzz Smoke、回归、构建与打包流程 | 已在 CI 实现 |
| CPA Store ZIP 命名、布局与安装源码契约 | 已使用 CPA v7.2.72 官方源码实现 |
| CPA Router 排序与回退源码契约 | 已使用 CPA v7.2.72 官方源码实现 |
| 本地 Executor 拒绝契约 | `execute`、`execute_stream`、`count_tokens` 的 RPC Error Envelope 请求 403；`http_request` 请求 405 |
| 当前差异的原生插件加载 | 未在本地执行 |
| OpenAI Chat / Responses / Claude / Gemini 服务器矩阵 | 需要服务器沙盒 |
| 阻断后 Auth Selector / Usage / Provider / 上游零调用 | 需要服务器沙盒 |
| 独立发布评估 | v10 已消耗且失败；必须使用全新未见盲集 |
| 生产发布 | 已阻断 |

Phase 0 证据和剩余服务器用例记录在
[PHASE0_CPA_CONTRACT.md](docs/reports/PHASE0_CPA_CONTRACT.md)。历史评估数据属于
冻结证据，不得重跑，也不得针对 v10 单条记录调参。

## 开发与审计检查

以下命令只进行源码检查，不部署 CPA，也不加载 `.so`：

```bash
make format-check git-diff-check module-verify
make test vet race fuzz-smoke corpus-regression
make script-test

# 明确的源码级 CPA v7.2.72 Store 与 Host 契约。
go -C integration/pluginstorecontract test ./... -count=1
```

发布工具链要求 Go `1.26.4`。Linux 原生构建、集成、SBOM、漏洞、产物和可复现性命令
见 [TEST_REPORT.md](docs/reports/TEST_REPORT.md) 与
[RELEASE_EVIDENCE.md](docs/reports/RELEASE_EVIDENCE.md)。

`make holdout-test` 不是普通开发检查。v10 已消耗，其门禁会主动拒绝重跑。
当前被阻断候选不得执行 `make formal-release`。

## 产物契约

开发态 CI 可以生成带 `-dirty` 后缀的证据产物；当前不存在正式 v0.1.2 发布产物。

| 产物 | 契约 |
|---|---|
| `cyber-abuse-guard_<version>_linux_amd64.zip` | CPA Store ZIP；根目录只能有一个普通可执行 `.so` |
| `cyber-abuse-guard-v<version>-audit-bundle.zip` | 独立的文档、元数据、SBOM、验证与运维资料包；不能交给 CPA Store 安装 |
| `cyber-abuse-guard-v<version>-source.tar.gz` | 源码审查/构建包；排除 `.git`，因此不能满足历史 Git 来源门禁 |

RAR 不是受支持的源码或二进制发布格式。

## 仓库结构

| 路径 | 用途 |
|---|---|
| `cmd/cyber-abuse-guard/` | 原生插件入口与 CPA ABI Bridge |
| `internal/classifier/` | 确定性策略评估与历史门禁 |
| `internal/extract/` | Provider 感知的有界请求提取与解码 |
| `internal/plugin/` | Router、Executor、管理接口、运行健康与热配置 |
| `internal/audit/` | 隐私最小化 SQLite 事件、迁移、保留和主体状态 |
| `rules/` | 内嵌、版本化的 YAML Cyber Abuse 规则资产 |
| `integration/` | CPA 集成与隔离的官方源码契约模块 |
| `scripts/` | 构建、打包、验证、可复现性、健康检查与发布工具 |
| `testdata/` | 回归与冻结评估证据；不是调参数据集 |
| `docs/` | 设计、运维、限制、威胁模型、审计交接与报告 |

本地被忽略的 `dist/`、`coverage.out`、数据库、日志和 Secret File 不属于仓库源码，
也不是正式发布证据。

## 文档入口

| 读者 | 建议入口 |
|---|---|
| 项目评估者 | [设计说明](docs/DESIGN.md)、[能力限制](docs/LIMITATIONS.md)、[威胁模型](docs/THREAT_MODEL.md) |
| 安全审计者 | [审计交接](docs/AUDIT_HANDOFF.md)、[发布证据](docs/reports/RELEASE_EVIDENCE.md)、[测试报告](docs/reports/TEST_REPORT.md) |
| CPA 集成人员 | [CPA 集成报告](docs/reports/CPA_INTEGRATION.md)、[Phase 0 契约](docs/reports/PHASE0_CPA_CONTRACT.md)、[Docker 运维](docs/INSTALL_DOCKER.md) |
| 策略审核人员 | [规则说明](docs/RULES.md)、[隐私报告](docs/reports/PRIVACY.md)、[提示注入复审](docs/reports/PROMPT_INJECTION_REVIEW.md) |
| 后续维护人员 | [下一版本建议](docs/NEXT_VERSION.md)、[变更记录](CHANGELOG.md) |

## 安全问题报告

请遵循 [SECURITY.md](SECURITY.md)。Issue 中不得包含真实凭证、私有 Prompt、OAuth
材料或生产账号标识。

## 许可证

[MIT](LICENSE)
