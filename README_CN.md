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
> `CONSUMED / FAIL`。CPA v7.2.72 真实 Host 自动化已通过授权 GitHub CI；里奥
> 独立复验仍未运行。不得创建 v0.1.2 Tag 或 GitHub Release，也不得把当前候选部署到
> 生产环境。

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
| 运行基线 | CPA `v7.2.72`，commit `6279bb8a4c2835ff6ed99c6b85083b2afbefa681`，C ABI/RPC schema v1 |
| CPA v7.2.72 校验 | module `h1:ppce0MLsz2xJi2yi3/A60zu03cM7bMWBAEJ6eC29E5Y=`；go.mod `h1:f4pcyAej8RoeRhIxJfm+OUMkCKaApiA8WzxR2XVlBh8=` |
| 文档化构建目标 | Linux amd64、glibc 2.34 或更高、CPA C ABI/RPC schema v1 |
| 不支持平台 | musl/Alpine |
| 内置 YAML 规则集 | `1.0.7`，SHA-256 `7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134` |
| 分类器策略身份 | `classifier-policy-v2`，SHA-256 `dc9a174099cb2f621e5333a508d4645604f96f470a6d9ae12a1acfb363d29cf2` |
| 当前验证 | Store 安装、`.so` 加载、四协议、零副作用与 15 场景多 Router Host 自动化均已 **GITHUB CI PASS**；里奥独立复验待运行 |

仓库根 `go.mod` 与 `integration/pluginstorecontract` 隔离模块都精确固定 CPA
v7.2.72。源码契约先列出并固定 16 个官方 Host 关键测试，再运行官方实现；额外 overlay
只向 checksum 已验证的临时 CPA 源码加入 `_test.go`，用于覆盖私有 fuse/panic/readiness
状态。黑盒自动化会通过官方 Store `InstallManifest` 安装真实 ZIP，加载真实 guard
`.so`，并使用纯 C 的第二 Router/executor 动态插件验证真实 Host 顺序与回退。该真实
加载路径只在 GitHub CI/指定隔离环境运行，不能由源码或 compile-only 结果冒充。

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

v10 之后的开发代码把 `META-OVERRIDE-001` 作为 wrapper/控制信号，而不是独立的
Cyber Abuse 类别。只有 wrapper 的文本可以放行或审计，但不能独立阻断，也不能凭空
生成 `defense_evasion`。只有已经建立底层危险行为时，wrapper 才能增强该候选，并且
不会替换原 taxonomy。本插件仍不是完整的通用模型安全过滤器。

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
          -> http_request 返回携带 405 的 Unsupported Method RPC Error；官方
             Adapter 返回 nil + status error，当前没有官方公开路由将其映射为最终客户端 405
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

非平凡结果可以携带隐私安全的 `BehaviorGraph`：它只记录稳定的请求者、动作、对象、
目标、去向、执行、凭证/访问、持久化、规避、外传、影响、规模、授权/防御范围、
wrapper/amplifier、角色范围、载体、组合方式和 reason code，不包含 Prompt 片段。

源码提取器覆盖 OpenAI Chat、OpenAI Responses、Anthropic Claude 和 Google Gemini
请求结构。真实 Host 自动化覆盖四协议安全请求的原生透传、恶意非流式/流式同步
403、流式 pre-SSE、Anthropic/Gemini token-count 403，以及每个本地
阻断请求的 Auth Selector、Provider executor、Usage queue、Mock Upstream 零副作用；
这些断言已在 Implementation Freeze 的授权 GitHub CI 中通过，里奥独立复验仍未运行。

已识别角色会把 System 安全策略和 Assistant 拒绝与 User 意图隔离。相邻 User 消息
以及一个显式关联的有界三轮计划可以组合；Provider 原生 Tool Payload 会独立扫描；
未知角色结构走保守回退。`<target>`、`${host}`、`VICTIM_IP` 等占位符只有在邻近文本
把它们绑定到危险对象或真实目标时才具有风险含义。

文本处理有明确上限：

- 最多两层解码、八个唯一变体；
- 编码源最多 128 KiB，解码文本合计最多 64 KiB；
- 支持 URL Percent、HTML Entity、可检查 Base64、文本型 Data URL、JSON Escape
  和有界嵌套 Tool JSON；
- 支持 Provider 感知的角色、Content Part、Tool Argument 和 Tool Output 载体；
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

只有 wrapper 的控制证据是普通 Strict 分数矩阵的明确例外：它始终保持
allow/observe/audit，不会直接成为 Cyber Abuse block；Strict 阻断仍要求先建立独立的
底层危险行为。

## 安全与隐私不变量

- 原始 Prompt、Messages、Tool Payload、Authorization Header、明文 API Key/IP、
  Cookie、OAuth Token、上传代码和上游账号身份不会写入审计库，也不会由管理接口返回。
- `audit.log_original_text: true` 会被拒绝，不存在 Debug 绕过开关。
- 稳定主体身份使用 HMAC；主体持久化可选、有容量上限，并要求稳定 Secret File。
- 永不抓取媒体 URL，也不把请求内容发送到公网分类服务。
- 审计、主体、查询、请求体、解码和 RPC 路径均有明确大小或容量限制。
- 认证状态接口同时暴露 YAML 规则集身份与完整分类器策略 version/hash，但不暴露请求文本。

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
| 根模块 Unit、Race、Vet、Fuzz Smoke、回归、构建、打包与可复现性流程 | Implementation Freeze `61536f9` 的 Push Run [29312969925](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29312969925) 和 PR Run [29312971717](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29312971717) 均 **GITHUB CI PASS** |
| 安全 Go 开发脚本 | `test`、`race`、`boundary` 已在审查修复前的实现树、WSL Ubuntu 26.04 / Go 1.26.4 **DEVELOPMENT SELF-CHECK PASS**；精确冻结覆盖由 GitHub CI 提供 |
| CPA Store ZIP 命名、布局与安装源码契约 | 已使用 CPA v7.2.72 官方源码实现 |
| CPA Router 排序与回退源码契约 | 已使用 CPA v7.2.72 官方源码实现 |
| 本地 Executor 拒绝契约 | `execute`、`execute_stream`、`count_tokens` 请求 403；`http_request` 只有 SOURCE/ADAPTER status-error 405（response=nil）检查 |
| Implementation Freeze 的原生插件加载 | **GITHUB CI PASS**：真实 Store ZIP 经 CPA v7.2.72 安装，已安装 `.so` 由 Host 加载 |
| OpenAI Chat / Responses / Claude / Gemini 服务器矩阵 | **GITHUB CI PASS**：allow、非流式/流式 403、pre-SSE、token-count 403 |
| 阻断后 Auth Selector / Usage / Provider / 上游零调用 | **GITHUB CI PASS** |
| 多 Router / fail-open 动态矩阵 | **GITHUB CI PASS**：15 个原生 Router 场景；panic/fuse 另由官方源码 overlay 覆盖 |
| `executor.http_request` 最终官方 CPA 客户端 HTTP 405 | **NOT AVAILABLE / NOT RUN**：`/v1/alpha/search` 是 provider-specific 路由，普通路径固定选择 `codex`，并把所有 Executor Error 映射为 502；当前没有官方路由把 Guard 的 405 Error 映射成最终 405 |
| 独立发布评估 | v10 已消耗且失败；必须使用全新未见盲集 |
| 生产发布 | 已阻断 |

曾在 WSL 中误执行以下三个未授权的本地目标：

```text
make cpa-router-fixture-blackbox
make cpa-v7272-host-blackbox
scripts/management-proxy-413-test.sh
```

它们只使用随机回环端口和 Mock 组件，没有连接真实 Provider 或生产服务，清理后没有残留
Fixture 进程。其唯一允许状态是：

```text
LOCAL MIS-EXECUTION RECORDED / EXCLUDED; NOT AUTHORITATIVE
```

这些本地结果绝不能写成交付 PASS。
上表中的授权 GitHub CI 是独立的远端证据；里奥独立验证仍未运行。

另有一次独立的方法学事件：三条作用域错误的 WSL 源码搜索命令意外输出了 retired
`testdata/holdout-v3` 的若干行。三次搜索均立即停止，输出内容未被分析，也未用于调参
或结论；evaluation v10 内容未被访问。retired holdout-v3 已不再具备独立证据资格，
该事件也独立使交接状态保持 `BLOCKED FOR HANDOFF`。

当前 v7.2.72 源码/原生证据边界记录在
[CPA_INTEGRATION.md](docs/reports/CPA_INTEGRATION.md) 与
[LEO_VERIFICATION_HANDOFF.md](docs/LEO_VERIFICATION_HANDOFF.md)。
[PHASE0_CPA_CONTRACT.md](docs/reports/PHASE0_CPA_CONTRACT.md) 只保留为历史 Phase 0
证据。历史评估数据不得重跑，也不得针对 v10 单条记录调参。

## 开发与审计检查

以下第一组命令只进行源码/安全开发检查，不部署 CPA、不加载 `.so`，也不打开已消费评估
样本：

```bash
make format-check git-diff-check module-verify
./scripts/go-safe-development-test.sh test
./scripts/go-safe-development-test.sh race
./scripts/go-safe-development-test.sh boundary
make vet fuzz-smoke corpus-regression script-test

# 可见的 development-only 对抗集；永远不能作为未来 Holdout。
go test ./cmd/development-adversarial-v11-prep-validator \
  -run '^TestDevelopmentAdversarialV11PrepCorpus$' -count=1

# 明确的源码级 CPA v7.2.72 Store 与 Host 契约。
go -C integration/pluginstorecontract test ./... -count=1
```

安全脚本是广泛 Go 门禁的唯一入口。`make unit-test`、`make race` 和
`make consumed-boundary-test` 已分别映射到这些安全模式；不得退回可能打开已消费评估
fixture 的广泛命令。

GitHub CI 的 Linux amd64 作业会运行以下目标，在临时目录构建并加载开发态 `.so`，
只连接随机端口的 Mock Upstream，不连接生产。本机仅做 compile-only/source-contract
检查时不要执行这些目标：

```bash
ALLOW_DIRTY_BUILD=1 make cpa-v7272-host-blackbox
ALLOW_DIRTY_BUILD=1 make cpa-router-fixture-blackbox
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
| `cmd/development-adversarial-v11-prep-validator/` | 可见 development-only 对抗集的严格校验器 |
| `internal/classifier/` | 确定性策略评估与历史门禁 |
| `internal/extract/` | Provider 感知的有界请求提取与解码 |
| `internal/plugin/` | Router、Executor、管理接口、运行健康与热配置 |
| `internal/audit/` | 隐私最小化 SQLite 事件、迁移、保留和主体状态 |
| `rules/` | 内嵌、版本化的 YAML Cyber Abuse 规则资产 |
| `integration/` | CPA 集成与隔离的官方源码契约模块 |
| `scripts/` | 构建、打包、验证、可复现性、健康检查与发布工具 |
| `testdata/` | 回归数据、明确标记的 development-only 对抗数据和冻结历史评估证据；开发数据永远不能成为未来 Holdout |
| `docs/` | 设计、运维、限制、威胁模型、审计交接与报告 |

本地被忽略的 `dist/`、`coverage.out`、数据库、日志和 Secret File 不属于仓库源码，
也不是正式发布证据。

## 文档入口

| 读者 | 建议入口 |
|---|---|
| 项目评估者 | [设计说明](docs/DESIGN.md)、[能力限制](docs/LIMITATIONS.md)、[威胁模型](docs/THREAT_MODEL.md) |
| 安全审计者 | [审计交接](docs/AUDIT_HANDOFF.md)、[发布证据](docs/reports/RELEASE_EVIDENCE.md)、[测试报告](docs/reports/TEST_REPORT.md) |
| CPA 集成人员 | [CPA 集成报告](docs/reports/CPA_INTEGRATION.md)、[Phase 0 契约](docs/reports/PHASE0_CPA_CONTRACT.md)、[Docker 运维](docs/INSTALL_DOCKER.md) |
| 策略审核人员 | [规则说明](docs/RULES.md)、[分类器重构基线](docs/reports/CLASSIFIER_REDESIGN_BASELINE.md)、[隐私报告](docs/reports/PRIVACY.md)、[提示注入复审](docs/reports/PROMPT_INJECTION_REVIEW.md) |
| 后续维护人员 | [下一版本建议](docs/NEXT_VERSION.md)、[变更记录](CHANGELOG.md) |

## 安全问题报告

请遵循 [SECURITY.md](SECURITY.md)。Issue 中不得包含真实凭证、私有 Prompt、OAuth
材料或生产账号标识。

## 许可证

[MIT](LICENSE)
