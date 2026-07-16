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
> 本源码树承载 **round5.2 source-freeze / pre-merge record**。它只记录可在合并前固定的
> 证据：源码身份、安全本地门禁、精确源码 Branch Push CI、PR 临时 Merge Result 门禁与
> 复核状态。合并后的 main CI、exact-main artifact、Tag、Release Flags 与发行资产哈希，
> 只能以 GitHub API metadata 为权威外部证据；对应 Release notes 负责链接这些记录、列出
> 逐资产哈希并保留全部未完成门禁。历史预发行
> `v0.1.2-dev.round5.1` 已标注 `BLOCKED / NOT FOR DEPLOYMENT`，其 Tag 固定指向
> `89b62b341278073e7b6518b85e41cd7f7c6b682c`，不得移动或复用。稳定版 v0.1.2 的发布
> 结论仍为 **BLOCKED**；唯一方法学有效的 v10 正式评估仍为 `CONSUMED / FAIL`。
> 不得把任一候选部署到生产环境。工程门禁成功不构成生产准入，已记录的方法学事件
> 仍会独立使交接保持阻断。

当 CPA 已加载并注册插件、Router 顺序能够到达本插件且自路由 Executor 已就绪时，
CPA Cyber Abuse Guard 会在 Provider 解析和账号认证调度之前检查受支持的模型请求。
它的目标是在本地拒绝明确的操作性 Cyber Abuse，同时尽量保留防御分析、漏洞修复、
事件响应、CTF/靶场和明确授权测试。请求内容只在进程内分析，不会发送到公网分类器。

## 当前状态

| 项目 | 当前状态 |
|---|---|
| 仓库状态 | `agent/post-release-reaudit-fixes` 上的 round5.2 source-freeze/pre-merge record；实现/源码冻结为 `170de7f324c2bdf9a473b1866bdfc1e097182301`，基于历史 `main@89b62b341278073e7b6518b85e41cd7f7c6b682c` |
| 发布结论 | **BLOCKED / NOT PRODUCTION-READY** |
| 正式评估 | v10 `CONSUMED / FAIL`：合法误报 28/320、恶意阻断 49/320、精确分类 33/320 |
| 历史开发预发行 | [`v0.1.2-dev.round5.1`](https://github.com/yujianwudi/cyber-abuse-guard/releases/tag/v0.1.2-dev.round5.1)，`prerelease=true`、`latest=false`、Tag 指向 `89b62b341278073e7b6518b85e41cd7f7c6b682c`；项目约定为历史快照，但 GitHub 报告 `isImmutable=false`，不是生产批准 |
| Round5.2 合并前证据 | Source freeze `170de7f324c2bdf9a473b1866bdfc1e097182301`、安全本地门禁、CPA 最新兼容检查、[Push CI 29467936241](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29467936241) 与 [PR CI 29467938359](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29467938359) 均 **PASS**；PR 临时 merge SHA 为 `fc8b5649505662e47bedbd85a41fbea306a2df7c`，两次 Run 的三个 Job 全绿；CodeRabbit CLI `0.6.5` 对最终源码 delta 为 0 issues，GitHub 检查通过 |
| Round5.2 合并后证据 | Main CI、exact-main artifact、Tag、Release Flags 与发行资产哈希为 **EXTERNAL EVIDENCE — GITHUB API METADATA + LINKED RELEASE NOTES** |
| 运行基线 | CPA `v7.2.75`，commit `e57416731aec87051ac00d0812df6aebd0e9d57a`，C ABI/RPC schema v1 |
| CPA v7.2.75 校验 | module `h1:WcCCeENtQ5F2bT86FVIOZJJbWCkPqrp3idl8kyZqARM=`；go.mod `h1:f4pcyAej8RoeRhIxJfm+OUMkCKaApiA8WzxR2XVlBh8=` |
| 最新 CPA 源码/编译兼容门禁 | CPA `v7.2.80`，commit `09da52ad509e2c18e7b9540db3b98c2214c280aa`；module `h1:QIa5T/KYvJACHVPPRzXcRwq/HLpbwWYJYpZAC1eY2WA=`；go.mod `h1:ytvZNWbCv7PrAyR80+RKsDJPODsdL6qxyFaXDBNZdqs=`；`CPA_LATEST_VERIFY_REMOTE=1 make cpa-latest-compat` 已验证 `releases/latest` 与 Tag→Commit；固定校验和、compile-only、Router、上游 CPA 源码级 Host/Interactions 测试包与 checksum 固定 overlay 已在本地及精确源码 Push/PR CI 通过；未启动 Host 或加载 `.so` |
| 文档化构建目标 | Linux amd64、glibc 2.34 或更高、CPA C ABI/RPC schema v1 |
| 不支持平台 | musl/Alpine |
| 内置 YAML 规则集 | `1.0.7`，SHA-256 `7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134` |
| Round5.2 source-bound 分类器策略身份 | `classifier-policy-v2`，SHA-256 `e9b87f7e2635495bdbceae469ef89e696b419f0a9a6fd129558a20bc4be947ec`；精确 source-freeze Commit 是单独的合并前字段 |
| Round5.2 反审阻断项 | 开发自检已关闭分类反转/性能缺陷、Balanced proof-budget 降级、大请求顶层 Tool Definition 漏扫和原生 `interactions` 格式注册缺失；精确源码 Push/PR CI 已通过 |
| 历史 round5.1 分类器策略身份 | `classifier-policy-v2`，SHA-256 `c2092d0949fcaa1d0f085dfe31a668d45cc4d14efc10427d0f3ebcf3e821a112` |
| Round5.2 source-freeze 验证 | 本地安全门禁、精确 Freeze `170de7f324c2bdf9a473b1866bdfc1e097182301`、Push CI `29467936241`、PR CI `29467938359` 与 CodeRabbit 均 **PASS**；真实 Host 与独立复核仍为 **NOT RUN**，所以交接与生产仍阻断。下方 round5.1 证据仅作历史记录，不得作为 round5.2 的验证。 |

## 第五轮边界与复核状态

- Router 只能看到 CPA 交给它的请求。它不能证明请求进入 CPA 前由本地
  `model_instructions_file`、`AGENTS.md`、远程指令模板或其他高优先级配置加载的内容，
  也看不到这些文件的路径、owner、mode、SHA-256/签名与 reload 历史。宿主必须实施
  路径白名单、owner/mode 校验、哈希或签名绑定、每次 reload 前复核及固定变更审计。
- `safetySettings`、`generationConfig`、`options` 等 Provider 控制字段不是普通 Prompt
  文本，不能依赖关键词扫描。宿主必须使用版本化 schema allowlist，并在进入 Router
  前拒绝或强制覆盖不安全值。
- 第五轮唯一的 key-only 映射只在已确认的 tool/tool-payload 对象内，由
  `cag_control_schema=meta_override_control/v1` 显式启用；相同字段出现在 Tool 来源之外
  不会启用语义映射，普通业务 JSON Key 也绝不会被提升为 Prompt 文本。
- 内置规则集 `1.0.7` 只标识 YAML Cyber Abuse 资产，**不包含** Go 代码中的
  `META-OVERRIDE-001` overlay、提取语义、Tool Schema 映射或 control-plane 遥测；交接
  时必须同时绑定 classifier-policy identity 与精确 Git Commit。
- 可见的 `development-public-jailbreak-patterns-v1` 现有 36 条净化用例（18 allow / 18
  audit）、5 种协议、13 种载体、19 种变换和 5 个抽象来源上下文；新增证据覆盖
  system/developer/tool 混合组合、本地指令与受管 `AGENTS`、Skill/MCP、语义别名、
  隐藏覆盖、边界分段续写、HTML 注释模块及长无害填充。它不含 live payload，且
  永久不得用于未来 Blind Holdout。`source_context` 只是开发测试元数据，不能证明
  运行时文本来自某个仓库或本地文件。
- 普通 CI 不再调用任何 evaluation-v10 边界目标。`consumed-boundary-test` 仅保留为
  需要单独授权的人工审计目标，不属于日常开发或 CI 门禁。
- 角色感知分类器不会把 System/Assistant 文本中的 base Cyber Abuse taxonomy 与后续
  User 消息合并。这能避免把 Provider 安全策略示例或拒绝内容误归因给用户，但也意味着
  宿主必须在请求进入 CPA 前验证所有高优先级指令来源，并强制检查 owner、mode、
  hash/签名及 reload 策略。
- 当前 `Segments` 仍在主提取 walk 之后执行第二次有界 JSON 解析。Differential、race、
  fuzz 与标量媒体测试尚未复现语义泄漏，但后续应让 Parts 与 Segments 复用同一份单次
  语义解析产物，以消除双解析漂移风险。
- Base 到 Freeze 之间只有一个第五轮综合实现 Commit。修复后的精确回归均为绿色，但没有
  独立保留修复前红测 Commit 或命令日志；任务书要求的“两个 HIGH 修复前为红”仍需独立
  审计确认，不能根据最终绿测反推。
- 本轮复核期间，一条范围过宽的只读 `git grep` 意外输出了受限
  `testdata/holdout/malicious-operational.jsonl` 的内容。没有运行 holdout 测试，输出没有
  重定向、复制进源码/测试/文档、分析，也没有用于调参或结论。后续发行审计中，一次
  classifier 源码搜索又意外匹配了历史 holdout gate-test 源码行；该搜索没有打开任何
  `testdata` 语料、没有运行 holdout/evaluation 测试，输出也没有用于实现判断。其余命令
  均明确排除 holdout/evaluation 路径。因此本轮不能声明“完全未访问受限语料”，且这些
  事件独立使交接保持阻断。
- 发行后的 round5.2 复审中，一次大小写不敏感的路径排除失效，只读状态搜索分别从
  `EVALUATION_V5_REPORT.md` 到 `EVALUATION_V10_REPORT.md` 各输出了恰好一行状态。
  没有打开或输出任何评估语料、样本行，也没有对其进行分类、提取，或据此作出源码、
  测试、文档或发行决策。该新增披露不改变冻结的 v10 `CONSUMED / FAIL`，并继续使
  方法学交接保持阻断。
- 同一轮复审中，classifier 子代理误启动了 `go test -shuffle=on -count=20 ./...`。主线程在
  进程运行约 23 秒时立即中断，并向 PID `265343` 发送 `TERM`；随后同一命令又以 PID
  `266741` 出现，其父进程为 WSL `/init`，与孤立的 CodeRabbit/工具会话一致。主线程再次
  interrupt classifier agent，终止所有匹配进程，并复查确认无残留。目前无法确认终止前
  是否有 consumed evaluation 或 Holdout 测试被选择、是否读取了受限 fixture。该命令及
  所有部分结果永久排除，未用于源码、测试、文档或发行决策；后续验证只允许显式 safe
  allowlist。本轮不得声明未访问受限内容；v10 仍为 `CONSUMED / FAIL`，交接继续阻断。
- 最终独立 diff 审计期间，一条过宽的只读 `cmd/**/*.go` 搜索打印了部分
  evaluation/holdout author 源码片段和少量合成示例；没有打开受限 `testdata` 语料、
  没有运行 author/evaluation/holdout 工具，也没有把输出用于实现、测试、文档或发行
  结论。该输出永久排除，本次新增披露继续使方法学声明保持阻断。

仓库根 `go.mod` 与 `integration/pluginstorecontract` 隔离模块都精确固定 CPA
v7.2.75。源码契约先列出并固定 16 个官方 Host 关键测试，再运行官方实现；额外 overlay
只向 checksum 已验证的临时 CPA 源码加入 `_test.go`，用于覆盖私有 fuse/panic/readiness
状态。黑盒自动化会通过官方 Store `InstallManifest` 安装真实 ZIP，加载真实 guard
`.so`，并使用纯 C 的第二 Router/executor 动态插件验证真实 Host 顺序与回退。该真实
加载路径只允许由显式 Host Target 在获授权的腾讯云隔离环境运行，普通 CI 不调用，且
不能由源码或 compile-only 结果冒充；本轮精确源码 Push CI、PR Merge Validation 与
canonical artifact 已记录，但
CPA v7.2.75 Host 和独立复核仍未运行。

独立的 `integration/cpalatestcontract` 模块与 `scripts/cpa-latest-compat.sh` 在不改变
上述运行基线的前提下，固定 CPA v7.2.80。它们通过临时 modfile 编译 Guard 与
integration 包，运行真实 Guard registration/role-routing 探针，列出并执行 17 个官方
Host routing/status 测试和 11 个官方 Interactions route/handler 测试，并只向临时官方
源码副本加入三个 checksum 固定的 overlay：Host fail-open、Interactions
handler/translator 与 direct executor-format。该门禁只证明源码/编译兼容；它不会启动
CPA、加载 Guard `.so`、执行 Store 安装，也不证明 v7.2.80 下的端到端请求重建或上游
隔离行为。

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

请求检查覆盖 OpenAI Chat、OpenAI Responses、CPA Interactions、Anthropic Claude、Google Gemini 和
OpenAI 图片请求结构。JSON object 的成员顺序不影响媒体语义：歧义 payload 只在有界
事务候选中暂存，后置媒体标记会丢弃候选；最终非媒体对象才把候选提交为正文。该规则
同时用于 `Parts` 与 `Segments`，但 Tool Payload 中的 `data` 始终可检查。JSON 与有界
`multipart/form-data` 通过统一的 Content-Type 入口处理；multipart 按 SourceFormat
profile 工作。`openai-image` 只把 `prompt` 与三种 `negative_prompt` 拼写视为正文；未知
非文件字段产生固定 schema incomplete，不进入分类器。图片、音频、视频和文件 part 只
标记为不透明媒体，不会转成分类文本。此前四协议真实 Host 的透传、同步 403、pre-SSE 和
零下游副作用矩阵是 Implementation Freeze `61536f9` 的历史 CPA v7.2.72 CI 证据。
历史 round5.1 已以 `89b62b341278073e7b6518b85e41cd7f7c6b682c` 合并，并具有精确 main CI
与静态核验的 dirty 开发 artifact，但仍没有 CPA v7.2.75 真实 Host 或独立隔离复验。
Round5.2 的 source-freeze 与合并前证据记录在本源码树；合并后证据记录在 GitHub API
metadata，并由对应 Release notes 链接、汇总逐资产哈希和未完成门禁。

已识别角色会把 System 安全策略和 Assistant 拒绝与 User 意图隔离。相邻 User 消息
以及一个显式关联的有界三轮计划可以组合；Provider 原生 Tool Payload 会独立扫描；
未知角色结构走保守回退；Interactions 当前固定使用无角色信任的保守文本遍历。`<target>`、`${host}`、`VICTIM_IP` 等占位符只有在邻近文本
把它们绑定到危险对象或真实目标时才具有风险含义。

文本处理有明确上限：

- 最多两层解码、八个唯一变体；
- 编码源最多 128 KiB，解码文本合计最多 64 KiB；
- 支持 URL Percent、HTML Entity、可检查 Base64、文本型 Data URL、JSON Escape
  和有界嵌套 Tool JSON；
- 支持 Provider 感知的角色、Content Part、Tool Argument 和 Tool Output 载体；
- JSON 媒体候选按对象事务式处理，候选数量/字节有固定上限，成员排列不改变固定
  `OpaqueMediaKinds` 顺序；
- 原始请求与提取文本使用独立预算，上传媒体不会消耗普通文本分类预算；
- multipart 按 SourceFormat 白名单处理，boundary、part、header、字段与累计文本均
  有界；Guard 不创建临时文件，也不抓取远程媒体；
- 不解压、不展开归档、不联网抓取，也没有跨请求语义记忆。

图片、音频、视频和文档附件属于不透明内容，可配置为 `block`、`audit` 或
`allow`。`allow` 只表示“未检查后放行”，不代表安全批准。

内容检查完整度是独立的策略输入。Malformed JSON、扫描/深度/文本段限制、不支持的
Content-Type、multipart 资源限制、未知 multipart schema、deferred candidate 上限和
插件 RPC Body 上限属于
`incomplete_inspection`，不是运行时崩溃。`balanced` 对这类请求放行并审计，
`strict` 本地阻断；任何半截前缀都不能触发 `balanced` 阻断、更新主体风险或持久化
部分 Rule ID。详见
[MULTIMODAL_INSPECTION_CONTRACT.md](docs/MULTIMODAL_INSPECTION_CONTRACT.md)。

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

以上“不持久化明文”和“不写临时文件”只覆盖 Guard extractor、管理面、metrics 与
plugin audit，不是 CPA 端到端日志保证。

CPA Host 边界仍存在插件无法消除的 Fail Open 条件：插件未加载、被 Fuse、Router
报错、在有效 Handled 结果被接收前 Panic、返回无效 Target，或自路由到宿主认为未就绪
的 Executor 时，CPA 可能继续其他 Router 或原生路由。更高优先级 Router 也可能先处理
请求；相同优先级按插件 ID 升序执行。

`loaded` 与 `enforcement_ready` 只表示 CPA 已经分派的管理回调所读取到的插件
内部状态，不能独立证明宿主发现并注册了插件、Router 顺序有利、插件未被 Fuse、
目录中不存在重复动态库，或某种请求格式的 Executor 已被宿主接受。运维人员必须单独
确认这些宿主条件。详见 [LIMITATIONS.md](docs/LIMITATIONS.md) 与
[THREAT_MODEL.md](docs/THREAT_MODEL.md)。

审计到的 CPA v7.2.75 Host 仍会在调用插件 Handler 前缓冲 Management Body，因此
反向代理必须自行限制 Body，并证明超限请求在到达 CPA 前收到 HTTP 413。CPA v7.2.75
请求日志还可能临时落盘非 multipart Body，并在 HTTP Error Log 中持久化原始 Body；
隔离沙盒必须使用临时日志目录，生产复审还需单独检查 commercial mode、保留期、权限
与清理策略。

## 验证状态

| 证据 | 状态 |
|---|---|
| Round5.2 Source Freeze、本地门禁、Branch Push CI、PR Merge Result CI、PR 与复核 | Freeze `170de7f324c2bdf9a473b1866bdfc1e097182301`；本地安全门禁 **PASS**；Push CI [29467936241](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29467936241) **PASS**；PR CI [29467938359](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29467938359) 对 base `89b62b341278073e7b6518b85e41cd7f7c6b682c`、head `170de7f324c2bdf9a473b1866bdfc1e097182301`、临时 merge `fc8b5649505662e47bedbd85a41fbea306a2df7c` **PASS**；PR [#8](https://github.com/yujianwudi/cyber-abuse-guard/pull/8)；CodeRabbit **PASS** |
| Round5.2 合并后 main CI、exact-main artifact、Tag 与 Release | **EXTERNAL EVIDENCE — GITHUB API METADATA + LINKED RELEASE NOTES**；本源码树不自引用未来 Merge/Release 身份 |
| 历史 round5.1 合并与开发预发行 | Merge/Tag Commit `89b62b341278073e7b6518b85e41cd7f7c6b682c`；main Run [29409182748](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29409182748) 的 attempt 1 在 fuzz 计时边界失败，attempt 2 全部 Job 通过；artifact ID `8340894661`、容器 Digest `sha256:7419fcf0c0745472728d6e9c73d99aa01737930ccf25e26501e17ae4d453db61`、SO SHA-256 `3176d2af23963a2768672034af02fc1ca9ebe0c3f29a3654aa802ce0f822b6be`；仅为历史预发行 |
| 第五轮 CPA v7.2.75 隔离 Host 与独立复核 | **NOT RUN / PENDING**：普通 CI 只有源码契约与 integration compile-only，没有启动 CPA 或加载 `.so` |
| CPA v7.2.80 最新源码/编译兼容 | **DEVELOPMENT SELF-CHECK 与精确源码 PUSH/PR CI PASS**：`CPA_LATEST_VERIFY_REMOTE=1 make cpa-latest-compat` 已验证 GitHub `releases/latest` 与 Tag→Commit；固定 module 校验、Guard/integration compile 探针、真实 Guard registration/route 测试、17 个官方 Host routing/status 测试、11 个官方 Interactions route/handler 测试和三个 checksum 固定 overlay 也已通过；不属于 Native Host 证据 |
| 历史根模块 Unit、Race、Vet、Fuzz Smoke、回归、构建、打包与可复现性流程 | 较早 Implementation Freeze `61536f9` 的 Push Run [29312969925](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29312969925) 和 PR Run [29312971717](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29312971717) 均 **GITHUB CI PASS**；不属于第五轮证据 |
| 安全 Go 开发脚本 | `test`、`race` 与有界开发门禁 **DEVELOPMENT SELF-CHECK PASS**；Implementation Freeze 也由精确源码 Push CI 与 PR Merge Validation 覆盖 |
| CPA Store ZIP 命名、布局与安装源码契约 | 针对 CPA v7.2.75 官方源码 **GITHUB CI PASS**；不代表真实 Store 安装或 Native Host 加载 |
| CPA Router 排序与回退源码契约 | 针对 CPA v7.2.75 官方源码 **GITHUB CI PASS**；不代表隔离 Host 矩阵 |
| 本地 Executor 拒绝契约 | `execute`、`execute_stream`、`count_tokens` 请求 403；`http_request` 只有 SOURCE/ADAPTER status-error 405（response=nil）检查 |
| Implementation Freeze 的原生插件加载 | 第五轮 CPA v7.2.75 腾讯云 isolated Host **PENDING**；普通 CI 仅 compile-only，历史 v7.2.72 证据不能替代本轮验证 |
| 历史 OpenAI Chat / Responses / Claude / Gemini 服务器矩阵 | 较早 v7.2.72 Freeze **GITHUB CI PASS**；第五轮 Host Case 待完成 |
| 历史阻断后 Auth Selector / Usage / Provider / 上游零调用 | 较早 Freeze **GITHUB CI PASS**；第五轮精确 artifact 的真实 Host 零副作用证明尚未运行 |
| 历史多 Router / fail-open 动态矩阵 | 较早 Freeze **GITHUB CI PASS**：15 个原生 Router 场景；当前 v7.2.75 复验待完成 |
| `executor.http_request` 最终官方 CPA 客户端 HTTP 405 | **NOT AVAILABLE / NOT RUN**：`/v1/alpha/search` 是 provider-specific 路由，普通路径固定选择 `codex`，并把所有 Executor Error 映射为 502；当前没有官方路由把 Guard 的 405 Error 映射成最终 405 |
| 历史 PR #7 CodeRabbit 证据 | 本地 CLI 后续复核记录为 0 issues，但 GitHub Bot 评论后来结束为 `Review failed — pull request is closed`；不声明 CodeRabbit 已批准 |
| Round5.2 CodeRabbit 复核 | **PASS**：CLI `0.6.5` 对最终源码 delta 为 0 issues；Freeze `170de7f324c2bdf9a473b1866bdfc1e097182301` 的 GitHub CodeRabbit 检查通过，9 个 review thread 均已处理并关闭 |
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

之后又发生了一次与上述历史事件不同的第五轮偏差：一条范围过宽的只读 `git grep`
意外输出了受限 `testdata/holdout/malicious-operational.jsonl` 的内容。没有运行 holdout
测试，没有重定向或保留独立输出文件，没有写入源码、测试或文档，也没有影响调参或
结论。即便工程门禁全部通过，本轮也不得声明“未访问任何受限语料”，方法学交接仍保持
阻断。

历史 v7.2.72 源码/原生证据边界记录在
[CPA_INTEGRATION.md](docs/reports/CPA_INTEGRATION.md) 与
[LEO_VERIFICATION_HANDOFF.md](docs/LEO_VERIFICATION_HANDOFF.md)。
[PHASE0_CPA_CONTRACT.md](docs/reports/PHASE0_CPA_CONTRACT.md) 只保留为历史 Phase 0
证据，[ROUND4_LEO_REVIEW_HANDOFF.md](docs/ROUND4_LEO_REVIEW_HANDOFF.md) 只保留为
第四轮历史交接。[PR #7](https://github.com/yujianwudi/cyber-abuse-guard/pull/7) 与
`v0.1.2-dev.round5.1` 按项目约定作为历史 round5.1 快照；GitHub 当前报告
`isImmutable=false`，因此 API 元数据与哈希只是时点证据。Round5.2 source-freeze/pre-merge
record 由
[AUDIT_HANDOFF.md](docs/AUDIT_HANDOFF.md)、
[TEST_REPORT.md](docs/reports/TEST_REPORT.md) 与
[RELEASE_EVIDENCE.md](docs/reports/RELEASE_EVIDENCE.md) 跟踪；合并后证据由 GitHub API
metadata 跟踪，并由对应 Release notes 链接。历史评估数据不得重跑，
也不得针对 v10 单条记录调参。

## 开发与审计检查

以下第一组命令只进行源码/安全开发检查，不部署 CPA、不加载 `.so`，也不打开已消费评估
样本：

```bash
make format-check git-diff-check module-verify
./scripts/go-safe-development-test.sh test
./scripts/go-safe-development-test.sh race
make vet fuzz-smoke corpus-regression script-test
make round4-regression round5-regression
make development-public-jailbreak-corpus

# 可见的 development-only 对抗集；永远不能作为未来 Holdout。
go test ./cmd/development-adversarial-v11-prep-validator \
  -run '^TestDevelopmentAdversarialV11PrepCorpus$' -count=1

go test ./cmd/development-public-jailbreak-patterns-v1-validator \
  -run '^TestDevelopmentPublicJailbreakPatternsV1Corpus$' -count=1

# 明确的源码级 CPA v7.2.75 Store 与 Host 契约。
go -C integration/pluginstorecontract test ./... -count=1

# 最新 CPA v7.2.80 源码/编译门禁；不启动 Host、不加载 .so。
make cpa-latest-compat

# 普通 CI 只编译 integration tag 代码，不启动 CPA。
make integration-compile
```

安全脚本是广泛 Go 门禁的唯一入口。`make unit-test` 与 `make race` 分别映射到其
样本安全模式；不得退回可能打开已消费评估 fixture 的广泛命令。单独命名的
`make consumed-boundary-test` 已从普通 CI 移除，未获得评估边界明确授权时不得运行。

第五轮普通 GitHub CI 只调用 `make integration-compile`，不会调用
`make integration-test` 或下面两个 Host blackbox 目标。真实 `.so` 加载与 Host 矩阵只
保留给后续获授权的腾讯云二号机 CPA v7.2.75 + Mock upstream 隔离沙盒，不属于本地开发
验证：

```bash
ALLOW_DIRTY_BUILD=1 make cpa-v7275-host-blackbox
ALLOW_DIRTY_BUILD=1 make cpa-router-fixture-blackbox
```

发布工具链要求 Go `1.26.4`。Linux 原生构建、集成、SBOM、漏洞、产物和可复现性命令
见 [TEST_REPORT.md](docs/reports/TEST_REPORT.md) 与
[RELEASE_EVIDENCE.md](docs/reports/RELEASE_EVIDENCE.md)。

`make holdout-test` 不是普通开发检查。v10 已消耗，其门禁会主动拒绝重跑。
当前被阻断候选不得执行 `make formal-release`。

## 产物契约

开发态 CI 可以生成带 `-dirty` 后缀的证据产物；当前不存在正式稳定版 v0.1.2 发布产物。
历史 `v0.1.2-dev.round5.1` 只附带了明确标记为 dirty、不可用于生产的资产，且必须继续
绑定原有 Tag，不得移动到后续源码。

历史 round5.1 精确 main 产物为 `cyber-abuse-guard-linux-amd64-dirty`，ID `8340894661`，
大小 `10691298` 字节，容器 Digest
`sha256:7419fcf0c0745472728d6e9c73d99aa01737930ccf25e26501e17ae4d453db61`，到期时间
`2026-10-13T10:54:12Z`。Build Metadata 绑定 Merge Commit
`89b62b341278073e7b6518b85e41cd7f7c6b682c`；SO SHA-256 为
`3176d2af23963a2768672034af02fc1ca9ebe0c3f29a3654aa802ce0f822b6be`。发行资产已逐项记录
SHA-256；Actions Artifact 仅记录容器级 Digest，未保留成员到发行资产的逐项等价映射。上述内容只是历史开发证据，不验证 round5.2。任何 round5.2
exact-main artifact 与发行资产哈希都刻意记录在 GitHub API metadata，并由对应 Release
notes 链接和汇总，而不是由本源码树自我声明。

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
| `cmd/development-public-jailbreak-patterns-v1-validator/` | 公开 taxonomy 派生、已净化开发 canary 的严格校验器 |
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
| 安全审计者 | [第四轮交接](docs/ROUND4_LEO_REVIEW_HANDOFF.md)、[审计交接](docs/AUDIT_HANDOFF.md)、[发布证据](docs/reports/RELEASE_EVIDENCE.md)、[测试报告](docs/reports/TEST_REPORT.md) |
| CPA 集成人员 | [CPA 集成报告](docs/reports/CPA_INTEGRATION.md)、[Phase 0 契约](docs/reports/PHASE0_CPA_CONTRACT.md)、[Docker 运维](docs/INSTALL_DOCKER.md) |
| 策略审核人员 | [规则说明](docs/RULES.md)、[分类器重构基线](docs/reports/CLASSIFIER_REDESIGN_BASELINE.md)、[隐私报告](docs/reports/PRIVACY.md)、[提示注入复审](docs/reports/PROMPT_INJECTION_REVIEW.md) |
| 后续维护人员 | [下一版本建议](docs/NEXT_VERSION.md)、[变更记录](CHANGELOG.md) |

## 安全问题报告

请遵循 [SECURITY.md](SECURITY.md)。Issue 中不得包含真实凭证、私有 Prompt、OAuth
材料或生产账号标识。

## 许可证

[MIT](LICENSE)
