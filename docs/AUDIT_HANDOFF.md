# 独立审计交接说明 — CPA Cyber Abuse Guard v0.1.2 开发树

最后更新：2026-07-14（Asia/Shanghai）

## 1. 当前结论

当前状态是：

```text
BLOCKED FOR HANDOFF
```

这不是最终质量 PASS，也不是生产批准。实际起始基线为
`a121a444cb0d82cba4e27754914a1f88258e1d7b`；实现冻结为 `61536f9`，两条精确 SHA 的
GitHub CI 均已通过。证据文档单独提交；最终交接时已核对工作树清洁。

方法学有效的 v10 首次且唯一正式运行仍为 `CONSUMED / FAIL`：合法误报 28/320，恶意
阻断 49/320，精确分类 33/320。该结论不变。不得读取、打印、执行、通过 Git 历史获取或
逐条分析 v10 样本，也不得用开发集冒充新盲测。

方法学事件：三条作用域错误的 WSL 源码搜索命令意外输出了已退役
`testdata/holdout-v3` 的若干行。三次搜索都被立即停止；输出内容没有被分析，也没有用于
分类器调优或任何结论。Evaluation v10 内容未被访问。即便如此，已退役 holdout-v3 不再
具备独立证据资格；该事件本身也使交接状态保持 `BLOCKED FOR HANDOFF`。

未创建 Tag、GitHub Release，未部署或修改生产 CPA。即使未来工程门禁通过，也不能保证
上游账号永不被警告、限流、暂停或封禁。

## 2. 证据标签

审计时必须严格区分：

| 标签 | 含义 |
|---|---|
| `DEVELOPMENT SELF-CHECK` | 指定本地开发命令已运行，只证明该命令和当时工作树 |
| `SOURCE IMPLEMENTED` | 源码/测试夹具存在，不表示已执行 |
| `SOURCE OVERLAY PASS` | 固定 CPA 上游源码契约已运行，不表示真实 Guard `.so` 已加载 |
| `GITHUB CI` | 精确推送 Commit 的远端检查；旧 main/旧分支结果不能继承 |
| `REAL HOST` | 真实 Guard `.so` 由 CPA v7.2.72 Host 加载，并经 HTTP 路径验证 |
| `LOCAL MIS-EXECUTION / EXCLUDED` | 命令在授权证据路径外运行；该结果永久排除，必须分别引用 GitHub CI 或 Leo 的独立结果 |
| `NOT RUN` | 没有该层结果 |
| `BLOCKED` | 缺少冻结、环境或前置条件，绝不是 PASS |

WSL 中曾误执行以下三个本地目标：

```text
make cpa-router-fixture-blackbox
make cpa-v7272-host-blackbox
scripts/management-proxy-413-test.sh
```

它们只使用随机回环端口和 Mock 组件，没有连接真实 Provider 或生产服务；清理核对确认无
Fixture 进程残留。其结果从交付证据中排除，状态固定为：

```text
LOCAL MIS-EXECUTION RECORDED / EXCLUDED; NOT AUTHORITATIVE
```

不得把这些本地结果改写成 PASS。

## 3. 精确开发身份

```text
repository: https://github.com/yujianwudi/cyber-abuse-guard
starting_baseline: a121a444cb0d82cba4e27754914a1f88258e1d7b
branch: agent/complete-classifier-cpa-v7272-handoff
reliability_checkpoint_commit: 573def2649d164161e2dfdfeb3f59b1e1b38ebbc
implementation_freeze_commit: 61536f9f02c47a4d79031a47dc8a284f040e41c1
evidence_document_commit: a2d30fc63fca4fba020cda282474aaca15a47d8f
root_cpa_version: v7.2.72
cpa_upstream_tag_commit: 6279bb8a4c2835ff6ed99c6b85083b2afbefa681
cpa_module_sum: h1:ppce0MLsz2xJi2yi3/A60zu03cM7bMWBAEJ6eC29E5Y=
cpa_go_mod_sum: h1:f4pcyAej8RoeRhIxJfm+OUMkCKaApiA8WzxR2XVlBh8=
target: Linux amd64, glibc 2.34+, C ABI/RPC schema v1
recorded_wsl_toolchain: go1.26.4 linux/amd64
ruleset: 1.0.7
ruleset_sha256: 7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134
classifier_policy: classifier-policy-v2
classifier_policy_sha256: dc9a174099cb2f621e5333a508d4645604f96f470a6d9ae12a1acfb363d29cf2
```

classifier-policy 哈希通过源码清单测试绑定分类器、Matcher、Normalizer、Role、Wrapper、
BehaviorGraph、语义组合、Extractor、规则加载/YAML 和依赖锁。管理状态会暴露版本/哈希，
但当前 Build Metadata/Artifact Verifier 尚未绑定该字段，因此最终完整 Git Commit 仍是行为
身份的一部分。

## 4. 请求安全链路

```text
下游请求
  -> CPA v7.2.72 ModelRouter（Auth Selector / Provider / Usage / Upstream 之前）
     -> 放行：Handled=false，保持模型、消息和 Tool 参数，进入 CPA 原生链路
     -> 阻断：Handled=true + TargetKind=self
        -> execute / execute_stream / count_tokens：策略 HTTP 403
        -> stream：在成功 SSE Header/Chunk 之前同步 403
        -> http_request：仅有 RPC/Adapter status-error 405（response=nil）
           /v1/alpha/search 普通路径选择 codex，并把 Executor Error 映射为 502；
           当前没有官方公开路由把 Guard Error 映射为最终客户端 405
        -> Auth Selector / Provider / Usage / Mock Upstream 应全部为 0
```

CPA Host 根本 fail-open 仍存在：插件未加载、注册失败、被 fuse、Router error、Host 接受
Handled Result 前 panic、invalid target、executor not-ready，或更高优先级 Router 先 Handle，
都可能继续后续 Router/原生路由。同优先级按 Plugin ID 升序。`enforcement_ready` 仅说明
插件内部 Runtime 状态，不能证明 Host 已加载、未 fuse、顺序正确或具体 Executor ready。

## 5. 分类器重构

本轮源码将危险底层行为与 Wrapper/Amplifier 分开：

- Wrapper-only 不能创建 Cyber Abuse Taxonomy；弱 Wrapper 放行，强 Wrapper 最多审计；
- Wrapper + 独立危险行为可提高置信度，但保留原危险类别；
- BehaviorGraph 表示 Actor/Action/Object/Target/Technique/Execution/Credential/
  Persistence/Evasion/Exfiltration/Impact/Scale/Authorization/Role/Carrier 等关系；
- 图和管理输出只含布尔/关系/固定 ID，不含原文、片段、目标、URL 或 Tool Arguments；
- System 安全政策和 Assistant refusal 不作为用户恶意意图；相邻用户续接和明确三轮计划可
  有界组合；
- Tool provenance、占位符绑定、URL percent、HTML entity、Base64、JSON Unicode、嵌套
  Tool JSON 和有限分片/同形字在资源上限内处理。

可见开发集 `testdata/development-adversarial-v11-prep` 共 35 条：16 block、14 allow、
2 audit、3 resource-boundary。覆盖八类、四协议、三种语言类型以及 Wrapper、Role、
Multi-turn、Tool、Carrier、Placeholder 和边界。其 Manifest 明确
`development_only=true`、`future_holdout_eligible=false`。里奥绝不能把它或派生措辞用于
独立 v11。

## 6. 主体、持久化与隐私

- 主体风险以 Subject HMAC + 域分离 Request Digest 幂等；execute/stream/token-count、
  retry、并发、pending miss/expiry、enabled reconfigure 和 shutdown race 不重复记分；
- 幂等 Receipt 随 Subject Snapshot 保存；旧快照保持兼容；
- Pending Cache 使用有序 O(1) 刷新/淘汰；
- Unix HMAC 文件校验 owner/mode/regular-file/symlink/FIFO/device/空短 Key；
- SQLite/迁移备份/Subject Snapshot/管理 API/CSV/日志/Panic/Watchdog/Release Evidence
  有 Canary 测试；
- v1→v2 迁移在发布备份或写入前验证旧库 `request_hash`、`subject_hash`、`model` 和
  `source_format` 隐私契约；任一值不是规定 Digest/固定 Provider Enum 时 fail closed，
  不发布备份、不执行迁移，原库保留给运营修复；不会自动清洗旧明文库；
- 插件不把 Prompt、Token、Cookie、OAuth、API Key、IP、域名或完整模型名写入这些表面；
- 仍未实现 HMAC 双密钥轮换和 keyed whole-snapshot MAC。

## 7. 当前已执行的开发检查

| 范围 | 结果 |
|---|---|
| Wrapper/BehaviorGraph/Role/Policy Identity 定向分类器测试 | **DEVELOPMENT SELF-CHECK PASS** |
| 35 条 Development Corpus Validator | **DEVELOPMENT SELF-CHECK PASS** |
| Prompt Injection/Tool/Encoding 定向 Plugin 测试 | **DEVELOPMENT SELF-CHECK PASS** |
| Classifier Validator `go vet`、gofmt、根 module verify/tidy、当时 diff check | **DEVELOPMENT SELF-CHECK PASS** |
| WSL `-race` Subject/Config/Audit 及定向 Plugin 生命周期/隐私测试 | **DEVELOPMENT SELF-CHECK PASS** |
| `go-safe-development-test.sh test`、`go-safe-development-test.sh race`、`go-safe-development-test.sh boundary` | **DEVELOPMENT SELF-CHECK PASS** — WSL Ubuntu 26.04 / Go 1.26.4；test/race 未运行 Evaluation/Holdout 测试名；boundary 只运行 3 个 v10 聚合/报告标记/拒绝重跑测试且日志确认 fixture 未访问 |
| WSL reliability `go vet`、Health Script、Release Evidence Privacy Script | **DEVELOPMENT SELF-CHECK PASS** |
| 同机 Classifier Benchmark 对比 | **DEVELOPMENT SELF-CHECK PASS / NOT FINAL EVIDENCE** |
| CPA 16 个精确官方 Host Source Tests | **SOURCE OVERLAY PASS** |
| 真实 `.so` Store Install/Host Load | **GITHUB CI PASS** — 真实 Store ZIP 首装并由 CPA v7.2.72 Host 加载；本地误执行仍排除 |
| 四协议 403/pre-SSE/token-count | **GITHUB CI PASS** — 32 个 Host 子测试；本地误执行仍排除 |
| `http_request` RPC/Adapter status-error 405（response=nil） | **SOURCE / ADAPTER CHECK** |
| 官方 CPA Handler 最终客户端 HTTP 405 | **NOT AVAILABLE / NOT RUN — BLOCKED FOR HANDOFF；当前 CI 无法补齐** |
| Auth/Provider/Usage/Mock Upstream 零调用 | **GITHUB CI PASS**；本地误执行仍排除 |
| Multi-Router/fail-open Native Fixture | **GITHUB CI PASS** — 15 个隔离原生场景；panic/fuse 另有官方源码 overlay |
| Management Proxy 413 | **GITHUB CI PASS** — 超限请求在计数 CPA Handler Stub 前返回 413 |
| GitHub CI | **PASS** — Push `29312969925`，PR `29312971717`；Push 长 Fuzz PASS，两条可复现性 PASS |
| CodeRabbit Ready Review | 首轮对 `8719c7f` 提出 8 个线程和 2 个 nitpick；有效问题由 `61536f9` 修复，`cmd` 缺失符号项经定向编译证伪；对 `8719c7f..61536f9` 的后续复审为 **NO ACTIONABLE COMMENTS** |
| 开发候选产物与哈希 | **GITHUB CI PASS / RECORDED**；不是正式发布产物 |

完整命令和矩阵见 `docs/reports/TEST_REPORT.md`，性能与隐私分别见
`docs/reports/PERFORMANCE.md`、`docs/reports/PRIVACY.md`。

## 8. 冻结 v10 结论

审计者只允许读取冻结聚合报告，不允许读取/打印/运行样本。v10 聚合：

| 指标 | 结果 |
|---|---:|
| 合法误报 | 28 / 320（8.75%） |
| 恶意阻断 | 49 / 320（15.31%） |
| 精确分类 | 33 / 320（10.31%） |

发布门槛全部失败，四个关键类别门槛也全部失败。该历史结果既不能被本轮源码改写，也不能
被开发集 PASS 覆盖。未来必须由开发流程外独立创建全新盲测。

## 9. 里奥建议验证顺序

在最终实现冻结前，本地只运行不会打开已消费评估样本、不会加载 `.so` 的安全开发门禁：

```bash
git status --short
git rev-parse HEAD
git log --oneline --decorate -10
go version
go env GOOS GOARCH CGO_ENABLED GOMAXPROCS GOAMD64

make format-check
make git-diff-check
make module-verify
./scripts/go-safe-development-test.sh test
./scripts/go-safe-development-test.sh race
./scripts/go-safe-development-test.sh boundary
make vet
make fuzz-smoke
make script-test
make corpus-regression
make benchmark
make vulncheck
make build-linux-amd64
make cpa-host-fixture-contract
```

不要运行已消费 v10 分类，不要运行独立 v11。若某个广泛 Target 会读取已消费样本，应先
审计其定义并改用不读取样本的精确定向命令；不得通过跳过失败或 `|| true` 制造 PASS。

`make integration-test`、`make management-proxy-413-test` 和带
`REQUIRE_DIST_ARTIFACTS=1` 的 `make cpa-store-contract` 只能由授权 GitHub CI 运行，并在
Leo 的授权隔离环境复验。CI 的 Host Blackbox 通过 `InstallManifest` 完成同一 Dist 身份的
首装和真实 Host 加载；随后 `TestPublishedStoreArchive` 对该身份验证 repeat-skip 与
tamper-repair。Synthetic fallback 不是 CI 证据。

现有项目 `httptest.Server` 是测试自建的包装，会手工把 `error.StatusCode()` 写入 HTTP
响应；它只能证明 RPC/Adapter 状态码错误层，不能冒充官方 CPA Handler。CPA v7.2.72
确有 provider-specific 的 `POST /v1/alpha/search`：普通路径固定选择 `codex`，而且对
任何 `HttpRequest` Error 固定返回 502。Guard 返回的是携带 405 的 Error，不是成功的
`ExecutorHTTPResponse`，所以当前没有官方公开路由把它映射为最终客户端 405。该项无法
由当前 CI 自然产生，是独立的 `BLOCKED FOR HANDOFF` 阻断项。

精确 Implementation Freeze 的 GitHub CI、产物 SHA-256、Store ZIP 根目录、完整 Install
Lifecycle、真实 Host 四协议和零副作用、Proxy 413 以及隐私 Canary 已记录。最终独立质量
结论仍由里奥给出。

## 10. 交接字段

```text
implementation_freeze_commit: 61536f9f02c47a4d79031a47dc8a284f040e41c1
evidence_document_commit: a2d30fc63fca4fba020cda282474aaca15a47d8f
pull_request: https://github.com/yujianwudi/cyber-abuse-guard/pull/4
clean_tree: YES AT FINAL HANDOFF
github_ci: PASS — push 29312969925; pull_request 29312971717
real_host_matrix: GITHUB CI PASS — 32 Host subtests; 15 Router scenarios
management_proxy_413: GITHUB CI PASS
http_request_adapter_405: SOURCE / ADAPTER STATUS-ERROR CHECK (response=nil)
official_cpa_final_client_http_405: NOT AVAILABLE / NOT RUN — BLOCKED FOR HANDOFF
development_artifact_hashes: RECORDED — see docs/reports/RELEASE_EVIDENCE.md
tag: NOT CREATED
github_release: NOT CREATED
production_deployment: NOT PERFORMED
leo_verification: NOT RUN
final_status: BLOCKED FOR HANDOFF
```

逐项 30 项交接清单见 `docs/LEO_VERIFICATION_HANDOFF.md`。
