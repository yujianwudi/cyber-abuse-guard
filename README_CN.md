# CPA Cyber Abuse Guard 本地封控插件

CPA Cyber Abuse Guard 是面向
[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)（CPA）的本地原生安全插件。
它在 Provider 解析和账号认证调度之前检查请求，把明确的操作性 Cyber Abuse 请求在
本地拒绝，同时尽量保留防御分析、漏洞修复、事件响应、CTF/靶场和明确授权测试。

v0.1.2 源码目标为 CPA `v7.2.67`、commit
`2075f77c8ebe9ec872759965661936fb1ac2931f`、Linux amd64、glibc 2.34 或更高版本、
CPA C ABI/RPC schema v1。不支持 musl/Alpine。

> **发布状态：** v0.1.2 是**被门禁阻断的候选版本**，不是生产发布。盲测 v1-v8
> 均为退役或已消耗失败；v9 因缺失固定 Taxonomy Enum 校验器而冻结为
> `CONSUMED / METHODOLOGY INVALID / FAIL`。方法学有效的 v10 首次且唯一正式运行
> 也失败：合法误报 28/320、恶意阻断 49/320、精确分类 33/320。v10 已消耗，
> `make holdout-test` 现在会拒绝重跑。不得创建 `v0.1.2` Tag 或 GitHub Release，
> 不得部署此候选版本。未来只能在新实现完成后，用全新独立盲集重新评审，禁止复用 v10。

> **能力边界：** 本插件只能减少到达上游账号的高风险请求，不能保证账号永不收到
> 警告、永不暂停、永不限流或永不封禁。上游平台仍会独立执行自己的安全策略。

## 安全链路

插件注册 CPA `ModelRouter` 和本地 Executor：

```text
下游请求
  -> CPA ModelRouter
    -> 放行：Handled=false，原请求不变，继续 CPA 原生链路
    -> 阻断：Handled=true, TargetKind=self
       -> 本地 Executor 返回 HTTP 403
       -> 不进入 Provider 解析、Auth Selector、Usage 或真实上游
```

插件不修改模型名、客户端身份、System Prompt 或安全声明；不伪装教育/研究用途；
不读取 CPA Auth/OAuth 文件；不执行用户代码；不把请求内容发送到公网分类器或第三方。
被放行的请求仍会按 CPA 配置正常进入上游。

内置确定性规则集版本为 `1.0.7`，canonical embedded SHA-256 为
`7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134`。阻断必须同时具备伤害意图、危险对象/影响，以及
操作化、真实目标、规避或规模证据；单个关键词不足以阻断。“教育”“CTF”“已授权”
等标签不能洗白部署型凭证窃取、钓鱼收集、勒索软件或数据外传。

## CPA v7.2.67 的 Fail Open 边界

CPA v7.2.67 在 Router 返回错误时可能继续原生路由，插件 panic 后也可能熔断插件。
v0.1.2 通过有界解析、入口 panic recovery、已知超大 RPC 的模式化本地处理、原子热
更新和健康计数器降低风险，但 ABI v1 插件无法修改 CPA Host 的这一行为。

生产环境必须监控：`loaded`、`enforcement_ready`、`router_errors`、
`panics_recovered`、`audit_degraded`、`hmac_stable`、`persistence_degraded`、
`last_reconfigure_error` 以及构建/规则身份。使用只读 Watchdog：

```bash
CPA_MANAGEMENT_KEY_FILE=/run/secrets/cpa-management.key \
EXPECTED_MODE=balanced \
./scripts/check-production-health.sh
```

Watchdog 只接受回环地址；它校验 runtime/build/rules 身份与健康，拒绝 Router Error 或
Recovered Panic 差量，报告未知 SourceFormat，并可用 `MAX_NEW_UNKNOWN_SOURCE_FORMATS`
限制探针窗口内的增量。无害和固定恶意探针内置于插件，经鉴权后的 Management API
在本地判断，不会把探针正文发送到 `/v1`、Auth Selector、Provider 或上游账号；脚本
不会修改 CPA 配置、删除账号或删除其他插件。

CPA ABI v1 也不能枚举 Router 顺序或检查插件目录。管理员必须人工确认：

- `priority: 300` 实际生效，且没有更高优先级 Router 提前 Handle 请求；
- 旧 `antigravity-coding-filter` 已禁用；
- 插件目录中只保留一个生效版本的 `.so`，不存在 v0.1.1/v0.1.2 并存歧义。

## 模式与灰度上线

| 模式 | 请求行为 | 事件行为 |
|---|---|---|
| `off` | 不提取、不分类、不阻断 | 不保存事件 |
| `observe` | 分类但永不阻断 | 只更新内存聚合统计 |
| `audit` | 分类但永不阻断 | SQLite 保存最小化事件 |
| `balanced` | 在均衡阈值阻断明确操作性滥用 | 最小事件和主体控制 |
| `strict` | 在更低的 audit 阈值阻断 | 最保守；没有 challenge 流程 |

新部署必须分三阶段：

1. **Observe，24–48 小时。** 不保存逐请求事件，不阻断；检查分类数量、延迟、
   CPU/内存、Router Error、Panic、HMAC 和审计健康。
2. **Audit，24–48 小时。** 审核隐私最小化的“如果开启封控会阻断”事件；任何阈值
   或策略调整都要留记录；禁止把生产危险测试发送给真实上游。
3. **Balanced。** 初始窗口内至少每小时检查阻断量、合法用户投诉、CPA 5xx、插件
   loaded/registered、审计库和 Watchdog 差量，并保持一键禁用回滚可用。

不要从未安装或 `off` 直接跳到 `strict`。完整晋级/中止/回滚标准见
[Docker 安装与运维](docs/INSTALL_DOCKER.md)。

## 隐私

原始 Prompt、Messages、Tool Payload、Authorization Header、明文 API Key/IP、
Cookie、OAuth Token、上传代码和上游账号身份不会写入审计库，也不会通过管理接口
返回。`audit.log_original_text: true` 会被拒绝，且不存在 Debug 例外。

审计只允许时间、动作、模式、粗粒度类别、分数、稳定规则 ID、请求 SHA-256、主体
HMAC、RequestedModel 的域分离摘要、固定来源枚举（`openai`、`openai-response`、
`claude`、`gemini` 或 `unknown`）、Stream 标志、扫描字节数和延迟。启用主体持久化时也只保存
HMAC Subject 及有界风险/Cooldown/Manual Block 状态。隐私验证方案见
[PRIVACY.md](docs/reports/PRIVACY.md)。

## 编码文本与不透明媒体

文本解码有严格上限：最多 2 层、8 个唯一变体；编码源最多 128 KiB，解码文本合计
最多 64 KiB。支持 URL Percent、HTML Entity、可检查 Base64 文本、文本型 Data URL、
JSON Escape 和有界二次 Tool JSON。插件不解压、不展开归档、不联网抓取。
完整但无法识别或仅表现为高熵的字符串仍按原始文本扫描，不会仅因“看起来像编码”就自动
封控；已识别编码若在预算边界内不完整则标记为 Truncated，Balanced/Strict 会失败关闭。
加密内容和新型未知编码仍是明确的检测限制。

图片、音频、视频和文档附件字节属于不透明内容；HTTPS 媒体 URL 永远不会被抓取。
`opaque_media_policy` 可取 `block|audit|allow`。未显式配置时：

| 模式 | 默认不透明媒体策略 |
|---|---|
| `off` | `allow` |
| `observe`、`audit`、`balanced` | `audit` |
| `strict` | `block` |

`audit` 只记录粗粒度“不透明媒体”动作，不保存媒体内容或 URL 内容；`allow` 仅表示
插件无法判断并放行，不代表安全批准。

## HMAC 主体与可选持久化

生产环境必须使用稳定 Secret File。以下命令不会把密钥打印到终端：

```bash
sudo install -d -m 0700 -o root -g root /opt/cliproxyapi/secrets
sudo ./scripts/generate-hmac-key.sh \
  /opt/cliproxyapi/secrets/cyber-abuse-guard-hmac.key
sudo chown root:root \
  /opt/cliproxyapi/secrets/cyber-abuse-guard-hmac.key
```

生成器要求输出目录归当前用户所有、路径中没有符号链接，且目录不可被 group/world
写入。它拒绝覆盖，使用私有临时文件，同步密钥内容，经 no-overwrite 身份校验发布
mode-0600 普通文件，并同步所在目录。

以只读方式挂载这个普通 0600 文件，并设置
`CYBER_ABUSE_GUARD_HMAC_KEY_FILE`。密钥不得进入 Git、Docker Image、发布包、日志
或状态响应。没有稳定密钥时，重启后主体关联会退化。

`subject_control.persistence` 默认 `false`。关闭时，风险累计、Cooldown 和 Manual Block
仅存在于进程内，CPA 重启会清空。开启时必须同时开启 Audit，`max_subjects` 不得超过
10,000，并提供稳定 HMAC Key。恢复过程应用过期、衰减和容量上限；HMAC Key 不匹配
会明确降级并禁止覆盖旧快照，但内存规则封控继续运行。

v0.1.2 尚未实现双密钥轮换。设计目标是：一个 Active Key + 一个只读 Previous Key；
状态只暴露指纹；旧 HMAC 在有限过渡表中恢复；新写入只用 Active Key；设置明确过渡
截止时间，并由管理员显式 finalize。在此状态机落地前，普通升级应保留当前密钥。
详见[设计说明](docs/DESIGN.md)。

## SQLite 迁移

审计库包含 `schema_version` 与 `migration_history`。Schema v2 增加可选 Subject State
表。启动时严格校验列名、顺序、类型、约束、索引、schema 单例行和完整迁移序列。
迁移在单个事务内完成；v0.1.1 旧库会识别为 schema v1，可在迁移前用 SQLite
`VACUUM INTO` 生成只读备份。`audit.max_migration_backups` 默认最多保留 3 份，避免
无限堆积。

升级通过本地健康检查前不要删除旧库和备份。v0.1.1 是否可直接读取 schema v2 不作
保证；二进制与数据库一起回滚时应使用迁移前备份。

## 构建、测试与发布

正式工具链锁定 Go `1.26.4`。需要 Linux amd64、cgo、GCC、GNU binutils、`file`、
`zip`、`unzip`、`sha256sum`、`jq`、CycloneDX GoMod `v1.9.0` 和
`govulncheck v1.6.0`。

```bash
make format-check git-diff-check module-verify
make test race vet fuzz-smoke corpus-regression
make benchmark integration-test
make vulncheck

# 仅用于确认历史冻结状态；v10 已消耗，因此应明确失败：
make holdout-test
```

`make formal-release` 是完整的本地正式发布入口，但当前被阻断候选不得执行。它只允许从版本匹配、工作树干净且真实
Annotated Tag `v0.1.2` 指向 `HEAD` 的 Commit 执行。它会运行全部发布门禁、严格校验、
故障注入、双 Clone 可复现性、源码打包和最终证据生成。`ALLOW_DIRTY_BUILD=1` 只用于
开发验证，文件名和链接元数据会带 `-dirty`，不得当作正式发布产物。普通分支 CI 使用
`REPRODUCIBILITY_MODE=development`：两次 commit-bound 构建只存在于临时 Clone，产物
带 `-dirty`，不会写入仓库根目录的 `dist/`。

预期正式产物：

```text
dist/cyber-abuse-guard-v0.1.2.so
dist/cyber-abuse-guard-v0.1.2.so.sha256
dist/cyber-abuse-guard_0.1.2_linux_amd64.zip
dist/build-metadata.json
dist/checksums.txt
dist/ruleset-manifest.json
dist/ruleset.sha256
dist/sbom.cdx.json
dist/release-test-summary.txt
dist/release-test-summary.txt.sha256
dist/release-evidence-final.md
dist/release-evidence-final.md.sha256
dist/cyber-abuse-guard-v0.1.2-source.tar.gz
dist/cyber-abuse-guard-v0.1.2-source.tar.gz.sha256
```

正式分发渠道是 GitHub Repository/Release、源码 `tar.gz` 和经过校验的 Release ZIP；
RAR 不作为正式源码或二进制发布格式。

缺少命令、哈希不一致、ELF/架构不符、ABI Symbol 缺失、glibc 超过 2.34、构建身份
不一致、规则/SBOM 不一致、ZIP 多余文件或权限不符，`verify-release` 都必须非零退出。
正式可复现性只接受真实 Annotated Release Tag，并把已发布的 `.so`、ZIP、SBOM 与两个
干净 Clone 对比；不会合成 Tag，也不会回填缺失的根目录产物。

项目内 Regression Corpus 不能代替盲测。v1-v8 均为退役或已消耗失败，v9 是已消耗的
方法学无效失败，方法学有效的 v10 是已消耗的正式门禁失败。冻结的聚合报告保存在
`docs/reports/`，当前结论见
[RELEASE_EVIDENCE.md](docs/reports/RELEASE_EVIDENCE.md)。这些集合都不得重跑，也不得用于逐条调参。

## 安装、回滚与完整清理

请按 [docs/INSTALL_DOCKER.md](docs/INSTALL_DOCKER.md) 完成：下载哈希校验、单版本
`.so` 安装、Secret File 挂载、数据库迁移、Observe → Audit → Balanced 灰度、Watchdog、
回滚上一 `.so`、恢复数据库以及显式完整清理。

最短禁用回滚：

```yaml
plugins:
  configs:
    cyber-abuse-guard:
      enabled: false
```

```bash
docker compose restart cli-proxy-api
```

随后必须确认插件未 loaded/registered、CPA 根路径正常、`/v1/models` 无 Key 仍为 401、
New API 到 CPA 连通、其他插件正常、Auth 文件数量不变。审计库和 HMAC Secret 默认
保留，只有管理员显式确认后才删除。

## 管理接口

以下精确路由先由 CPA Management Key 鉴权：

```text
GET    /v0/management/plugins/cyber-abuse-guard/status
GET    /v0/management/plugins/cyber-abuse-guard/events
GET    /v0/management/plugins/cyber-abuse-guard/stats
POST   /v0/management/plugins/cyber-abuse-guard/test
POST   /v0/management/plugins/cyber-abuse-guard/health/probe
POST   /v0/management/plugins/cyber-abuse-guard/subjects/unblock
DELETE /v0/management/plugins/cyber-abuse-guard/events
```

CPA v7.2.67 的插件路由不能安全使用动态路径参数，因此 Unblock 使用固定路径和有界
JSON Body：

```json
{"subject_hash":"hmac-sha256:<64 个小写十六进制字符>"}
```

普通下游 API Key 无权访问这些接口；响应不包含原始 Prompt 或明文凭证。

更多资料：[DESIGN.md](docs/DESIGN.md)、[RULES.md](docs/RULES.md)、
[LIMITATIONS.md](docs/LIMITATIONS.md)、[THREAT_MODEL.md](docs/THREAT_MODEL.md) 和
[SECURITY.md](SECURITY.md)。
