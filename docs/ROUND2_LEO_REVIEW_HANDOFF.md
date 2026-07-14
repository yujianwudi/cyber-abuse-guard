# Cyber Abuse Guard 第二轮优化：Leo 复验交接

## 1. 当前状态

**PARTIAL — implementation candidate**

P0 源码修复、单元测试、race、vet、fuzz、benchmark 和 GitHub CPA Host fixture
已经完成并形成可复验 CI/artifact 证据。腾讯云二号机隔离 CPA + Mock upstream 的
真实协议矩阵仍未执行，因此本文件不声明 `PASS`、`LEO PASS` 或生产准入。

- 审计实现基线：`61536f9f02c47a4d79031a47dc8a284f040e41c1`
- 本轮起点 `origin/main`：`9422087b5381bd06be9bc02a32ecdecffceef705`
- 工作分支：`agent/multimodal-incomplete-inspection-round2`
- implementation freeze / artifact source commit：
  `c27294db917097224b2a3b84bae1b65fa6a9ba24`
- 证据文档版本：本文件所在 commit，由 Git/PR history 定位；不把 docs-only commit
  冒充上述构建来源
- 分类器/提取器策略身份（不覆盖 plugin disposition 映射）：`classifier-policy-v2` /
  `bd55065bc3f1fd350148ad8f2f440c8f606aeb02fabd0024d7a350fe23ee4585`
- Draft PR：<https://github.com/yujianwudi/cyber-abuse-guard/pull/5>

## 2. 分阶段 commits

| Commit | 内容 |
|---|---|
| `2e886e5` | 冻结 complete/incomplete/opaque/operational 契约 |
| `43fe9b2` | 统一 JSON/multipart 提取、独立预算和完整度原因 |
| `c698d04` | 集中 disposition，修复 balanced/strict、subject 和 oversize 语义 |
| `b2ebda9` | 扩展 CPA 图片/多模态 Host fixture 和 source format 审计 |
| `e374f33` | README、fuzz 和 benchmark CI 门禁 |
| `1e7fdc4` | 收紧零值状态、UTF-8 截断原因和 opaque 遥测边界 |
| `ddd6606` | 新增第二轮 Leo 复验交接文档 |
| `7afc772` | 对齐 native ABI oversize 旧测试与新 mode 契约 |
| `c27294d` | 将新增提取器源码纳入策略身份并刷新现行哈希 |

`origin/main@9422087` 到 implementation freeze `c27294d` 的精确 tree diff：
31 个文件，3,708 行新增、339 行删除；新增文件 8、修改文件 23、二进制文件 0。

## 3. 关键设计变化

1. Router 使用 `ExtractRequest` / `ExtractUntrustedRequest`，用
   `mime.ParseMediaType` 分派 JSON、`application/*+json` 和 multipart。
2. `Result` 分离 `TextBytesScanned`、`RawBytesObserved`、`Completeness` 和固定、
   去重、稳定排序的 `IncompleteReasons`；保留旧字段供兼容。
3. JSON 媒体 Base64/data URL/URL 不计入普通文本预算；JSON 另有 raw、token、
   node、depth、text part 上限。
4. multipart 使用 `multipart.NewReader`，不调用 `ParseMultipartForm`；文件 part
   流式丢弃，不转字符串、不写临时文件、不进入分类器。
5. multipart 在标准库 MIMEHeader 分配前执行 raw framing/header preflight，兼容
   CRLF 和 Go 标准库接受的 LF-only framing。
6. CPA 图片 handler 可能把 ingress multipart 重建为新 multipart，或转为 JSON 后
   保留旧 multipart Content-Type。提取器只对语法完整的 JSON object/array启用该
   Host 转换兼容，不把 malformed multipart 误判为完整。
7. incomplete disposition 优先于任何已解析前缀的恶意分数；incomplete 不调用
   subject risk evaluation，也不持久化 partial score。
8. CPA 的 `openai-image` 与 `openai-video` 已加入 executor input/output formats 和
   audit canonical enum，避免 self-route 因 format 不受支持而回退到原生 provider。

## 4. 模式行为矩阵

| 状态 | off | observe | audit | balanced | strict |
|---|---|---|---|---|---|
| complete + safe | allow | allow/counter | allow | allow | allow/strict policy |
| complete + audit score | allow | observe | audit | audit | audit/strict policy |
| complete + malicious block | allow | observe | audit | local block | local block |
| incomplete inspection | allow | observe | audit | **allow + audit** | **local block** |
| opaque media + policy audit | allow | observe | audit | allow + audit | allow + audit |
| operational failure | 独立的既有 lifecycle policy，不复用 content disposition |

固定 decision 语义包括 `allow_due_to_incomplete_inspection`；当前持久化 schema 使用
稳定 `action + category`，没有为 decision code 做数据库迁移。

## 5. incomplete reason 与审计 category

固定原因包括：

```text
parse_error
scan_byte_limit
json_depth_limit
json_token_limit
json_node_limit
text_part_limit
text_part_byte_limit
multipart_boundary_limit
multipart_part_limit
multipart_header_limit
multipart_text_limit
multipart_parse_error
unsupported_media_type
unsupported_content_encoding
raw_body_limit
rpc_body_limit
```

审计聚合 category 为 `parse_error`、`scan_limit`、`json_depth_limit`、
`text_part_limit`、`multipart_limit`、`unsupported_content_type`、
`rpc_body_limit` 或 `incomplete_inspection`。不保存原始 parser error、Content-Type
参数、boundary、field name、filename、URL 或 payload。

## 6. 资源边界

| 资源 | 默认 | 硬上限/插件边界 |
|---|---:|---:|
| 提取文本 | 256 KiB | 4 MiB |
| 原始 body | 16 MiB | 64 MiB；Router 另受 8 MiB RPC envelope 限制 |
| JSON depth | 32 | 128 |
| JSON tokens | 65,536 | 1,048,576 |
| JSON nodes | 32,768 | 1,048,576 |
| text parts | 512 | 4,096 |
| 单 text part | 16 KiB | 1 MiB |
| multipart boundary | 70 B | 256 B |
| multipart parts | 1,024 | 4,096 |
| part headers | 32 | 256 |
| part header bytes | 16 KiB | 1 MiB |
| multipart text fields | 512 | 4,096 |
| multipart aggregate text | 256 KiB | 4 MiB |
| multipart text field | 16 KiB | 1 MiB |

媒体字节只计入 raw body，不减少 `TextBytesScanned`。

## 7. 本地验证结果

没有启动或部署本地 CPA。以下均为 Go 包级、fixture compile-only 或纯本地工具验证。

| 命令/门禁 | 结果 | 证据等级 |
|---|---|---|
| `go mod verify`; `go mod tidy -diff`（根模块和 pluginstorecontract） | PASS | UNIT TEST |
| `go test ./internal/extract ./internal/config ./internal/audit ./internal/subject -count=1` | PASS | UNIT TEST |
| `go test ./internal/plugin -count=1` | PASS | UNIT TEST |
| `go test -race ./internal/extract ./internal/config ./internal/plugin ./internal/subject -count=1` | PASS | UNIT TEST |
| `go vet`：extract/config/plugin/classifier/subject/audit | PASS | SOURCE REVIEW |
| integration tags，`-run '^$'` | PASS，compile-only；未执行 Host | SOURCE REVIEW |
| `FuzzExtractText`，2s | PASS，8,303 execs | UNIT TEST |
| `FuzzExtractRequestContentType`，2s | PASS，23,966 execs | UNIT TEST |
| `FuzzExtractRequestMultipart`，2s | PASS，14,978 execs | UNIT TEST |
| classifier performance acceptance | p50 118.748 µs；p95 275.084 µs；p99 540.613 µs | UNIT TEST |
| classifier concurrency/resource sanity | 10,000 classifications；goroutines 2→2 | UNIT TEST |
| `go test ./internal/classifier -run=^TestClassifierPolicyIdentity$ -count=1` | PASS；策略哈希 `bd55065...` | UNIT TEST |
| `release-evidence-privacy-test.sh`（经 `make script-test`） | PASS；CI `operational-script-security` | GITHUB CI |

最新 multipart benchmark（Linux amd64，3 次）：

| Fixture | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| 1 MiB file + small prompt | 847,316 | 50,936 | 58 |
| 8 MiB file + small prompt | 5,506,003 | 50,936 | 58 |

额外分配没有随 1 MiB→8 MiB 文件大小等量增长。

本次证据续跑所在 Windows 会话为 `CGO_ENABLED=0`，因此涉及 `go-sqlite3` 的
`cmd/cyber-abuse-guard` / `internal/plugin` 定向复跑在本机会报
`SQLiteConn.Backup undefined`。这属于本地 CGO 工具链不可用，不作为产品失败；同一
代码在下述 pinned Linux GitHub CI 的 unit-test、race、vet 与 Host 构建中通过。

## 8. CPA Host fixture 覆盖

以下矩阵未在本机启动 CPA；已由 pinned Linux GitHub runner 安装的官方 CPA v7.2.72
Store-installed Host fixture 执行并通过（证据等级 `HOST FIXTURE` / `GITHUB CI`）：

- OpenAI Chat、Responses、Anthropic、Gemini 回归；
- JSON audio/data URL 媒体不进入文本分类，恶意文本仍阻断；
- `/v1/images/generations` safe/block；
- `/v1/images/edits` JSON safe/block；
- `/v1/images/edits` multipart 大文件 + 小 prompt；
- 文件字节包含恶意关键词但 safe prompt 不误报；
- malicious prompt + safe file 本地阻断；
- balanced malformed/scan/RPC oversize 继续 Auth/Provider/Mock upstream，usage +1；
- strict 对应请求本地 403，Auth/Provider/upstream/usage 增量 0；
- guard enabled/disabled JSON raw upstream fingerprint；
- multipart 排除 CPA 随机 boundary 后的 canonical semantic fingerprint；
- malformed ingress multipart 标为 `HOST_PREVALIDATION`，不归功于插件。

Push/PR 两条 CI 的 `build-linux-amd64-and-CPA-v7.2.72-store-installed-host` 步骤均为
`success`。这证明 GitHub runner 上的官方 Host 安装、`.so` 加载和 fixture 契约，
但不等同于腾讯云二号机 `REAL CPA ISOLATED HOST` 复验。

CPA v7.2.72 源码确认：

- 公开支持图片和视频 route；
- 没有公开 `/v1/audio/*` 或 `/v1/files` route，标记 `HOST_UNSUPPORTED`；
- Chat/Responses 等 JSON 中的 audio/file 载体仍可由插件检查；
- ingress multipart 图片在 Router 前已由 CPA 解析/转换，插件不能声称看到原 ingress
  boundary/order/header。

## 9. CI 与 artifact

两条 run 都绑定 implementation freeze
`c27294db917097224b2a3b84bae1b65fa6a9ba24`：

| Event | Run | quality-and-artifacts | reproducibility | fuzz-long |
|---|---|---|---|---|
| push | [29331122678](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29331122678) | success | success | success |
| pull_request | [29331125309](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29331125309) | success | success | skipped（仅 push 运行，符合 workflow 条件） |

Canonical candidate 使用 push run 的 artifact：

| 字段 | 值 |
|---|---|
| name / id | `cyber-abuse-guard-linux-amd64-dirty` / `8310297554` |
| GitHub archive size | 10,484,112 bytes |
| GitHub archive digest | `sha256:99944b39ef5c302a6c7aa875b975ec57c830e6e855ee09cab22be6fa73715129` |
| created / expires | `2026-07-14T12:16:49Z` / `2026-10-12T12:04:05Z` |
| build metadata commit | `c27294db917097224b2a3b84bae1b65fa6a9ba24` |

GitHub archive digest 是 Actions 压缩容器身份，不是 `.so` SHA-256。下载解包后的 9 个
文件已逐一独立计算：

| 文件 | bytes | SHA-256 |
|---|---:|---|
| `build-metadata.json` | 400 | `9c68de871ccf2be746677febaeba9e4ddd94908cf5b4beba14cbf5d831500b7e` |
| `checksums.txt` | 768 | `d2b74998f7ac234493cf5bc4d9023dfced34c622f67859277ca81e298c536a6c` |
| `cyber-abuse-guard_0.1.2-dirty_linux_amd64.zip` | 3,433,903 | `bd96ef8595639341a69f06d6d4e9bda3dfac4c0f73d856eb45375333d5c561ed` |
| `cyber-abuse-guard-v0.1.2-dirty.so` | 8,303,688 | `226771590f3081aa5c687c6847a2816ef4c893c1c413ffd50473e270a99dd4a3` |
| `cyber-abuse-guard-v0.1.2-dirty.so.sha256` | 100 | `7fa52dcdf155dfde060b2ff72089adf708d61e0d180a5ee137b041e15395eb78` |
| `cyber-abuse-guard-v0.1.2-dirty-audit-bundle.zip` | 3,592,236 | `e021c9a453aafb3e0625f748930bd97a8bd63c79bc4047836d402668b0429d12` |
| `ruleset.sha256` | 88 | `a8ff687340617dc18832047f841979a0bd06ff8c50a4bc3c15dd7da37b6fbee2` |
| `ruleset-manifest.json` | 1,475 | `486a4dfad49b4e96a600f908cbea47376baab5c8875324999ae50b6251f1af7e` |
| `sbom.cdx.json` | 5,919 | `3990029ecc17936fc054ee275d4ba114c3bcc917fe851dc3cd8c623a2a668666` |

一致性核验：

- `checksums.txt` 的 8 个条目全部与独立 SHA-256 匹配；
- `.so.sha256`、外层 `.so`、Store ZIP 内 `.so`、audit bundle 内 `.so` 全部为
  `226771590f3081aa5c687c6847a2816ef4c893c1c413ffd50473e270a99dd4a3`；
- audit bundle 内的 build metadata、ruleset manifest/hash、SBOM 与外层副本哈希一致；
- 两个 ZIP 均无重复/大小写碰撞、绝对路径、盘符、反斜杠、路径穿越、NUL、symlink
  或 encrypted entry；受限 report entry 只核对中央目录元数据，未解压或读取正文；
- reproducibility job 为 `success`。

静态 ELF/ABI 结果：

- ELF64、little-endian、System V、ABI version 0、`DYN`、x86-64、stripped，BuildID
  `937bbbabe2b13f2a0598ce48b7a88acef74b3030`；
- 唯一 `NEEDED` 为 `libc.so.6`，最高 symbol version 需求为 `GLIBC_2.34`；
- Go `1.26.4`，`-buildmode=c-shared`，`CGO_ENABLED=1`，`GOOS=linux`，
  `GOARCH=amd64`，`GOAMD64=v1`，`-trimpath`，tag `sqlite_omit_load_extension`；
- `cliproxy_plugin_init`、`cliproxyPluginCall`、`cliproxyPluginFree`、
  `cliproxyPluginShutdown` 四个 Host ABI 导出均存在；
- 两条 CI 的 CPA v7.2.72 Store-installed Host build/load 步骤均为 `success`。

未创建 tag 或 GitHub Release；该 artifact 只能作为 dirty candidate 供 Leo/腾讯二号机
隔离复验，不能称为正式 release。

## 10. 已知限制

1. `encoding/json.Decoder.Token` 对单个大型媒体字符串仍会产生受 raw 上限约束的临时
   string 分配；完全常量额外内存需要后续自定义 JSON tokenizer。
2. 大 JSON 媒体 body 为避免第二次 `RawMessage` 大对象解析，会跳过 role index，转用
   conservative parts；这不消耗媒体文本预算，但仍是后续可优化的角色精度/内存权衡。
3. audit schema 尚未持久化 decision code；action/category/counters 已表达本轮策略。
4. GitHub Host fixture 不能替代腾讯云二号机真实隔离环境。
5. CPA 未加载、注册失败、被 fuse、被高优先级 Router 抢先或 self executor 不 ready
   时仍存在 Host 级 fail-open，插件无法单独消除。
6. `classifier-policy-v2` 身份覆盖 classifier/extract/rules 与依赖锁，不覆盖
   `internal/plugin/disposition.go` 的全部 enforcement mapping；完整 provenance 仍需 Git
   commit 与 artifact hash 共同定位。

## 11. Leo / 腾讯二号机复验步骤

1. 固定候选 commit `c27294d`、push run `29331122678` 和 `.so` SHA-256
   `226771590f3081aa5c687c6847a2816ef4c893c1c413ffd50473e270a99dd4a3`。
2. 仅在 `cpa-v7272-test` + `cpa-mock-upstream`、`127.0.0.1:18317` 执行。
3. 确认 plugin inventory、priority、`openai-image`/`openai-video` executor readiness。
4. 对每个 case 记录合成 request ID、status、Content-Type、Mock `/stats` 前后值、access
   log、Auth/Provider/usage delta、audit action/category。
5. 对 allow case 比较 guard enabled/disabled 的 upstream payload/header 指纹。
6. 对 block case确认 SSE 前同步拒绝、upstream delta 0、usage delta 0。
7. 将 CPA prevalidation 400/404 与插件策略结果分开记录。
8. 不连接真实号池或真实 upstream；不修改洛杉矶生产 CPA。

## 12. 合规声明与方法限制

- 未部署或修改洛杉矶生产 CPA，未连接真实账号池/真实 upstream。
- 未创建 release tag 或 GitHub Release。
- 未打开、恢复或重跑 evaluation-v10 / 退休 holdout 样本 JSONL，未将样本正文用于
  实现或调参；CI 仅执行既有冻结 aggregate-boundary regression gate。
- 本轮 artifact 静态核验只枚举 audit bundle entry 名称/大小，并读取、哈希明确的安全
  元数据/二进制；没有打开 evaluation/holdout 报告正文或任何样本 JSONL。
- 实施过程中有三次过宽的源码检索/错误 glob，意外显示了受限路径名、gate/source
  reference 行以及少量受限路径行；发现后立即停止。没有主动打开、恢复或重跑
  evaluation-v10/retired holdout JSONL，没有把意外输出用于任何实现判断。该方法学例外
  必须保留给 Leo 审计，不应改写为“零触及”。
