# Cyber Abuse Guard 第二轮优化：Leo 复验交接

## 1. 当前状态

**PARTIAL — implementation candidate**

P0 源码修复、单元测试、race、vet、fuzz、benchmark 和 CPA Host fixture
编译已经完成。GitHub CI 与腾讯云二号机隔离 CPA + Mock upstream 的真实协议矩阵尚未
形成最终证据，因此本文件不声明 `PASS`、`LEO PASS` 或生产准入。

- 审计实现基线：`61536f9f02c47a4d79031a47dc8a284f040e41c1`
- 本轮起点 `origin/main`：`9422087b5381bd06be9bc02a32ecdecffceef705`
- 工作分支：`agent/multimodal-incomplete-inspection-round2`
- 当前候选 HEAD：`1e7fdc41892de72938336cc922391570e4028051`
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

相对 `origin/main`：24 个文件，约 3,471 行新增、330 行删除。

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
| integration tags，`-run '^$'` | PASS，compile-only | HOST FIXTURE |
| `FuzzExtractText`，2s | PASS，8,303 execs | UNIT TEST |
| `FuzzExtractRequestContentType`，2s | PASS，23,966 execs | UNIT TEST |
| `FuzzExtractRequestMultipart`，2s | PASS，14,978 execs | UNIT TEST |
| classifier performance acceptance | p50 118.748 µs；p95 275.084 µs；p99 540.613 µs | UNIT TEST |
| classifier concurrency/resource sanity | 10,000 classifications；goroutines 2→2 | UNIT TEST |

最新 multipart benchmark（Linux amd64，3 次）：

| Fixture | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| 1 MiB file + small prompt | 847,316 | 50,936 | 58 |
| 8 MiB file + small prompt | 5,506,003 | 50,936 | 58 |

额外分配没有随 1 MiB→8 MiB 文件大小等量增长。

## 8. CPA Host fixture 覆盖

已编译但尚未在本机执行：

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

CPA v7.2.72 源码确认：

- 公开支持图片和视频 route；
- 没有公开 `/v1/audio/*` 或 `/v1/files` route，标记 `HOST_UNSUPPORTED`；
- Chat/Responses 等 JSON 中的 audio/file 载体仍可由插件检查；
- ingress multipart 图片在 Router 前已由 CPA 解析/转换，插件不能声称看到原 ingress
  boundary/order/header。

## 9. CI 与 artifact

当前 run：

- Push CI：<https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29329495186>
- PR CI：<https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29329590706>

本文件首次提交时 CI/artifact 可能仍在运行。最终复验必须补录 job 结论、artifact
文件列表、大小、SHA-256、ELF/ABI 信息。未创建 tag 或 GitHub Release。

## 10. 已知限制

1. `encoding/json.Decoder.Token` 对单个大型媒体字符串仍会产生受 raw 上限约束的临时
   string 分配；完全常量额外内存需要后续自定义 JSON tokenizer。
2. 大 JSON 媒体 body 为避免第二次 `RawMessage` 大对象解析，会跳过 role index，转用
   conservative parts；这不消耗媒体文本预算，但仍是后续可优化的角色精度/内存权衡。
3. audit schema 尚未持久化 decision code；action/category/counters 已表达本轮策略。
4. GitHub Host fixture 不能替代腾讯云二号机真实隔离环境。
5. CPA 未加载、注册失败、被 fuse、被高优先级 Router 抢先或 self executor 不 ready
   时仍存在 Host 级 fail-open，插件无法单独消除。

## 11. Leo / 腾讯二号机复验步骤

1. 固定候选 commit 和 GitHub artifact SHA-256。
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
- 未把 evaluation-v10 或退休 holdout 用于实现、调参或结论。
- 实施过程中有三次过宽的源码检索/错误 glob，意外显示了受限路径名、gate/source
  reference 行以及少量受限路径行；发现后立即停止。没有主动打开、恢复或重跑
  evaluation-v10/retired holdout JSONL，没有把意外输出用于任何实现判断。该方法学例外
  必须保留给 Leo 审计，不应改写为“零触及”。
