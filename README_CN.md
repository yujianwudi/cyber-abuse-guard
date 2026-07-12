# CPA Cyber Abuse Guard 本地封控插件

Cyber Abuse Guard 是面向
[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)（CPA）的本地原生安全插件。
它在 Provider 解析和账号调度之前分析请求，把明确的操作性 Cyber Abuse 请求在本地
阻断，同时尽量放行防御分析、漏洞修复、CTF/靶场、事件响应和明确授权测试。

插件版本 `0.1.1`；目标为 CPA `v7.2.67`，commit
`2075f77c8ebe9ec872759965661936fb1ac2931f`；Linux amd64；C ABI/RPC schema v1。
发布二进制兼容官方 Debian Bookworm CPA 镜像，需要 glibc 2.34 或更高版本，
不支持 musl/Alpine 环境。

> 本插件只能降低风险，不能保证上游账号永不收到警告、永不暂停或永不封禁。
> 上游平台仍会独立执行自己的安全策略。

## 工作原理

插件注册 CPA `ModelRouter` 和本地 Executor：

- 安全请求返回 `Handled: false`，不改模型、不改身份、不改系统提示，继续走 CPA 原生链路；
- 风险请求返回 `Handled: true, TargetKind: self`，由本地 Executor 在流建立前返回
  HTTP 403；它不调用 Provider、Host HTTP callback 或 Host model callback，因此原始
  风险请求不会进入上游账号池。

分类器要求“伤害意图 + 危险对象/影响 + 操作化、真实目标、规避或规模证据”的组合，
不是单关键词黑名单。内置规则集版本为 `1.0.1`，支持中英文、大小写、零宽字符、空格标点和轻度混淆，
同时显式识别防御、修复、静态分析、CTF/靶场和授权上下文。

插件不会：

- 伪装 Antigravity、Codex、Claude Code 等客户端身份；
- 修改模型名、系统提示或安全声明；
- 读取 CPA Auth/OAuth 文件；
- 执行 Shell 或用户代码；
- 向额外分类器或第三方上传 Prompt、Token、Cookie 或 API Key；允许的请求仍会按
  CPA 配置正常发送到上游模型；
- 代替上游安全系统。

设计细节见 [设计说明](docs/DESIGN.md)、[威胁模型](docs/THREAT_MODEL.md) 和
[已知限制](docs/LIMITATIONS.md)；后续版本建议见
[docs/NEXT_VERSION.md](docs/NEXT_VERSION.md)。
安全漏洞请按 [SECURITY.md](SECURITY.md) 通过私密渠道报告。

验收证据见[测试报告](docs/reports/TEST_REPORT.md)、
[性能报告](docs/reports/PERFORMANCE.md)、[误报与召回报告](docs/reports/CORPUS_REPORT.md)
和 [CPA v7.2.67 集成报告](docs/reports/CPA_INTEGRATION.md)。最终 Balanced 语料结果为
误报 0/142（0.00%）、明确恶意召回 154/154（100.00%）；在报告所列测试机上，
10,000 次本地判断的 P95 为 53.809 微秒。

## 构建与测试

需要 Linux amd64（glibc 2.34 或更高版本）、Go 1.26.0、C 编译器、`make`、
`file`、`zip`、`unzip` 和 GNU `sha256sum`。CPA 与插件都必须启用 cgo；
不支持 musl/Alpine。Go 1.26 不在 `PATH` 时可显式传入，
例如 `GO=/opt/go1.26/bin/go make test`。Windows 用户可在 amd64 WSL 中执行：

```bash
make test
make race
make fuzz-smoke
make build-linux-amd64
make integration-test
make release
```

发布产物：

```text
dist/cyber-abuse-guard-v0.1.1.so
dist/cyber-abuse-guard-v0.1.1.so.sha256
dist/cyber-abuse-guard_0.1.1_linux_amd64.zip
dist/checksums.txt
```

`make release` 会在打包前运行锁定版本的真实 CPA 集成测试；
`make verify-release` 还会拒绝依赖高于 `GLIBC_2.34` 符号版本的二进制。

也可以使用测试镜像：

```bash
docker build -f Dockerfile.test -t cyber-abuse-guard-test .
docker run --rm cyber-abuse-guard-test
```

## Docker 安装

1. 校验下载文件：

   ```bash
   sha256sum -c cyber-abuse-guard-v0.1.1.so.sha256
   ```

2. 放到 CPA 首选的平台目录，并创建权限收紧的数据目录：

   ```bash
   mkdir -p ./plugins/linux/amd64 ./plugin-data/cyber-abuse-guard
   install -m 0755 cyber-abuse-guard-v0.1.1.so \
     ./plugins/linux/amd64/cyber-abuse-guard-v0.1.1.so
   chmod 0700 ./plugin-data/cyber-abuse-guard
   ```

3. 挂载目录并设置 HMAC 密钥：

   ```yaml
   services:
     cli-proxy-api:
       volumes:
         - ./plugins:/CLIProxyAPI/plugins:ro
         - ./plugin-data:/root/.cli-proxy-api/plugins
       environment:
         CYBER_ABUSE_GUARD_HMAC_KEY: ${CYBER_ABUSE_GUARD_HMAC_KEY}
   ```

4. 把 [config.example.yaml](config.example.yaml) 中的配置放到
   `plugins.configs.cyber-abuse-guard`。首次部署先使用 `mode: audit`，保留
   `subject_control.max_subjects: 10000`，本地核查判断结果后再切换为 `balanced`；
   确认新插件正常后禁用旧的身份改写过滤器。

5. 重启并验证：

   ```bash
   docker compose restart cli-proxy-api
   docker compose logs cli-proxy-api | grep -E 'plugin (loaded|registered)'
   curl -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
     http://127.0.0.1:8317/v0/management/plugins/cyber-abuse-guard/status
   ```

完整安装、升级和回滚步骤见 [docs/INSTALL_DOCKER.md](docs/INSTALL_DOCKER.md)。

## 模式

| 模式 | 行为 |
|---|---|
| `off` | 完全跳过扫描、统计、审计和阻断。 |
| `observe` | 只更新内存聚合统计，不保存逐请求事件，不阻断。 |
| `audit` | 保存最小审计事件，不阻断。 |
| `balanced` | 默认；达到均衡阈值时阻断明确的操作性滥用。 |
| `strict` | 达到审计阈值即阻断；v0.1.1 不实现 challenge。 |

主体风险状态默认最多保留 10,000 项。容量满时淘汰最久未出现风险的非人工封控主体；
人工封控主体不会被容量淘汰，如果已无可淘汰条目，新风险主体会保守阻断。

请把 `CYBER_ABUSE_GUARD_HMAC_KEY` 设置为至少 32 字节的高熵随机秘密。
插件不保存密钥明文。没有稳定密钥时会使用进程级临时密钥，并在状态接口报告重启后
主体哈希无法连续关联。

`classifier` 与 `trusted_proxy` 的启用开关是后续版本预留接口。v0.1.1 在它们被设为
`true` 时会明确拒绝配置，不会静默制造“已经启用但实际上未生效”的安全错觉。

## 管理接口

以下路由全部先经过 CPA Management Key 鉴权：

```text
GET    /v0/management/plugins/cyber-abuse-guard/status
GET    /v0/management/plugins/cyber-abuse-guard/events
GET    /v0/management/plugins/cyber-abuse-guard/stats
POST   /v0/management/plugins/cyber-abuse-guard/test
POST   /v0/management/plugins/cyber-abuse-guard/subjects/unblock
DELETE /v0/management/plugins/cyber-abuse-guard/events
```

状态响应以 `started_at` 表示进程内插件启动时间，以 `configured_at` 表示最近一次成功
配置时间；兼容热更新不会改变 `started_at`。其中 `subject_control` 容量快照包含
`subjects`、`max_subjects`、`manual_blocked`、`evicted` 和 `rejected_capacity`。

解除主体封控的请求体：

```json
{"subject_hash":"hmac-sha256:..."}
```

CPA v7.2.67 的插件管理路由只支持精确路径，不支持 `{hash}` 动态段，因此采用固定路径
和 JSON 请求体。插件不注册任何未鉴权的审计页面。

## 隐私

审计事件只包含时间、动作、模式、粗粒度分类、分数、规则 ID、请求 SHA-256、主体
HMAC、模型、协议、流标志、扫描字节数和延迟等最小字段。默认绝不保存原始 Prompt、
Messages、Authorization、明文 Key/IP、Cookie、OAuth Token、上传代码或上游账号身份。
如果请求在 native no-copy RPC 大小边界直接被拒绝，只记录最小 `scan_limit` 事件，
不会伪造当时不可获得的请求哈希、模型、协议或扫描字节数。

## 回滚

把 `plugins.configs.cyber-abuse-guard.enabled` 设为 `false`，重启 CPA 并确认
`effective_enabled: false`，随后可删除 `.so`。是否删除审计数据库由管理员显式决定，
无需重装 CPA。
