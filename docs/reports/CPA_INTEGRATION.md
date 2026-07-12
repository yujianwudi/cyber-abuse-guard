# CPA v7.2.67 Integration Report — v0.1.1

Date: 2026-07-12 (Asia/Shanghai)

Host under test: real CLIProxyAPI `v7.2.67` Plugin Host at commit
`2075f77c8ebe9ec872759965661936fb1ac2931f`. The test imports CPA's public
`sdk/cliproxy`, starts the actual service and native loader, copies the built
ELF into `plugins/linux/amd64`, and uses a local `httptest` OpenAI-compatible
Mock Upstream with an atomic call counter.

Command:

```bash
make integration-test
```

Final release-gate result: PASS (`cyber-abuse-guard/integration`, 0.950 s in the recorded
run).

## Verified behavior

| Assertion | Result |
|---|---|
| `.so` discovered and `dlopen`-loaded | PASS; host logged `plugin loaded` |
| ABI metadata accepted and registered | PASS; host logged `plugin registered` |
| Wrong/missing Management Key rejected | PASS; HTTP 401 |
| Correct Management Key accepted | PASS; HTTP 200 |
| Safe OpenAI Chat follows CPA native path unchanged | PASS; HTTP 200, original model/role/content preserved, Mock Upstream +1 |
| Safe role-aware policy/refusal context | PASS; HTTP 200 and Mock Upstream +1 |
| Safe requests prove auth-selection and usage probes are live | PASS; injected CPA `auth.Selector` count > 0 and usage queue receives records |
| Risky OpenAI Chat request | PASS; HTTP 403, no auth selection, upstream call, or usage record |
| Risky OpenAI Tool Call with nested `data` argument | PASS; HTTP 403, no auth selection, upstream call, or usage record |
| Risky tool payload field named `name` | PASS; HTTP 403, no auth selection, upstream call, or usage record |
| Unrelated negation followed by an abuse directive | PASS; HTTP 403, no auth selection, upstream call, or usage record |
| User abuse + assistant refusal + “now give code” follow-up | PASS; HTTP 403, no auth selection, upstream call, or usage record |
| Risky OpenAI Responses request | PASS; HTTP 403, no auth selection, upstream call, or usage record |
| Risky Anthropic Messages request | PASS; HTTP 403, no auth selection, upstream call, or usage record |
| Risky Anthropic `tool_use.input.name` payload | PASS; HTTP 403, no auth selection, upstream call, or usage record |
| Risky Gemini `generateContent` request | PASS; HTTP 403, no auth selection, upstream call, or usage record |
| Raw body >6 MiB producing an RPC >8 MiB | PASS; no-copy fail-closed HTTP 403 in approximately 94 ms, no auth selection, upstream call, or usage record |
| Risky streaming request | PASS; pre-stream HTTP 403, prompt termination, no auth selection, upstream call, or usage record |
| Invalid reconfigure | PASS; previous Balanced runtime retained and still blocks |
| Valid reconfigure to Audit | PASS; risky request allowed to Mock Upstream |
| Plugin disable | PASS; `effective_enabled:false`, native behavior restored |
| Shutdown | PASS; host logged `plugin unloaded` |

The harness injects a counting selector through CPA's public
`Builder.WithCoreAuthManager` seam. It first proves the selector and usage queue
with safe requests, drains those usage records, and resets both auth and
upstream counters. It then asserts zero auth selections and zero Mock Upstream
calls across all locally blocked cases, followed by an empty CPA usage queue.
This directly verifies that local enforcement occurs before provider auth
scheduling and upstream token accounting.

The oversized case sends a raw JSON body slightly above 6 MiB. Base64 encoding
inside `ModelRouteRequest` expands the native RPC beyond its 8 MiB boundary-copy
budget, exercising the method-specific no-copy route rather than ordinary body
scanning. Balanced mode returns a local policy refusal without copying the
oversized RPC into Go and without entering CPA auth or upstream execution.

CPA v7.2.67 normalizes executor errors into Anthropic's native
`policy_violation` envelope and drops custom `code`/`category` fields for that
protocol. Ordinary OpenAI and Gemini blocks preserve the stable
`cyber_abuse_guard_blocked` marker; the oversized no-copy OpenAI executor error
is normalized to CPA's generic 403 code but retains the local refusal message.
A stream is rejected before an SSE stream is established because the ABI cannot
attach an HTTP 403 to a successful terminal SSE frame.

The test deliberately waits for plugin status to confirm completion of an
invalid reconfigure before submitting the next valid config. CPA's file watcher
may coalesce immediately adjacent management writes; this wait reflects the
asynchronous management contract and avoids testing an update the host has not
delivered yet.
