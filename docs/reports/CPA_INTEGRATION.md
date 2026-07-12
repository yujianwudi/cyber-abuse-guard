# CPA v7.2.67 Integration Report — v0.1.0

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

Final result: PASS (`cyber-abuse-guard/integration`, 0.877 s in the recorded
run).

## Verified behavior

| Assertion | Result |
|---|---|
| `.so` discovered and `dlopen`-loaded | PASS; host logged `plugin loaded` |
| ABI metadata accepted and registered | PASS; host logged `plugin registered` |
| Wrong/missing Management Key rejected | PASS; HTTP 401 |
| Correct Management Key accepted | PASS; HTTP 200 |
| Safe OpenAI Chat follows CPA native path unchanged | PASS; HTTP 200, original model/role/content preserved, Mock Upstream +1 |
| Safe request proves auth-selection probe is live | PASS; injected CPA `auth.Selector` count > 0 |
| Risky OpenAI Chat request | PASS; HTTP 403, Mock Upstream remains 0 |
| Risky OpenAI Tool Call with nested `data` argument | PASS; HTTP 403, Mock Upstream remains 0 |
| Risky OpenAI Responses request | PASS; HTTP 403, Mock Upstream remains 0 |
| Risky Anthropic Messages request | PASS; HTTP 403, Mock Upstream remains 0 |
| Risky Gemini `generateContent` request | PASS; HTTP 403, Mock Upstream remains 0 |
| Risky streaming request | PASS; pre-stream HTTP 403, prompt termination, Mock Upstream remains 0 |
| Blocked requests do not enter CPA auth selection | PASS; injected selector count remains 0 |
| Blocked requests do not create CPA upstream usage | PASS; usage queue stays empty |
| Invalid reconfigure | PASS; previous Balanced runtime retained and still blocks |
| Valid reconfigure to Audit | PASS; risky request allowed to Mock Upstream |
| Plugin disable | PASS; `effective_enabled:false`, native behavior restored |
| Shutdown | PASS; host logged `plugin unloaded` |

The harness injects a counting selector through CPA's public
`Builder.WithCoreAuthManager` seam. It first proves the probe with a safe
request, resets the count, then asserts zero selections across all locally
blocked calls. This directly verifies that the provider auth scheduler is not
entered. The result matches CPA's source ordering: `ModelRouter` dispatches a
self-target to the plugin executor before the native `AuthManager.Execute`
path. The test also drains a known-safe usage record and verifies that blocked
calls leave the usage queue empty, independently proving that upstream token
accounting is skipped.

CPA v7.2.67 normalizes executor errors into Anthropic's native
`policy_violation` envelope and drops custom `code`/`category` fields for that
protocol. OpenAI and Gemini preserve the stable
`cyber_abuse_guard_blocked` marker. A stream is rejected before an SSE stream is
established because the ABI cannot attach an HTTP 403 to a successful terminal
SSE frame.

The test deliberately waits for the plugin status to confirm completion of an
invalid reconfigure before submitting the next valid config. CPA's file watcher
may coalesce immediately adjacent management writes; this wait reflects the
asynchronous management contract and avoids testing an update that the host has
not delivered yet.
