# CPA v7.2.67 Integration Report — v0.1.2 candidate

## Status

The v0.1.2 candidate integration run is **PASS**. It built and loaded the current
dirty-suffixed development artifact through the real CPA v7.2.67 Plugin Host;
this is engineering evidence only. Methodologically valid evaluation v10 is
`CONSUMED / FAIL`, so no clean `v0.1.2` release tag or production artifact may
be created. Integration PASS cannot override the failed release gate.

Target host: CLIProxyAPI `v7.2.67` at commit
`2075f77c8ebe9ec872759965661936fb1ac2931f`, CPA C ABI/RPC schema v1.

Final command:

```bash
make integration-test
```

The test must build/load the exact release-candidate `.so`, start the real CPA
Plugin Host and native loader, use a local counting Mock Upstream, inject a
counting CPA auth selector and usage-queue probe, and avoid all real providers.

## Mandatory assertions

| Assertion | Final result |
|---|---|
| ELF discovered, `dlopen` loaded, ABI metadata registered | **PASS** |
| Runtime version/commit/dirty/ruleset version/hash match build metadata | **PASS** |
| `loaded=true`, `enforcement_ready=true`, expected mode/priority | **PASS** |
| Missing Management Key returns 401 | **PASS** |
| Wrong Management Key returns 401 | **PASS** |
| Ordinary downstream client key cannot use management routes | **PASS** |
| Correct Management Key returns 200 | **PASS** |
| Oversized management body/query/path/method rejected safely | **PASS** |
| Safe OpenAI Chat reaches mock unchanged | **PASS** |
| Safe OpenAI Responses reaches mock unchanged | **PASS** |
| Safe Anthropic Messages/Tool reaches mock unchanged | **PASS** |
| Safe Gemini reaches mock unchanged | **PASS** |
| Safe tool arguments/model/client/system behavior unchanged | **PASS** |
| Risky OpenAI Chat returns local 403 | **PASS** |
| Risky Responses returns local 403 | **PASS** |
| Risky Anthropic and tool input return local 403 | **PASS** |
| Risky Gemini returns local 403 | **PASS** |
| Risky streaming request is rejected before stream establishment | **PASS** |
| Multi-turn follow-up/history padding/unknown role cannot hide risk | **PASS** |
| URL/HTML/Base64/JSON/tool double encoding uses bounded production path | **PASS** |
| Every blocked case leaves Mock Upstream call count at zero | **PASS** |
| Every blocked case leaves CPA Auth Selector count at zero | **PASS** |
| Every blocked case leaves usage queue empty | **PASS** |
| Opaque media follows explicit and mode-aware policy | **PASS (unit + host-path policy tests)** |
| HTTPS media URL is never fetched | **PASS (unit + host-path policy tests)** |
| Raw body >6 MiB / RPC >8 MiB is no-copy local 403 in Balanced | **PASS** |
| Injected ModelRouter panic/error increments status and self-routes in Balanced | **PASS (router fault tests)** |
| SQLite unavailable/locked does not weaken local block | **PASS (fault tests)** |
| Invalid reconfigure retains last valid runtime and exposes error | **PASS** |
| HMAC/persistence degradation is visible without secret output | **PASS** |
| Built-in health probes remain local and non-mutating | **PASS** |
| Plugin disable restores native CPA behavior | **PASS** |
| Shutdown completes within its bound | **PASS** |

## Allowed-request integrity

The Mock Upstream must receive the exact original safe model name, text, role
history, stream setting, and tool arguments. The plugin must not add or modify:

- a client identity or impersonation header;
- model aliases or provider selection;
- System Prompt, safety declaration, or educational preface;
- request text or tool JSON;
- an auxiliary classifier request.

Auth-selector and usage probes must first be shown live with a safe request;
otherwise a zero count on blocked requests is not meaningful.

## Blocked-request isolation

For each blocked protocol/shape, assert all three counters after resetting and
draining the safe-request control:

```text
mock_upstream_call_count == 0
auth_selector_call_count == 0
usage_queue_no_blocked_request == true
```

This is a release redline. A block response alone is insufficient if the raw
request has already entered auth scheduling, usage accounting, or upstream.

## Health and fail-open verification

CPA v7.2.67 may continue native routing after a Router error, and a panic can
fuse a plugin. The test must exercise the plugin's mode-aware recovery:

- in a validated Balanced/Strict runtime, known Router failures and recovered
  `model.route` panics return `Handled=true, TargetKind=self` with ABI return
  code zero;
- the local executor rejects the request and no auth/upstream/usage occurs;
- `router_errors` and `panics_recovered` increase as appropriate;
- non-Router callback panics still return a parseable internal error and a
  non-zero ABI failure signal;
- status/read-only watchdog alarms on counter deltas or unready state.

This mitigation cannot change CPA's host-level fail-open policy and is not a
guarantee against every future host or ABI failure.

The test must also call the authenticated built-in benign/malicious health
probes and verify `local_only=true`, `upstream_attempted=false`. Those routes
must not mutate audit events, subject state, CPA configuration, or accounts.

## CPA ABI-v1 response constraints

`ExecutorResponse` has no plugin-controlled HTTP status field. A blocked
request therefore uses an RPC error envelope so CPA returns HTTP 403. A blocked
stream is rejected before SSE is established; ABI v1 cannot provide both a 403
and a successful terminal SSE frame. Protocol adapters may normalize custom
error fields, especially Anthropic. The security assertion is the local 403 and
zero auth/upstream/usage, not identical JSON across protocols.

CPA ABI v1 cannot enumerate Router ordering or the active plugin directory.
Integration can validate the controlled fixture, but production still requires
manual confirmation that no higher-priority Router bypasses this plugin and
that only one `cyber-abuse-guard` `.so` is active.

## Final evidence block

```text
release_commit_tag_and_artifact_hashes: NOT CREATED — RELEASE BLOCKED
ruleset_version: 1.0.7
ruleset_sha256: 7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134
cpa_version: v7.2.67
cpa_commit: 2075f77c8ebe9ec872759965661936fb1ac2931f
command_exit_status: 0
integration_log_sha256: candidate evidence only; no formal tagged release log
overall_cpa_integration_gate: PASS (engineering preflight only); RELEASE GATE remains FAIL
```
