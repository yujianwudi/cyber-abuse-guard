# CPA Integration and Store-Contract Report — v0.1.2 candidate

## 2026-07-16 latest-compat addendum

The runtime/artifact baseline for the round5.2 development tree remains CPA
v7.2.75. A separate source/compile compatibility lane now pins the latest
audited CPA release, `v7.2.80` at commit
`09da52ad509e2c18e7b9540db3b98c2214c280aa`:

```text
module: github.com/router-for-me/CLIProxyAPI/v7 v7.2.80
module_sum: h1:QIa5T/KYvJACHVPPRzXcRwq/HLpbwWYJYpZAC1eY2WA=
go_mod_sum: h1:ytvZNWbCv7PrAyR80+RKsDJPODsdL6qxyFaXDBNZdqs=
plugin_abi_rpc_router_store_diff: no breaking change found
public_plugin_api_delta: UsageRecord.Generate bool (Guard does not register UsagePlugin)
guard_and_integration_compile_probes: PASS
guard_registration_and_route_tests: PASS
official_host_routing_status_contracts: PASS / 17 fixed tests
official_interactions_route_handler_contracts: PASS / 11 fixed tests
checksum_pinned_ephemeral_overlays: PASS / 3 fixtures
native_host_or_guard_so_load: NOT RUN
```

The reproducible entrypoint is `make cpa-latest-compat`. With
`CPA_LATEST_VERIFY_REMOTE=1`, it first requires GitHub `releases/latest` to
resolve to `v7.2.80` and the Tag to resolve to the pinned commit. It then uses a temporary
modfile, an isolated `integration/cpalatestcontract` module, and three
checksum-pinned overlays. The official source checks include public
Interactions route registration, handler/auth-selection behavior, ModelRouter
field visibility, translator registration, direct plugin-format readiness, and
plugin HTTP-status preservation. It does not start CPA, load a `.so`, install the
Store archive, contact a Provider/account, or validate request reconstruction,
logging, and zero-upstream side effects. Those remain owner-operated server
sandbox work. The remainder of this report preserves historical v7.2.72
implementation-freeze evidence and must not be relabeled as v7.2.80 Host proof.

## Historical v7.2.72 implementation-freeze status

**IMPLEMENTED — AUTHORIZED REAL-HOST EVIDENCE REQUIRES GITHUB CI.** The current
tree builds the dirty-suffixed guard `.so`, produces the one-entry Store ZIP,
installs that archive through CPA's public `pluginstore.Client.InstallManifest`,
loads the installed binary through the real native Host, and exercises the
protocol and multi-Router matrices below. The authoritative run must occur in
the GitHub CI Linux job and then be independently repeated by Leo.

A local WSL run was mistakenly performed outside that authorized evidence path.
It used only random loopback ports and a Mock Upstream and left no live fixture
process, but its result is deliberately excluded from the delivery PASS/FAIL
record. No production service or real provider was contacted.

The methodologically valid v10 result remains `CONSUMED / FAIL`; no clean
`v0.1.2` tag, GitHub Release, or production deployment may be created.

Target host: CLIProxyAPI `v7.2.72` at commit
`6279bb8a4c2835ff6ed99c6b85083b2afbefa681`, CPA C ABI/RPC schema v1.
Module checksum: `h1:ppce0MLsz2xJi2yi3/A60zu03cM7bMWBAEJ6eC29E5Y=`. go.mod
checksum: `h1:f4pcyAej8RoeRhIxJfm+OUMkCKaApiA8WzxR2XVlBh8=`.

Independent Host audit found one non-closable gap in the current upstream
surface. Guard `executor.http_request` returns an RPC error carrying status 405;
the official `ProviderExecutor.HttpRequest` adapter returns `(nil, error)`.
CPA v7.2.72 does expose the provider-specific public consumer
`POST /v1/alpha/search`, but ordinary selection is fixed to `codex`, not
Guard's `cyber-abuse-guard` executor, and the handler maps every
`HttpRequest` error to HTTP 502. The repository's `httptest.Server` manually
maps the status error and is adapter-level evidence only. No current official
public route maps Guard's error to final client 405, so that result is `NOT
AVAILABLE / NOT RUN`; current CI cannot close it and this remains an explicit
`BLOCKED FOR HANDOFF` item.

In Home mode the external dispatcher can select by a returned auth provider
rather than the handler's `codex` argument. That conditional path is not runtime
evidence here; even if it returned `cyber-abuse-guard`, the same handler error
branch would still emit 502, not 405.

The repository root and isolated contract module are both pinned exactly to
CPA v7.2.72. The isolated module pins 16 official Host test names and adds only
a `_test.go` overlay to an ephemeral checksum-verified source copy. The native
tests separately load the real guard `.so` and a minimal pure-C Router/executor
fixture through the official Host.

GitHub CI commands:

```bash
ALLOW_DIRTY_BUILD=1 make cpa-v7272-host-blackbox
ALLOW_DIRTY_BUILD=1 make cpa-router-fixture-blackbox
make cpa-host-fixture-contract
```

`make integration-test` composes both native black-box targets. The tests use
random loopback ports, a counting Mock Upstream, a counting CPA auth selector,
a wrapped provider executor, and the Management usage queue; they never connect
to real providers. Do not infer a PASS from source inspection or compile-only
testing.

## CPA v7.2.72 evidence status

The following table separates source evidence, exact-freeze authorized GitHub
CI evidence, and items that still require Leo's independent rerun:

| Assertion | Current status |
|---|---|
| Root `go.mod` resolves CPA v7.2.72 with both pinned checksums | **PASS** |
| Sixteen required official Host tests are listed and run by exact name | **PASS** |
| Ephemeral official-source fail-open overlay covers private panic/fuse/readiness state | **PASS — source fixture** |
| Store ZIP name `cyber-abuse-guard_<version>_linux_amd64.zip` | **PASS** |
| Real Store ZIP installs to the exact platform path through public `InstallManifest` | **GITHUB CI PASS** |
| Installed real `.so` is loaded and registered by the CPA v7.2.72 Host | **GITHUB CI PASS** |
| Legacy nested `plugins/linux/amd64/...` store layout rejected | **PASS — official installer contract** |
| Separate `cyber-abuse-guard-v<version>-audit-bundle.zip` | **GITHUB CI VERIFIED** |
| `execute`, `execute_stream`, and `count_tokens` use policy 403 | **GITHUB CI PASS** |
| `http_request` unsupported-method status at official ProviderExecutor adapter | **SOURCE / ADAPTER CHECK (nil response + status-error 405)** |
| Final official CPA handler/client HTTP 405 for Guard `http_request` | **NOT AVAILABLE / NOT RUN — BLOCKED FOR HANDOFF; current public consumer maps the error to 502** |
| OpenAI Chat/Responses/Claude/Gemini allow and refusal matrices | **GITHUB CI PASS** |
| Blocked Auth Selector/Provider/Usage/Mock Upstream counts remain zero | **GITHUB CI PASS** |
| Pure-C second Router/executor priority and fail-open matrix | **GITHUB CI PASS (15 scenarios)** |

The source-level contracts can be exercised without native loading:

```bash
go -C integration/pluginstorecontract test ./... -count=1
```

After a development build populates `dist/`, `make cpa-store-contract` checks the
real artifact shape. Native load is proven separately by the two black-box
targets above.

## Mandatory assertions

| Assertion | Current authoritative evidence |
|---|---|
| ELF discovered, `dlopen` loaded, ABI metadata registered | **GITHUB CI PASS** |
| Runtime version/commit/dirty/ruleset version/hash match build metadata | **GITHUB CI PASS** |
| `loaded=true`, `enforcement_ready=true`, expected mode/priority | **GITHUB CI PASS** |
| Missing/wrong/client Management keys return 401; correct key returns 200 | **GITHUB CI PASS** |
| Oversized management body/query/path/method rejected safely | **GITHUB CI PASS** |
| Safe OpenAI Chat/Responses/Anthropic/Gemini requests reach mock unchanged | **GITHUB CI PASS** |
| Safe model, role history, stream setting, and tool arguments remain unchanged | **GITHUB CI PASS** |
| Risky OpenAI Chat/Responses/Anthropic/Gemini return local 403 | **GITHUB CI PASS** |
| Risky streaming requests are rejected before stream establishment | **GITHUB CI PASS** |
| Risky Anthropic and Gemini token-count requests return policy 403 | **GITHUB CI PASS** |
| Executor HTTP forwarding request produces nil response + adapter/status-error 405 | **SOURCE / ADAPTER CHECK** |
| Official CPA public handler produces final client HTTP 405 | **NOT AVAILABLE / NOT RUN — BLOCKER** |
| Multi-turn and bounded encoded carrier handling | **GITHUB CI PASS** |
| Every blocked case leaves Mock Upstream, Auth Selector, provider execution, and usage counts at zero | **GITHUB CI PASS** |
| Opaque media and no-fetch behavior | **GITHUB CI UNIT PASS**; opaque media semantics remain a limitation |
| Raw body >6 MiB / RPC >8 MiB is no-copy local 403 in Balanced | **GITHUB CI PASS** |
| Injected ModelRouter panic/error recovery and counters | **UNIT PASS; OFFICIAL-SOURCE FIXTURE PASS** |
| SQLite unavailable/locked does not weaken local block | **FAULT TEST PASS** |
| Invalid reconfigure retains the last valid runtime and exposes a sanitized error | **GITHUB CI PASS** |
| HMAC/persistence degradation is visible without secret output | **UNIT PASS** |
| Built-in health probes remain local and non-mutating | **GITHUB CI PASS** |
| Plugin disable restores native CPA behavior | **GITHUB CI PASS** |
| Shutdown completes within its bound | **GITHUB CI PASS** |

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

CPA may continue other Routers or native routing when the plugin is not loaded,
registration fails, it is fused, a Router returns an error, a panic occurs
before a valid handled result is accepted, a target is invalid/empty, or the
self executor is not ready. A higher-priority handled Router also wins; at equal
priority, CPA orders by plugin ID ascending. The test must exercise the plugin's
mode-aware recovery while retaining these host-level facts:

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

The real native matrix adds a minimal pure-C Router/executor rather than a
second Go `c-shared` runtime. Fifteen CI scenarios are defined to prove:
guard-first and fixture-first priority, equal-priority plugin-ID ordering
(`aaa-router` before the guard and `zzz-router` after it), Router error, invalid
target, empty executor identifier, empty format declarations, missing executor
capability, OAuth-only scope, unhandled continuation, guard not loaded, guard
registration failure, guard disabled, fixture handling, and continuation to the
native provider. The fixture-handled response and native response are
distinguished, and every non-native scenario asserts zero Auth selection and
zero Mock Upstream calls. All 15 scenarios passed in exact-freeze GitHub CI;
Leo's independent rerun remains not run.

The native C ABI has no safe way to manufacture a Go panic that the Host can
recover, or to mutate the Host's private fuse map. The fixture therefore does
not use a segmentation fault as false panic/fuse evidence. Those two states are
covered by the checksum-verified official-source overlay; Leo must retain this
evidence distinction.

`enforcement_ready` is an internal plugin runtime signal. It does not prove
host load/registration, favorable ordering, non-fused state, valid target
acceptance, or per-request executor readiness.

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
that only one `cyber-abuse-guard` `.so` is active. Same-priority Router IDs must
also be compared because lexicographically smaller plugin IDs run first.

The policy executor method matrix is:

| Method | Required policy result |
|---|---|
| `executor.execute` | synchronous RPC error carrying HTTP 403 |
| `executor.execute_stream` | synchronous RPC error carrying HTTP 403 before SSE/headers commit |
| `executor.count_tokens` | synchronous RPC error carrying HTTP 403 |
| `executor.http_request` | unsupported RPC/status-error; official ProviderExecutor adapter returns nil + error carrying 405; no current official route maps that error to final 405 |

The automation checks real HTTP status and response-shape compatibility
separately for OpenAI Chat, OpenAI Responses, Claude, and Gemini. It asserts safe
non-stream and stream controls, synchronous pre-SSE 403 refusal,
Anthropic/Gemini token-count 403, adapter-level `http_request` status-error 405, and zero Auth Selector,
Provider, Usage, and Mock Upstream calls for locally blocked requests. These
assertions are **GITHUB CI PASS** on implementation freeze `9c8114e`.

The adapter assertion above must not be promoted to final Host HTTP evidence.
CPA's provider-specific `/v1/alpha/search` consumer maps any executor error to
502; therefore Guard's status-error 405 remains `NOT AVAILABLE / NOT RUN` as a
final client result even after the current CI job.

## Management HTTP buffering boundary

CPA currently invokes `io.ReadAll` inside `ServeManagementHTTP` before the
plugin receives the management request. The plugin's 1 MiB body bound and 2 MiB
RPC-envelope bound therefore do not cap CPA's HTTP memory allocation. The
deployment reverse proxy must enforce its own limit; the Docker/Nginx example
uses `client_max_body_size 1m`. `make management-proxy-413-test` implements a
counted Nginx fixture. Exact-freeze GitHub CI proved that a request slightly
above the limit returns HTTP 413 before the counted CPA-handler stub observes
it. Leo must repeat the check in the target sandbox.

## Final evidence block

```text
release_commit_tag_and_artifact_hashes: NOT CREATED — RELEASE BLOCKED
ruleset_version: 1.0.7
ruleset_sha256: 7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134
cpa_version: v7.2.72
cpa_commit: 6279bb8a4c2835ff6ed99c6b85083b2afbefa681
cpa_module_sum: h1:ppce0MLsz2xJi2yi3/A60zu03cM7bMWBAEJ6eC29E5Y=
cpa_go_mod_sum: h1:f4pcyAej8RoeRhIxJfm+OUMkCKaApiA8WzxR2XVlBh8=
official_host_source_contract_exit_status: 0
implementation_freeze_commit: 9c8114e22841f9a19b15b1f4b3c48531aa2453a0
github_ci_runs: PASS — push 29292693070; pull_request 29292695293
implementation_freeze_real_store_installed_host_exit_status: 0 / GITHUB CI PASS
implementation_freeze_real_multi_router_fixture_exit_status: 0 / GITHUB CI PASS (15 scenarios)
management_proxy_413_exit_status: 0 / GITHUB CI PASS
panic_and_fuse_evidence: official-source overlay only; not claimed as native C ABI evidence
http_request_adapter_405: SOURCE / ADAPTER STATUS-ERROR CHECK (response=nil)
official_cpa_final_client_http_405: NOT AVAILABLE / NOT RUN — BLOCKED FOR HANDOFF
overall_cpa_integration_gate: BLOCKED — engineering CI passed; Leo is not run and final official CPA client HTTP 405 is unavailable; RELEASE GATE remains FAIL
```
