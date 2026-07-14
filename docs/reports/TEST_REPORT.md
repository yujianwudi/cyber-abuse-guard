# Test Report — post-v10 development handoff

Last updated: 2026-07-14 (Asia/Shanghai)

## Current status

**BLOCKED FOR HANDOFF.** The actual starting baseline is
`a121a444cb0d82cba4e27754914a1f88258e1d7b`. Classifier reference commit
`a1be19f` is followed by idempotency/reliability commits `b84ed2a` and
`573def2`, Host/isolation commit `1973083`, review-closure commit `8814dbf`, and
provider-probe lifecycle implementation freeze
`9c8114e22841f9a19b15b1f4b3c48531aa2453a0`. Evidence documents are
committed separately and identify themselves through their containing commit.

The root dependency is CLIProxyAPI v7.2.72 at upstream tag commit
`6279bb8a4c2835ff6ed99c6b85083b2afbefa681`. Module checksums are:

```text
module_sum: h1:ppce0MLsz2xJi2yi3/A60zu03cM7bMWBAEJ6eC29E5Y=
go_mod_sum: h1:f4pcyAej8RoeRhIxJfm+OUMkCKaApiA8WzxR2XVlBh8=
```

The classifier identity is `classifier-policy-v2` /
`dc9a174099cb2f621e5333a508d4645604f96f470a6d9ae12a1acfb363d29cf2`.
Ruleset `1.0.7` remains separate YAML identity.

No consumed v10 sample was opened, printed, classified, extracted, inspected
through Git history, or emitted by a helper. Only the frozen aggregate report
was used. v10 remains `CONSUMED / FAIL`.

Methodology incident: two incorrectly scoped WSL source-search commands
unexpectedly emitted several rows from the retired `testdata/holdout-v3`
corpus. Both searches were stopped immediately; those rows were not analyzed
or used for tuning or conclusions. Evaluation v10 content was not accessed.
The retired holdout-v3 corpus is no longer eligible as independent evidence,
and this incident independently keeps the handoff `BLOCKED FOR HANDOFF`.

## Evidence vocabulary

| Label | Meaning |
|---|---|
| `DEVELOPMENT SELF-CHECK` | A named local command ran on a development tree; useful but not final evidence. |
| `SOURCE IMPLEMENTED` | Code/tests exist; no execution result is implied. |
| `SOURCE OVERLAY PASS` | A pinned upstream source/contract test ran; this is not a native Guard Host run. |
| `GITHUB CI` | A remote check on the exact pushed commit. Older/main checks are not transferable. |
| `REAL HOST` | The real Guard `.so` loaded by CPA v7.2.72 and exercised through HTTP. |
| `LOCAL MIS-EXECUTION / EXCLUDED` | The command ran outside the authorized evidence path; its result is permanently excluded and any GitHub CI or Leo result must be cited separately. |
| `NOT RUN` | No result exists for the named tree/environment. |
| `BLOCKED` | A prerequisite or final freeze is missing; never equivalent to PASS. |

Three WSL commands were mistakenly executed outside the authorized evidence
path:

```text
make cpa-router-fixture-blackbox
make cpa-v7272-host-blackbox
scripts/management-proxy-413-test.sh
```

They used random loopback ports and Mock components only, contacted no real
provider or production service, and cleanup left no fixture process running.
Their results are excluded and must never be reported as PASS:

```text
LOCAL MIS-EXECUTION RECORDED / EXCLUDED; NOT AUTHORITATIVE
```

## Classifier and development-corpus checks

| Evidence class | Command | Result |
|---|---|---|
| DEVELOPMENT SELF-CHECK | `go test ./internal/classifier -run '^(TestWrapper|TestBehaviorGraph|TestMetaOverride|TestAssistant|TestSystem|TestNoPermission|TestExplicitNoPermission|TestNegativeAuthorization|TestMaliciousSystemPolicy|TestClassifierPolicyIdentity|TestEvaluationV10)' -count=1` | **PASS**; v10 cases here are aggregate/consumed-boundary checks only, not sample classification |
| DEVELOPMENT SELF-CHECK | `go test ./cmd/development-adversarial-v11-prep-validator -run '^TestDevelopmentAdversarialV11PrepCorpus$' -count=1` | **PASS — 35 visible development cases** |
| DEVELOPMENT SELF-CHECK | `CGO_ENABLED=0 go test ./internal/plugin -run '^TestPromptInjection(ControlPlaneRegression|NestedToolAndSplitEncodingRegression)$' -count=1` | **PASS** |
| DEVELOPMENT SELF-CHECK | `go vet ./internal/classifier ./cmd/development-adversarial-v11-prep-validator` | **PASS** |
| DEVELOPMENT SELF-CHECK | classifier-related `gofmt -l` | **PASS — empty output** |
| DEVELOPMENT SELF-CHECK | `git diff --check` at time of classifier review | **PASS** |
| DEVELOPMENT SELF-CHECK | root `go mod verify` | **PASS — all modules verified** |
| DEVELOPMENT SELF-CHECK | root `go mod tidy -diff` | **PASS — empty output** |
| Safe broad Go test/race/boundary | `scripts/go-safe-development-test.sh test|race|boundary` | **DEVELOPMENT SELF-CHECK PASS** on WSL Ubuntu 26.04 / Go 1.26.4; test/race ran no Evaluation/Holdout test name; boundary ran only 3 v10 aggregate/report-marker/rerun-rejection tests and logged fixture not accessed |
| GITHUB CI | implementation freeze `9c8114e` | **PASS** — push run [29292693070](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29292693070), PR run [29292695293](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29292695293); push long fuzz PASS, both reproducibility jobs PASS |
| CodeRabbit CLI | base `8814dbf`, reviewed HEAD `9c8114e` plus evidence-doc worktree | **0 issues**; the GitHub bot skipped because PR #4 is Draft, so the bot status is not used as review evidence |

The development corpus contains 16 block, 14 allow, 2 audit, and 3 resource-
boundary fixtures. It covers all eight taxonomies, four protocols, English,
Chinese, mixed language, wrapper contrasts, defensive/remediation/CTF/lab/
authorized contexts, role and multi-turn composition, tool payload/output,
bounded encodings, placeholders, max parts, near scan budget, and truncation.
It is permanently `development_only=true` and
`future_holdout_eligible=false`; Leo must not reuse it as a future v11.

## Reliability, idempotency, lifecycle, and privacy

Executed on WSL/ext4 with Go 1.26.4, CGO enabled, and `-race` where shown:

| Evidence class | Command/scope | Result |
|---|---|---|
| DEVELOPMENT SELF-CHECK | `go test -race ./internal/subject ./internal/config -count=1 -v` | **PASS** |
| DEVELOPMENT SELF-CHECK | `go test -race ./internal/audit -count=1 -v` | **PASS** |
| DEVELOPMENT SELF-CHECK | plugin tests for subject idempotency, concurrent duplicate/shutdown, register/reconfigure/shutdown, privacy canaries, caller metadata, production status, persistence restore, pending/logger race | **PASS** |
| DEVELOPMENT SELF-CHECK | `go vet ./internal/audit ./internal/config ./internal/plugin ./internal/subject` | **PASS** |
| DEVELOPMENT SELF-CHECK | `scripts/check-production-health-test.sh` | **PASS** |
| DEVELOPMENT SELF-CHECK | `scripts/release-evidence-privacy-test.sh` | **PASS** |
| DEVELOPMENT SELF-CHECK, Windows | targeted idempotency, pending-cache, and lifecycle tests | **PASS** |
| Windows native SQLite/race | release-equivalent CGO/NTFS path | **NOT RUN / unsupported release path** |

The idempotency checks cover execute, execute_stream, count_tokens, retry,
same request hash, concurrent duplicate, pending miss/expiry, enabled
reconfigure, persistence restore, and shutdown race. HMAC/SQLite checks cover
owner/mode, symlink/FIFO/device, empty/short keys, key-ID change, migration
backup collision/rollback, audit flush/close, and coarse error privacy.

## CPA v7.2.72 source and Host matrix

Local WSL native runs were mistakenly executed and remain excluded; they are
not converted into PASS. Separately authorized GitHub CI on the exact
implementation freeze passed the real Host and artifact paths. Leo independent
verification remains not run.
One exception cannot be closed by that CI: Guard returns an RPC status error
carrying 405, while CPA v7.2.72's provider-specific public
`POST /v1/alpha/search` consumer normally selects `codex` and maps every
executor error to final HTTP 502. No current official route maps Guard's error
to final client HTTP 405.

| Gate | Evidence class | Result |
|---|---|---|
| Root `go.mod` pins CPA v7.2.72 | source inspection/module verify | **PASS** |
| Exact set of 16 official Host tests exists and runs by name | SOURCE OVERLAY | **PASS on Windows/source-contract path** |
| Official `InstallArchive` source contract | SOURCE OVERLAY | **PASS with synthetic bytes** |
| Real Guard `.so` first install and Host load through `InstallManifest` | REAL HOST | **GITHUB CI PASS**; local mis-execution remains excluded |
| Same-Dist repeat-skip and tamper-repair through `TestPublishedStoreArchive` | REAL ARTIFACT | **GITHUB CI PASS** with required real Dist artifacts; synthetic fallback was disabled |
| OpenAI Chat allow/block, stream pre-SSE, token-count | REAL HOST | **GITHUB CI PASS** |
| OpenAI Responses allow/block, stream pre-SSE, token-count | REAL HOST | **GITHUB CI PASS** |
| Anthropic allow/block, stream pre-SSE, token-count 403 | REAL HOST | **GITHUB CI PASS** |
| Gemini allow/block, stream pre-SSE, token-count 403 | REAL HOST | **GITHUB CI PASS** |
| `executor.http_request` unsupported status at official `ProviderExecutor.HttpRequest` adapter | SOURCE / ADAPTER | **CHECKED — nil response + 405 status error** |
| Final official CPA handler/client HTTP 405 for Guard `http_request` | OFFICIAL HOST | **NOT AVAILABLE / NOT RUN — BLOCKED FOR HANDOFF; project `httptest.Server` is not official Host evidence** |
| Blocked Auth Selector/Provider/Usage/Mock Upstream all zero | REAL HOST | **GITHUB CI PASS** |
| Safe allow path increments native counters and preserves model/body/tools | REAL HOST | **GITHUB CI PASS** |
| Router priority, equal-ID ordering, route error, invalid target, identifier/format/scope not-ready, guard missing/register-fail/disabled, native fallback | REAL HOST fixture | **GITHUB CI PASS — 15 isolated scenarios** |
| Fuse and pre-result panic | official source overlay | **SOURCE OVERLAY ONLY**; no safe native C-ABI seam exists |
| Management proxy >1 MiB returns 413 before CPA `io.ReadAll` | proxy fixture | **GITHUB CI PASS** — counted CPA-handler stub remained at zero |

CI must set `REQUIRE_DIST_ARTIFACTS=1` for `cpa-store-contract`: missing real
`.so`, Store ZIP, metadata, or checksums must fail. The Host Blackbox first
install/load and the published-archive repeat/tamper checks must use the same
Dist identity to form one install-lifecycle-plus-load evidence chain.

## Performance

Same-machine Windows classifier medians improved in every measured latency case
from `a121a44` to `a1be19f`; ordinary classifier was 165,552→103,190 ns/op and
candidate-rich max-parts was 119,484,917→97,126,983 ns/op. Allocations increased
on the ordinary, candidate-rich, and role-aware paths. Pending-cache full insert
measured hundreds of nanoseconds instead of the previous linear hundreds of
microseconds, and duplicate subject requests remained zero-allocation. Full
tables are in `PERFORMANCE.md`.

Status: **IMPLEMENTATION-FREEZE DEVELOPMENT SELF-CHECK PASS / NOT FINAL
EVIDENCE**. Leo independent rerun: **NOT RUN**.

## Frozen v10 conclusion

The methodologically valid first-and-only v10 run remains immutable:

| Aggregate | Frozen result |
|---|---:|
| Benign false positives | 28 / 320 (8.75%) |
| Policy blocked | 49 / 320 (15.31%) |
| Policy exact taxonomy | 33 / 320 (10.31%) |

All release floors failed. This development work does not rewrite that result,
and no visible regression corpus can prove that the new classifier generalizes.

## Required full development gates

The following task-book gates record the implementation-freeze development
self-check. An item may be skipped only by marking it `NOT RUN`/`BLOCKED`; no
`|| true`, waiver, or inherited result is acceptable.

| Command/gate | Final-commit status |
|---|---|
| `make format-check` | **DEVELOPMENT SELF-CHECK PASS** |
| `make git-diff-check` | **DEVELOPMENT SELF-CHECK PASS** |
| `make module-verify` equivalent root/isolated verify + tidy-diff commands | **DEVELOPMENT SELF-CHECK PASS** |
| `scripts/go-safe-development-test.sh test` / `make unit-test` mapping | **DEVELOPMENT SELF-CHECK PASS** |
| `scripts/go-safe-development-test.sh race` / `make race` mapping | **DEVELOPMENT SELF-CHECK PASS; no race found** |
| `scripts/go-safe-development-test.sh boundary` / `make consumed-boundary-test` mapping | **DEVELOPMENT SELF-CHECK PASS; fixture not accessed** |
| `make vet` equivalent command | **DEVELOPMENT SELF-CHECK PASS** |
| `make fuzz-smoke` | **DEVELOPMENT SELF-CHECK PASS** |
| `make script-test` | **DEVELOPMENT SELF-CHECK PASS** |
| `make corpus-regression` | **DEVELOPMENT SELF-CHECK PASS** |
| `make benchmark` | **DEVELOPMENT SELF-CHECK PASS** |
| `make vulncheck` | **DEVELOPMENT SELF-CHECK PASS — 0 reachable vulnerabilities** |
| `make build-linux-amd64` | **GITHUB CI PASS** for the implementation freeze |
| `make cpa-host-fixture-contract` (source-only) | **SOURCE OVERLAY PASS; not native Host evidence** |
| Authorized CI `make integration-test` | **GITHUB CI PASS** — 32 Host subtests and 15 Router scenarios |
| Authorized CI `REQUIRE_DIST_ARTIFACTS=1 make cpa-store-contract` | **GITHUB CI PASS** |
| Authorized CI `make management-proxy-413-test` | **GITHUB CI PASS** |
| GitHub Actions CI | **PASS** for exact implementation freeze in push and PR runs |
| Final official CPA client HTTP 405 for `executor.http_request` | **NOT AVAILABLE / NOT RUN — current public consumer maps the error to 502; BLOCKER** |

Do not execute consumed v10 classification. Any future blind quality check must
use a new independently authored isolated set and must not reuse the 35 visible
development cases.

## Evidence block

```text
starting_baseline: a121a444cb0d82cba4e27754914a1f88258e1d7b
reliability_checkpoint_commit: 573def2649d164161e2dfdfeb3f59b1e1b38ebbc
implementation_freeze_commit: 9c8114e22841f9a19b15b1f4b3c48531aa2453a0
evidence_document_commit: SELF (resolve with git log -1 -- this file)
branch: agent/complete-classifier-cpa-v7272-handoff
root_cpa_version: v7.2.72
cpa_upstream_tag_commit: 6279bb8a4c2835ff6ed99c6b85083b2afbefa681
go_version_used_for_wsl_checks: go1.26.4 linux/amd64
ruleset_version: 1.0.7
ruleset_sha256: 7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134
classifier_policy_version: classifier-policy-v2
classifier_policy_sha256: dc9a174099cb2f621e5333a508d4645604f96f470a6d9ae12a1acfb363d29cf2
development_corpus: 35 visible cases; never future holdout
github_ci: PASS — push 29292693070; pull_request 29292695293
real_host_matrix: GITHUB CI PASS — 32 Host subtests; 15 Router scenarios
http_request_adapter_405: SOURCE / ADAPTER STATUS-ERROR CHECK (response=nil)
official_cpa_final_client_http_405: NOT AVAILABLE / NOT RUN — BLOCKED FOR HANDOFF
development_candidate_artifacts: CREATED / HASHED / VERIFIED IN GITHUB CI; see RELEASE_EVIDENCE.md
formal_blind_result: v10 CONSUMED / FAIL; unchanged
handoff_status: BLOCKED FOR HANDOFF
```
