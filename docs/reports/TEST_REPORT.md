# Test Report — fifth-round post-v10 development handoff

Last updated: 2026-07-15 (Asia/Shanghai)

## Fifth-round evidence status

The fifth-round branch starts from
`main@67b2470cf9be434adc0ce0c62fa6d2c0f9d21363`. Its implementation-freeze
commit, exact-commit GitHub CI run, artifact ID/hashes, Tencent Cloud isolated
Host result, and independent source/artifact review are not yet recorded in
this report. Current status is:

```text
LOCAL ENGINEERING GATES PASS / IMPLEMENTATION FREEZE AND CI PENDING /
METHODOLOGY HANDOFF BLOCKED
```

The following local results are `DEVELOPMENT SELF-CHECK` evidence only. They do
not replace exact-commit GitHub CI, artifact verification, Tencent Cloud Host
validation, or independent review. General gates were rerun with the repository
CI toolchain (`GOTOOLCHAIN=go1.26.4`) after the final Tool-schema test change;
the earlier full safe race and fuzz runs used the installed Go 1.26.0 toolchain.
No command below started CPA, loaded the real Guard `.so`, ran
`make integration-test`, or selected a holdout/evaluation test.

| Command | Exit | Result |
|---|---:|---|
| `GOTOOLCHAIN=go1.26.4 make format-check git-diff-check module-verify round5-regression development-public-jailbreak-corpus` | 0 | Final pre-freeze rerun passed. Round 5 covered scalar media, multipart schema precedence, all five Tool-schema boolean mappings plus false controls, meta families, negation reversal, plugin counters/privacy, and the canonical development corpus validator. |
| `GOTOOLCHAIN=go1.26.4 make test vet` | 0 | Safe-package unit tests, explicitly allowlisted classifier tests, and vet passed. Historical/evaluation author packages were compile-only with `-run='^$'`; no consumed/holdout test was selected. |
| `make race` | 0 | Full safe allowlist race gate passed, including extract, plugin, classifier, audit, subject, and validator packages. |
| `GOTOOLCHAIN=go1.26.4 go test -race ./internal/extract -run='^TestToolSchemaKnownBooleanControlIsMapped$' -count=1` | 0 | Final added Tool-schema true/false mapping test passed under race instrumentation. |
| `make fuzz-smoke` | 0 | Eleven bounded fuzz targets passed: six extract, four classifier/meta, and one config target. |
| `make benchmark` | 0 | Quiet rerun passed all acceptance gates and benchmarks. Candidate-rich classifier `135.042168ms/op` (<250ms), near-budget `19.833569ms/op` (<50ms), near-budget allocation `302962 B/op`; meta long/many-parts/bilingual `22.002828ms` / `11.591201ms` / `41.129us`; negation flood `616.791us`, `259295 B/op`, 309 allocs; multipart unknown-file 1/8 MiB remained `44946 B/op`, 61 allocs. |
| Privacy command shown below | 0 | Route/audit/SQLite/management/export/multipart privacy canaries passed with no reported canary leakage. |
| `make script-test` | 0 | Safe-development script syntax, mock production-health isolation, Store archive layout, HMAC-key generation, release-evidence privacy, and release-document consistency tests passed. |
| `make integration-compile` | 0 | Integration-tagged package compiled with no tests selected; CPA was not started and no `.so` was loaded. |
| `GOTOOLCHAIN=go1.26.4 make cpa-host-fixture-contract` | 0 | Pinned CPA v7.2.75 source-contract and temporary source-fixture fail-open tests passed. This is source evidence, not a real Guard artifact/Host run. |
| `GOTOOLCHAIN=go1.26.4 make vulncheck` | 0 | `No vulnerabilities found`; zero called vulnerabilities on the pinned CI Go version. |

Exact privacy command:

```bash
go test -tags=sqlite_omit_load_extension \
  ./internal/plugin ./internal/audit ./internal/extract \
  -run='^(TestManagementEventDeletionWritesPrivacySafeAuditMarker|TestCallerControlledAuditMetadataIsPrivateAcrossEventsSQLiteAndManagementAPI|TestMultipartSchemaAuditIsFixedAndPrivate|TestOversizedRouteWritesPrivacyMinimalAuditEvent|TestEndToEndPrivacyCanariesStayOutOfAllowedOutputs|TestMultipartUnknownFileFieldAuditIsFixedAndPrivate|TestStrictUnknownSourceFormatPersistsPrivacyMinimalAudit|TestMigrationRejectsPrivacyUnsafeLegacyRowsBeforePublishingBackup|TestStoreRoundTripPrivacyAndSafeExports|TestExtractRequestMultipartUnknownFieldIsIncompleteAndPrivate|TestExtractRequestMultipartJSONLikeUnknownFieldsAreSchemaIncompleteAndPrivate)$' \
  -count=1 -v
```

Two non-PASS first attempts are retained for audit transparency:

- The first `make benchmark` exited 1 while an unrelated WSL benchmark process
  consumed a CPU core: candidate-rich `402.684538ms/op` and near-budget
  `60.416452ms/op`. After that process ended, the isolated acceptance rerun was
  `152.461093ms/op` / `23.804648ms/op` (exit 0), followed by the full quiet
  `make benchmark` PASS recorded above. No source change was made to obtain the
  performance PASS.
- The first `make vulncheck` exited 3 under local Go 1.26.0 because three
  standard-library findings were already fixed in Go 1.26.1/1.26.4. The exact
  CI toolchain rerun under Go 1.26.4 exited 0 as recorded above.

Required fifth-round evidence and remaining remote gates are:

| Gate | Required evidence before handoff |
|---|---|
| HIGH-A scalar `source`/`uri`/`url`/`image_url` order invariance | `make round5-regression`, dedicated permutation fuzz, and bounded benchmark on the exact commit |
| HIGH-B multipart unknown-field precedence | Fixed `multipart_unknown_field` disposition, plugin privacy/counter tests, evidence-order fuzz, and 1/8 MiB allocation benchmarks |
| Meta-override families and benign neighbors | Fixed family evidence, wrapper-only allow/audit, persistent-injection, compound-intent, quoted-analysis, bilingual, fuzz, and benchmarks |
| Tool key-only control | `cag_control_schema=meta_override_control/v1` activates mapping only in established tool/tool-payload provenance; ordinary business JSON keys remain inert and unknown known-schema controls become `tool_schema` incomplete |
| Sanitized public-taxonomy corpus | `make development-public-jailbreak-corpus`; manifest must remain development-only, never Holdout, and contain no live payloads |
| General quality | module verify/tidy-diff, safe unit/race, vet, fuzz-smoke, benchmark, privacy, script and artifact checks |
| Integration | `make integration-compile` only in ordinary CI; it must not start CPA or perform local Host validation |
| Host/independent review | Tencent Cloud CPA v7.2.75 isolated container, Mock upstream only, then separate source/artifact review |

Ordinary CI deliberately excludes `make consumed-boundary-test` and every
evaluation-v10/retired-Holdout content path. The target remains only as an
explicit, separately authorized manual audit entry. Ordinary CI also no longer
runs `make integration-test`; the real CPA Host targets remain explicit/manual
and the fifth-round Tencent Cloud Host matrix is pending.

Fifth-round methodology deviation: one over-broad read-only `git grep`
unexpectedly emitted content from the restricted
`testdata/holdout/malicious-operational.jsonl` file. No holdout test ran; the
output was not redirected, copied into source/tests/docs, analyzed, or used for
tuning or conclusions. All subsequent gate commands explicitly exclude
holdout, evaluation-v10, and retired/historical paths. The final report must not
claim that this round had zero restricted-corpus access, and the methodological
handoff remains blocked independently of engineering test results.

The Router cannot attest to local `model_instructions_file`, `AGENTS.md`, or
remote-template integrity before CPA receives a request. Provider
`safetySettings`, `generationConfig`, `options`, and equivalent controls require
a host-side versioned schema allowlist with rejection or forced-safe-value
overrides. Embedded ruleset `1.0.7` covers YAML assets only and excludes the Go
`META-OVERRIDE-001` overlay and related extractor/tool-schema/control-plane
logic. The fifth-round policy identity is `classifier-policy-v2` /
`5fc25855a868cba206123697c1631ba251575157f37cd79654e9a65c888a750b`.

Two P2 items remain explicit review scope. First, role-aware classification
does not compose base taxonomy from system/assistant text into a later user
message; host validation of high-priority instruction provenance,
owner/mode/hash/signature, and reload state is therefore mandatory. Second,
`Segments` currently performs a second bounded JSON parse after the primary
extractor walk. Existing differential/race/fuzz tests have not reproduced a
leak, but a single shared semantic parse product is still the intended future
hardening.

Unit or CI success is not production admission. After all source and artifact
gates, the maximum permitted status is
`READY FOR INDEPENDENT SOURCE/ARTIFACT REVIEW`, never `PRODUCTION APPROVED`.

---

## Historical prior-round report

## Historical current status

**BLOCKED FOR HANDOFF.** The actual starting baseline is
`a121a444cb0d82cba4e27754914a1f88258e1d7b`. Classifier reference commit
`a1be19f` is followed by idempotency/reliability commits `b84ed2a` and
`573def2`, Host/isolation commit `1973083`, review-closure commit `8814dbf`,
provider-probe lifecycle commit `9c8114e`, evidence reconciliation commit
`8719c7f`, and final review-correctness implementation freeze
`61536f9f02c47a4d79031a47dc8a284f040e41c1`. Evidence documents are
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

Methodology incident: three incorrectly scoped WSL source-search commands
unexpectedly emitted several rows from the retired `testdata/holdout-v3`
corpus. All three searches were stopped immediately; those rows were not
analyzed or used for tuning or conclusions. Evaluation v10 content was not accessed.
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
| DEVELOPMENT SELF-CHECK | `go test ./internal/classifier -run '^(TestWrapper\|TestBehaviorGraph\|TestMetaOverride\|TestAssistant\|TestSystem\|TestNoPermission\|TestExplicitNoPermission\|TestNegativeAuthorization\|TestMaliciousSystemPolicy\|TestClassifierPolicyIdentity\|TestEvaluationV10)' -count=1` | **PASS**; v10 cases here are aggregate/consumed-boundary checks only, not sample classification |
| DEVELOPMENT SELF-CHECK | `go test ./cmd/development-adversarial-v11-prep-validator -run '^TestDevelopmentAdversarialV11PrepCorpus$' -count=1` | **PASS — 35 visible development cases** |
| DEVELOPMENT SELF-CHECK | `CGO_ENABLED=0 go test ./internal/plugin -run '^TestPromptInjection(ControlPlaneRegression\|NestedToolAndSplitEncodingRegression)$' -count=1` | **PASS** |
| DEVELOPMENT SELF-CHECK | `go vet ./internal/classifier ./cmd/development-adversarial-v11-prep-validator` | **PASS** |
| DEVELOPMENT SELF-CHECK | classifier-related `gofmt -l` | **PASS — empty output** |
| DEVELOPMENT SELF-CHECK | `git diff --check` at time of classifier review | **PASS** |
| DEVELOPMENT SELF-CHECK | root `go mod verify` | **PASS — all modules verified** |
| DEVELOPMENT SELF-CHECK | root `go mod tidy -diff` | **PASS — empty output** |
| Safe broad Go test/race/boundary | `scripts/go-safe-development-test.sh test`, `scripts/go-safe-development-test.sh race`, `scripts/go-safe-development-test.sh boundary` | **DEVELOPMENT SELF-CHECK PASS** on WSL Ubuntu 26.04 / Go 1.26.4; test/race ran no Evaluation/Holdout test name; boundary ran only 3 v10 aggregate/report-marker/rerun-rejection tests and logged fixture not accessed |
| GITHUB CI | implementation freeze `61536f9` | **PASS** — push run [29312969925](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29312969925), PR run [29312971717](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29312971717); push long fuzz PASS, both reproducibility jobs PASS |
| CodeRabbit Ready review | Initial review of `8719c7f`, followed by delta review through `61536f9` | Initial review posted 8 actionable threads and 2 nitpicks; valid findings were fixed in `61536f9`, the missing `cmd` symbols finding was disproved by targeted compilation, and the follow-up review reported no actionable comments |

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
implementation_freeze_commit: 61536f9f02c47a4d79031a47dc8a284f040e41c1
evidence_document_commit: a2d30fc63fca4fba020cda282474aaca15a47d8f
branch: agent/complete-classifier-cpa-v7272-handoff
root_cpa_version: v7.2.72
cpa_upstream_tag_commit: 6279bb8a4c2835ff6ed99c6b85083b2afbefa681
go_version_used_for_wsl_checks: go1.26.4 linux/amd64
ruleset_version: 1.0.7
ruleset_sha256: 7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134
classifier_policy_version: classifier-policy-v2
classifier_policy_sha256: dc9a174099cb2f621e5333a508d4645604f96f470a6d9ae12a1acfb363d29cf2
development_corpus: 35 visible cases; never future holdout
github_ci: PASS — push 29312969925; pull_request 29312971717
real_host_matrix: GITHUB CI PASS — 32 Host subtests; 15 Router scenarios
http_request_adapter_405: SOURCE / ADAPTER STATUS-ERROR CHECK (response=nil)
official_cpa_final_client_http_405: NOT AVAILABLE / NOT RUN — BLOCKED FOR HANDOFF
development_candidate_artifacts: CREATED / HASHED / VERIFIED IN GITHUB CI; see RELEASE_EVIDENCE.md
formal_blind_result: v10 CONSUMED / FAIL; unchanged
handoff_status: BLOCKED FOR HANDOFF
```
