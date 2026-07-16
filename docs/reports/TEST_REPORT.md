# Test Report — round5.2 post-release re-audit candidate

Last updated: 2026-07-16 (Asia/Shanghai)

## Round5.2 source-freeze / pre-merge evidence status

This section records only evidence that can be frozen before merge: source
identity, safe local gates, exact-source branch push CI, the PR synthetic
merge-result gate, and review state. It deliberately does
not self-reference a future merge commit. Post-merge main CI, the exact-main
artifact, tag, release flags, and release asset hashes are authoritative only
through GitHub API metadata; the corresponding Release notes link those records
and preserve per-asset hashes and incomplete gates. The repair
branch starts from historical
`main@89b62b341278073e7b6518b85e41cd7f7c6b682c`; pending fields must be
backfilled before merge without inventing future values. Tencent Cloud isolated
Host validation and independent source/artifact review remain separate gates.

```text
ROUND5.2 SOURCE FIXES IN PROGRESS /
FREEZE, CI, PR, MERGE, ARTIFACT, AND RELEASE PENDING /
REAL HOST AND INDEPENDENT REVIEW NOT RUN /
METHODOLOGY HANDOFF BLOCKED
```

| Round5.2 evidence | Result |
|---|---|
| Source fixes | **COMPLETE / SOURCE FREEZE READY** |
| Source-freeze commit | **PENDING PRE-MERGE BACKFILL** |
| Source-bound classifier identity | `classifier-policy-v2` / `e9b87f7e2635495bdbceae469ef89e696b419f0a9a6fd129558a20bc4be947ec`; identity test **PASS** |
| CPA v7.2.80 latest source/compile lane | **DEVELOPMENT SELF-CHECK PASS / EXACT-SOURCE GITHUB CI PENDING**; `CPA_LATEST_VERIFY_REMOTE=1 make cpa-latest-compat` verified GitHub `releases/latest` and Tag-to-Commit; pinned checksums, Guard/integration compile probes, real Guard registration/route tests, 17 official Host routing/status tests, 11 official Interactions route/handler tests, and three checksum-pinned overlays passed; no Host or `.so` load |
| Public-reference sanitized corpus | **PASS**; 36 cases = 18 allow + 18 audit, 34 role-aware + 2 conservative-untrusted; development-only and future-Holdout-ineligible |
| Safe local gate record | **PASS** — format/diff/module, Round5, safe test/vet, sanitized public corpus, scripts, and CPA latest remote identity/contracts |
| Exact-source branch push CI and PR synthetic merge-result CI | **PENDING PRE-MERGE BACKFILL** |
| PR and CodeRabbit follow-up | PR [#8](https://github.com/yujianwudi/cyber-abuse-guard/pull/8); CodeRabbit CLI `0.6.5` uncommitted review **PASS / 0 issues** |
| Post-merge main CI and exact-main artifact | **EXTERNAL EVIDENCE — GITHUB API METADATA + LINKED RELEASE NOTES** |
| Tag, release flags, and release asset hashes | **EXTERNAL EVIDENCE — GITHUB API METADATA + LINKED RELEASE NOTES** |

Targeted round5.2 checks already completed before the final broad safe-gate
rerun are recorded below. They do not replace the pending source-freeze commit,
full local gate record, branch/PR CI, or CodeRabbit follow-up.

| Targeted command | Exit | Scope |
|---|---:|---|
| `go test ./internal/classifier -run='^TestClassifierPolicyIdentity$' -count=1` | 0 | Source-bound policy identity `e9b87f7e...` matched the reviewed source list |
| `go test ./internal/classifier -run='^TestRound5(RepeatedIntentYInflectionsFailActive\|NegatedProhibitionModalBridgeFailsActive)$' -count=1` | 0 | Sanitized CANARY regressions preserved active EXFIL-003 risk across `copy/copies/copied` and negated prohibition modal/contraction variants |
| `GOMAXPROCS=1 go test ./internal/classifier -run='^TestMetaOverrideClauseBudget' -count=1 -v` | 0 | Period/semicolon/newline `8 x 32 KiB` inputs rejected defensive credit; about 7-10 ms, 1.36 MiB/op, 40 allocs/op after the bounded-clause fix |
| `go test ./internal/classifier -run='^TestRound5RefusalScopeOutputAndCompoundIntentHardening$' -count=1` | 0 | Concealed override and filter-boundary/long-padding regressions passed with benign neighbors |
| `go test ./internal/extract -run='^TestExtractRawPartsToolTransactionSharesPartBudget$' -count=1` | 0 | Shared part budget retained `content=first`, excluded tool argument `second`, and reported truncation |
| `go test ./cmd/development-public-jailbreak-patterns-v1-validator -count=1` | 0 | 36 sanitized cases: 18 allow, 18 audit, 34 role-aware, 2 conservative-untrusted |
| `CPA_LATEST_VERIFY_REMOTE=1 make cpa-latest-compat` | 0 | CPA v7.2.80 `releases/latest`, Tag-to-Commit, checksums, Guard/integration compile probes, real Guard registration/route tests, 17 official Host routing/status tests, 11 official Interactions route/handler tests, and three checksum-pinned overlays; no Host or `.so` load |
| `ALLOW_DIRTY_BUILD=1 make release-preflight` | 0 | Every tracked shell script has Git mode `100755`; dirty development preflight passed without creating a formal release |

## Historical round5.1 release evidence

Historical `v0.1.2-dev.round5.1` is treated as a project-policy snapshot, while
GitHub reports `isImmutable=false`; it remains a `BLOCKED / NOT FOR DEPLOYMENT`
prerelease. Its tag must remain at
`89b62b341278073e7b6518b85e41cd7f7c6b682c` and must not be moved to round5.2.

| Evidence | Historical result |
|---|---|
| PR #7 | Merged as `89b62b341278073e7b6518b85e41cd7f7c6b682c` |
| Main CI | [29409182748](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29409182748): attempt 1 failed at a fuzz timer-boundary `context deadline exceeded`; attempt 2 passed `quality-and-artifacts`, `fuzz-long`, and `reproducibility` |
| Canonical exact-main artifact | ID `8340894661`, `cyber-abuse-guard-linux-amd64-dirty`, `10691298` bytes, container digest `sha256:7419fcf0c0745472728d6e9c73d99aa01737930ccf25e26501e17ae4d453db61`, expiry `2026-10-13T10:54:12Z` |
| Build identity | `build-metadata.json` binds commit `89b62b341278073e7b6518b85e41cd7f7c6b682c`; SO SHA-256 `3176d2af23963a2768672034af02fc1ca9ebe0c3f29a3654aa802ce0f822b6be` |
| Release flags | `prerelease=true`, `latest=false`; stable `v0.1.2` tag absent |
| CodeRabbit | Local CLI follow-up recorded 0 issues, but the GitHub Bot comment later ended `Review failed — pull request is closed`; no CodeRabbit approval is claimed |

The following local results are historical round5.1 `DEVELOPMENT SELF-CHECK`
evidence only. They do not validate the current round5.2 working tree and do not
replace Tencent Cloud Host validation or independent review. General gates were
rerun with the repository CI toolchain (`GOTOOLCHAIN=go1.26.4`) after the final
Tool-schema test change; the earlier full safe race and fuzz runs used the
installed Go 1.26.0 toolchain. No command below started CPA, loaded the real
Guard `.so`, ran `make integration-test`, or selected a holdout/evaluation test.

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

Historical round5.1 exact-freeze coverage and remaining remote gates were:

| Gate | Executed evidence / remaining status |
|---|---|
| HIGH-A scalar `source`/`uri`/`url`/`image_url` order invariance | **PASS** — `round5-regression`, permutation fuzz, privacy assertions, and bounded benchmark passed locally and in exact-source CI |
| HIGH-B multipart unknown-field precedence | **PASS** — fixed `multipart_unknown_field` disposition, plugin privacy/counter tests, evidence-order fuzz, and 1/8 MiB allocation benchmarks passed |
| Meta-override families and benign neighbors | **PASS** — fixed family evidence, wrapper-only allow/audit, persistent injection, compound intent, quoted analysis, bilingual cases, fuzz, and benchmarks passed |
| Tool key-only control | **PASS** — `meta_override_control/v1` maps all five approved booleans only in tool provenance; false controls remain inert and unknown known-schema controls become `tool_schema` incomplete |
| Sanitized public-taxonomy corpus | **PASS** — strict validator passed; manifest remains development-only, future-Holdout-ineligible, and contains no live payloads |
| General quality | **PASS** — module verify/tidy-diff, safe unit/race, vet, fuzz-smoke/long fuzz, benchmark, privacy, scripts, vulncheck, SBOM, package verification, and reproducibility |
| Integration | **PASS AT COMPILE/SOURCE-CONTRACT LEVEL ONLY** — ordinary CI ran `make integration-compile` and CPA v7.2.75 source contracts; it did not start CPA or load `.so` |
| Artifact | **VERIFIED HISTORICAL DEVELOPMENT EVIDENCE** — exact-main artifact `8340894661` has an archive-level digest; release assets have individual SHA-256 records, but no retained member-to-asset equivalence map; audit bundle body was not opened |
| Host/independent review | **NOT RUN** — reserved for Tencent Cloud CPA v7.2.75 isolated container with Mock upstream, followed by separate source/artifact review |

No PASS in this table transfers to the current round5.2 working tree. Round5.2
must establish a new freeze and rerun every applicable gate.

Ordinary CI deliberately excludes `make consumed-boundary-test` and every
evaluation-v10/retired-Holdout content path. The target remains only as an
explicit, separately authorized manual audit entry. Ordinary CI also no longer
runs `make integration-test`; the real CPA Host targets remain explicit/manual
and the fifth-round Tencent Cloud Host matrix is pending.

Fifth-round methodology deviation: one over-broad read-only `git grep`
unexpectedly emitted content from the restricted
`testdata/holdout/malicious-operational.jsonl` file. No holdout test ran; the
output was not redirected, copied into source/tests/docs, analyzed, or used for
tuning or conclusions. During the later release audit, one classifier source
search also unintentionally matched historical holdout gate-test source lines;
it opened no `testdata` corpus, selected no holdout/evaluation test, and did not
influence the fixes. All remaining commands explicitly exclude holdout,
evaluation-v10, and retired/historical paths. The final report must not claim
zero restricted-corpus access, and methodology handoff remains blocked.

During the post-release round5.2 re-audit, a case-insensitive path exclusion
failed and a read-only status search printed exactly one status line from each
of `EVALUATION_V5_REPORT.md` through `EVALUATION_V10_REPORT.md`. No evaluation
corpus or sample row was opened, printed, classified, extracted, or used for a
source, test, documentation, or release decision. This additional disclosure
does not change v10 `CONSUMED / FAIL` and keeps methodology handoff blocked.

During the same re-audit, a classifier sub-agent mistakenly started
`go test -shuffle=on -count=20 ./...`. The root process interrupted it after
about 23 seconds and sent `TERM` to PID `265343`. The same command then
reappeared as PID `266741` with WSL `/init` as its parent, consistent with an
orphaned CodeRabbit/tool session. The root interrupted the classifier agent
again, terminated every matching process, and verified that none remained. It
is unknown whether a consumed evaluation or Holdout test selected or read a
restricted fixture before termination. The command and every partial result
are permanently excluded and did not inform source, tests, documentation, or
release decisions. All subsequent validation is constrained to the explicit
safe allowlist. This round cannot claim no restricted access; v10 remains
`CONSUMED / FAIL`, and methodology handoff remains blocked.

During the final independent diff audit, an overly broad read-only
`cmd/**/*.go` search printed evaluation/holdout author-source snippets and a
few synthetic examples. It did not open restricted `testdata`, execute an
author/evaluation/holdout tool, or influence source, tests, documentation, or
release conclusions. The output is permanently excluded; the methodology
handoff remains blocked.

The Router cannot attest to local `model_instructions_file`, `AGENTS.md`, or
remote-template integrity before CPA receives a request. Provider
`safetySettings`, `generationConfig`, `options`, and equivalent controls require
a host-side versioned schema allowlist with rejection or forced-safe-value
overrides. Embedded ruleset `1.0.7` covers YAML assets only and excludes the Go
`META-OVERRIDE-001` overlay and related extractor/tool-schema/control-plane
logic. The historical round5.1 policy identity is `classifier-policy-v2` /
`c2092d0949fcaa1d0f085dfe31a668d45cc4d14efc10427d0f3ebcf3e821a112`.
The round5.2 source-bound identity is `classifier-policy-v2` /
`e9b87f7e2635495bdbceae469ef89e696b419f0a9a6fd129558a20bc4be947ec`;
the exact source-freeze Commit remains a separate pre-merge field.

Two P2 items remain explicit review scope. First, role-aware classification
does not compose base taxonomy from system/assistant text into a later user
message; host validation of high-priority instruction provenance,
owner/mode/hash/signature, and reload state is therefore mandatory. Second,
`Segments` currently performs a second bounded JSON parse after the primary
extractor walk. Existing differential/race/fuzz tests have not reproduced a
leak, but a single shared semantic parse product is still the intended future
hardening.

One historical round5.1 task-book evidence gap also remains: base `67b2470` to
pre-audit freeze `1466b2e7` is a single composite implementation commit. Exact
post-fix regressions are green, but no independently preserved pre-fix red-test
commit or command log exists for the two HIGH cases. This report does not infer
historical red status from the final green result.

Unit or CI success is not production admission. The engineering evidence package
can be inspected independently, but the recorded methodology incident keeps the
formal handoff `BLOCKED FOR HANDOFF`; it must never be labeled
`PRODUCTION APPROVED`.

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
