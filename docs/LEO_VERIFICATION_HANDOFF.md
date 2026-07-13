# Leo Verification Handoff

Last updated: 2026-07-14 (Asia/Shanghai)

This document is the 30-item verification handoff required by the continuation
task book. It describes a shared development tree, not a release approval.
Every PASS is scoped to its named evidence class. Missing final data is marked
`NOT RUN`, `NOT CREATED`, or `BLOCKED`; no source implementation is promoted to
an execution PASS.

Evaluation v10 was not opened, printed, classified, extracted, obtained through
Git history, or rerun. Only its frozen aggregate report was used. Do not inspect
or execute any consumed blind sample during this handoff.

Methodology incident: two incorrectly scoped WSL source-search commands
unexpectedly emitted several rows from the retired `testdata/holdout-v3`
corpus. Both searches were stopped immediately; the emitted rows were not
analyzed and were not used for classifier tuning or any conclusion. Evaluation
v10 content was not accessed. The retired holdout-v3 corpus is nevertheless no
longer eligible as independent evidence, and this incident independently keeps
the handoff status `BLOCKED FOR HANDOFF`.

## 1. Suggested frozen commit

```text
starting_baseline: a121a444cb0d82cba4e27754914a1f88258e1d7b
reliability_checkpoint_commit: 573def2649d164161e2dfdfeb3f59b1e1b38ebbc
implementation_freeze_commit: 9c8114e22841f9a19b15b1f4b3c48531aa2453a0
evidence_document_commit: SELF (resolve with git log -1 -- this file)
```

The implementation SHA must be frozen after all code/test work is reviewed. The
evidence document is then committed separately so it can record the immutable
implementation SHA without trying to self-reference its own Git commit.

## 2. Worktree status

```text
status: CLEAN AFTER EVIDENCE COMMIT
clean_tree_check: PASS AT FINAL HANDOFF (`git status --short` empty)
```

Do not claim a clean tree until `git status --short` is empty after the final
commit and all evidence files are intentionally included or excluded.

## 3. Branch and PR

```text
branch: agent/complete-classifier-cpa-v7272-handoff
pull_request: https://github.com/yujianwudi/cyber-abuse-guard/pull/4 (Draft)
github_ci_push: PASS — https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29292693070
github_ci_pull_request: PASS — https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29292695293
```

Three WSL commands were mistakenly executed outside the authorized evidence
path:

```text
make cpa-router-fixture-blackbox
make cpa-v7272-host-blackbox
scripts/management-proxy-413-test.sh
```

They used random loopback ports and Mock components only, contacted no real
provider or production service, and cleanup left no fixture process running.
Their only permitted status is:

```text
LOCAL MIS-EXECUTION RECORDED / EXCLUDED; CI REQUIRED / NOT YET AUTHORITATIVE
```

## 4. Root CPA dependency

The root `go.mod` pins:

```text
github.com/router-for-me/CLIProxyAPI/v7 v7.2.72
```

The isolated source-contract module also targets v7.2.72. This corrects the old
root v7.2.67 split.

## 5. CPA commit and module checksums

```text
upstream_tag: v7.2.72
upstream_tag_commit: 6279bb8a4c2835ff6ed99c6b85083b2afbefa681
module_sum: h1:ppce0MLsz2xJi2yi3/A60zu03cM7bMWBAEJ6eC29E5Y=
go_mod_sum: h1:f4pcyAej8RoeRhIxJfm+OUMkCKaApiA8WzxR2XVlBh8=
```

Leo must re-resolve the tag and compare `go list -m -json`/`go.sum` on the final
commit.

## 6. Go and toolchain

Recorded WSL development checks used:

```text
go version: go1.26.4 linux/amd64
CGO: enabled for SQLite/race/Host paths
target: linux/amd64, glibc 2.34+
```

Windows classifier benchmarks used Go 1.26.4 on an Intel i7-13650HX. Final
runner kernel, CPU, `GOMAXPROCS`, `GOAMD64`, and CGO values are `NOT RECORDED`.

## 7. Ruleset identity

```text
ruleset_version: 1.0.7
ruleset_sha256: 7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134
```

This identifies embedded YAML assets only.

## 8. Classifier-policy identity

```text
classifier_policy_version: classifier-policy-v2
classifier_policy_sha256: dc9a174099cb2f621e5333a508d4645604f96f470a6d9ae12a1acfb363d29cf2
source_digest_test: DEVELOPMENT SELF-CHECK PASS
authenticated_status_fields: SOURCE IMPLEMENTED / TARGETED TEST PASS
build_metadata_binding: NOT IMPLEMENTED
artifact_verifier_binding: NOT IMPLEMENTED
```

Because artifact binding is incomplete, the final Git commit remains part of
the complete behavior identity.

## 9. New classifier architecture

The deterministic classifier now separates evidence axes and emits a privacy-
safe `BehaviorGraph`: requester, action, object/asset, target/victim, technique,
delivery/execution, credential/access, persistence, evasion, exfiltration,
impact, scale, authorization/defensive purpose, wrapper/amplifier, role scope,
carrier, composition mode, and reason codes. No graph node contains raw text.

Status: **SOURCE IMPLEMENTED; TARGETED DEVELOPMENT SELF-CHECK PASS; BLIND
GENERALIZATION NOT ESTABLISHED**.

## 10. Wrapper and base-behavior separation

- wrapper-only cannot create a Cyber Abuse taxonomy;
- weak wrapper-only text allows;
- strong wrapper-only combinations are capped at non-blocking audit/observe;
- wrapper plus an independent dangerous behavior can amplify the existing
  taxonomy;
- quoted defensive wrapper analysis remains allow/audit when non-execution
  scope is genuine.

Status: **TARGETED DEVELOPMENT SELF-CHECK PASS**.

## 11. Safety-context scope

System safety policies and Assistant refusals do not supply user malicious
intent. Adjacent user continuation and one explicitly linked bounded three-turn
plan can compose behavior. Tool payload/output provenance is inspected
separately; unsupported roles use conservative fallback. Placeholders require a
nearby binding to a dangerous object/target.

Cross-request state remains stateless. Arbitrary pronoun resolution and omitted
history are not solved.

## 12. Development corpus size and coverage

`testdata/development-adversarial-v11-prep` contains 35 visible cases:

```text
block: 16
allow: 14
audit: 2
resource-boundary fixtures: 3
```

Coverage includes all eight taxonomies; OpenAI Chat, OpenAI Responses,
Anthropic, Gemini; English, Chinese, mixed language; wrapper contrasts; safety
policy/refusal; defensive, remediation, static analysis, CTF, lab,
authorization, incident response, legal/news; multi-turn; Tool payload/output;
URL percent, HTML entity, Base64, JSON Unicode, nested Tool JSON; placeholders;
max parts, near scan budget, truncation, and long input.

Validator status: **DEVELOPMENT SELF-CHECK PASS**.

## 13. Development test commands and results

Recorded PASS commands/scopes:

```bash
go test ./internal/classifier \
  -run '^(TestWrapper|TestBehaviorGraph|TestMetaOverride|TestAssistant|TestSystem|TestNoPermission|TestExplicitNoPermission|TestNegativeAuthorization|TestMaliciousSystemPolicy|TestClassifierPolicyIdentity|TestEvaluationV10)' \
  -count=1

go test ./cmd/development-adversarial-v11-prep-validator \
  -run '^TestDevelopmentAdversarialV11PrepCorpus$' -count=1

CGO_ENABLED=0 go test ./internal/plugin \
  -run '^TestPromptInjection(ControlPlaneRegression|NestedToolAndSplitEncodingRegression)$' \
  -count=1

go vet ./internal/classifier ./cmd/development-adversarial-v11-prep-validator
go mod verify
go mod tidy -diff
```

Also PASS on WSL/ext4/Go 1.26.4: `-race` subject/config/audit and targeted
plugin idempotency/lifecycle/privacy tests; reliability `go vet`; health and
release-evidence privacy scripts. `reports/TEST_REPORT.md` records their scopes
and representative reproducibility commands; this section is the authoritative
list of commands used for the current handoff.

The safe broad development gate uses:

```bash
./scripts/go-safe-development-test.sh test
./scripts/go-safe-development-test.sh race
./scripts/go-safe-development-test.sh boundary
```

All three direct modes passed on WSL Ubuntu 26.04 with Go 1.26.4. `test` and
`race` ran no Evaluation/Holdout test name; `boundary` executed only the three
v10 aggregate/report-marker/rerun-rejection tests and logged that the fixture
was not accessed. This is **DEVELOPMENT SELF-CHECK / NOT FINAL EVIDENCE**.

The Makefile exposes these as `make unit-test`, `make race`, and
`make consumed-boundary-test`; exact-freeze CI passed the mapped gates. Broad
commands that open consumed fixtures remain prohibited.

## 14. Evidence classification notice

All results in items 8–13 are:

```text
DEVELOPMENT SELF-CHECK / NOT FINAL EVIDENCE
```

They are not GitHub CI, not real-Host evidence, not final artifacts, not Leo's
independent result, and not a blind quality score.

## 15. Performance reference

Same Windows machine/command, median of three:

| Case | `a121a44` | `a1be19f` |
|---|---:|---:|
| Classifier | 165,552 ns/op; 24,446 B; 43 allocs | 103,190 ns/op; 25,487 B; 46 allocs |
| LargeBenign | 18,461,010 ns/op; 301,778 B; 9 allocs | 17,682,477 ns/op; 300,966 B; 9 allocs |
| LargePunctuation | 17,705,454 ns/op; 301,778 B; 9 allocs | 16,397,845 ns/op; 299,551 B; 9 allocs |
| CandidateRichMaxParts | 119,484,917 ns/op; 82,548 B; 175 allocs | 97,126,983 ns/op; 83,588 B; 178 allocs |
| RoleAwareConversation | 383,775 ns/op; 130,412 B; 198 allocs | 356,226 ns/op; 135,614 B; 213 allocs |

Latency improved; several allocation counts increased. Pending-cache full insert
measured 266.4–318.5 ns/op on Windows versus a 105.2–112.3 us/op linear
reference; duplicate subject request was 374.9–405.5 ns/op, 0 B/op, 0 allocs.

Review-closure commit `8814dbf` was rerun locally on WSL/Linux amd64 with Go
1.26.4. Median-of-three results were: Classifier 92,070 ns/op; LargeBenign
15,612,625 ns/op; LargePunctuation 15,395,706 ns/op;
CandidateRichMaxParts 88,235,463 ns/op; RoleAwareConversation 333,250 ns/op.
The exact implementation freeze `9c8114e` separately passed GitHub CI benchmark
acceptance; its median Classifier result was 94,050 ns/op. Full bytes/allocation
data and acceptance percentiles are in `reports/PERFORMANCE.md`.

Status: **IMPLEMENTATION-FREEZE DEVELOPMENT SELF-CHECK PASS / LEO INDEPENDENT
RERUN NOT RUN**.

## 16. Privacy canary method and result

Unique synthetic prompt/key/auth/cookie/OAuth/domain/model/subject canaries are
exercised across DB/WAL/SHM, migration backup, subject snapshot, JSON/CSV,
management/executor response, panic/logger output, watchdog, and release
evidence. Recorded WSL/script targeted tests: **DEVELOPMENT SELF-CHECK PASS**.

Real Host management authentication, proxy 413, and development-candidate
artifact/SBOM scans: **GITHUB CI PASS**. Leo independent review: **NOT RUN**.

The v1→v2 migration validates legacy `request_hash`, `subject_hash`, `model`,
and `source_format` before publishing a backup or writing schema v2. A non-
digest value or non-canonical provider value fails closed: no backup is
published, no migration occurs, and the original database is retained for
operator repair. The implementation does not automatically sanitize a legacy
plaintext database.

## 17. CPA Store ZIP root listing

Required final shape:

```text
cyber-abuse-guard_<version>_linux_amd64.zip
└── cyber-abuse-guard-v<version>.so  (root, regular, mode 0755)
```

The implementation-freeze GitHub CI artifact has this Store ZIP root listing:

```text
cyber-abuse-guard_0.1.2-dirty_linux_amd64.zip
└── cyber-abuse-guard-v0.1.2-dirty.so
```

Development-candidate artifact: `cyber-abuse-guard-linux-amd64-dirty`, artifact
ID `8295799031`, 10,240,174 uploaded bytes. These are not formal release
artifacts.

| Candidate file | SHA-256 |
|---|---|
| `cyber-abuse-guard-v0.1.2-dirty.so` | `e7562d3993e69ec3b0bbb052b1cb472aa6b7e527afce7ca36342b90aeec869b9` |
| `cyber-abuse-guard_0.1.2-dirty_linux_amd64.zip` | `544406fbf246f4989f1e4275cce69f0d112d0ff68a5c720d4ecf5113d4a87121` |
| `cyber-abuse-guard-v0.1.2-dirty-audit-bundle.zip` | `4ada1c9a802f68390f03ed0ac672497fbb6e70e638e689d27a68c57203d55a8d` |
| `build-metadata.json` | `01ba04cac4058c008a3790626f02a7b545ce92c31afd1423a9f5316c9b6e2fb8` |
| `checksums.txt` | `ccc17d139a3a9e74b9f021998c1c7151adb177303c18a14b1b93ad53061dbb10` |
| `ruleset-manifest.json` | `486a4dfad49b4e96a600f908cbea47376baab5c8875324999ae50b6251f1af7e` |
| `ruleset.sha256` | `a8ff687340617dc18832047f841979a0bd06ff8c50a4bc3c15dd7da37b6fbee2` |
| `sbom.cdx.json` | `72ab91ed1b0ee8cb461b8847a18c759f324b34299b2bb6a5d854e467954690c0` |

## 18. Official InstallArchive result and path

Synthetic official installer tests remain source-contract evidence only and are
not accepted as GitHub CI artifact evidence.

Required real result fields:

```text
real_store_zip_sha256: 544406fbf246f4989f1e4275cce69f0d112d0ff68a5c720d4ecf5113d4a87121
installed_path: <host-test-temp>/plugins/linux/amd64/cyber-abuse-guard-v0.1.2-dirty.so
installed_artifact_identity_and_layout: GITHUB CI PASS
first_install_and_real_host_load: GITHUB CI PASS
repeat_install_skip_same_dist_identity: GITHUB CI PASS
tamper_repair_same_dist_identity: GITHUB CI PASS
```

The authorized CI lifecycle is one combined evidence chain: Host Blackbox uses
`InstallManifest` for first install and real Host load, then
`TestPublishedStoreArchive` uses the same Dist identity for repeat-skip and
tamper-repair. `REQUIRE_DIST_ARTIFACTS=1` must make missing `.so`, ZIP, metadata,
or checksums fail; synthetic fallback is not CI evidence.

## 19. Four-protocol refusal matrix

| Protocol | Non-stream block | Stream block | Allow control | Status |
|---|---:|---:|---:|---|
| OpenAI Chat | 403 | 403 before SSE | native path | **GITHUB CI PASS** |
| OpenAI Responses | 403 | 403 before SSE | native path | **GITHUB CI PASS** |
| Anthropic | native 403 | native 403 before SSE | native path | **GITHUB CI PASS** |
| Gemini | native 403 | native 403 before SSE | native path | **GITHUB CI PASS** |

## 20. Stream pre-SSE result

Required assertion: no successful SSE header or chunk before the policy 403,
prompt connection termination, and no 200-with-error-chunk substitution.

Status: **GITHUB CI PASS** on the exact implementation freeze; Leo independent
rerun is **NOT RUN**.

## 21. Token-count 403 and `http_request` 405

Token-count RPC/unit contract and the supported Anthropic/Gemini Host paths:
**GITHUB CI PASS**. Leo independent rerun is **NOT RUN**.

Guard `executor.http_request` returns an RPC error carrying status 405, and the
official `ProviderExecutor.HttpRequest` adapter returns `(nil, error)`. This is
a **SOURCE / ADAPTER CHECK**. CPA v7.2.72 does expose the provider-specific
public consumer `POST /v1/alpha/search`, but ordinary selection is fixed to
`codex` and the handler maps every `HttpRequest` error to HTTP 502. The project
`httptest.Server` manually maps `error.StatusCode()` and is not an official CPA
public handler. In addition, the official `NewHttpRequest` path requires a
`RequestPreparer` capability that the current plugin executor adapter does not
provide, so it can fail with 502 before `executor.http_request` is reached. No
current official public route maps Guard's error to final client 405.

```text
official_cpa_final_client_http_405: NOT AVAILABLE / NOT RUN
handoff_effect: BLOCKED FOR HANDOFF
ci_effect: current CI cannot change the official handler's error-to-502 mapping
```

## 22. Zero upstream side effects

For every blocked Host request, required counters are:

```text
Auth Selector calls = 0
Provider calls = 0
Usage queue records = 0
Mock Upstream calls = 0
```

The implementation-freeze CI Host run passed all 32 Host subtests. Every blocked
case retained zero Auth Selector, Provider, Usage Queue, and Mock Upstream side
effects; safe controls crossed the native downstream seams. Local WSL data
remains excluded, and Leo independent verification is **NOT RUN**.

## 23. Router priority/fail-open matrix

Second Router/executor fixture source covers Guard priority win, fixture
priority win, equal-priority ID ordering, Guard missing, registration failure,
disabled state, route error, invalid target, missing identifier, format/scope
not-ready, and native fallback. Fuse and pre-result panic remain official source
overlay cases; a segfault is not accepted as a substitute.

Status: **GITHUB CI PASS — 15 isolated native Router scenarios**. Fuse/panic
behavior remains separately covered by the pinned official source overlay; Leo
independent rerun is **NOT RUN**.

## 24. Management proxy 413

Required chain:

```text
reverse proxy body limit
  -> oversized management request returns 413
  -> CPA management handler receives zero requests
  -> plugin receives/parses zero oversized RPCs
```

Fixture/script: **GITHUB CI PASS**. The oversized request returned 413 before
the counted CPA-handler stub; the local WSL execution remains excluded. Leo
independent rerun is **NOT RUN**.

## 25. Known limitations

- CPA ABI-v1 Host fail-open, no in-process Router inventory or duplicate `.so`
  directory visibility;
- no HMAC dual-key rotation or keyed whole-snapshot MAC;
- bounded decoding cannot cover arbitrary encoding/encryption/archive/document
  transforms;
- opaque media semantics are not inspected and remote media is never fetched;
- classifier is stateless across separate API calls;
- trusted peer/principal identity is not exposed by CPA;
- classifier-policy identity is not yet artifact-metadata-bound;
- final official CPA client HTTP 405 for Guard `executor.http_request` is
  unavailable in the v7.2.72 public handler surface; adapter status-error 405 is not a
  substitute;
- only Linux amd64/glibc 2.34+ is in release scope;
- no guarantee against upstream account action.

## 26. Items not yet run

```text
implementation freeze: 9c8114e22841f9a19b15b1f4b3c48531aa2453a0
evidence document commit: SELF (resolve with git log -1 -- this file)
safe development quality matrix: DEVELOPMENT SELF-CHECK PASS
GitHub CI on exact implementation commit: PASS (push + PR runs)
real CPA v7.2.72 store install/load: GITHUB CI PASS
four-protocol Host matrix: GITHUB CI PASS
zero-side-effect counters: GITHUB CI PASS
Router fixture Host matrix: GITHUB CI PASS (15 scenarios)
management proxy 413: GITHUB CI PASS
http_request adapter/status-error 405: SOURCE / ADAPTER CHECK (response=nil)
official CPA final client HTTP 405: NOT AVAILABLE / NOT RUN — BLOCKER
development-candidate artifact build/hash/scan: GITHUB CI PASS; not a release
Leo independent verification: NOT RUN
new independent blind evaluation: NOT CREATED
```

## 27. Leo verification order and commands

First freeze and identify the implementation commit. Local work is limited to
source-only and safe development gates; Host, Router, Nginx, and real Store
lifecycle execution is restricted to authorized GitHub CI and Leo's isolated
environment.

```bash
git status --short
git rev-parse HEAD
git log --oneline --decorate -10
go version
go env GOOS GOARCH CGO_ENABLED GOMAXPROCS GOAMD64

make format-check
make git-diff-check
make module-verify
./scripts/go-safe-development-test.sh test
./scripts/go-safe-development-test.sh race
./scripts/go-safe-development-test.sh boundary
make vet
make fuzz-smoke
make script-test
make corpus-regression
make benchmark
make vulncheck
make build-linux-amd64
make cpa-host-fixture-contract
```

The authorized GitHub CI job must then run `make integration-test`,
`make management-proxy-413-test`, and
`REQUIRE_DIST_ARTIFACTS=1 make cpa-store-contract`, followed by artifact
inspection with `sha256sum -c`, `file`, `readelf`, `nm`, and `unzip -Z -l`.
Leo repeats those native checks only in the authorized isolated environment.
Verify CI belongs to the implementation freeze SHA; do not use `|| true`, a
silent skip, synthetic artifact fallback, or an older result.

Neither the current CI job nor Leo can claim final official CPA client HTTP 405
while the only relevant public consumer selects a different provider in its
ordinary path and maps every executor error to HTTP 502. If no official route
can map Guard's status error to 405, retain `BLOCKED FOR HANDOFF`; do not treat
the project-owned `httptest.Server` as closure.

## 28. Development corpus prohibition

The 35-case `development-adversarial-v11-prep` corpus and all derived wording
are permanently prohibited as an independent v11 or future Holdout. Leo may use
it only as visible regression evidence. Any blind quality result requires a new
author, isolated inputs, frozen hashes, aggregate-only output, and zero row-level
inspection before the decision.

## 29. No release or production action

```text
annotated_tag: NOT CREATED
github_release: NOT CREATED
formal_release_artifacts: NOT PUBLISHED
production_cpa_deployment_or_change: NOT PERFORMED
independent_v11: NOT CREATED / NOT RUN
```

## 30. Final handoff status

```text
BLOCKED FOR HANDOFF
```

Reason: engineering and authorized GitHub CI gates pass, but Leo independent
verification and a new independent blind evaluation are not run; two accidental
retired holdout-v3 row exposures invalidate that corpus as independent evidence;
and official CPA final client HTTP 405 is unavailable. The status may change
only after the remaining independent verification and the 405 requirement are
resolved without reading or rerunning consumed samples.
