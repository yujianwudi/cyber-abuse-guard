# Test Report — v0.1.2 candidate

Last updated: 2026-07-13 (Asia/Shanghai)

Target: CLIProxyAPI `v7.2.67`, commit
`2075f77c8ebe9ec872759965661936fb1ac2931f`, C ABI/RPC schema v1, Linux amd64,
glibc 2.34+, pinned Go `1.26.4`.

## Release status

**RELEASE GATE FAIL / RELEASE BLOCKED.** The earlier non-blind functional and
engineering candidate gates recorded below are a pre-prompt-injection-change
baseline; they cannot be inherited by the current diff or override the formal
evaluation. Methodologically valid v10 was executed exactly once against
ruleset 1.0.7 and failed with benign FP 28/320, policy blocked 49/320, and exact
33/320. v10 is consumed and cannot be rerun. Do not create a `v0.1.2` tag,
GitHub Release, formal artifact set, or production deployment. A future attempt
requires a new implementation and a new independently authored unseen set.

The current development tree is a post-v10 implementation. Evaluation tooling,
extraction edges, cross-Unix secret-file handling, operational scripts, and
dependencies changed after the v10 implementation snapshot. Historical v9/v10
checks retain recorded corpus and snapshot hashes without forcing later
development HEADs to equal those implementations. In a full Git checkout, v9
and v10 now recompute those hashes from the frozen historical commit/tree, and
verify the corresponding corpus and formal report Git blobs. The validator
requires the exact path, SHA-256, and row inventory of every earlier JSONL
corpus. Missing Git metadata or a shallow checkout without the recorded commit
is a hard test failure, not a skipped integrity gate. This does not relax the
release gate: current source is unevaluated and needs a new independent set.

Known history: v1 is a retired methodology-invalid diagnostic; v2-v8 are
consumed failures; v9 is `CONSUMED / METHODOLOGY INVALID / FAIL` because the
exact taxonomy-enum validator was missing; v10 is a methodologically valid
`CONSUMED / FAIL`. None may be used for row-specific tuning.

## Current prompt-injection development diff

The following checks were run against the post-v10 prompt-injection source on
2026-07-13. A PASS here means only that developer-visible regression/static
checks passed. It is not blind evidence, server-sandbox evidence, native-load
evidence, real-CPA integration evidence, or release approval.

| Gate | Command | Current-diff result |
|---|---|---|
| Modified Go formatting | `/home/yujian/.local/toolchains/go1.26.4/bin/gofmt -l internal/classifier/classifier.go internal/classifier/matcher.go internal/classifier/meta_override.go internal/classifier/meta_override_test.go internal/classifier/normalize.go internal/classifier/roles.go internal/extract/extract.go internal/extract/roles.go internal/extract/roles_test.go internal/plugin/router.go internal/plugin/prompt_injection_regression_test.go internal/rules/types.go` | **PASS — empty output** |
| Related source packages | `/home/yujian/.local/toolchains/go1.26.4/bin/go test -tags=sqlite_omit_load_extension ./internal/rules ./internal/extract ./internal/classifier ./internal/plugin -count=1` | **PASS** |
| Targeted static analysis | `/home/yujian/.local/toolchains/go1.26.4/bin/go vet -tags=sqlite_omit_load_extension ./internal/rules ./internal/extract ./internal/classifier ./internal/plugin` | **PASS** |
| Module integrity | `/home/yujian/.local/toolchains/go1.26.4/bin/go mod verify` | **PASS — all modules verified** |
| Module graph cleanliness | `/home/yujian/.local/toolchains/go1.26.4/bin/go mod tidy -diff` | **PASS — empty output** |
| Diff whitespace | `git diff --check` | **PASS** |
| Targeted race detector | `/home/yujian/.local/toolchains/go1.26.4/bin/go test -race -tags=sqlite_omit_load_extension ./internal/extract ./internal/classifier ./internal/plugin -run '^(TestMetaOverride.*|TestNegativeAuthorizationClearsLabLaundering|TestMaliciousSystemPolicyCannotNegateRefusalInsteadOfAbuse|TestSystemClosedQuoteCannotHideNewOperationalSentence|TestAssistant.*|Test.*Permission.*|TestExtractTextRoleAmbiguityReextractsUnknownTopLevelSemantics|TestExtractTextUnknownTopLevelMetadataDoesNotEraseRoleIsolation|TestExtractTextRedecodesEncodedContentSplitAcrossBlocks|TestExtractTextRedecodesEncodedToolFieldsAfterPristineJoin|TestExtractTextRecursesJSONStringUnderArbitraryToolPayloadField|TestPromptInjection.*)$' -count=1` | **PASS** |
| Server sandbox | owner-operated server sandbox | **PENDING / NOT RUN** |
| Current-diff real CPA integration | not authorized locally | **NOT RUN** |
| Native plugin load/deployment | not authorized locally | **NOT RUN** |
| Formal Holdout | prohibited; v10 is consumed | **NOT RUN** |
| Release packaging/tag/GitHub Release | prohibited by failed gate | **NOT RUN / NOT CREATED** |

## Pre-change candidate command matrix

This matrix records the broader candidate baseline before the current
prompt-injection diff and the final v10 gate. Its PASS rows must not be read as
current-diff verification or converted into a tagged-release matrix.

| Gate | Command | Final result |
|---|---|---|
| Format | `make format-check` | **PASS** |
| Diff whitespace | `make git-diff-check` | **PASS** |
| Module integrity | `make module-verify` | **PASS** |
| Unit/package tests | `make test` | **PASS** |
| Static analysis | `make vet` | **PASS** |
| Race detector | `make race` | **PASS** |
| Fuzz smoke | `make fuzz-smoke` | **PASS — 363,059 + 98,493 + 149,048 executions** |
| Regression corpus | `make corpus-regression` | **PASS — FP 0/142; recall/exact 154/154** |
| Retired Holdout v1 frozen integrity | default unit test | **PASS (no classification)** |
| Consumed Holdout v2 integrity only | `go test -tags=sqlite_omit_load_extension ./internal/classifier -run '^TestIndependentHoldoutV2FrozenIntegrity$' -count=1` | PASS (no classification) |
| Consumed Holdout v3 frozen integrity | default unit test | **PASS (no classification)** |
| Consumed evaluation v4-v8 frozen integrity/history | default unit tests + frozen reports | **PASS / frozen (no authorized rerun)** |
| Consumed invalid evaluation v9 integrity/history | default unit tests + historical Git-blob recomputation + `EVALUATION_V9_REPORT.md` | **METHODOLOGY INVALID / FAIL** |
| Formal evaluation v10 | first and only `make holdout-test` | **FAIL — FP 28/320; blocked 49/320; exact 33/320** |
| Consumed v10 rerun protection | current `make holdout-test` | **PASS — rerun rejected with non-zero exit** |
| Development generalization Round 4 | default classifier development tests | **PASS — malicious 64/64; legitimate FP 0/64** |
| Benchmark acceptance | `make benchmark` | **PASS** |
| Dependency vulnerability evidence | `make vulncheck` + GitHub Dependabot | **0 reachable vulnerabilities; 14 open module alerts (7 critical, 2 high, 5 moderate); no release exception** |
| Linux amd64 build | `make build-linux-amd64` | **PASS (dirty-suffixed candidate)** |
| Real CPA integration | `make integration-test` | **PASS** |
| Formal clean-tag release | `make release` | **NOT RUN / BLOCKED by v10 FAIL** |
| Candidate release packaging | `make sbom package-release` | **PASS — dirty development ZIP/SO/SBOM regenerated after dependency upgrade** |
| Strict release verification | `make verify-release` | **PASS (candidate artifact)** |
| Verifier fault injection | `make verification-fault-test` | **PASS — all 14 faults rejected** |
| Artifact hashes | `make artifact-hash` | **PASS (candidate artifact)** |
| Two-clone formal reproducibility | `make reproducibility-test` | **NOT FINALIZED — release blocked** |
| Clean tagged source tree | `make clean-tree-check` | **NOT APPLICABLE — no release tag may be created** |

The consolidated task-book sequence is:

```bash
gofmt -w .
git diff --check
go mod verify
go test -tags=sqlite_omit_load_extension ./...
CGO_ENABLED=1 go test -race -tags=sqlite_omit_load_extension ./...
go vet -tags=sqlite_omit_load_extension ./...
make fuzz-smoke
make benchmark
make integration-test
# This now fails immediately because v10 is consumed; do not bypass it.
make holdout-test
govulncheck ./...
```

`make release` and `make formal-release` must remain blocked. Do not create a
tag or add build outputs merely to manufacture a clean-tree/release result.

## Required security assertions

The final test log must prove every item below:

- blocked raw content leaves Mock Upstream calls at zero;
- blocked requests leave CPA Auth Selector calls at zero;
- blocked requests create no real-upstream usage record;
- safe OpenAI Chat, Responses, Anthropic, Gemini, tool, and stream requests
  preserve the original model, content, tool arguments, and client behavior;
- there is no System Prompt injection, identity spoofing, model rewrite, or
  request laundering;
- encoded URL/HTML/Base64/JSON/tool payloads use bounded production extraction;
- prompt-injection labels such as education, authorization, and CTF do not wash
  protected operational categories;
- assistant refusal and system safety text do not become user malicious intent;
- old malicious intent plus a follow-up is retained despite safe padding;
- unknown roles, deep JSON, too many parts, truncated UTF-8/escapes, and an RPC
  beyond the native copy budget do not panic or silently bypass enforcement;
- recognized opaque media follows `block|audit|allow` and mode-aware defaults;
  pure text is unaffected and no media URL is fetched;
- Router panics/errors update counters and an active Balanced/Strict runtime
  self-routes known/recovered failure paths instead of entering auth/upstream;
- invalid reconfigure preserves the last valid runtime and reports the error;
- SQLite unavailable/locked, queue full, and persistence failure do not disable
  local classification/blocking;
- v0.1.1 → schema-v2 migration is atomic, preserves events, creates only bounded
  backups when enabled, and rolls back after injected migration failure;
- optional subject persistence stores HMAC IDs only, applies expiry/decay and
  capacity on restore, and explicitly rejects an HMAC-key mismatch;
- management routes reject missing/wrong/normal client keys at the CPA host,
  reject oversized bodies and unsupported queries/methods, and withstand
  injection, traversal, deletion, and concurrency probes;
- privacy canaries are absent from DB, WAL, SHM, logs, management responses,
  panic output, release ZIP, and SBOM metadata;
- the local watchdog probes never invoke `/v1`, Auth Selector, usage, provider,
  or upstream and never mutate account/configuration state.

## Holdout evidence handling

Regression and Holdout data must be reported separately. The regression corpus
is co-maintained with rules and cannot establish blind accuracy.

v1-v8 are retired or consumed failures. v9 is a consumed methodology-invalid
failure. The methodologically valid v10 record is retained in
`EVALUATION_V10_REPORT.md` and is the final release-blocking result for this
candidate. Generation-specific reports and frozen identities must not be
edited, relabelled, reclassified for a release decision, or used for row-
specific tuning.

Any future release evaluation, after a new implementation exists, must include:

- frozen benign/malicious file names, record counts, bytes, SHA-256, source
  marker, authoring/review process, and deduplication method;
- at least 200 benign and 200 malicious records;
- Balanced FP `< 5%`, total recall `> 90%`, and each critical category
  (`credential_theft`, `phishing_deployment`, `ransomware_deployment`,
  `data_exfiltration`) `>= 95%`;
- production extraction path, exact command, clean commit/tag, ruleset version
  and hash, exit status, and aggregate-only output;
- confirmation that no individual miss text/ID was inspected before the release
  decision.

## Final evidence block

Fill only after all gates pass:

```text
release_commit_tag_tree_and_artifact_hashes: NOT CREATED — RELEASE BLOCKED
go_version: go1.26.4 linux/amd64
runner_os_kernel: WSL2 Linux 6.18.33.1-microsoft-standard-WSL2
cpu: 13th Gen Intel Core i7-13650HX; 20 logical CPUs
ruleset_version: 1.0.7
ruleset_sha256: 7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134
formal_evaluation_result: v10 CONSUMED / FAIL; FP 28/320; blocked 49/320; exact 33/320
server_sandbox_validation: PENDING / NOT RUN
current_diff_real_cpa_integration: NOT RUN
current_diff_native_loading_or_deployment: NOT RUN
test_log_sha256: no formal tagged release log — release blocked
overall_release_gate: FAIL / NOT PRODUCTION-READY
```

Historical v0.1.1 measurements may be consulted through Git history, but they
are context only and are not evidence for this candidate.
