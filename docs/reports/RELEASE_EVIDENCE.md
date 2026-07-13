# v0.1.2 Release Evidence and Audit Closure

Last updated: 2026-07-13 (Asia/Shanghai)

## Decision

**RELEASE DECISION: FAIL / NOT PRODUCTION-READY.**

Reasons:

1. Holdout and evaluation generations v1-v9 are consumed or frozen historical
   evidence and cannot approve this release.
2. Independently authored evaluation v9 was executed once, then invalidated
   because its taxonomy names violated the fixed authoring contract and the
   static gate had failed to reject those names. It is frozen against reruns.
3. Methodologically valid evaluation v10 was executed once against ruleset
   1.0.7 and failed benign false-positive, overall, and all four critical
   category floors. The release is blocked and v10 is frozen against reruns.
4. Non-blind functional, performance, real-CPA integration, privacy,
   vulnerability, candidate packaging, and verifier-fault checks passed as a
   pre-prompt-injection-change engineering baseline. The current diff has only
   the source-level checks recorded in `TEST_REPORT.md`; it does not inherit
   current-diff CPA/native/deployment evidence. Neither baseline nor current
   checks can override the blind release-gate failure.
5. The clean release commit, annotated tag `v0.1.2`, GitHub Release, formal
   artifact set, and formal artifact SHA-256 values were deliberately not
   created because the release gate failed.

No pending or failed item may be converted to PASS based on design intent,
historical v0.1.1 output, a dirty development build, or a retest of consumed
holdout/evaluation data.

## Target and release identity

```text
source_version: 0.1.2
target_cpa_version: v7.2.67
target_cpa_commit: 2075f77c8ebe9ec872759965661936fb1ac2931f
cpa_abi: C ABI/RPC schema v1
target_platform: linux/amd64
glibc_floor: 2.34
go_version: 1.26.4
ruleset_version: 1.0.7
release_commit: NOT CREATED — RELEASE BLOCKED
annotated_tag: NOT CREATED — RELEASE BLOCKED
ruleset_sha256: 7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134
source_tree_clean: NOT A RELEASE TREE; no tag may be created
server_sandbox_validation: PENDING / NOT RUN
current_diff_real_cpa_integration: NOT RUN
current_diff_native_loading_or_deployment: NOT RUN
prompt_injection_blind_evaluation: NOT CREATED
```

## Audit-item closure matrix

“Implemented” describes source state; it is not a release PASS until the
evidence column is complete.

| Audit item | Source response | Evidence status |
|---|---|---|
| Clean Git commit and annotated tag | Formal preflight rejects dirty source, mismatched version/tag/HEAD | NOT CREATED; blocked by v10 FAIL |
| Script executable bits | Shell scripts tracked as executable in release source | PASS candidate Git-mode check; no tagged release source |
| Verifier must fail hard | `set -euo pipefail`, strict dependency/artifact/ELF/ABI/hash/archive checks, fault injection | PASS candidate fault suite; no formal artifact |
| Clean-tag-only artifacts | formal builds reject modified/staged/untracked files; dirty override is visibly suffixed | PASS mechanism; no release tag created |
| Independent evaluation | v1-v9 history frozen; v9/v10 implementation, rules, corpus, and formal report evidence bound to a recomputable historical Git commit/tree with missing/shallow history rejected; exact prior-corpus paths/hashes/rows frozen; methodologically valid v10 consumed after one formal run | **FAIL: v10 GATE / RELEASE BLOCKED** |
| Encoding/bypass tests | bounded URL/HTML/Base64/text-data/JSON/tool decoding; ambiguous-schema fallback; recursive JSON in tool payloads; split-block and ordered tool-field re-decode; isolated-character reconstruction | PASS current-diff source tests; server sandbox pending |
| Prompt-injection washing | post-v10 `META-OVERRIDE-001` source overlay covers hierarchy/refusal/persona/scope/output/disclosure/negative-authorization combinations while retaining ordinary taxonomy | SOURCE IMPLEMENTED; current-diff source tests PASS; server sandbox PENDING; formal evidence unresolved; v10 remains FAIL |
| Multi-turn/role pollution | per-segment plus adjacent-user analysis; conservative unsupported roles; no semantic state across separate API calls | PASS current-diff source tests; cross-request continuation remains a limitation |
| Router fail-open mitigation | panic recovery, mode-aware self-route, counters, readiness, local probes | PASS controlled CPA tests; host boundary remains |
| Health monitoring | authenticated status plus read-only loopback watchdog | PASS local candidate tests; production deployment prohibited |
| No original-text logging | unsafe field rejected; typed minimal events; no debug override | PASS candidate privacy scan |
| SQLite migration | schema version/history, atomic v1→v2, bounded optional read-only backup | PASS candidate engineering tests |
| Subject persistence | optional HMAC-only typed snapshots, decay/capacity restore, key mismatch protection | PASS candidate engineering tests; no keyed whole-snapshot MAC |
| HMAC production handling | atomic no-output generator, mode-0600 secret file, stable/degraded status | PASS candidate tests; dual-key rotation remains design-only |
| Dual-key rotation | design documented; not implemented | ACCEPTED LIMITATION, operator must preserve key |
| Opaque media | explicit policy, mode-aware defaults, separate signal/counters, no public fetch | PASS candidate engineering tests |
| Rule version/hash | embedded YAML ruleset 1.0.7 remains canonical and status-visible; meta, matcher/normalizer, role, and extractor semantics require the containing build commit too | YAML identity PASS; complete classifier-policy identity UNRESOLVED until separately versioned or provenance-bound |
| Performance gates | acceptance/benchmark/CPU-profile procedure documented | PASS candidate engineering gate; host-specific |
| Management hardening | CPA-authenticated exact routes, body/query/page/method bounds, fixed unblock body | PASS controlled real-CPA tests |
| Router conflict/duplicate binary | ABI limitation surfaced; manual deployment checks/watchdog notice | MANUAL CONTROL REQUIRED |
| CI/CD | explicit quality, Holdout, benchmark, vuln, CPA, artifact, fault, clean/repro gates | NO TAGGED RUN; release correctly blocked |
| SBOM/vulnerability | CycloneDX 1.6 and pinned govulncheck in release workflow | PASS candidate checks; no formal release SBOM |
| Reproducibility | fixed metadata/time/order and two-clean-clone byte comparison | NOT FINALIZED; release blocked before tag |
| Gray rollout | Observe → Audit → Balanced with promotion/abort criteria | DOCUMENTED; prohibited for this candidate |
| Rollback/cleanup | disable, previous binary/DB restore, secret retention, explicit data removal | DOCUMENTED; no production rollout authorized |

## Evidence documents

| Document | Scope | Current status |
|---|---|---|
| `TEST_REPORT.md` | full command/test matrix | pre-change baseline PASS; current-diff targeted source checks PASS; v10 release FAIL |
| `HOLDOUT_REPORT.md` | frozen v1 calibration diagnostic | consumed history |
| `HOLDOUT_V2_REPORT.md` | independently authored frozen v2 aggregate | consumed; FAIL |
| `HOLDOUT_V3_REPORT.md` | historical blind generation v3 | consumed; FAIL |
| `EVALUATION_V4_REPORT.md` | independent evaluation v4 | consumed history |
| `EVALUATION_V5_REPORT.md` | independent evaluation v5 | consumed history |
| `EVALUATION_V6_REPORT.md` | independent evaluation v6 | consumed; FAIL |
| `EVALUATION_V7_REPORT.md` | independent evaluation v7 | consumed; FAIL |
| `EVALUATION_V8_REPORT.md` | independent evaluation v8 | consumed; FAIL |
| `EVALUATION_V9_REPORT.md` | independent evaluation v9 | consumed; METHODOLOGY INVALID / FAIL |
| `EVALUATION_V10_REPORT.md` | current methodologically valid formal gate | consumed; FAIL |
| `CORPUS_REPORT.md` | project-maintained regression corpus | PASS candidate engineering signal; not blind evidence |
| `PERFORMANCE.md` | latency, CPU, allocation, profile procedure | PASS pre-change baseline; current diff not benchmarked |
| `CPA_INTEGRATION.md` | real CPA + mock upstream/auth/usage isolation | PASS pre-change baseline; current prompt-injection diff NOT RUN |
| `PRIVACY.md` | DB/WAL/SHM/log/API/artifact/network canary scan | PASS pre-change baseline; current diff not rerun end-to-end |
| `PROMPT_INJECTION_REVIEW.md` | sanitized external defensive review and current source response | development input only; not blind; server sandbox pending |

## Mandatory redlines

Every row must be PASS before “production-ready” is used:

| Redline | Status |
|---|---|
| Blocked raw content never reaches Mock Upstream | PASS PRE-CHANGE BASELINE; CURRENT DIFF NOT RUN |
| Blocked request never enters CPA Auth Selector | PASS PRE-CHANGE BASELINE; CURRENT DIFF NOT RUN |
| Blocked request creates no real-upstream usage record | PASS PRE-CHANGE BASELINE; CURRENT DIFF NOT RUN |
| Raw prompt and plaintext credentials absent from all persistent/returned/logged surfaces | PASS PRE-CHANGE BASELINE; CURRENT DIFF END-TO-END PRIVACY NOT RUN |
| Safe request identity, model, body, and tools remain unchanged | PASS PRE-CHANGE BASELINE; CURRENT DIFF NOT RUN |
| No safety-system bypass, identity spoofing, or request laundering | DEVELOPMENT REGRESSION PASS ONLY; no blind generalization proof; server sandbox PENDING; release remains blocked |
| Legitimate defense/remediation/CTF/authorized work meets FP gate | FAIL v10 (28 / 320 false positives; 8.75%) |
| Clean Git worktree | NOT A RELEASE TREE; release stopped before tag |
| Release built from exact annotated tag and commit | NOT CREATED because v10 failed |
| Verifier returns non-zero on every injected missing/mismatch fault | PASS candidate fault suite |
| Independent blind evaluation v10 meets all gates | **FAIL: method valid; release blocked** |
| Documentation states risk reduction, not an account-ban guarantee | PASS (documentation) |

## Historical consumed evaluation v7 evidence

Generated after classifier, rules, decoder, and test methodology were frozen.
The author/reviewer did not use prior rows as templates for row-specific fixes.
Record:

```text
dataset_file: testdata/evaluation-v7/evaluation-v7.jsonl
total_records: 640
benign_records: 320
policy_violation_records: 320
dataset_bytes: 404528
dataset_sha256: bd7ec34c6b38244d9b2cf28512b2b427c855129f290f9ef1feec13fc545e5afc
implementation_sha256: 62f0fe804b5f2f38bf74c26d4b347827899053c2f6d71a4d9d60583310bde6c3
rules_sha256: a3641baffbb65f1de8ba73ad98fb69446122b9712e12bc2b02ba7f37a2027e10
source_marker: independent-evaluation-v7-2026-07-13
dedup_against_all_3822_prior_rows: PASS (normalized exact semantic overlap 0)
production_path_command: make holdout-test
benign_fp: 4/320 = 1.25% (PASS; required < 5%)
overall_policy_blocked: 97/320 = 30.31% (FAIL; required > 90%)
overall_policy_exact: 97/320 = 30.31% (FAIL; required > 90%)
credential_theft_blocked_exact: 40/40 = 100% (PASS; required >= 95%)
phishing_deployment_blocked_exact: 0/40 = 0% (FAIL; required >= 95%)
ransomware_deployment_blocked_exact: 40/40 = 100% (PASS; required >= 95%)
data_exfiltration_blocked_exact: 0/40 = 0% (FAIL; required >= 95%)
row_level_output_disabled: PASS (gate implementation inspection)
formal_command: make holdout-test
exit_status: non-zero (quality gate failed)
consumption_status: EXECUTED ONCE / FAIL; rerun rejected by gate
```

## Historical consumed evaluation v8 evidence

Generated after classifier, ruleset 1.0.6, decoder, and test methodology were
frozen. The author/reviewer did not use prior rows as templates for row-specific
fixes. Record:

```text
dataset_file: testdata/evaluation-v8/evaluation-v8.jsonl
total_records: 640
benign_records: 320
policy_violation_records: 320
dataset_bytes: 442461
dataset_sha256: c722af0c6aae0bd909e808c8bb7a25f3e3481d8e135206e4d8e8ab3efb54edcd
implementation_dependency_sha256: 67dc31487d5453827e18f4c8d2586e9f4f35684b32a136463c94f64f314d5452
yaml_rules_snapshot_sha256: ca37b48e484e37376d80db31b7521cfbf722c5e4a454b80cca8085316bc9e3bb
ruleset_sha256: e25b781bfc88dac1e50e09147902f0debf7075368ea5709d73b8d32543c1ff75
source_marker: independent_synthetic_v8
dedup_against_all_4462_prior_rows: PASS (normalized exact semantic overlap 0)
production_path_command: make holdout-test
benign_fp: 13/320 = 4.06% (PASS; required < 5%)
overall_policy_blocked: 126/320 = 39.38% (FAIL; required > 90%)
overall_policy_exact: 119/320 = 37.19% (FAIL; required > 90%)
credential_theft_blocked_exact: 37/40 = 92.5% (FAIL; required >= 95%)
phishing_deployment_blocked_exact: 40/40 = 100% (PASS; required >= 95%)
ransomware_deployment_blocked_exact: 40/40 = 100% (PASS; required >= 95%)
data_exfiltration_blocked_exact: 1/40 = 2.5% (FAIL; required >= 95%)
row_level_output_disabled: PASS (gate implementation inspection)
formal_command: make holdout-test
exit_status: non-zero (quality gate failed)
consumption_status: EXECUTED ONCE / FAIL; rerun rejected by gate
```

## Historical invalid evaluation v9 evidence

Generated after classifier, ruleset 1.0.7, decoder, and test methodology were
frozen. The author/reviewer did not use prior rows as templates for row-specific
fixes. Record:

```text
dataset_file: testdata/evaluation-v9/evaluation-v9.jsonl
total_records: 640
benign_records: 320
policy_records: 320
dataset_bytes: 312095
dataset_sha256: 0481ee919f12a267458f99780fdd2c252209de81b89d5e6c9cac156e38c12c0c
implementation_dependency_sha256: 090955c800944f8d248ff960cd5c860b17ea0d566cfa0aae90554db30248096b
yaml_rules_snapshot_sha256: 3fb15df990c7e6369b8dc4c4e725cf1b09a8251275b2145afcd1cd9a859741db
ruleset_sha256: 7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134
source_marker: independent-evaluation-v9-author
dedup_against_all_5102_prior_rows: PASS (normalized exact semantic overlap 0)
production_path_command: make holdout-test
methodology_status: INVALID (unexpected taxonomy names; exact enum gate missing)
release_gate_eligible: false
benign_fp_observed: 8/320 = 2.5% (diagnostic only)
overall_policy_blocked_observed: 32/320 = 10% (diagnostic only)
overall_policy_exact_observed: 32/320 = 10% (diagnostic only)
row_level_output_disabled: PASS (gate implementation inspection)
formal_command: make holdout-test
exit_status: non-zero
consumption_status: EXECUTED ONCE / METHODOLOGY INVALID / FAIL; rerun rejected
```

## Historical consumed evaluation v10 evidence

Generated after classifier, ruleset 1.0.7, decoder, exact taxonomy methodology,
and test procedure were frozen. Record:

```text
dataset_file: testdata/evaluation-v10/evaluation-v10.jsonl
total_records: 640
benign_records: 320
policy_records: 320
dataset_bytes: 394629
dataset_sha256: e42b881103a00c0a7bf0359f8494804bc3aeabc6c2e0bafff99593043129cbef
implementation_dependency_sha256: 090955c800944f8d248ff960cd5c860b17ea0d566cfa0aae90554db30248096b
yaml_rules_snapshot_sha256: 3fb15df990c7e6369b8dc4c4e725cf1b09a8251275b2145afcd1cd9a859741db
ruleset_sha256: 7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134
source_marker: evaluation-v10-author
exact_taxonomy_enum_gate: PASS (0 unexpected, 0 missing, eight categories x 40)
dedup_against_all_5742_prior_rows: PASS (normalized exact semantic overlap 0)
production_path_command: make holdout-test
methodology_status: VALID
benign_fp: 28/320 = 8.75% (FAIL; required < 5%)
overall_policy_blocked: 49/320 = 15.31% (FAIL; required > 90%)
overall_policy_exact: 33/320 = 10.31% (FAIL; required > 90%)
credential_theft_blocked_exact: 8/40 = 20% (FAIL; required >= 95%)
phishing_deployment_blocked_exact: 0/40 = 0% (FAIL; required >= 95%)
ransomware_deployment_blocked_exact: 24/40 = 60% (FAIL; required >= 95%)
data_exfiltration_blocked_exact: 0/40 = 0% (FAIL; required >= 95%)
row_level_output_disabled: PASS (gate implementation inspection)
formal_command: make holdout-test
exit_status: non-zero (quality gate failed)
consumption_status: EXECUTED ONCE / FAIL; rerun rejected by gate
```

If any floor fails, preserve the files and hashes, publish aggregate failure,
and stop the release. Do not delete/relabel misses or tune one literal per row.

The current development tree is newer than the implementation/dependency
snapshot recorded above. Post-v10 audit fixes and dependency updates must not
replace that historical hash or be evaluated by rerunning the consumed corpus.
CI verifies the frozen corpus, historical report markers, and rerun rejection
separately. Current source has no independent release result and remains
blocked until a new unseen set is authored outside the implementation process.

## Required formal artifacts

| Artifact | SHA-256 | Verified |
|---|---|---|
| `cyber-abuse-guard-v0.1.2.so` | NOT CREATED | RELEASE BLOCKED |
| `cyber-abuse-guard-v0.1.2.so.sha256` | NOT CREATED | RELEASE BLOCKED |
| `cyber-abuse-guard_0.1.2_linux_amd64.zip` | NOT CREATED | RELEASE BLOCKED |
| `checksums.txt` | NOT CREATED | RELEASE BLOCKED |
| `build-metadata.json` | NOT CREATED | RELEASE BLOCKED |
| `ruleset-manifest.json` | NOT CREATED | RELEASE BLOCKED |
| `ruleset.sha256` | NOT CREATED | RELEASE BLOCKED |
| `sbom.cdx.json` | NOT CREATED | RELEASE BLOCKED |
| `release-test-summary.txt` | NOT CREATED | RELEASE BLOCKED |
| `release-test-summary.txt.sha256` | NOT CREATED | RELEASE BLOCKED |

Release ZIP verification must use an exact allowlist and reject `.git`, DB/WAL/
SHM, migration backups, secret/key/PEM/env files, logs, and unexpected paths.
GitHub Repository/Release, source `tar.gz`, and the audited ZIP are supported;
RAR is not a formal release format.

## Vulnerability and exception record

```text
govulncheck_command: govulncheck ./...
govulncheck_version: v1.6.0
result: PASS (candidate engineering check; 0 reachable vulnerabilities)
github_dependabot_open_alerts: 14 (7 critical, 2 high, 5 moderate)
github_dependabot_packages: golang.org/x/crypto; golang.org/x/net
post_v10_source_versions: golang.org/x/crypto v0.52.0; golang.org/x/net v0.55.0
patched_version_floor_status: SATISFIED IN DEVELOPMENT BRANCH; GitHub closure requires merge to the default branch and repository rescan
unfixed_high_severity_findings: OPEN IN GITHUB against prior pushed module graph; not reachable according to prior govulncheck
exceptions: NONE GRANTED; production release remains prohibited
required_follow_up: review and merge the dependency remediation, confirm GitHub alerts close after rescan, rerun all gates, and use a new independent evaluation
```

GitHub's dependency-version alerts and `govulncheck` answer different questions.
The latter found no reachable vulnerable call path in this candidate, but that
does not waive the 14 open Dependabot alerts. No time-bounded release exception
was granted; the already-failed blind gate and these unresolved module alerts
both prohibit a production release.

## Reproducibility record

```text
status: NOT FINALIZED — release stopped after v10 FAIL
source_date_epoch: NOT APPLICABLE
clone_a_commit: NOT APPLICABLE
clone_b_commit: NOT APPLICABLE
so_sha256_a: NOT CREATED
so_sha256_b: NOT CREATED
zip_sha256_a: NOT CREATED
zip_sha256_b: NOT CREATED
byte_identical: NOT CLAIMED
```

## Final approval block

This block must be completed by the release owner after independent review:

```text
release_commit: NOT CREATED — RELEASE BLOCKED
annotated_tag_object: NOT CREATED — RELEASE BLOCKED
tag_target_commit: NOT CREATED — RELEASE BLOCKED
github_release_url: NOT CREATED — RELEASE BLOCKED
github_actions_release_run: NOT RUN — RELEASE BLOCKED
server_sandbox_validation: PENDING / NOT RUN
current_diff_real_cpa_integration: NOT RUN
prompt_injection_blind_evaluation: NOT CREATED
classifier_policy_identity: UNRESOLVED — ruleset 1.0.7 hash covers YAML assets only; code semantics require containing build commit
all_redlines_pass: NO
known_unimplemented_requirements:
  - dual-key HMAC rotation (design only)
  - CPA ABI-v1 host fail-open/router enumeration/duplicate-directory visibility
  - persisted subject snapshot has no keyed whole-snapshot MAC
  - unknown or encrypted encodings may evade semantic detection
known_non_guarantee:
  - cannot guarantee that an upstream account will never be warned, suspended, or banned
release_owner: NOT APPROVED
independent_reviewer: NOT APPROVED
approval_time_utc: NOT APPLICABLE
decision: REJECT / FAIL
```

Even after approval, the release statement remains: the plugin reduces risk and
cannot guarantee that an upstream account will never be warned, suspended, or
deactivated.
