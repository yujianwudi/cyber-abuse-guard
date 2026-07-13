# Independent Holdout v2 Report

## Status

**CONSUMED — FAILED — NOT RELEASE EVIDENCE**

The frozen v2 holdout was executed exactly once on 2026-07-12 (Asia/Shanghai). A package-level security-review command unintentionally selected the gate after the data had been frozen. That first and only classifier run exited non-zero. The data was not changed, the classifier and rules were not tuned from the result, and the classifier gate was not run again.

The consumed classifier test is now named `TestRetiredHoldoutV2Gate` and skips immediately so a broad package test cannot reuse the holdout. `TestIndependentHoldoutV2FrozenIntegrity` remains runnable for hash, count, and duplicate checks. This report does not support a release claim or a production-ready claim.

The separately authored formal successor is frozen and documented in
`HOLDOUT_V3_REPORT.md`; no v2 row or aggregate was used to tune that gate.

## Independence and generation principles

- The 500 prompts were independently authored before any v2 classifier result was available.
- The evaluator read only task-book sections 3, 4, 17, and 21 plus exported `internal/extract`, `internal/classifier`, and `internal/rules` API/type documentation.
- The evaluator did not open or search `testdata/holdout/**`, `docs/reports/HOLDOUT_REPORT.md`, `cmd/holdout-fixtures/**`, `internal/classifier/holdout_gate_test.go`, any `testdata/corpus` text, `rules/*.yaml`, classifier tests, or classifier term lists.
- Samples use original natural Chinese, English, and mixed-language phrasing. They were not produced by adapting existing rule phrases.
- The benign set covers security review, remediation, isolated CTF/lab work, high-level analysis, and non-executable detection logic. The malicious set contains explicit operational intent, including safety-label washing and authorization conflicts.
- Every sample has one of 20 frozen structures: plain, Base64, URL encoding, HTML entity, JSON Unicode escape, zero width, homoglyph, typo, NBSP, Markdown, string concatenation, nested tool JSON, multi-turn, role pollution, prompt injection, authorization conflict, defensive repair, CTF, high-level, or detection-rule framing.
- Every sample is marshalled into a production-style OpenAI Chat, OpenAI Responses, Anthropic, Gemini, or nested-tool JSON request and passed through `extract.ExtractText`. Trusted-role results use `ClassifySegmentsWithPolicy`; missing or unknown role provenance uses `ClassifyUntrustedPartsWithPolicy`.
- The files contain no sample ID field. Test output and this report contain aggregate values only; no individual text, ID, or decision is emitted.

Source marker:

```text
independent-original-holdout-v2-2026-07-12
benign=e88f9a1dc4bd3465b041ab2e636dbde74f7e48aa319b2ff42c26ae46d06b5b4b
malicious=64f1fb64494458a4e937c83970ca0a90b1f9f367e7e021fe7018365fc97d4ab4
```

## Frozen artifacts

| File | Lines | Bytes | SHA-256 |
|---|---:|---:|---|
| `testdata/holdout-v2/benign-security.jsonl` | 240 | 76,837 | `e88f9a1dc4bd3465b041ab2e636dbde74f7e48aa319b2ff42c26ae46d06b5b4b` |
| `testdata/holdout-v2/malicious-operational.jsonl` | 260 | 99,987 | `64f1fb64494458a4e937c83970ca0a90b1f9f367e7e021fe7018365fc97d4ab4` |
| `internal/classifier/holdout_v2_gate_test.go` (retired gate plus active integrity test) | 478 | 16,193 | `7fbafd3ea7571f235d5c0264f63f143994d18977b8d920bc0c427c7045ba0cc8` |

The test hard-codes both JSONL hashes and the exact expected distributions. It also rejects normalized duplicates within v2 and direct normalized duplicates against v1/corpus, without printing either side. Before the classifier run, frozen integrity passed with `validation_errors=0`, `self_duplicates=0`, `legacy_direct_duplicates=0`, and `legacy_read_errors=0`.

## Frozen population

- Labels: benign 240; malicious 260.
- Languages: Chinese 168; English 168; mixed 164.
- Categories: benign 240; credential theft 35; phishing deployment 35; ransomware deployment 35; data exfiltration 35; malware deployment 30; unauthorized exploitation 30; service disruption 30; defense evasion 30.
- Structures: 20 structures, exactly 25 samples each.
- Providers: Anthropic 125; Gemini 100; OpenAI Chat 137; OpenAI Responses 100; nested tool JSON 25; unknown-role fallback 13.

## Commands and execution record

Static frozen-integrity command, run before the classifier result:

```powershell
wsl.exe -- bash -lc "export HOME=/home/yujian; export PATH=/home/yujian/.local/toolchains/go1.26.0/bin:/usr/bin:/bin; cd /mnt/d/御剑无敌/文档/世界杯/cyber-abuse-guard; go test -count=1 -run '^TestIndependentHoldoutV2FrozenIntegrity$' -v ./internal/classifier"
```

Result: exit 0; integrity PASS.

First and only formal classifier execution, triggered by the security-review package test:

```powershell
wsl.exe -d Ubuntu-26.04 --cd 'D:\御剑无敌\文档\世界杯\cyber-abuse-guard' -- /home/yujian/.local/toolchains/go1.26.4/bin/go test -count=1 -tags=sqlite_omit_load_extension ./internal/audit ./internal/subject ./internal/extract ./internal/classifier
```

Result: exit 1. The classifier package failed in 1.512 seconds. No second classifier run was made.

Ruleset identity from that run:

```text
version=1.0.2
sha256=a76796ddb712edb9fbbeb4596e559b984043b622ef62537d466ec715f35ecc81
```

Extraction aggregate: errors 0; empty results 0; truncated results 0.

## Gate result

The Balanced gate requires benign FP `< 5%`, overall malicious recall `> 90%`, and correct-category recall `>= 95%` for each critical category. A malicious sample contributes to correct-category recall only when it is blocked and assigned its expected category.

| Gate | Result | Requirement | Status |
|---|---:|---:|---|
| Benign false-positive rate | 18/240 = 7.50% | < 5% | FAIL |
| Overall malicious blocked recall | 103/260 = 39.62% | > 90% | FAIL |
| Credential-theft correct-category recall | 20/35 = 57.14% | >= 95% | FAIL |
| Phishing-deployment correct-category recall | 11/35 = 31.43% | >= 95% | FAIL |
| Ransomware-deployment correct-category recall | 30/35 = 85.71% | >= 95% | FAIL |
| Data-exfiltration correct-category recall | 1/35 = 2.86% | >= 95% | FAIL |

All six gate conditions failed (`failures=6`). Overall correct-category accuracy was 82/260 = 31.54%.

## Language aggregates

| Language | Benign | FP | FP rate | Malicious | Blocked | Blocked recall | Correct category | Category recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| English | 80 | 4 | 5.00% | 88 | 34 | 38.64% | 26 | 29.55% |
| Mixed | 80 | 10 | 12.50% | 84 | 30 | 35.71% | 26 | 30.95% |
| Chinese | 80 | 4 | 5.00% | 88 | 39 | 44.32% | 30 | 34.09% |

## Category aggregates

| Category | Total | FP | FP rate | Blocked | Blocked recall | Correct category | Category recall |
|---|---:|---:|---:|---:|---:|---:|---:|
| Benign | 240 | 18 | 7.50% | 0 | n/a | 0 | n/a |
| Credential theft | 35 | 0 | n/a | 20 | 57.14% | 20 | 57.14% |
| Data exfiltration | 35 | 0 | n/a | 2 | 5.71% | 1 | 2.86% |
| Defense evasion | 30 | 0 | n/a | 10 | 33.33% | 10 | 33.33% |
| Malware deployment | 30 | 0 | n/a | 9 | 30.00% | 6 | 20.00% |
| Phishing deployment | 35 | 0 | n/a | 27 | 77.14% | 11 | 31.43% |
| Ransomware deployment | 35 | 0 | n/a | 30 | 85.71% | 30 | 85.71% |
| Service disruption | 30 | 0 | n/a | 1 | 3.33% | 1 | 3.33% |
| Unauthorized exploitation | 30 | 0 | n/a | 4 | 13.33% | 3 | 10.00% |

## Structure aggregates

Every structure contains 12 benign and 13 malicious samples.

| Structure | FP | FP rate | Blocked | Blocked recall | Correct category | Category recall |
|---|---:|---:|---:|---:|---:|---:|
| Authorization conflict | 0 | 0.00% | 5 | 38.46% | 3 | 23.08% |
| Base64 | 2 | 16.67% | 4 | 30.77% | 4 | 30.77% |
| CTF | 0 | 0.00% | 1 | 7.69% | 1 | 7.69% |
| Defensive repair | 0 | 0.00% | 5 | 38.46% | 5 | 38.46% |
| Detection rule | 0 | 0.00% | 3 | 23.08% | 2 | 15.38% |
| High level | 0 | 0.00% | 3 | 23.08% | 3 | 23.08% |
| Homoglyph | 0 | 0.00% | 7 | 53.85% | 4 | 30.77% |
| HTML entity | 2 | 16.67% | 8 | 61.54% | 6 | 46.15% |
| JSON Unicode | 0 | 0.00% | 7 | 53.85% | 6 | 46.15% |
| Markdown | 0 | 0.00% | 6 | 46.15% | 4 | 30.77% |
| Multi-turn | 2 | 16.67% | 4 | 30.77% | 4 | 30.77% |
| NBSP | 0 | 0.00% | 7 | 53.85% | 7 | 53.85% |
| Plain | 0 | 0.00% | 7 | 53.85% | 6 | 46.15% |
| Prompt injection | 0 | 0.00% | 4 | 30.77% | 3 | 23.08% |
| Role pollution | 12 | 100.00% | 4 | 30.77% | 3 | 23.08% |
| String concatenation | 0 | 0.00% | 7 | 53.85% | 6 | 46.15% |
| Nested tool JSON | 0 | 0.00% | 3 | 23.08% | 2 | 15.38% |
| Typo | 0 | 0.00% | 4 | 30.77% | 3 | 23.08% |
| URL encoding | 0 | 0.00% | 7 | 53.85% | 4 | 30.77% |
| Zero width | 0 | 0.00% | 7 | 53.85% | 6 | 46.15% |

## Interpretation and release disposition

The extraction layer processed every frozen request, but the Balanced classifier missed most operationally malicious prompts and exceeded the permitted benign false-positive rate. The particularly weak aggregate groups are evidence of release risk; they are not authorization to inspect individual cases or tune against this consumed set.

Post-consumption code review identified two harness limitations that invalidate claims of complete provider-path coverage:

- The `tool_json` wrapper placed nested JSON inside user message content rather than using a provider-native `tool_calls.function.arguments` request shape.
- The intended unknown-role wrapper used `developer`; the current extractor normalizes that role as system, so it did not exercise a genuinely unknown-role fallback.

These limitations were not used to alter or rerun the frozen gate. A future independent holdout must correct both before its first execution. The v2 critical-category gate deliberately used blocked-and-correct-category recall; the report separately preserves blocked-only recall so the two meanings cannot be conflated.

Holdout v2 remains frozen solely as an audit record. Any future release claim requires a newly generated, independently controlled holdout that has not been used for rule or classifier development. The plugin can reduce abuse risk but cannot guarantee that an upstream account will never receive a warning or suspension.
