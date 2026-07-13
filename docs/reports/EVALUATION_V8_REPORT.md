# Evaluation v8 Report

Status: **CONSUMED / FAIL**

## Isolation

Evaluation v8 was created independently after production ruleset 1.0.6 was
frozen. The author did not run a classifier. Independent validation and this
report used aggregate-only output and did not expose fixture text, IDs, or
row-level results.

## Frozen corpus

- Artifact: `testdata/evaluation-v8/evaluation-v8.jsonl`
- SHA-256: `c722af0c6aae0bd909e808c8bb7a25f3e3481d8e135206e4d8e8ab3efb54edcd`
- Lines: 640
- Bytes: 442,461
- Benign: 320
- Policy violations: 320

Every record has exactly eight fields: `id`, `source`, `label`, `taxonomy`,
`language`, `carrier`, `tags`, and `input`. IDs are globally unique, tags are
non-empty and duplicate-free, and every `input` is a production-style JSON
object.

## Aggregate distribution

The eight policy taxonomies contain 40 records each: `credential_theft`,
`phishing_deployment`, `malware_deployment`, `ransomware_deployment`,
`unauthorized_exploitation`, `service_disruption`, `data_exfiltration`, and
`defense_evasion`. The benign taxonomy contains 320 records.

Language totals are `en=227`, `zh-CN=187`, and `zh-en=226`. The sixteen
carriers each contain 40 records, split evenly as 20 benign and 20 policy
violations: `anthropic_messages`, `anthropic_tool_use`, `api_query_wrapper`,
`base64_prompt`, `gemini_contents`, `gemini_function_call`, `generic_prompt`,
`multi_turn_chat`, `nested_json`, `openai_chat`, `openai_responses`,
`openai_tool_call`, `responses_function_call`, `unicode_confusable`,
`url_encoded_prompt`, and `zero_width_dialogue`.

## Independent aggregate-only static verification

- Invalid JSON, schema, input, tag, or duplicate-ID records: 0
- Production `extract.ExtractText(record.Input)` failures: 0 / 640
- Empty extractions, truncations, or parse errors: 0
- Routing aggregate: role-aware 440; untrusted 200
- Normalized semantic duplicate groups: 0
- Duplicate records after first: 0
- Prior-data index: 4,462 records across all 14 earlier corpus, holdout, and
  evaluation JSONL files; parse/extraction fallback failures: 0
- Cross-old normalized semantic overlap: 0 records / 0 unique hashes
- Author no-overwrite rerun: PASS

## Consumed independent gate

The gate is `internal/classifier/evaluation_v8_gate_test.go`. Static corpus and
production-snapshot integrity tests remain available. The one opt-in run used
production `extract.ExtractText`, role-aware or untrusted classification as
indicated by the extractor, balanced mode, default thresholds, and default
policy. It emitted only benign false positives, overall blocked/exact counts,
eight taxonomy blocked/exact counts, and routing aggregates. The gate now
rejects `INDEPENDENT_HOLDOUT_V8=1` immediately so the consumed corpus cannot be
classified again.

- Production implementation/dependency snapshot SHA-256:
  `67dc31487d5453827e18f4c8d2586e9f4f35684b32a136463c94f64f314d5452`
- YAML rules snapshot SHA-256:
  `ca37b48e484e37376d80db31b7521cfbf722c5e4a454b80cca8085316bc9e3bb`
- Canonical embedded ruleset SHA-256:
  `e25b781bfc88dac1e50e09147902f0debf7075368ea5709d73b8d32543c1ff75`

Release thresholds are benign false-positive rate `<5%`, overall blocked and
exact rates `>90%`, and blocked plus exact rates `>=95%` for
`credential_theft`, `phishing_deployment`, `ransomware_deployment`, and
`data_exfiltration`.

## First and only formal run result

- Date: `2026-07-13` (Asia/Shanghai)
- Command: `make holdout-test`
- Exit status: non-zero (quality gate failed)
- Gate result: **FAIL**

| Aggregate | Total | Blocked / FP | Exact |
|---|---:|---:|---:|
| Benign | 320 | 13 false positives | n/a |
| Policy violations | 320 | 126 blocked | 119 |
| Role-aware | 440 total | 6 benign FP; 90/220 policy blocked | 83 |
| Untrusted | 200 total | 7 benign FP; 36/100 policy blocked | 36 |

| Taxonomy | Total | Blocked | Exact |
|---|---:|---:|---:|
| `credential_theft` | 40 | 37 | 37 |
| `phishing_deployment` | 40 | 40 | 40 |
| `malware_deployment` | 40 | 7 | 0 |
| `ransomware_deployment` | 40 | 40 | 40 |
| `unauthorized_exploitation` | 40 | 0 | 0 |
| `service_disruption` | 40 | 0 | 0 |
| `data_exfiltration` | 40 | 1 | 1 |
| `defense_evasion` | 40 | 1 | 1 |

The benign false-positive rate was 4.06% and passed its floor. Overall blocked
and exact rates were 39.38% and 37.19%, so the overall release floors failed.
Critical-category floors passed for phishing and ransomware deployment, but
failed for credential theft and data exfiltration. No fixture text, ID, or
row-level outcome was printed or inspected. Evaluation v8 is frozen and must
not be rerun or used for row-specific tuning.

Formal classification run: **EXECUTED ONCE / FAIL**

Quality gate: **FAIL**
