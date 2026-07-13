# Evaluation v9 Report

Status: **CONSUMED / METHODOLOGY INVALID / FAIL**

## Isolation

Evaluation v9 was created independently after production ruleset 1.0.7 was
frozen. The author did not run a classifier. Independent validation and this
report used aggregate-only output and did not expose fixture text, IDs, or
row-level results.

## Frozen corpus

- Artifact: `testdata/evaluation-v9/evaluation-v9.jsonl`
- SHA-256: `0481ee919f12a267458f99780fdd2c252209de81b89d5e6c9cac156e38c12c0c`
- Lines: 640
- Bytes: 312,095
- Benign: 320
- Policy: 320

Every record has exactly eight fields: `id`, `source`, `label`, `taxonomy`,
`language`, `carrier`, `tags`, and `input`. IDs are globally unique, tags are
non-empty and duplicate-free, and every `input` is a production-style JSON
object.

## Aggregate distribution

The eight policy taxonomies contain 40 records each: `credential_theft`,
`phishing_social_engineering`, `malware_development`, `ransomware_extortion`,
`denial_of_service_botnet`, `data_exfiltration`, `defense_evasion`, and
`destructive_disruption`. The benign taxonomy contains 320 records.

Language totals are `en=160`, `mixed=160`, and `zh=320`. The sixteen carriers
each contain 40 records, split evenly as 20 benign and 20 policy:
`anthropic_messages`, `anthropic_tool_use`, `base64_text`, `gemini_contents`,
`gemini_function_call`, `html_entity`, `multi_turn`, `nested_request`,
`openai_chat`, `openai_chat_blocks`, `openai_responses`, `openai_tool_call`,
`prompt_scalar`, `text_data_url`, `tool_result`, and `url_encoded`.

## Independent aggregate-only static verification

- Invalid JSON, schema, input, tag, or duplicate-ID records: 0
- Production `extract.ExtractText(record.Input)` failures: 0 / 640
- Empty extractions, truncations, or parse errors: 0
- Routing aggregate: role-aware 400; untrusted 240
- Normalized semantic duplicate groups: 0
- Duplicate records after first: 0
- Prior-data index: 5,102 records across all 15 earlier corpus, holdout, and
  evaluation JSONL files; parse/extraction fallback failures: 0
- Cross-old normalized semantic overlap: 0 records / 0 unique hashes
- Author no-overwrite rerun: PASS

## Methodology invalidation

The authoring contract required exactly these eight policy taxonomy values:
`credential_theft`, `phishing_deployment`, `malware_deployment`,
`ransomware_deployment`, `unauthorized_exploitation`, `service_disruption`,
`data_exfiltration`, and `defense_evasion`.

The v9 corpus instead used five unexpected replacements:
`phishing_social_engineering`, `malware_development`, `ransomware_extortion`,
`denial_of_service_botnet`, and `destructive_disruption`, while omitting five
required values. The pre-run static gate verified the corpus's internally
declared taxonomy list but failed to reject names outside the fixed contract.
That missing exact-enum validation invalidates the methodology. The observed
classification aggregates are retained as historical diagnostics only and
must not be used as a release gate.

## Consumed independent gate

The gate is `internal/classifier/evaluation_v9_gate_test.go`. Static corpus and
production-snapshot integrity tests remain available. The one opt-in run used
production `extract.ExtractText`, balanced mode, default thresholds, and
default policy, but the corpus taxonomy contract was invalid. The gate now
rejects `INDEPENDENT_HOLDOUT_V9=1` immediately so the consumed corpus cannot be
classified again.

The attempted label mapping does not repair the authoring-contract violation
and is not accepted as a valid release-gate methodology.

- Production implementation/dependency snapshot SHA-256:
  `090955c800944f8d248ff960cd5c860b17ea0d566cfa0aae90554db30248096b`
- YAML rules snapshot SHA-256:
  `3fb15df990c7e6369b8dc4c4e725cf1b09a8251275b2145afcd1cd9a859741db`
- Canonical embedded ruleset SHA-256:
  `7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134`

Release thresholds are benign false-positive rate `<5%`, overall blocked and
exact rates `>90%`, and blocked plus exact rates `>=95%` for
`credential_theft`, `phishing_social_engineering`, `ransomware_extortion`, and
`data_exfiltration`.

## First and only formal run result

- Date: `2026-07-13` (Asia/Shanghai)
- Command: `make holdout-test`
- Exit status: non-zero
- Gate result: **METHODOLOGY INVALID / FAIL**

| Aggregate | Total | Blocked / FP | Exact |
|---|---:|---:|---:|
| Benign | 320 | 8 false positives | n/a |
| Policy | 320 | 32 blocked | 32 |

| Corpus taxonomy | Total | Blocked | Exact |
|---|---:|---:|---:|
| `credential_theft` | 40 | 8 | 8 |
| `phishing_social_engineering` | 40 | 0 | 0 |
| `malware_development` | 40 | 8 | 8 |
| `ransomware_extortion` | 40 | 0 | 0 |
| `denial_of_service_botnet` | 40 | 8 | 8 |
| `data_exfiltration` | 40 | 8 | 8 |
| `defense_evasion` | 40 | 0 | 0 |
| `destructive_disruption` | 40 | 0 | 0 |

The observed benign false-positive rate was 2.5%, and observed blocked/exact
rates were 10%. These numbers are not valid release-gate evidence because the
fixed taxonomy contract was violated before classification. No fixture text,
ID, or row-level outcome was printed or inspected. Evaluation v9 is frozen and
must not be rerun or used for row-specific tuning.

Formal classification run: **EXECUTED ONCE / METHODOLOGY INVALID / FAIL**

Quality gate: **INVALID / FAIL**
