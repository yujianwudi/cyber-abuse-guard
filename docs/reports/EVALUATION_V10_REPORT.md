# Evaluation v10 Report

Status: **CONSUMED / FAIL**

## Isolation

Evaluation v10 was created independently after production ruleset 1.0.7 was
frozen. The author did not run a classifier. Independent validation and this
report used aggregate-only output and did not expose fixture text, IDs, or
row-level results.

## Frozen corpus

- Artifact: `testdata/evaluation-v10/evaluation-v10.jsonl`
- SHA-256: `e42b881103a00c0a7bf0359f8494804bc3aeabc6c2e0bafff99593043129cbef`
- Lines: 640
- Bytes: 394,629
- Benign: 320
- Policy: 320

Every record has exactly eight fields: `id`, `source`, `label`, `taxonomy`,
`language`, `carrier`, `tags`, and `input`. IDs are globally unique, tags are
non-empty and duplicate-free, and every `input` is a production-style JSON
object.

## Exact taxonomy contract

The static gate rejects any missing, unexpected, or miscounted policy taxonomy
before classification. The only accepted values are `credential_theft`,
`phishing_deployment`, `malware_deployment`, `ransomware_deployment`,
`unauthorized_exploitation`, `service_disruption`, `data_exfiltration`, and
`defense_evasion`, with exactly 40 records each. v10 passes this exact-enum gate
with zero failures.

Language totals are `en=320` and `zh-CN=320`. The sixteen carriers each contain
40 records, split evenly as 20 benign and 20 policy:
`anthropic_messages_plain`, `anthropic_tool_use`, `base64_text`,
`gemini_contents_plain`, `gemini_function_call`, `html_entity_text`,
`markdown_fence`, `nested_json_text`, `openai_chat_content_parts`,
`openai_chat_plain`, `openai_responses_function_call`,
`openai_responses_input`, `tool_arguments_json_string`,
`tool_parameters_object`, `url_encoded_text`, and `xml_wrapper`.

## Independent aggregate-only static verification

- Invalid JSON, schema, input, tag, or duplicate-ID records: 0
- Unexpected, missing, or miscounted fixed taxonomies: 0
- Production `extract.ExtractText(record.Input)` failures: 0 / 640
- Empty extractions, truncations, or parse errors: 0
- Routing aggregate: role-aware 520; untrusted 120
- Normalized semantic duplicate groups: 0
- Duplicate records after first: 0
- Prior-data index: 5,742 records across all 16 earlier corpus, holdout, and
  evaluation JSONL files; parse/extraction fallback failures: 0
- Cross-old normalized semantic overlap: 0 records / 0 unique hashes
- Author no-overwrite rerun: PASS

## Consumed independent gate

The gate is `internal/classifier/evaluation_v10_gate_test.go`. Static corpus,
exact-taxonomy, and historical snapshot-record integrity tests remain
available. The recorded snapshot hashes identify the implementation used by
the consumed run; a later post-v10 development HEAD is intentionally not
required to reproduce those hashes. The one opt-in run used production
`extract.ExtractText`, role-aware or untrusted classification as indicated by
the extractor, balanced mode, default thresholds, and default policy. It
emitted only aggregate metrics. The gate now rejects
`INDEPENDENT_HOLDOUT_V10=1` immediately so the consumed corpus cannot be
classified again. Future implementation quality must be evaluated with a new
independent blind set.

- Historical snapshot commit:
  `0f1d68717daadfd5dfc514ff2174cfb641a5d845`
- Historical snapshot tree:
  `df878c537bca9fd71256b1c81ced18e72b583cf3`
- Historical report Git-blob SHA-256:
  `e4c293eaae0fa29b5ccea8c43d09a76f98ef8827cd428de574c0942f24816010`
- Production implementation/dependency snapshot SHA-256:
  `090955c800944f8d248ff960cd5c860b17ea0d566cfa0aae90554db30248096b`
- YAML rules snapshot SHA-256:
  `3fb15df990c7e6369b8dc4c4e725cf1b09a8251275b2145afcd1cd9a859741db`
- Canonical embedded ruleset SHA-256:
  `7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134`

In a full Git checkout, the frozen-integrity test resolves that commit to the
recorded tree, verifies the frozen corpus and formal report Git blobs, and
recomputes all three implementation/rules hashes directly from Git blobs. This
keeps later development HEADs free to evolve without reducing the historical
record to editable report strings or mutable corpus constants.

Release thresholds are benign false-positive rate `<5%`, overall blocked and
exact rates `>90%`, and blocked plus exact rates `>=95%` for
`credential_theft`, `phishing_deployment`, `ransomware_deployment`, and
`data_exfiltration`.

## First and only formal run result

- Date: `2026-07-13` (Asia/Shanghai)
- Command: `make holdout-test`
- Exit status: non-zero (quality gate failed)
- Methodology: valid
- Gate result: **FAIL**

| Aggregate | Total | Blocked / FP | Exact |
|---|---:|---:|---:|
| Benign | 320 | 28 false positives | n/a |
| Policy | 320 | 49 blocked | 33 |
| Role-aware | 520 total | 22 benign FP; 38/260 policy blocked | 25 |
| Untrusted | 120 total | 6 benign FP; 11/60 policy blocked | 8 |

| Taxonomy | Total | Blocked | Exact |
|---|---:|---:|---:|
| `credential_theft` | 40 | 8 | 8 |
| `phishing_deployment` | 40 | 0 | 0 |
| `malware_deployment` | 40 | 16 | 0 |
| `ransomware_deployment` | 40 | 24 | 24 |
| `unauthorized_exploitation` | 40 | 0 | 0 |
| `service_disruption` | 40 | 0 | 0 |
| `data_exfiltration` | 40 | 0 | 0 |
| `defense_evasion` | 40 | 1 | 1 |

The benign false-positive rate was 8.75% and failed its floor. Overall blocked
and exact rates were 15.31% and 10.31%, so both overall floors failed. All four
critical taxonomy floors failed. No fixture text, ID, or row-level outcome was
printed or inspected. Evaluation v10 is frozen and must not be rerun or used
for row-specific tuning.

Formal classification run: **EXECUTED ONCE / FAIL**

Quality gate: **FAIL**
