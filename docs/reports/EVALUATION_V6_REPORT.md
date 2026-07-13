# Evaluation v6 Report

Status: **CONSUMED / FAIL**

## Isolation

Evaluation v6 was created by a fresh fork-none author using only section 3 of
the production task book, the fixed schema/carrier contract, and the production
text extractor for envelope health checks. The author did not read repository
classifier logic, rules, tests, corpora, testdata, prior evaluation data,
reports, or authors, and did not run a classifier.

## Frozen corpus

- Artifact: `testdata/evaluation-v6/evaluation-v6.jsonl`
- SHA-256: `d3b74587a787251f0ddad46189236fbe3059db683fb023583517f0092710b265`
- Lines: 640
- Bytes: 278,974
- Benign: 320
- Policy violations: 320

Every record has exactly eight fields: `id`, `split`, `expected`, `taxonomy`,
`language`, `carrier`, `tags`, and `input`. IDs are globally unique, tags are
sorted and duplicate-free, and every `input` is a non-null production-style
JSON object.

## Aggregate distribution

Policy taxonomies contain 40 records each:

- `credential_theft`
- `phishing_deployment`
- `malware_deployment`
- `ransomware_deployment`
- `unauthorized_exploitation`
- `service_disruption`
- `data_exfiltration`
- `defense_evasion`

Benign taxonomies contain 40 records each: `defense`, `remediation`,
`education`, `toy_ctf`, `compliance`, `refusal`, `incident_response`, and
`safe_research`.

Language totals are `en=213`, `zh=214`, and `mixed=213`. The ten carriers each
contain 64 records, split evenly as 32 benign and 32 policy violations:
`openai_chat`, `openai_responses`, `anthropic_messages`, `gemini_contents`,
`multi_turn_roles`, `tool_arguments`, `base64_text`, `url_encoded_text`,
`html_entity_text`, and `json_string_text`.

## Independent static verification

- Invalid JSON, schema, input, tag, or duplicate-ID records: 0
- Production `extract.ExtractText(record.Input)` failures: 0 / 640
- Empty extractions: 0; truncations: 0; parse errors: 0
- Routing aggregate: role-aware 320; untrusted 320
- Normalized semantic duplicate groups: 0
- Duplicate records after first: 0
- Overlap with 3,182 records across all 12 prior corpus, holdout, and evaluation
  JSONL files: 0 records / 0 unique hashes
- Author deterministic regeneration: PASS
- Author no-overwrite rerun: PASS

No fixture text, ID, or per-record result was emitted during independent
validation.

## Consumed independent gate

The gate is `internal/classifier/evaluation_v6_gate_test.go`. Static corpus and
production-snapshot integrity tests run by default. Classification skips unless
`INDEPENDENT_HOLDOUT_V6=1` is set exactly. The one opt-in run used production
`extract.ExtractText`, role-aware or untrusted classification as indicated by
the extractor, balanced mode, default thresholds, and default policy. It emits
only benign false positives, overall blocked/exact, eight taxonomy
blocked/exact, and role-aware/untrusted aggregates.

- Production implementation snapshot SHA-256:
  `fa7e1e38ade077a812e775ecc96e0a557ebd6879d88c96d7fd50c8936f13b049`
- Embedded rules snapshot SHA-256:
  `367e9523408916831378856b470e6ebe5079779e8316bc1f2fc0771821648370`

Release thresholds are benign false-positive rate `<5%`, overall blocked and
exact rates `>90%`, and blocked plus exact rates `>=95%` for
`credential_theft`, `phishing_deployment`, `ransomware_deployment`, and
`data_exfiltration`.

## First formal run result

- Start (UTC): `2026-07-12T20:21:08Z`
- End (UTC): `2026-07-12T20:21:10Z`
- Command: `make holdout-test`
- Gate result: **FAIL**
- Pipeline failures: `0`

| Aggregate | Total | Blocked / FP | Exact |
|---|---:|---:|---:|
| Benign | 320 | 8 false positives | n/a |
| Policy violations | 320 | 39 blocked | 39 exact |
| Role-aware | 320 total | 6 benign FP; 20/160 policy blocked | 20 |
| Untrusted | 320 total | 2 benign FP; 19/160 policy blocked | 19 |

| Taxonomy | Total | Blocked | Exact |
|---|---:|---:|---:|
| `credential_theft` | 40 | 10 | 10 |
| `phishing_deployment` | 40 | 0 | 0 |
| `malware_deployment` | 40 | 5 | 5 |
| `ransomware_deployment` | 40 | 24 | 24 |
| `unauthorized_exploitation` | 40 | 0 | 0 |
| `service_disruption` | 40 | 0 | 0 |
| `data_exfiltration` | 40 | 0 | 0 |
| `defense_evasion` | 40 | 0 | 0 |

The benign false-positive rate was below 5%, but overall and critical-category
recall failed. No fixture text, ID, or row-level outcome was printed or
inspected. v6 is frozen and will not be rerun or used for row-specific tuning.
The test now skips normally and fails immediately if the old opt-in variable is
set.

Classification run: **EXECUTED ONCE / FAIL**

Quality gate: **FAIL**
