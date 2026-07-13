# Evaluation v7 Report

Status: **CONSUMED / FAIL**

## Isolation

Evaluation v7 was created by a fresh `fork_turns="none"` author using only
section 3 of the production task book, the fixed schema/carrier contract, and
the production text extractor for envelope health checks. The author did not
read classifier logic, rules, tests, corpora, testdata, prior evaluation data,
reports, or authors, and did not run a classifier.

## Frozen corpus

- Artifact: `testdata/evaluation-v7/evaluation-v7.jsonl`
- SHA-256: `bd7ec34c6b38244d9b2cf28512b2b427c855129f290f9ef1feec13fc545e5afc`
- Lines: 640
- Bytes: 404,528
- Benign: 320
- Policy violations: 320

Every record has exactly eight fields: `id`, `split`, `expected`, `taxonomy`,
`language`, `carrier`, `tags`, and `input`. IDs are globally unique, tags are
non-empty and duplicate-free, and every `input` is a production-style JSON
object.

## Aggregate distribution

The eight policy taxonomies contain 40 records each:

- `credential_theft`
- `phishing_deployment`
- `malware_deployment`
- `ransomware_deployment`
- `unauthorized_exploitation`
- `service_disruption`
- `data_exfiltration`
- `defense_evasion`

The benign taxonomy contains 320 records spanning defensive prevention,
remediation, education, toy CTF, compliance, refusal, incident response, and
safe research intents. Language totals are `en=214`, `zh=214`, and
`mixed=212`.

The ten carriers each contain 64 records, split evenly as 32 benign and 32
policy violations: `openai_chat`, `openai_responses`, `anthropic_messages`,
`gemini_contents`, `multi_turn_roles`, `tool_arguments`, `base64_text`,
`url_encoded_text`, `html_entity_text`, and `json_string_text`.

## Independent aggregate-only static verification

- Invalid JSON, schema, input, tag, or duplicate-ID records: 0
- Production `extract.ExtractText(record.Input)` failures: 0 / 640
- Empty extractions, truncations, or parse errors: 0
- Routing aggregate: role-aware 640; untrusted 0
- Normalized semantic duplicate groups: 0
- Duplicate records after first: 0
- Prior-data index: 3,822 records across all 13 earlier corpus, holdout, and
  evaluation JSONL files; parse/extraction fallback failures: 0
- Cross-old normalized semantic overlap: 0 records / 0 unique hashes
- Author deterministic generation: PASS
- Author no-overwrite rerun: PASS

No fixture text, ID, or per-record result was emitted during independent
validation.

## Consumed independent gate

The gate is `internal/classifier/evaluation_v7_gate_test.go`. Static corpus and
production-snapshot integrity tests remain available. The one opt-in run used
production `extract.ExtractText`, role-aware classification, balanced mode,
default thresholds, and default policy. It emitted only benign false positives,
overall blocked/exact counts, eight taxonomy blocked/exact counts, and routing
aggregates. The gate now rejects `INDEPENDENT_HOLDOUT_V7=1` immediately so the
consumed corpus cannot be classified again.

- Production implementation snapshot SHA-256:
  `62f0fe804b5f2f38bf74c26d4b347827899053c2f6d71a4d9d60583310bde6c3`
- Embedded rules snapshot SHA-256:
  `a3641baffbb65f1de8ba73ad98fb69446122b9712e12bc2b02ba7f37a2027e10`

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
| Benign | 320 | 4 false positives | n/a |
| Policy violations | 320 | 97 blocked | 97 |
| Role-aware | 640 total | 4 benign FP; 97/320 policy blocked | 97 |
| Untrusted | 0 total | 0 | 0 |

| Taxonomy | Total | Blocked | Exact |
|---|---:|---:|---:|
| `credential_theft` | 40 | 40 | 40 |
| `phishing_deployment` | 40 | 0 | 0 |
| `malware_deployment` | 40 | 15 | 15 |
| `ransomware_deployment` | 40 | 40 | 40 |
| `unauthorized_exploitation` | 40 | 2 | 2 |
| `service_disruption` | 40 | 0 | 0 |
| `data_exfiltration` | 40 | 0 | 0 |
| `defense_evasion` | 40 | 0 | 0 |

The benign false-positive rate was 1.25% and passed its floor. Overall blocked
and exact rates were 30.31%, so the overall release floors failed. Critical
category floors passed for credential theft and ransomware deployment, but
failed for phishing deployment and data exfiltration. No fixture text, ID, or
row-level outcome was printed or inspected. Evaluation v7 is frozen and must
not be rerun or used for row-specific tuning.

Formal classification run: **EXECUTED ONCE / FAIL**

Quality gate: **FAIL**
