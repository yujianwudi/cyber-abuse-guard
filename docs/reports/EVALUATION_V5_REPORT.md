# Evaluation v5 Report

Status: **CONSUMED / FAIL**

The independent holdout was classified exactly once. Its aggregate result is
frozen below; reruns are prohibited.

- Benign: 320
- Policy violations: 320
- Total: 640

## Isolation

The fork-none author read only section 3 of the production task book. It did
not read repository classifier implementations, rules, tests, corpora,
testdata, earlier evaluation authors, or earlier reports, and it did not run a
classifier. The independent validator inspected v5 content and all earlier
sets only through aggregate schema, extraction, and normalized-hash programs;
no fixture text, ID, or per-record result was emitted.

## Policy distribution

- `credential_theft`: 40
- `data_exfiltration`: 40
- `defense_evasion`: 40
- `malware_creation`: 40
- `phishing_deployment`: 40
- `ransomware_deployment`: 40
- `service_disruption`: 40
- `vulnerability_exploitation`: 40

## Frozen corpus

- `testdata/evaluation-v5/benign-security.jsonl`: SHA-256 `589aa8e7609b5d28d6a35577f2908813f97d50ea9fdb152cf926e425518ac842`, lines 320, bytes 148283
- `testdata/evaluation-v5/policy-violations.jsonl`: SHA-256 `ab012072260a953b98bd84c582d5a317fe41df903fd1724aaf80662cbfd19edc`, lines 320, bytes 174924
- `testdata/evaluation-v5/manifest.json`: SHA-256 `99c1ea6f6709e98d672fb97d3735f5b31e3e95679b390a8de61882cd253bb7e6`, lines 112, bytes 3142

- Semantic self-duplicate groups: 0
- Semantic duplicate records after first: 0

## Independent static verification

- All 640 records have exactly eight fields: `id`, `split`, `expected`,
  `taxonomy`, `language`, `carrier`, `tags`, and `input`.
- IDs are globally unique; tags are sorted and duplicate-free; every `input` is
  a non-null JSON object.
- Languages total `en=214`, `zh=214`, and `mixed=212`; each of the ten carriers
  has 64 records; each policy taxonomy has 40 records.
- The ten carriers are `openai_chat`, `openai_responses`,
  `anthropic_messages`, `gemini_contents`, `multi_turn_roles`,
  `tool_arguments`, `base64_text`, `url_encoded_text`, `html_entity_text`, and
  `json_string_text`.
- Production `extract.ExtractText(record.Input)` processed all 640 records with
  zero parse errors, empty results, truncations, or extraction failures. Routing
  was 320 role-aware and 320 untrusted.
- Unicode-NFKC normalized semantic hashing found zero internal duplicate groups
  and zero overlaps with 2,542 records across all ten earlier corpus, holdout,
  and evaluation JSONL files. Only aggregate counts were inspected or emitted.

## Official consumed result

- Start: `2026-07-12T19:36:23Z`
- End: `2026-07-12T19:36:25Z`
- Exit: **FAIL**
- Benign false positives: `0 / 320`
- Overall policy blocked: `53 / 320`
- Overall policy exact: `53 / 320`

| Taxonomy | Blocked | Exact | Total |
|---|---:|---:|---:|
| `credential_theft` | 9 | 9 | 40 |
| `data_exfiltration` | 0 | 0 | 40 |
| `defense_evasion` | 0 | 0 | 40 |
| `malware_creation` | 9 | 9 | 40 |
| `phishing_deployment` | 0 | 0 | 40 |
| `ransomware_deployment` | 23 | 23 | 40 |
| `service_disruption` | 0 | 0 | 40 |
| `vulnerability_exploitation` | 12 | 12 | 40 |

- Role-aware policy aggregate: blocked `26 / 160`, exact `26 / 160`
- Untrusted policy aggregate: blocked `27 / 160`, exact `27 / 160`

Only these aggregate counts were retained. No fixture text, ID, matched rule, or
per-record result is recorded in this report.

## Consumed independent gate

The aggregate-only gate is `internal/classifier/evaluation_v5_gate_test.go`.
Static integrity continues to run by default. The holdout test normally skips;
if `INDEPENDENT_HOLDOUT_V5=1` is set, it immediately fails with a consumed
holdout message and cannot invoke classification.

The opt-in path locks the frozen data, production implementation (including
`go.mod` and `go.sum`), and embedded rules snapshots. It loads the production
default rules and classifier, uses balanced mode with default thresholds and
default policy, and selects role-aware or untrusted classification from the
extractor result. It logs only benign false positives, overall blocked/exact,
all eight taxonomy blocked/exact, and role-aware/untrusted aggregates; it never
logs fixture IDs or text.

- Production implementation snapshot SHA-256:
  `fa7e1e38ade077a812e775ecc96e0a557ebd6879d88c96d7fd50c8936f13b049`
- Embedded rules snapshot SHA-256:
  `367e9523408916831378856b470e6ebe5079779e8316bc1f2fc0771821648370`

Release thresholds are benign false-positive rate `<5%`, overall blocked and
exact rates `>90%`, and blocked plus exact rates `>=95%` for
`credential_theft`, `phishing_deployment`, `ransomware_deployment`, and
`data_exfiltration`. Evaluation taxonomy aliases map `malware_creation` to the
production `malware_deployment` category and `vulnerability_exploitation` to
`unauthorized_exploitation` for exact-category accounting.

Classification run: **COMPLETED ONCE / CONSUMED**

Quality gate: **FAIL**
