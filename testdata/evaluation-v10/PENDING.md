# evaluation-v10 — CONSUMED / FAIL

Independent aggregate-only static validation completed before the first formal
run. The classifier was then executed exactly once through the methodologically
valid v10 gate; the quality gate failed, and the corpus is frozen against
reruns.

- JSONL: `evaluation-v10.jsonl`
- SHA-256: `e42b881103a00c0a7bf0359f8494804bc3aeabc6c2e0bafff99593043129cbef`
- Lines: 640
- Bytes: 394629
- Benign: 320
- Policy: 320
- Exact fixed taxonomy-enum failures: 0
- Production `ExtractText` failures: 0
- Canonical semantic self-repeat groups: 0
- Cross-old overlap: 0 rows / 0 hashes across 5,742 rows in 16 prior JSONL files
- Authoring mode: deterministic, no-overwrite
- Classifier run: executed once / fail
- Benign false positives: 28 / 320
- Policy blocked: 49 / 320
- Policy exact: 33 / 320

## Frozen production snapshots

- Implementation/dependency SHA-256: `090955c800944f8d248ff960cd5c860b17ea0d566cfa0aae90554db30248096b`
- YAML rules snapshot SHA-256: `3fb15df990c7e6369b8dc4c4e725cf1b09a8251275b2145afcd1cd9a859741db`
- Canonical embedded ruleset SHA-256: `7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134`

## Distribution

- Required policy taxonomies: eight fixed categories, 40 each
- Carriers: sixteen carriers, 40 each, with 20 benign and 20 policy
- Languages: `en=320`, `zh-CN=320`
- Extraction routing: role-aware 520, untrusted 120
