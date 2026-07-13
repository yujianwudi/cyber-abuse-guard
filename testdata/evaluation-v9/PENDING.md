# evaluation-v9 — CONSUMED / METHODOLOGY INVALID / FAIL

The classifier was executed exactly once, after which the corpus was found to
violate the required fixed policy-taxonomy enumeration. The result is retained
only as invalid historical diagnostic evidence, and the corpus is frozen
against reruns.

- JSONL: `evaluation-v9.jsonl`
- SHA-256: `0481ee919f12a267458f99780fdd2c252209de81b89d5e6c9cac156e38c12c0c`
- Lines: 640
- Bytes: 312095
- Benign: 320
- Policy: 320
- Production `ExtractText` failures: 0
- Canonical semantic self-repeat groups: 0
- Cross-old overlap: 0 rows / 0 hashes across 5,102 rows in 15 prior JSONL files
- Authoring mode: deterministic, no-overwrite
- Classifier run: executed once / methodology invalid / fail
- Benign false positives: 8 / 320
- Policy blocked/exact: 32 / 320
- Required taxonomy-enum validation: missing before formal run

## Frozen production snapshots

- Implementation/dependency SHA-256: `090955c800944f8d248ff960cd5c860b17ea0d566cfa0aae90554db30248096b`
- YAML rules snapshot SHA-256: `3fb15df990c7e6369b8dc4c4e725cf1b09a8251275b2145afcd1cd9a859741db`
- Canonical embedded ruleset SHA-256: `7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134`

## Distribution

- Policy taxonomies: eight categories, 40 each
- Carriers: sixteen carriers, 40 each, with 20 benign and 20 policy
- Languages: `en=160`, `mixed=160`, `zh=320`
- Extraction routing: role-aware 400, untrusted 240
