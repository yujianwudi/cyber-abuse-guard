# evaluation-v8 — CONSUMED / FAIL

Independent aggregate-only static validation completed before the first formal
run. The classifier was then executed exactly once through the opt-in v8 gate;
the quality gate failed, and the corpus is now frozen against reruns.

- JSONL: `evaluation-v8.jsonl`
- SHA-256: `c722af0c6aae0bd909e808c8bb7a25f3e3481d8e135206e4d8e8ab3efb54edcd`
- Lines: 640
- Bytes: 442461
- Benign: 320
- Policy violations: 320
- Production `ExtractText` failures: 0
- Canonical semantic self-repeat groups: 0
- Cross-old overlap: 0 rows / 0 hashes across 4,462 rows in 14 prior JSONL files
- Authoring mode: deterministic, no-overwrite
- Classifier run: executed once / fail
- Benign false positives: 13 / 320
- Policy blocked: 126 / 320
- Policy exact: 119 / 320

## Frozen production snapshots

- Implementation/dependency SHA-256: `67dc31487d5453827e18f4c8d2586e9f4f35684b32a136463c94f64f314d5452`
- YAML rules snapshot SHA-256: `ca37b48e484e37376d80db31b7521cfbf722c5e4a454b80cca8085316bc9e3bb`
- Canonical embedded ruleset SHA-256: `e25b781bfc88dac1e50e09147902f0debf7075368ea5709d73b8d32543c1ff75`

## Distribution

- Policy taxonomies: eight categories, 40 each
- Carriers: sixteen carriers, 40 each, with 20 benign and 20 policy violations
- Languages: `en=227`, `zh-CN=187`, `zh-en=226`
- Extraction routing: role-aware 440, untrusted 200
