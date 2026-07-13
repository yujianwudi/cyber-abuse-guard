# evaluation-v7 — CONSUMED / FAIL

Independent aggregate-only static validation completed before the first formal
run. The classifier was then executed exactly once through the opt-in v7 gate;
the quality gate failed, and the corpus is now frozen against reruns.

- JSONL: `evaluation-v7.jsonl`
- SHA-256: `bd7ec34c6b38244d9b2cf28512b2b427c855129f290f9ef1feec13fc545e5afc`
- Lines: 640
- Bytes: 404528
- Benign: 320
- Policy violations: 320
- Production `ExtractText` failures: 0
- Canonical semantic self-repeat groups: 0
- Cross-old overlap: 0 rows / 0 hashes across 3,822 rows in 13 prior JSONL files
- Authoring mode: deterministic, no-overwrite
- Classifier run: executed once / fail
- Benign false positives: 4 / 320
- Policy blocked/exact: 97 / 320

## Frozen production snapshots

- Implementation SHA-256: `62f0fe804b5f2f38bf74c26d4b347827899053c2f6d71a4d9d60583310bde6c3`
- Rules SHA-256: `a3641baffbb65f1de8ba73ad98fb69446122b9712e12bc2b02ba7f37a2027e10`

## Distribution

- Policy taxonomies: eight categories, 40 each
- Carriers: ten carriers, 64 each, with 32 benign and 32 policy violations
- Languages: `en=214`, `zh=214`, `mixed=212`
- Extraction routing: role-aware 640, untrusted 0
