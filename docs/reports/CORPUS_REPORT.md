# False-Positive and Recall Report — v0.1.0

Measured 2026-07-12 with the embedded ruleset and default Balanced policy.

The evaluation corpus is stored separately from rule YAML:

- `testdata/corpus/benign-security.jsonl`: 142 legitimate requests;
- `testdata/corpus/malicious-operational.jsonl`: 154 explicit operational-abuse
  requests.

Rows are labelled `evaluation_v2`; tests reject the word `holdout` so these
numbers are not misrepresented as an unseen external benchmark. The set mixes
Chinese and English, ordinary programming, defensive and remediation work,
CTF/lab/authorized scenarios, negation, multi-turn prompts, light obfuscation,
and natural paraphrases.

## Results

| Measure | Result | Required | Status |
|---|---:|---:|---|
| Balanced benign false positives | 0 / 142 (0.00%) | < 5% | PASS |
| Malicious operational recall | 152 / 154 (98.70%) | > 90% | PASS |
| Exact category recall | 152 / 154 (98.70%) | informational | PASS |
| Natural-paraphrase exact recall | 17 / 18 (94.44%) | informational | PASS |

Exact recall by category:

| Category | Exact recall |
|---|---:|
| credential_theft | 21 / 21 (100%) |
| phishing_deployment | 18 / 18 (100%) |
| malware_deployment | 17 / 17 (100%) |
| ransomware_deployment | 20 / 20 (100%) |
| unauthorized_exploitation | 19 / 19 (100%) |
| service_disruption | 19 / 19 (100%) |
| data_exfiltration | 18 / 20 (90%) |
| defense_evasion | 20 / 20 (100%) |

The two retained false negatives are corpus IDs `M128` and `M150`, both
indirect data-exfiltration paraphrases. They remain in the evaluation set to
make the limitation visible. Operators should not treat the classifier as a
complete substitute for upstream safety controls, and the next ruleset should
improve exfiltration paraphrase coverage without sacrificing the measured
benign false-positive rate.

Reproduce with:

```bash
go test -v -count=1 ./internal/classifier -run TestBalancedCorpusMetrics
```
