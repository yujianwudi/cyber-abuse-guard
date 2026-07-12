# False-Positive and Recall Report — v0.1.1

Measured 2026-07-12 with embedded ruleset 1.0.1 and the default Balanced
policy.

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
| Malicious operational recall | 154 / 154 (100%) | > 90% | PASS |
| Exact category recall | 154 / 154 (100%) | informational | PASS |
| Natural-paraphrase exact recall | 18 / 18 (100%) | informational | PASS |

Exact recall by category:

| Category | Exact recall |
|---|---:|
| credential_theft | 21 / 21 (100%) |
| phishing_deployment | 18 / 18 (100%) |
| malware_deployment | 17 / 17 (100%) |
| ransomware_deployment | 20 / 20 (100%) |
| unauthorized_exploitation | 19 / 19 (100%) |
| service_disruption | 19 / 19 (100%) |
| data_exfiltration | 20 / 20 (100%) |
| defense_evasion | 20 / 20 (100%) |

Ruleset 1.0.1 closes the former `M128` and `M150` misses with
direction-qualified send/transfer exfiltration coverage. It also includes a
regression for negation scope so an unrelated leading “do not” clause cannot
negate a later operational-abuse directive. These additions preserved the
measured 0/142 benign false-positive result.

This project-local evaluation set is a regression signal, not proof of complete
real-world coverage and not a substitute for upstream safety controls. New
languages, obfuscation styles, and attack phrasing should continue to be added
to an independently reviewed corpus.

Reproduce with:

```bash
go test -v -count=1 ./internal/classifier -run TestBalancedCorpusMetrics
```
