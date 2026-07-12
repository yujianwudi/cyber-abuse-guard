# Rule System

Rule set version `1.0.0` is embedded into the shared object from the YAML
files in `/rules`. Every rule has a unique stable ID, category, severity,
weighted score, bilingual evidence groups, allow contexts, and optional hard
authorization floor.

Covered categories:

- `credential_theft`
- `phishing_deployment`
- `malware_deployment`
- `ransomware_deployment`
- `unauthorized_exploitation`
- `service_disruption`
- `data_exfiltration`
- `defense_evasion`

The matcher normalizes Unicode with NFKC, lower-cases Latin text, removes
zero-width format characters, folds whitespace, applies conservative adjacent
letter leet substitutions, and produces a compact punctuation-free view.
Rules use validated literal patterns compiled into an Aho-Corasick automaton;
there are no runtime backtracking regular expressions.

A rule cannot block from a lone keyword. It needs a configured combination of
harmful action/object signals and additional operational, target, evasion, or
scale evidence. Each dimension contributes its strongest signal rather than
adding points for repeated words.

Negative contexts include defensive explanation, remediation, detection-rule
creation, static analysis, incident response, high-level education, CTF/lab,
and explicit authorization. Authorization alone does not override deployment
requests for credential theft, phishing collection, ransomware, or data
exfiltration.

The classifier returns only stable evidence and rule IDs. It never returns or
persists the matched prompt fragment.

## Corpus gates

`testdata/corpus/benign-security.jsonl` and
`testdata/corpus/malicious-operational.jsonl` are separate acceptance corpora.
The automated gate requires:

- balanced false-positive rate `< 5%` (not `<= 5%`);
- clear malicious recall `> 90%` (not `>= 90%`);
- every rule/category and both Chinese and English represented.

The examples are descriptive test prompts and intentionally do not contain a
working exploit or deployable malicious payload.

Rule changes require updating the manifest version, loader validation tests,
corpus report, and changelog. Do not tune against acceptance samples alone;
add an independently sourced external evaluation set.
