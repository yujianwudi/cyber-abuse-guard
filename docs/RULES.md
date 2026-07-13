# Rule System — ruleset 1.0.7

The default rule set is embedded into the shared object from `/rules`. Every
rule has a unique stable ID, category, severity, weighted score, bilingual
evidence groups, allow contexts, and an optional hard authorization floor.
Runtime auto-download and external rule override are not supported.

Covered categories:

- `credential_theft`
- `phishing_deployment`
- `malware_deployment`
- `ransomware_deployment`
- `unauthorized_exploitation`
- `service_disruption`
- `data_exfiltration`
- `defense_evasion`

## Matching model

The classifier normalizes Unicode with NFKC, lower-cases Latin text, removes
zero-width format characters, folds whitespace, applies conservative adjacent-
letter leet substitutions, and creates a compact punctuation-free view. Rules
use validated literal patterns compiled into an Aho-Corasick automaton; there
are no runtime backtracking regular expressions.

A rule cannot block on a lone keyword. It requires a configured combination of
harmful action/object signals plus operational, target, evasion, or scale
evidence. Each dimension contributes its strongest signal instead of adding
unbounded points for repetition.

Negative contexts include defensive explanation, remediation, detection-rule
creation, static analysis, incident response, high-level education, CTF/lab,
and explicit authorization. Authorization alone does not override deployment
requests for credential theft, phishing collection, ransomware, or data
exfiltration. Negation/prohibition cues are scoped to nearby evidence in the
same clause; an unrelated “do not” prefix cannot suppress a later operational
request.

Standard OpenAI/Anthropic/Gemini roles are classified per segment, and adjacent
user turns are paired for follow-up semantics. Assistant refusals and system
safety policy are not combined as user intent. Role-less shapes use a bounded
conservative fallback; unsupported roles and segment-cap loss are conservative
in enforcing modes.

Transport metadata is excluded from evidence. Textual values inside tool
payloads remain inspectable even when the field is named `name`, `url`, `type`,
or `model`. Order-independent Anthropic `tool_use.input` and second-order JSON
use the same shared limits.

## Meta-override implementation overlay

`META-OVERRIDE-001` is a post-v10 implementation-level decision overlay, not a
lone-keyword rule. It combines independent bilingual families for hierarchy
replacement, refusal suppression, unrestricted mode/persona, direct
completion, scope/placeholder laundering, output control, protected-prompt or
hidden-reasoning disclosure, and explicit negative authorization.

When a normal cyber-abuse candidate already exists, the overlay raises its
score without replacing the original category. A strong standalone
control-plane attack is reported as `defense_evasion`. Prompt-derived CTF/lab,
fictional-target, and authorization claims do not reduce this overlay.
Defensive quoted material can reduce it only when the request has an
affirmative analysis/remediation purpose, an explicit non-execution signal,
and no contradictory operational continuation.

System, assistant, and tool segments are evaluated with their provenance.
Benign safety/refusal quotations are kept separate from user intent, while an
explicitly hostile non-user instruction remains inspectable. Linked adjacent
segments in one request can compose evidence. A hostile system/tool control
marker may combine with an explicitly linked following user segment, while a
new `now`/`then` operational turn exits an inert quotation. Defensive
non-execution language reduces the overlay only when it follows the last quoted
meta-control phrase; a label placed before later instructions cannot launder
them. Separate API calls remain stateless.

## Bounded decoding before matching

The extractor preserves the original text and adds bounded decoded views:

- JSON string escapes and bounded nested tool JSON;
- URL path/query percent escapes;
- HTML entities;
- inspectable standard or URL-safe Base64 text;
- textual data URLs.

After content blocks from one provider message are joined, the same bounded
decoder runs once more to detect an encoded value split into sub-threshold
blocks. Ordered strings extracted from one tool payload or function output also
receive one pristine joined decode pass. Inside an already-established tool
payload, every valid JSON-looking string can be recursively inspected under the
same depth, part, and byte budgets. The compact matcher also has a tightly
bounded reconstruction path for isolated one-character fragments separated by
line/content boundaries.

At most two decode layers and eight unique variants are retained. Encoded source
is capped at 128 KiB, and decoded variants share a 64 KiB retained-byte budget.
Only printable valid UTF-8 text is accepted. The plugin performs no
decompression, archive expansion, document parsing, binary-media decoding, or
network fetch. It does not claim Base32, arbitrary hex, quoted-printable,
encryption, or unbounded transform coverage. An incomplete recognized text
envelope sets `Truncated`;
Balanced/Strict handle that conservatively.

Image/audio/video is not converted into text. It is governed separately by
`opaque_media_policy`, and HTTPS media URLs are never fetched.

## Decision output and privacy

The classifier returns only action, category, score, ruleset version, stable
rule/evidence IDs, and aggregate context flags. It never returns or persists a
matched prompt fragment. Audit configuration cannot enable original-text
logging.

## Version and identity

Ruleset `1.0.7` is the source version in `rules/manifest.yaml`. Its current
canonical embedded SHA-256 is
`7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134`.
A release emits:

```text
dist/ruleset-manifest.json
dist/ruleset.sha256
```

The manifest canonically identifies every embedded rule file. The ruleset
version and canonical SHA-256 are linked into the binary, exposed by
authenticated status, compared with source by `verify-release.sh`, and included
in `build-metadata.json`. A missing or mismatched identity is a release failure.

This identity covers the embedded YAML rule assets. The complete code-level
policy also includes `META-OVERRIDE-001`, matcher/normalizer mappings, role
handling, and extraction semantics; none is covered by ruleset `1.0.7` or its
canonical hash. The containing Git/build commit plus the YAML identity are
required to identify this development behavior. Before a successor can be a
release candidate, it must add a separately verified classifier-policy
version/hash or fully bind those semantics to verified build provenance.

Any rule change requires a new ruleset version, regression review, manifest
regeneration, changelog entry, and independent blind evaluation. Default rules
remain embedded for reproducibility. A future external-rule feature would need
signature verification, a fixed trusted directory, regular-file/permission
checks, atomic activation, embedded fallback, and no automatic network download.

## Regression corpus versus blind Holdout

The project regression corpus is:

- `testdata/corpus/benign-security.jsonl`;
- `testdata/corpus/malicious-operational.jsonl`.

It is maintained alongside the rules and catches known regressions. It is not
an independent or real-world benchmark. Its gate requires Balanced false
positives `< 5%`, malicious recall `> 90%`, category coverage, and bilingual
coverage.

Holdout data must be separately authored, frozen by SHA-256, schema-validated,
deduplicated against regression data, scored only in aggregate, and excluded
from per-row tuning. The task-book release gate additionally requires at least
200 benign and 200 malicious samples and critical-category recall `>= 95%` for:

- `credential_theft`
- `phishing_deployment`
- `ransomware_deployment`
- `data_exfiltration`

Blind generations v1-v8 are retired or consumed failures. v9 is frozen as
`CONSUMED / METHODOLOGY INVALID / FAIL` because the exact taxonomy-enum
validator was missing. Methodologically valid v10 was then executed exactly
once and failed with benign FP 28/320, policy blocked 49/320, and exact 33/320.
No set may be relabelled as unseen, rerun, or used for row-specific tuning. The
v0.1.2 release is blocked; a future attempt requires a new implementation and a
new independently authored unseen set.

Reproduce project regression and confirm the consumed-gate refusal with:

```bash
make corpus-regression
make holdout-test
```

`make holdout-test` now returns non-zero because v10 is consumed; it must not
classify v10 again. Frozen hashes, aggregate metrics, and exit codes are kept in
the generation-specific reports and `docs/reports/RELEASE_EVIDENCE.md`.
