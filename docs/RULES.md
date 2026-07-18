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

A rule cannot block on a lone keyword or wrapper. It requires a configured
harmful action/object core or an equivalent bounded semantic relation, plus
independent operationalization, target, evasion, impact, or scale evidence.
Each dimension contributes its strongest owned signal instead of adding
unbounded points for repetition.

The classifier materializes a privacy-safe `BehaviorGraph` with stable flags and
edges for requester, action, object/asset, target/victim, technique,
delivery/execution, credential/access, persistence, evasion, exfiltration,
impact, scale, authorization/defensive purpose, wrapper/amplifier, role scope,
carrier, composition mode, and reason codes. Graph nodes contain no prompt span,
decoded payload, URL, credential, tool argument, or victim identifier.

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

## Wrapper/amplifier overlay

`META-OVERRIDE-001` is a post-v10 implementation-level decision overlay, not a
lone-keyword rule. It combines independent bilingual families for hierarchy
replacement, refusal suppression, unrestricted mode/persona, direct
completion, scope/placeholder laundering, output control, protected-prompt or
hidden-reasoning disclosure, and explicit negative authorization.

The fifth-round source extends this bounded family model with
`benchmark_coercion`, `persistent_instruction_injection`,
`persona_takeover`, and `agentic_execution_escalation`, and strengthens
compound-intent routing, refusal/output coercion, scope laundering, and the
quoted-analysis boundary. These are combination signals: benchmark wording,
fixed output, persona role-play, tool use, placeholders, or configuration
management alone remain valid benign neighbors and do not create a block.

When a normal Cyber Abuse candidate already exists, the overlay may raise its
score without replacing the original category and records an amplifier
relation. Without an independent base behavior, wrapper-only text never creates
`defense_evasion` or any other Cyber Abuse category. Weak wrapper-only text
allows; a strong control-plane combination is capped at the non-blocking audit
boundary, including classifier Strict mode. Prompt-derived CTF/lab,
fictional-target, and authorization claims do not wash an established dangerous
behavior. Defensive quoted material can reduce wrapper evidence only when the
request has an affirmative analysis/remediation purpose, an explicit
non-execution signal, and no contradictory operational continuation.

System, assistant, and tool segments are evaluated with their provenance.
Benign safety/refusal quotations are kept separate from user intent, while an
explicitly hostile non-user instruction remains inspectable. Linked adjacent
segments in one request can compose evidence. A hostile system/tool control
marker may combine with an explicitly linked following user segment, while a
new `now`/`then` operational turn exits an inert quotation. Defensive
non-execution language reduces the overlay only when it follows the last quoted
meta-control phrase; a label placed before later instructions cannot launder
them. Separate API calls remain stateless.

The management plane may count a fixed low-cardinality
`control_plane_event=meta_override` dimension. It remains orthogonal to the
base Cyber Abuse taxonomy, contains no prompt text, repository name, dynamic
field, target, or prompt hash, and does not change subject-risk semantics.

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
envelope becomes incomplete inspection. Balanced allows+audits it without using
a prefix score; Strict blocks for the fixed incomplete reason.

Image/audio/video is not converted into text. It is governed separately by
`opaque_media_policy`, and HTTPS media URLs are never fetched.

JSON media recognition is independent of object-member order. Payload-adjacent
`data`/`bytes`/`blob`/`binary`/`filename`/`format`/`detail`/`width`/`height`/
`duration` strings are deferred within fixed bounds until a later marker proves
media or the object closes as non-media. Proven media never
enters decoding, `Parts`, role-aware `Segments`, or the text budget; non-media
and tool-payload `data` are committed as inspectable text. Crossing a tool
boundary cuts inherited media meaning, and overflow classifies no retained
prefix.

Multipart does not expose an open-ended text surface. A fixed `SourceProfile`
derived from canonical `SourceFormat` selects fields. `openai-image` admits only
`prompt` and `negative_prompt` (plus `negative-prompt` and `negative prompt`)
as text. Reviewed metadata and file fields are discarded; unknown non-file
fields become `multipart_unknown_field`, and text fields with file evidence
become `multipart_text_field_type_mismatch`. These reasons take precedence over
partial classification: Balanced allows+audits as `multipart_schema`, Strict
blocks locally, and no partial score/rule IDs or subject-risk update survives.

Approved key-only tool controls are also schema-bound. The classifier does not
scan every JSON property name. A versioned approved tool schema may map a
reviewed boolean/numeric/null control to fixed semantic evidence; an unknown
control key in that known schema becomes `tool_schema` incomplete: Balanced
allows+audits without classification, while Strict blocks locally without
classification. Ordinary
business keys are never promoted to prompt text. The current mapping requires
`cag_control_schema=meta_override_control/v1` inside an established
tool/tool-payload object; the marker has no mapping authority outside that
provenance. Provider fields such as
`safetySettings`, `generationConfig`, and `options` are deliberately left to a
host-side versioned schema allowlist and forced-safe-value policy.

## Decision output and privacy

The classifier returns only action, category, score, ruleset version,
classifier-policy version/hash, stable rule/evidence IDs, aggregate context
flags, and the privacy-safe behavior graph. It never returns or persists a
matched prompt fragment. Audit configuration cannot enable original-text
logging.

This privacy statement covers classifier output and Guard/plugin audit. It does
not override CPA Host behavior: request logging may temporarily spool a
non-multipart body and persist a raw body in an HTTP error log. Host log mode,
directory, retention, permissions, and cleanup require separate review.

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

Ruleset `1.0.7` identifies only the embedded YAML Cyber Abuse assets. It does
**not** contain the Go-code `META-OVERRIDE-001` overlay, extractor/media and
multipart semantics, approved tool-schema mappings, or control-plane event
logic. Those behaviors require the separately verified classifier-policy
identity and exact Git commit.

This identity covers the embedded YAML rule assets. The complete code-level
policy is separately identified as:

```text
classifier_policy_version: classifier-policy-v4
classifier_policy_sha256: 2763f10e2565dce2ffcf700f5d6566e9fbac68f3fedd08fcce20bceff450b4c8
```

The policy digest test binds the deterministic classifier, matcher,
normalizer, role logic, wrapper assessment, behavior graph, semantic
composition, bounded extractor, rule loader/schema, embedded YAML files, and
module dependency locks. Classifier results and authenticated status expose the
identity. Build metadata and the artifact verifier bind it, but a handoff must
still record the exact full Git commit/tree and candidate workflow run.

`Result.finding_origin` is a text-free closed value: `user_content` or
`non_user_or_untrusted`; neutral/incomplete results omit it. It never contains
provider field names, role text, prompt fragments, or tool arguments.

Commit `21ceb57e6b6030e56d7820c9a67a8eecd068c669` passed push and PR CI
with this policy identity as a pre-version-migration checkpoint. It is not the
final v0.15 candidate identity. Automated review is development feedback only.
The final PR head must have no unresolved, non-outdated actionable review
threads before merge; no independent approval is claimed.

Release eligibility is governed by [RELEASE_POLICY.md](RELEASE_POLICY.md) and
the external `round6-prerelease-attestation.json` and
`formal-release-attestation.json` assets, not by rule-document self-claims.

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

The visible development adversarial corpus is:

```text
testdata/development-adversarial-v11-prep/
```

It contains 35 development cases: 16 block, 14 allow, 2 audit, and 3
resource-boundary fixtures. It covers all eight taxonomies, four provider
protocols, English/Chinese/mixed language, wrapper contrasts, role and
multi-turn scope, tool payload/output, bounded encodings, placeholders, and
scan/part/truncation boundaries. The validator checks schema, fixed taxonomy,
IDs, exact/near duplicates, balance, coverage, production extraction, recovered
semantics, and expected action/category. The manifest permanently sets
`development_only=true` and `future_holdout_eligible=false`; this corpus and any
derived wording must never be reused as a future blind v11.

The fifth-round sanitized public-taxonomy corpus is:

```text
testdata/development-public-jailbreak-patterns-v1/
```

Its manifest is required to set `development_only=true`,
`future_holdout_eligible=false`,
`derived_from_public_adversarial_taxonomy=true`, and
`contains_live_payloads=false`. It stores harmless canaries, abstract
placeholders, and minimal pairs only; it is neither a prompt bank nor blind
evidence. Validate it with:

```bash
make development-public-jailbreak-corpus
```

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
v0.15 release is blocked; a future attempt requires a new implementation and a
candidate-bound external `evaluation-v11` or later first-and-only
`CONSUMED / PASS` report.

Run the visible development validator with:

```bash
go test ./cmd/development-adversarial-v11-prep-validator \
  -run '^TestDevelopmentAdversarialV11PrepCorpus$' -count=1
```

The broad development gate must use the sample-safe wrapper rather than
`go test ./...`:

```bash
./scripts/go-safe-development-test.sh test
./scripts/go-safe-development-test.sh race
```

The ordinary Makefile aliases are `unit-test` and `race`. The explicit
`consumed-boundary-test` alias is retained only for separately authorized audit
work and is excluded from ordinary CI. The wrapper must not open v4-v10
consumed or retired fixtures during normal development.

Passing unit or CI gates does not authorize deployment. The exact v0.15 chain
requires final PR CI, merge to `main`, exact post-merge main push CI, and a
private untagged clean candidate dispatched from `refs/heads/main`, followed by
CPA v7.2.88 + Mock-upstream Host validation against one SO SHA-256 and independent
source/artifact/Host review. An optional annotated development prerelease is
allowed only after a candidate-bound external `evaluation-v11` or later
first-and-only `CONSUMED / PASS` attestation and is not a formal release. The
annotated `v0.15` tag and verified draft consume that same attestation; a
protected promotion may publish only the unchanged draft.

Earlier v7.2.85/v7.2.84/v7.2.83/v7.2.82/v7.2.81 source/compile profiles are historical non-gating
engineering evidence, not current release requirements.

Do not run, inspect, print, or obtain through Git history any consumed blind
sample. Evaluation v10 remains `CONSUMED / FAIL`; only its frozen aggregate
report may be used. Frozen hashes, aggregate metrics, and exit codes are kept in
the generation-specific reports and `docs/reports/RELEASE_EVIDENCE.md`.
Evaluation v10 cannot be rerun and is not a formal-build or formal-bundle input.
Formal source/audit bundles exclude evaluation, Holdout, private, blind, and
retired material.
