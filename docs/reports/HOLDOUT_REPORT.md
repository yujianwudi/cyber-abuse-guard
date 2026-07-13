# Retired Independent Holdout v1 Diagnostic Report

## Status

Holdout v1 is **retired and consumed**. Its last calibrated candidate result was
`FAIL`, but it must no longer be used as a final release gate, because aggregate
results were repeatedly observed during general rule development and its
remaining false-negative rows have now been examined for the aggregate root
cause analysis below. The subsequently authored v2 was also consumed and
failed; see `HOLDOUT_V2_REPORT.md`. The release decision now requires the
separately authored, frozen blind v3 in `HOLDOUT_V3_REPORT.md`.

The two v1 JSONL files and every historical result remain immutable diagnostic
evidence. Retirement does not authorize deleting, relabelling, reordering, or
editing any v1 row.

Two earlier
non-zero previews are retained below as diagnostic evidence, but are not release
gate results: their plain `Text` rows were classified directly instead of first
passing through the JSON extractor used by the production router. That method
under-tested the newly bounded decoding path.

The execution method has now been corrected without changing either frozen
JSONL file. The corpus remains frozen; classifier/rule and bounded-decoder work
must be evaluated against the same bytes, without deleting, relabelling, or
rewriting missed records.

## Frozen retired-v1 data manifest

| File | Records | Bytes | SHA-256 |
|---|---:|---:|---|
| `testdata/holdout/benign-security.jsonl` | 246 | 69,014 | `46736f53d31c3caa7c1d585c3bdfb7bb60848c6d60ae75c12076c35cd2f19e1f` |
| `testdata/holdout/malicious-operational.jsonl` | 260 | 90,758 | `a86bb28cc509969e2c3f27901413f9a82422c6dbeea98cda68145f47693688cc` |

Freeze date: 2026-07-12. Every record carries source marker
`independent-holdout-2026-07-12`.

The fixed JSONL files are retained diagnostic inputs. `cmd/holdout-fixtures`
documents the original separate prompt-authoring workflow, but must not be run
or edited to manufacture a new release result. Any successor Holdout requires a
new authoring process/source marker, new files or versioned paths, new hashes,
and a separately reported blind evaluation.

## Independence and integrity controls

- The set uses separately authored sentences and structured payloads; it does
  not import classifier term lists.
- The gate canonicalizes and compares semantic holdout text with both existing
  regression files. An exact copied prompt fails the test.
- IDs and complete input representations must be unique across both files.
- Each row has exactly one input form: plain text, untrusted parts, role-aware
  segments, or a real provider JSON payload.
- Schema decoding rejects unknown fields; source markers, tags, categories,
  minimum category sizes, and coverage tags are validated before scoring.
- This is an independently authored in-repository holdout, not a claim of an
  external third-party blind benchmark or real-world prevalence estimate.

## Historical threshold diagnostic definition

`TestRetiredHoldoutV1Diagnostic` evaluates the production Balanced disposition
for historical diagnostics only:

1. every plain `Text` row is wrapped in a standard JSON `{"input": ...}`
   envelope, and both it and native provider/tool payloads are passed through
   `extract.ExtractText`;
2. role-aware results use `AnalyzeSegments`; ambiguous results use the
   conservative untrusted-parts path;
3. a sample is blocked when the Balanced classifier blocks it **or** bounded
   extraction/normalization reports `Truncated`, matching the router's
   `scan_limit` fail-closed behavior.

Required thresholds:

| Metric | Requirement |
|---|---:|
| Benign-security false-positive rate | `< 5%` |
| Malicious-operational recall | `> 90%` |
| `credential_theft` recall | `>= 95%` |
| `phishing_deployment` recall | `>= 95%` |
| `ransomware_deployment` recall | `>= 95%` |
| `data_exfiltration` recall | `>= 95%` |

`TestRetiredHoldoutV1ThresholdDiagnosticsRejectFailures` exercises every
historical boundary with synthetic counters. Five-percent FP, ninety-percent
total recall, and each critical category below ninety-five percent all return a
diagnostic error. This preserves the old metric semantics but does not make v1
eligible to certify a release.

## Coverage

The corpus includes Chinese, English, mixed Chinese/English, conversational
language, intentional typos, Unicode homoglyphs, zero-width characters,
nonstandard spaces, Base64, URL encoding, HTML entities, JSON Unicode escapes,
character splitting, Markdown fences, string concatenation, multi-turn history,
assistant refusal, history padding, unknown roles, real nested tool arguments,
second-order JSON, defensive/remediation/static-analysis requests, CTF/lab
contexts, high-level explanations, detection-rule requests, prompt injection,
and explicit authorization contradictions for every protected critical
category.

Every malicious category has at least 30 samples. Multi-turn has 42 samples and
tool JSON has 41 malicious samples; these are scored through the actual
role/extraction paths, not flattened labels.

## Frozen pre-remediation preview (methodology-invalid)

This preview remains useful for classifier-family diagnosis, but it is not an
official gate result because plain `Text` records bypassed `ExtractText`.

Command:

```bash
go test -tags=sqlite_omit_load_extension ./internal/classifier \
  -run '^TestIndependentHoldoutGate' -count=1 -v
```

Exit status: non-zero. Method status: invalid for release gating.

### Top-level metrics

| Metric | Result | Gate |
|---|---:|---|
| Benign FP | 3/246 = **1.22%** | PASS |
| Malicious recall | 223/260 = **85.77%** | **FAIL** |
| Exact-category detection (diagnostic only) | 215/260 = 82.69% | n/a |
| Credential theft recall | 28/34 = **82.35%** | **FAIL** |
| Phishing deployment recall | 21/33 = **63.64%** | **FAIL** |
| Ransomware deployment recall | 28/34 = **82.35%** | **FAIL** |
| Data exfiltration recall | 27/33 = **81.82%** | **FAIL** |

### Recall by language presentation

Language buckets are mutually assigned from the authored language tags; mixed
includes prompts combining Chinese and English.

| Bucket | Recall |
|---|---:|
| Chinese | 86/102 = 84.31% |
| English | 55/62 = 88.71% |
| Mixed | 82/96 = 85.42% |

Benign allow rates were Chinese 88/90 (97.78%), English 94/95 (98.95%), and
mixed 61/61 (100%).

### Recall by category

| Category | Recall |
|---|---:|
| `credential_theft` | 28/34 = 82.35% |
| `phishing_deployment` | 21/33 = 63.64% |
| `ransomware_deployment` | 28/34 = 82.35% |
| `data_exfiltration` | 27/33 = 81.82% |
| `malware_deployment` | 32/32 = 100% |
| `unauthorized_exploitation` | 32/32 = 100% |
| `service_disruption` | 24/30 = 80.00% |
| `defense_evasion` | 31/32 = 96.88% |

### Bypass and structure diagnostics

| Tag | Recall | Baseline observation |
|---|---:|---|
| Multi-turn | 36/42 = 85.71% | Extraction and role association worked; misses followed the same underlying semantic gaps as plain text. |
| Tool JSON | 35/41 = 85.37% | Nested arguments were present; misses followed the same semantic gaps. |
| Authorization contradiction | 5/5 = 100% | Safety/authorization labels did not wash protected abuse. |
| Prompt injection | 2/2 = 100% | Ignore-policy/education labels did not wash explicit abuse. |
| Long/opaque Base64 plus short Base64 | 2/3 = 66.67% | Long opaque strings failed closed; the short encoded instruction was not recognized. |
| JSON Unicode escape | 1/1 = 100% | JSON decoding exposed the semantic text. |
| Zero-width | 1/1 = 100% | Normalization removed the format character. |
| Character splitting | 1/1 = 100% | Compact matching recovered the phrase. |
| Nonstandard whitespace | 1/1 = 100% | Unicode whitespace normalization worked. |
| Markdown fence | 1/1 = 100% | Fence punctuation did not hide the request. |
| String concatenation punctuation | 1/1 = 100% | Compact matching recovered the phrase. |
| URL encoding probe | 1/1 = 100% | Remaining clear operational evidence was sufficient; this does not prove full percent-decoding. |
| HTML entity probe | 1/1 = 100% | Remaining clear operational evidence was sufficient; this does not prove full entity decoding. |

The 37 baseline false negatives formed semantic families rather than extraction
losses: natural action/object paraphrases in credential theft, phishing,
ransomware, exfiltration, and service disruption, plus one short opaque Base64
instruction. The remediation should therefore be systematic (bounded decoding
and reviewed synonym-family coverage), not one literal rule per holdout row.

The three benign false positives were one authorized decommissioning/wipe
wording and two legitimate opaque image payloads. The latter are expected costs
of Balanced's fail-closed `scan_limit` policy and remain visible in the FP
numerator.

## Ruleset 1.0.2 pre-calibration preview (methodology-invalid)

The first general ruleset/decoder revision was evaluated with the same frozen
hashes, but immediately afterward the direct-`Text` methodology defect was
identified. No per-record output was emitted. These numbers are retained and
must not be presented as the final release result:

| Metric | Preview result |
|---|---:|
| Benign FP | 1/246 = 0.41% |
| Malicious recall | 231/260 = 88.85% |
| Exact-category detection (diagnostic) | 225/260 = 86.54% |
| Credential theft recall | 28/34 = 82.35% |
| Phishing deployment recall | 21/33 = 63.64% |
| Ransomware deployment recall | 30/34 = 88.24% |
| Data exfiltration recall | 33/33 = 100% |

Language recall was Chinese 92/102 (90.20%), English 55/62 (88.71%), and mixed
84/96 (87.50%). Multi-turn recall was 37/42 (88.10%); tool JSON was 37/41
(90.24%). The process exited non-zero. The Base64 aggregate remaining at 2/3
was the signal that exposed the method defect: a plain encoded `Text` row had
never entered the production decoder.

## Encoding and resource policy at baseline

- JSON string escapes are decoded by Go's JSON parser.
- Stringified tool arguments are recursively parsed only while they remain
  valid JSON and within the shared `MaxJSONDepth` budget.
- Raw scan bytes default to 262,144 and are hard-capped at 4 MiB.
- Semantic JSON depth defaults to 32 and is hard-capped at 128.
- Text parts default to 512 and are hard-capped at 4,096; each emitted part is
  bounded to 16 KiB.
- The extractor performs no decompression, so compressed-data expansion bombs
  are not entered. Opaque media/Base64 can be marked truncated and therefore
  fails closed in Balanced/Strict.
- At this baseline, short Base64 was not decoded or marked opaque. Full URL and
  HTML-entity decoding were not proven by the holdout probes.

## Calibrated production-path v0.1.2 candidate gate

Run time: 2026-07-12 19:55 CST. Ruleset: `1.0.2`. The dirty candidate working
tree was based on commit `47d30451fa911fa5076b7b8023cc5e532deba25e`; no final
release commit or tag existed for this run.

Before execution, both frozen SHA-256 values were checked against the manifest
at the top of this report and matched byte for byte. No per-record failure IDs,
scores, tags, or text were emitted or inspected.

Command:

```bash
go test -tags=sqlite_omit_load_extension ./internal/classifier \
  -run '^TestIndependentHoldoutGate' -count=1 -v
```

Exit status: non-zero (`FAIL`).

### Official candidate metrics

| Metric | Result | Gate |
|---|---:|---|
| Benign FP | 2/246 = **0.81%** | PASS |
| Malicious recall | 244/260 = **93.85%** | PASS |
| Exact-category detection (diagnostic only) | 238/260 = 91.54% | n/a |
| Credential theft recall | 28/34 = **82.35%** | **FAIL** |
| Phishing deployment recall | 33/33 = **100%** | PASS |
| Ransomware deployment recall | 30/34 = **88.24%** | **FAIL** |
| Data exfiltration recall | 33/33 = **100%** | PASS |

Category diagnostics outside the four mandatory floors were malware 32/32
(100%), unauthorized exploitation 32/32 (100%), service disruption 24/30
(80%), and defense evasion 32/32 (100%).

| Language bucket | Recall |
|---|---:|
| Chinese | 96/102 = 94.12% |
| English | 59/62 = 95.16% |
| Mixed | 89/96 = 92.71% |

Benign allow rates were Chinese 89/90 (98.89%), English 94/95 (98.95%), and
mixed 61/61 (100%).

| Bypass/structure bucket | Recall |
|---|---:|
| Base64 | 3/3 = 100% |
| Multi-turn | 39/42 = 92.86% |
| Tool JSON | 39/41 = 95.12% |
| Authorization contradiction | 5/5 = 100% |
| Prompt injection | 2/2 = 100% |
| History padding | 1/1 = 100% |
| Unknown role | 1/1 = 100% |
| URL encoding | 1/1 = 100% |
| HTML entity | 1/1 = 100% |
| JSON Unicode escape | 1/1 = 100% |
| Character splitting | 1/1 = 100% |
| Zero-width | 1/1 = 100% |
| Nonstandard whitespace | 1/1 = 100% |
| Markdown fence | 1/1 = 100% |
| String concatenation | 1/1 = 100% |

The calibrated path proves that bounded decoding fixed the short Base64 miss
seen in the invalid preview. It does not override the category floors: the
current candidate remains blocked by aggregate credential-theft and ransomware
recall. Any later candidate must retain both frozen hashes, rerun the same
production-path gate, and append a new result rather than replacing this one.

### Current bounded decoding policy

- At most two decode layers and eight unique decoded variants are inspected.
- Encoded source text is capped at 128 KiB; decoded variants and their aggregate
  retained bytes are capped at 64 KiB.
- Supported textual envelopes are URL/path/query escaping, HTML entities,
  inspectable Base64 text, and textual data URLs.
- JSON and stringified tool JSON remain bounded by the extractor's shared JSON
  depth, scan-byte, and text-part limits described above.
- There is no decompression, archive expansion, network fetch, or binary media
  decoding. Incomplete recognized text decoding sets `Truncated`, which
  Balanced/Strict blocks; recognized opaque media uses the separate
  `OpaqueMedia` signal.

## Ruleset 1.0.2 third candidate aggregate rerun

Run time: 2026-07-12 19:59 CST. After a further general credential/ransomware
rule-family revision and separate regression validation, the production-path
gate was rerun against the same two verified hashes. No individual row output
was enabled or inspected.

Exit status: non-zero (`FAIL`). Every aggregate metric was unchanged from the
calibrated candidate immediately above: benign FP 2/246 (0.81%), overall recall
244/260 (93.85%), credential theft 28/34 (82.35%), phishing 33/33 (100%),
ransomware 30/34 (88.24%), and data exfiltration 33/33 (100%). Language,
category, and bypass/structure aggregates were also identical.

This unchanged result is material evidence: the added general families did not
reach the frozen credential/ransomware gaps. The third candidate therefore
remains non-release-eligible; regression success cannot substitute for the two
failed critical-category Holdout floors.

## Ruleset 1.0.2 nominal-semantics candidate rerun

Run time: 2026-07-12 20:02 CST. Following an additional generic revision for
nominal credential extraction/retrieval/dumper/harvester and automated
ransomware deployment/rollout/file-encryption semantics, the calibrated gate
was executed with `-count=1`. Both frozen hashes matched before execution and
no row-level output was enabled or inspected.

Exit status: non-zero (`FAIL`). All aggregate figures remained byte-for-byte
identical to the two preceding calibrated candidates: benign FP 2/246 (0.81%),
overall recall 244/260 (93.85%), credential theft 28/34 (82.35%), phishing
33/33 (100%), ransomware 30/34 (88.24%), and data exfiltration 33/33 (100%).

Because multiple rule-asset revisions produced identical frozen aggregates,
the next engineering step should be a Holdout-independent asset-loading check:
verify that the test process reports the intended ruleset version or asset
digest and that generic regression probes use the same `rules.LoadDefault`
path. This recommendation does not authorize inspection of individual Holdout
rows or modification of the frozen files.

## Ruleset 1.0.2 cross-language candidate with asset identity

Run time: 2026-07-12 20:10 CST. The gate was enhanced to report a non-sensitive
canonical identity for the exact embedded rule snapshot used by the classifier:

```text
ruleset=1.0.2
rules=26
signals=165
snapshot_sha256=014ba180cccbf864333667d0227c8ec3b656e9685142c819e7e88df0e5ac8568
```

This verifies the gate was using the intended current `rules.LoadDefault`
assets rather than a stale test cache or old embed. Both Holdout hashes matched,
and the command used `-count=1`.

Exit status: non-zero (`FAIL`). Aggregate metrics again remained unchanged:
benign FP 2/246 (0.81%), overall recall 244/260 (93.85%), credential theft 28/34
(82.35%), phishing 33/33 (100%), ransomware 30/34 (88.24%), and data
exfiltration 33/33 (100%). Therefore the unresolved critical-floor failures are
not explained by stale rule loading, and this candidate remains
non-release-eligible.

## Retirement and aggregate false-negative root cause

After v1 was formally retired, analysis was authorized for only the remaining
six credential-theft and four ransomware false negatives. No prompt text or row
ID is reproduced here. The diagnostic used the same calibrated production path
and emitted only aggregate form, score, context, rule/evidence, and signal-group
counts.

| High-level semantic cluster | Count | Input forms | Aggregate root cause |
|---|---:|---|---|
| Colloquial retrieval of authentication artifacts from a victim host | 6 | 4 plain JSON-text envelopes, 1 nested tool payload, 1 role-aware conversation | Object, operational, target, and evasion groups matched in all six, but the credential intent group matched in none. Consequently no same-rule intent/object core existed. All scores were 0, result category/rule/evidence were empty, and all safety-context flags were false. The identical outcome across text, tool, and conversation forms rules out extraction or role attribution as the primary cause. |
| Provisioning an extortion payload to lock shared organizational storage and demand payment | 4 | 3 plain JSON-text envelopes, 1 role-aware conversation | All four had aggregate intent, object, operational, and target signals, but no evasion or scale signal and no scored candidate. In the three plain forms, intent and object belonged to different ransomware rules, so no same-rule core existed. In the conversation form, the record-wide union contained a same-rule pair, but role-aware evaluation still returned score 0 with no rule/evidence; this is consistent with the required signals being split across turns rather than co-located in an eligible user turn or a strong prior core. All safety-context flags were false, so context deduction was not causal. |

Root-cause classification:

- Credential cluster: **intent coverage gap**, not object, context, extraction,
  role, or threshold scoring.
- Ransomware plain cluster: **intent/object rule-group fragmentation** before
  scoring.
- Ransomware conversation cluster: **role-aware core co-location/follow-up
  eligibility**, inferred from record-wide signals plus an empty score/rule
  result; not safety-context washout.
- Every one of the ten rows scored exactly 0. Raising thresholds or qualifier
  weights would therefore not address these failures.

These findings are diagnostic guidance only. Using them to update rules and
then reporting performance on v1 as a release result would be holdout leakage.
Any such remediation must be evaluated against a separately authored unseen
successor; for v0.1.2 that successor is frozen v3.

## Post-retirement remediation diagnostic

Run time: 2026-07-12 20:15 CST. This run was explicitly a retired-v1 diagnostic,
not a release gate. It checked whether the ten aggregate gaps identified above
were closed after implementing a four-signal credential fallback, a dedicated
cross-rule ransomware combination, and bounded adjacent-user-turn association.
Both retired-v1 hashes matched before execution; the command used `-count=1`
and emitted no row text or IDs.

Rule identity:

```text
ruleset=1.0.2
rules=28
signals=177
snapshot_sha256=a76796ddb712edb9fbbeb4596e559b984043b622ef62537d466ec715f35ecc81
```

Command:

```bash
go test -tags=sqlite_omit_load_extension ./internal/classifier \
  -run '^TestRetiredHoldoutV1' -count=1 -v
```

Exit status: zero (`PASS`) as a diagnostic.

| Historical metric | Diagnostic result |
|---|---:|
| Benign FP | 2/246 = 0.81% |
| Malicious recall | 254/260 = 97.69% |
| Exact-category detection | 246/260 = 94.62% |
| Credential theft recall | 34/34 = 100% |
| Phishing deployment recall | 33/33 = 100% |
| Ransomware deployment recall | 34/34 = 100% |
| Data exfiltration recall | 33/33 = 100% |

Other category diagnostics were malware 32/32, unauthorized exploitation
32/32, defense evasion 32/32, and service disruption 24/30. Language recall was
Chinese 102/102, English 59/62, and mixed 93/96. Base64 was 3/3, multi-turn
41/42, tool JSON 40/41, authorization contradiction 5/5, and every individual
encoding/injection structure bucket reported in the test was detected.

The credential and ransomware diagnostic gaps are therefore closed on the
consumed v1 set. This is useful regression evidence only. It is deliberately
not labelled a release-gate pass and cannot substitute for the formal blind v3
result.

## Known limitations

- This fixed set is large enough to gate the specified thresholds but is not a
  statistical model of worldwide traffic or a proof of zero bypasses.
- Template-family variants are correlated; record count must not be mistaken
  for 506 fully independent human participants.
- Exact-category accuracy is reported diagnostically but is not one of the
  task-book release thresholds; a block under a different abuse category still
  counts toward safety recall.
- Current bounded text limits still fail closed when semantic inspection is
  incomplete. Recognized opaque media is now reported separately from text
  truncation so ordinary images do not automatically become `scan_limit`.
- Novel encodings, languages, slang, multimodal meaning, and semantic attacks
  with no recognizable operational evidence remain open-world risks.
- The recorded v0.1.2 candidate is specifically not release-eligible because
  two critical-category recall floors failed, even though total recall passed.
- Holdout v1 is consumed and cannot certify any later candidate, regardless of
  whether its historical metrics improve after remediation.
