# Independent Holdout v3 Release-Gate Report

## Status

**CONSUMED — FORMAL GATE FAILED. THIS HOLDOUT MUST NEVER BE USED FOR TUNING OR
RELEASE AUTHORIZATION AGAIN.**

The first and only pre-release formal classification ran on the frozen source
snapshot and ruleset `1.0.3`. It emitted aggregate counts only and failed the
release thresholds. No row ID, row text, score, miss, or false-positive sample
was emitted or inspected. The implementation must not be tuned against v3; a
fresh independently authored blind set is required after general hardening.

The retained gate now defaults to `t.Skip` and fails explicitly if
`INDEPENDENT_HOLDOUT_V3=1` is set. It cannot authorize a future release.

## Isolation and authoring controls

Holdout v3 was authored from the task-book category, threshold, provider, and
structure requirements plus the public extraction/classification API shapes.
During authoring, the following were not read or reused:

- `testdata/holdout` and `testdata/holdout-v2` row content;
- prior Holdout reports or metrics;
- earlier Holdout gate source;
- classifier rule YAML term lists;
- classifier/extractor unit-test prompt strings;
- the prior fixture generator.

No production classifier, extraction, plugin, or rule code was modified by the
v3 authoring work. The retained `cmd/holdout-v3-author` program documents the
separate deterministic authoring process and refuses to overwrite frozen files.

## Frozen manifest

Source marker: `independent-holdout-v3-2026-07-12`

| File | Records | Bytes | SHA-256 |
|---|---:|---:|---|
| `testdata/holdout-v3/benign-security.jsonl` | 300 | 170,980 | `7edc6d5ff97b04c005bdeb2e66de585b9d50d261a128a54f229af57cb0bb5d25` |
| `testdata/holdout-v3/malicious-operational.jsonl` | 320 | 221,904 | `8d7ddbae41f0b6f4870febc4b1ba73c490b92b920f19db4f4290b3ff3227710e` |

Frozen embedded-rule identity:

```text
ruleset_version: 1.0.3
canonical_rules_snapshot_sha256: d497823cf77ea987623a9a80c92e3eee94e15b82e4273d908967f395284755fa
classifier_extractor_dependency_snapshot_sha256: 70fe792aae4223da724f809ba64b63959c6749473c9bb073b43953a742d057a7
```

The snapshot digest is the SHA-256 of sorted lines containing each embedded
`rules/*.yaml` file SHA-256 and repository-relative path. A change to any rule
file or version invalidates FrozenIntegrity before classification.

The implementation snapshot uses the same line format over `go.mod`, `go.sum`,
the four production classifier files, the three production extractor files,
and both production rule-loader files. FrozenIntegrity checks it before loading
the v3 fixtures. This prevents classifier, extractor, rule-loader, or dependency
changes between the first formal result and the clean-tag rerun.

## Frozen distributions

Language:

| Label | Chinese | English | Mixed | Total |
|---|---:|---:|---:|---:|
| Benign | 100 | 100 | 100 | 300 |
| Malicious | 104 | 104 | 112 | 320 |

Every malicious category contains exactly 40 records:

- `credential_theft`
- `phishing_deployment`
- `malware_deployment`
- `ransomware_deployment`
- `unauthorized_exploitation`
- `service_disruption`
- `data_exfiltration`
- `defense_evasion`

The corpus contains 34 distinct request structures. Exact totals across both
files are:

| Structure | Records | Structure | Records |
|---|---:|---|---:|
| `anthropic_messages` | 19 | `anthropic_multi` | 19 |
| `anthropic_tool_use` | 19 | `assistant_refusal` | 18 |
| `authorization_conflict` | 18 | `base64_text` | 18 |
| `ctf_label` | 18 | `education_label` | 17 |
| `gemini` | 19 | `gemini_multi` | 19 |
| `generic_input` | 18 | `generic_parts` | 18 |
| `history_padding` | 18 | `homoglyph` | 18 |
| `html_entity` | 18 | `json_unicode` | 18 |
| `markdown` | 18 | `nbsp` | 18 |
| `nested_tool_json` | 19 | `openai_chat` | 18 |
| `openai_chat_multi` | 18 | `openai_chat_role_pollution` | 19 |
| `openai_chat_tool` | 18 | `openai_responses` | 19 |
| `openai_responses_multi` | 18 | `openai_responses_tool` | 18 |
| `prompt_injection` | 17 | `second_order_json` | 19 |
| `string_concat` | 18 | `system_policy` | 18 |
| `typo` | 18 | `unknown_role` | 19 |
| `url_encoded` | 18 | `zero_width` | 18 |

Coverage includes true provider-native OpenAI Chat and Responses function/tool
calls, Anthropic `tool_use`, Gemini, a genuinely unknown role that enters the
untrusted fallback, role pollution, assistant refusal, system policy, multiple
turns, history padding, second-order tool JSON, Base64, URL encoding, HTML
entities, JSON Unicode escapes, zero-width characters, homoglyphs, typos,
non-breaking spaces, Markdown, string concatenation, prompt injection, and
authorization/CTF/education label contradictions.

Benign records separately cover defense, remediation, incident response,
detection-rule design, offline static analysis, local CTF/lab work, high-level
education, awareness training, safe approved read-only review, synthetic-data
testing, and recovery planning.

## Default FrozenIntegrity result

Command executed:

```bash
go test -tags=sqlite_omit_load_extension ./internal/classifier \
  -run TestIndependentHoldoutV3FrozenIntegrity -count=1
```

Result: **PASS**.

FrozenIntegrity asserts, without invoking the classifier:

- exact file byte counts, line counts, and SHA-256 values;
- strict JSON schema, source marker, sequential unique IDs, sorted unique tags,
  labels, languages, categories, and all exact distributions above;
- every request is valid JSON and traverses production `extract.ExtractText`;
- extraction parse errors = 0, empty semantic results = 0, truncation = 0;
- every native tool structure produces tool-payload provenance;
- every `unknown_role` fixture uses the non-role-aware fallback;
- no exact normalized semantic duplicate exists inside v3;
- no exact normalized semantic duplicate exists against v1, v2, or the project
  regression corpus. The comparison emits neither prior nor v3 text;
- the embedded rule files still match the frozen `1.0.3` snapshot.

## Formal gate definition

Every row is first serialized as its native JSON request and passed through
production `extract.ExtractText`. Role-aware results use
`ClassifySegmentsWithPolicy`; all other valid results use
`ClassifyUntrustedPartsWithPolicy`. Balanced defaults and the production context
policy are used.

Required gates:

| Metric | Requirement | Result |
|---|---:|---|
| Benign false-positive rate | `< 5%` | PENDING |
| Overall malicious blocked recall | `> 90%` | PENDING |
| Credential-theft blocked recall | `>= 95%` | PENDING |
| Credential-theft exact-category recall | `>= 95%` | PENDING |
| Phishing blocked recall | `>= 95%` | PENDING |
| Phishing exact-category recall | `>= 95%` | PENDING |
| Ransomware blocked recall | `>= 95%` | PENDING |
| Ransomware exact-category recall | `>= 95%` | PENDING |
| Data-exfiltration blocked recall | `>= 95%` | PENDING |
| Data-exfiltration exact-category recall | `>= 95%` | PENDING |
| Extraction errors / empty / truncated | `0 / 0 / 0` | PASS (FrozenIntegrity) |

Only aggregate totals by label/category and role-aware/untrusted path counts are
logged. The gate does not print row IDs, text, scores, rule IDs, tags, or
individual outcomes.

## Authorized formal command — not yet executed

Direct command:

```bash
INDEPENDENT_HOLDOUT_V3=1 \
go test -tags=sqlite_omit_load_extension ./internal/classifier \
  -run '^TestIndependentHoldoutV3Gate$' -count=1 -v
```

Release command:

```bash
make holdout-test
```

`make holdout-test` first uses `-list` to require the exact
`TestIndependentHoldoutV3Gate` name, then sets the opt-in environment variable
on only that exact test command. CI also marks its dedicated step with the
opt-in; the tag-only workflow reaches the same exact Make target without
exporting the variable to broad tests. Ordinary `go test` and `go test -race`
execute FrozenIntegrity but the classification gate skips.

## Formal result

Aggregate output from the first formal run:

| Category | Blocked | Exact category |
|---|---:|---:|
| `credential_theft` | 34/40 (85.00%) | 29/40 (72.50%) |
| `phishing_deployment` | 20/40 (50.00%) | 5/40 (12.50%) |
| `malware_deployment` | 40/40 (100.00%) | 16/40 (40.00%) |
| `ransomware_deployment` | 38/40 (95.00%) | 38/40 (95.00%) |
| `unauthorized_exploitation` | 5/40 (12.50%) | 5/40 (12.50%) |
| `service_disruption` | 11/40 (27.50%) | 11/40 (27.50%) |
| `data_exfiltration` | 14/40 (35.00%) | 10/40 (25.00%) |
| `defense_evasion` | 12/40 (30.00%) | 12/40 (30.00%) |

```text
run_time_utc: 2026-07-12T17:29:18Z
release_commit: not created (dirty pre-release candidate; release rejected)
annotated_tag: not created
ruleset_version: 1.0.3
rules_snapshot_sha256: d497823cf77ea987623a9a80c92e3eee94e15b82e4273d908967f395284755fa
classifier_extractor_dependency_snapshot_sha256: 70fe792aae4223da724f809ba64b63959c6749473c9bb073b43953a742d057a7
benign_fp: 35/300 (11.67%) -- FAIL, required <5%
overall_malicious_blocked_recall: 174/320 (54.38%) -- FAIL, required >90%
credential_theft_blocked_recall: 34/40 (85.00%) -- FAIL
credential_theft_exact_category_recall: 29/40 (72.50%) -- FAIL
phishing_blocked_recall: 20/40 (50.00%) -- FAIL
phishing_exact_category_recall: 5/40 (12.50%) -- FAIL
ransomware_blocked_recall: 38/40 (95.00%) -- PASS
ransomware_exact_category_recall: 38/40 (95.00%) -- PASS
data_exfiltration_blocked_recall: 14/40 (35.00%) -- FAIL
data_exfiltration_exact_category_recall: 10/40 (25.00%) -- FAIL
role_aware_paths: 258
untrusted_paths: 362
command_exit_status: 1
overall_gate: FAIL; CONSUMED
```

Holdout v3 permanently rejects this candidate and provides no release approval.
Its aggregate result may be cited as history, but its samples and category
outcomes must not be used to tune the next classifier or rule candidate.
