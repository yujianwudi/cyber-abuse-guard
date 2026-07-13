# Defensive Review: `MDX-Tom/gpt-5.6-instruct`

Status: **development input only / not blind evidence / server sandbox validation pending**

Implementation branch: `agent/post-v10-production-hardening`

Starting source commit for this diff:
`68ce0f662cbb034e61e1f3a8b91f50ea20c57637`

Delivery identity: the base commit above is comparison context only. The Git
commit that contains this report and its code diff, together with the YAML
ruleset identity, is the authoritative development-tree identity. This is
still **RELEASE BLOCKED** and is not a release commit/tag identity.

Reviewed source:

- Repository: <https://github.com/MDX-Tom/gpt-5.6-instruct>
- Read-only snapshot: `680c3d3d1c4a27fb7c8f9aae678e89cfa351b4d4`
- Review date: 2026-07-13 (Asia/Shanghai)

No script, deployment helper, instruction file, or prompt-bank runner from the
external repository was executed. The repository was used only to derive a
sanitized defensive taxonomy. Complete jailbreak prompts are not copied into
this project, its tests, or this report.

## Observed attack mechanisms

The relevant mechanisms are compositional rather than keyword-only:

1. configuration-level instruction replacement through a
   `model_instructions_file`-style control;
2. instruction-hierarchy inversion and unrestricted/developer persona claims;
3. evaluation reversal in which refusal or a safe fallback is declared a test
   failure;
4. explicit suppression of refusal, policy framing, risk assessment,
   clarification, and authorization checks;
5. sandbox, benchmark, fictional-target, or local-fixture claims used to wash
   real or unauthorized scope;
6. replacement of concrete targets with placeholders while preserving a full
   operational workflow;
7. bilingual and mixed-language routing across several related sub-intents;
8. forced first lines, exact templates, autonomous slot filling, and immediate
   code/step output;
9. system/developer-prompt or hidden-reasoning disclosure requests; and
10. delivery through system/developer content, tool payloads, nested JSON,
    encoded text, or split content blocks.

## Implemented in development source

The post-v10 development tree adds a deterministic `META-OVERRIDE-001` overlay.
It compiles bilingual signal families into the existing bounded literal matcher
and requires combinations of independent control-plane evidence. It does not
block a lone word such as `jailbreak`, `benchmark`, or `developer`.

The overlay covers:

- hierarchy replacement;
- refusal suppression;
- unrestricted-mode/persona declarations;
- direct-completion demands;
- sandbox and placeholder laundering;
- exact-output and no-clarification controls;
- system/developer-prompt or hidden-reasoning disclosure; and
- explicit negative authorization.

When ordinary cyber-abuse evidence is already present, the overlay raises that
candidate without replacing its original taxonomy. A strong standalone
control-plane attack is reported under `defense_evasion`. Prompt-derived CTF,
lab, fictional-target, and authorization claims do not reduce the overlay.
Explicit defensive analysis, quoted-sample review, detection, and mitigation
can reduce it only when the request also has an affirmative non-execution
purpose.

Additional extraction and scope hardening in the same change:

- a supported provider label whose role schema is ambiguous is re-extracted by
  the router with the conservative untrusted walker;
- JSON-looking strings under any already-established tool-payload field are
  recursively inspected under the existing depth/part/byte budgets;
- content joined from multiple provider blocks and ordered strings from a tool
  payload or function output are decoded again, closing sub-threshold Base64
  splits;
- one-character fragments may be reconstructed across line/content boundaries,
  while ordinary multi-character clauses remain hard-separated;
- unknown semantic siblings are retained in top-level JSON order as untrusted
  user segments, while recognized `metadata`/`options` containers do not erase
  role isolation; hostile linked system/tool control may carry into a user
  continuation regardless of top-level property order;
- linked meta chains retain a bounded cumulative family bitset while only the
  latest eight evidence-bearing text parts are kept for contextual review; a
  non-meta part breaks the chain, preventing quadratic tail construction;
- an inert refusal quotation exits scope on a new `now`/`then` operational
  turn, direct protected-prompt disclosure requests are audited, and defensive
  non-execution text must follow the final quoted meta phrase;
- dotless `ı` and Cyrillic `к` join the narrow high-risk homoglyph map;
- negative-authorization conflict phrases clear prompt-derived lab/authorization
  deductions; and
- a system message that negates refusal, blocking, filtering, guardrails, or
  safety checks is no longer suppressed as a benign safety policy.

Primary implementation and regression files:

- `internal/classifier/meta_override.go`
- `internal/classifier/meta_override_test.go`
- `internal/classifier/classifier.go`
- `internal/classifier/roles.go`
- `internal/classifier/matcher.go`
- `internal/classifier/normalize.go`
- `internal/extract/extract.go`
- `internal/extract/roles.go`
- `internal/extract/roles_test.go`
- `internal/plugin/router.go`
- `internal/plugin/prompt_injection_regression_test.go`

## Source-level validation performed

On 2026-07-13 (Asia/Shanghai), the following current-diff checks exited zero.
The invoked toolchain reported `go version go1.26.4 linux/amd64`:

```text
/home/yujian/.local/toolchains/go1.26.4/bin/go test -tags=sqlite_omit_load_extension \
  ./internal/rules ./internal/extract ./internal/classifier ./internal/plugin \
  -count=1
/home/yujian/.local/toolchains/go1.26.4/bin/go vet -tags=sqlite_omit_load_extension \
  ./internal/rules ./internal/extract ./internal/classifier ./internal/plugin
/home/yujian/.local/toolchains/go1.26.4/bin/go test -race -tags=sqlite_omit_load_extension \
  ./internal/extract ./internal/classifier ./internal/plugin \
  -run '^(TestMetaOverride.*|TestNegativeAuthorizationClearsLabLaundering|TestMaliciousSystemPolicyCannotNegateRefusalInsteadOfAbuse|TestSystemClosedQuoteCannotHideNewOperationalSentence|TestAssistant.*|Test.*Permission.*|TestExtractTextRoleAmbiguityReextractsUnknownTopLevelSemantics|TestExtractTextUnknownTopLevelMetadataDoesNotEraseRoleIsolation|TestExtractTextRedecodesEncodedContentSplitAcrossBlocks|TestExtractTextRedecodesEncodedToolFieldsAfterPristineJoin|TestExtractTextRecursesJSONStringUnderArbitraryToolPayloadField|TestPromptInjection.*)$' \
  -count=1
/home/yujian/.local/toolchains/go1.26.4/bin/gofmt -l internal/classifier/classifier.go \
  internal/classifier/matcher.go internal/classifier/meta_override.go \
  internal/classifier/meta_override_test.go internal/classifier/normalize.go \
  internal/classifier/roles.go internal/extract/extract.go \
  internal/extract/roles.go internal/extract/roles_test.go \
  internal/plugin/router.go internal/plugin/prompt_injection_regression_test.go \
  internal/rules/types.go
/home/yujian/.local/toolchains/go1.26.4/bin/go mod verify
/home/yujian/.local/toolchains/go1.26.4/bin/go mod tidy -diff
git diff --check
```

These are developer-visible source checks only. Current-diff real-CPA
integration, native plugin loading, deployment, formal
Holdout, formal packaging, tag, and GitHub Release were not run. **SERVER
SANDBOX VALIDATION: PENDING / NOT RUN.** See `TEST_REPORT.md` and
`RELEASE_EVIDENCE.md` for the evidence boundary.

## Ruleset and policy identity

Ruleset `1.0.7` and its canonical SHA-256 identify the embedded YAML
cyber-abuse assets. They do not include the complete Go-level policy:
`META-OVERRIDE-001`, matcher/normalizer mappings, role handling, and extraction
semantics all affect decisions. The containing Git/build commit plus the YAML
identity are required for this development behavior. A release-eligible
successor must add a separately verified classifier-policy version/hash or
fully bind these semantics to verified build provenance.

## External evidence quality warning

The external repository is useful as an adversarial development source, but its
published performance claims are not independently reproducible from the
reviewed tree:

- README declares SHA-256
  `08a257814f515bbcb842be7ff4932a48ba112a56caef91371369881c256efd0c`;
- the reviewed ZIP hashes to
  `398ebd9e04141cbf0baf598fbbe6db0eb508f7e5f1d49207ca18c1beac37b097`;
- the Markdown extracted from that ZIP hashes to
  `5867af4e6d039fb331e2368ec13499b01c8e93d189e072631f31a226108becf7`;
- README references `tests/` and `reports/`, but neither directory exists in
  the reviewed Git tree; and
- the repository's safety-evaluation note still describes an older prompt
  version.

The archive hashes above were reproduced without executing or writing its
contents to the workspace:

- pinned raw path:
  `https://raw.githubusercontent.com/MDX-Tom/gpt-5.6-instruct/680c3d3d1c4a27fb7c8f9aae678e89cfa351b4d4/gpt-5.6-sol-unrestricted.zip`;
- Git path: `gpt-5.6-sol-unrestricted.zip`, 2,881 bytes;
- in-archive path: `gpt-5.6-sol-unrestricted.md`, 5,137 bytes.

Reproduction used the GitHub Contents API and an in-memory ZIP reader:

```powershell
$ref = '680c3d3d1c4a27fb7c8f9aae678e89cfa351b4d4'
$j = gh api "repos/MDX-Tom/gpt-5.6-instruct/contents/gpt-5.6-sol-unrestricted.zip?ref=$ref" | ConvertFrom-Json
$bytes = [Convert]::FromBase64String(($j.content -replace '\s',''))
$sha = [Security.Cryptography.SHA256]::Create()
([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-','').ToLowerInvariant()
Add-Type -AssemblyName System.IO.Compression
$stream = [IO.MemoryStream]::new($bytes, $false)
$zip = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Read, $false)
$entry = $zip.GetEntry('gpt-5.6-sol-unrestricted.md')
([BitConverter]::ToString($sha.ComputeHash($entry.Open())) -replace '-','').ToLowerInvariant()
gh api "repos/MDX-Tom/gpt-5.6-instruct/git/trees/$ref?recursive=1" --jq '.tree[].path'
```

Accordingly, claims such as `120/120` are not treated as verified facts and are
not used as release evidence.

## Validation and release boundary

Only source-level unit checks are authorized for this change. No local CPA
deployment, native plugin loading, real-CPA integration, release packaging,
formal holdout run, tag, or GitHub Release is part of this work. Server-side
sandbox validation remains pending for the project owner.

This public repository and every derived regression case are developer-visible.
They must never be reused, relabelled, or counted as a future independent
holdout. The v0.1.2 release decision remains **FAIL / NOT PRODUCTION-READY**;
the consumed v10 result remains immutable.

## Remaining limits

- The plugin can inspect only the request that reaches its router. It cannot
  attest to the ownership, permissions, or hash of a local Codex instruction
  file before CPA receives the request.
- Provider transport/configuration containers such as `safetySettings`,
  `generationConfig`, and generic `options` are not semantically enforced as
  upstream safety policy; the server must constrain them separately.
- Tool JSON property names with only boolean/numeric/null values are not treated
  as standalone prompt text; schema allowlists must reject unapproved key-only
  controls.
- Classification is stateless across separate API calls unless the caller sends
  the relevant history in the current body. No prompt text is persisted.
- Decoding remains intentionally bounded and does not claim coverage for
  arbitrary encryption, compression, Base32, hex, quoted-printable, or novel
  transforms.
- Opaque documents, images, audio, and video are not converted to text.
