# Round 4 Leo review handoff

Last updated: 2026-07-15 (Asia/Shanghai)

## Identity and status

```text
repository: https://github.com/yujianwudi/cyber-abuse-guard
base: 2d81ebdd5943c0334c484a146ce74f0069b1942f
branch: agent/round4-order-independent-media-schema-bound-multipart
CPA source pin: v7.2.75
CPA tag commit: e57416731aec87051ac00d0812df6aebd0e9d57a
CPA module sum: h1:WcCCeENtQ5F2bT86FVIOZJJbWCkPqrp3idl8kyZqARM=
CPA go.mod sum: h1:f4pcyAej8RoeRhIxJfm+OUMkCKaApiA8WzxR2XVlBh8=
classifier policy: classifier-policy-v2
classifier policy SHA-256: 6a0480acc63617b688484c81baf4991cad48b57ad4414b1a8aeab0f0d196c51c
```

Branch HEAD, implementation freeze, artifact source commit, CI URLs, and
artifact hashes must be filled from the pushed Draft PR. Until CI and the
authorized CPA v7.2.75 Host matrix finish, this is a development handoff and
not production approval.

| Evidence field | Current value |
|---|---|
| branch HEAD | PENDING COMMIT |
| implementation freeze | PENDING |
| artifact source commit | PENDING |
| Draft PR / CI run | PENDING |
| `.so`, `.so.sha256`, Store ZIP, audit bundle, build metadata, ruleset manifest/SHA, SBOM, checksums | PENDING BUILD AND HASH |
| exact diff stat / docs-only commits | PENDING COMMIT |
| CPA v7.2.75 isolated Host | NOT RUN FOR THIS CANDIDATE |
| Leo independent result | NOT RUN |

## Defects fixed

### A. JSON member-order bypass

Before: a marker-first media object skipped `source.data`, while the equivalent
marker-last object admitted the media canary to Parts/Segments and text budget.

After: ambiguous payload candidates are transactional and propagate only through
bounded media-style `source` ownership. A later media marker drops them and
records fixed opaque telemetry. A final non-media object commits them as text;
overflow commits no prefix: a final media object remains complete/opaque, while
a final non-media object becomes `deferred_text_candidate_limit`. Tool payload
`data` stays inspectable, crossing into a tool boundary cuts inherited media
meaning, and fixed `OpaqueMediaKinds` ordering makes equivalent permutations
stable.

Repository regressions include:

```text
TestExtractRequestMediaObjectMemberOrderInvariant
TestExtractRequestReverseOrderedMediaPayloadNeverEntersParts
TestExtractRequestReverseOrderedMediaPayloadNeverEntersSegments
TestExtractRequestDeferredMediaDoesNotConsumeTextBudget
TestExtractRequestToolPayloadDataStillInspectable
TestExtractRequestNonMediaDataFallsBackToInspectableText
TestExtractRequestProviderMediaFamiliesAreOrderInvariant
TestExtractRequestDeferredCandidateOverflowFinalMediaIsCompleteOpaque
TestExtractRequestDeferredCandidateOverflowFinalNonMediaIsIncompleteWithoutPrefix
FuzzExtractRequestMediaMemberOrder
BenchmarkExtractRequestReverseOrderedMedia
```

### B. Multipart unknown-field injection

Before: a denylist caused any unknown non-file multipart value, such as
`telemetry`, to become classifier text.

After: the Router maps canonical SourceFormat to a fixed profile. Only the
`openai-image` fields `prompt`, `negative_prompt`, `negative-prompt`, and
`negative prompt` are text. Reviewed metadata and `image`/`image[]`/`images`/
`images[]`/`mask` files are discarded, unknown fields become
`multipart_unknown_field`, and text fields with file evidence become
`multipart_text_field_type_mismatch`. Unknown field names and values are not
retained in classifier input, Guard errors/logs, metrics, or plugin audit.

Router regressions cover balanced allow+audit, strict local block, incomplete
precedence over a malicious prompt, complete malicious prompt blocking, fixed
counter/category semantics, and audit privacy.

```text
TestExtractRequestOpenAIImageMultipartProfile
TestExtractRequestMultipartUnknownFieldIsIncompleteAndPrivate
TestExtractRequestMultipartTextFieldTypeMismatch
TestExtractRequestMultipartFileEvidencePrecedesFieldProfile
TestExtractRequestUnknownMultipartProfileIsIncomplete
TestBalancedMultipartUnknownFieldAllowsWithoutClassification
TestStrictMultipartUnknownFieldBlocksWithoutClassification
TestMultipartIncompleteOverridesMaliciousPrompt
TestCompleteMaliciousMultipartPromptStillBlocks
TestMultipartSchemaAuditIsFixedAndPrivate
FuzzExtractRequestMultipart
BenchmarkExtractRequestMultipartProfileUnknownField
```

## CPA boundary

CPA v7.2.75 `ModelRouteRequest` has no general HTTP path. The official image
handler can call `MultipartForm` and rebuild multipart before routing, including
unknown form values. Parser tests therefore prove the plugin-input contract;
the isolated Host matrix must separately prove behavior through real image
handlers and Mock upstream.

CPA v7.2.75 also has a Host-side privacy limitation: default request
logging middleware may spool a non-multipart body temporarily and persist the
raw body in an HTTP error log. The Guard's no-tempfile/no-raw-prompt claims are
limited to its extractor and plugin audit. Leo must review the temporary log
directory, commercial-mode, retention, and access policy.

The plugin-input audit contract requires `source_format=openai-image`, category
`multipart_schema`, exactly one primary event, zero partial score/rule IDs, and
absence of unknown field names/values, media payload, filename, boundary, and
credentials. This remains a pending Host/audit verification item.

## Required independent evidence

The Draft PR CI must pass unit, race, vet, module verification, explicit
round-four regressions, 60-second JSON/multipart fuzzing, benchmarks, source
contracts, Store-installed Host tests, artifact verification, SBOM, and
reproducibility. The authorized server matrix must additionally show per case:

```text
HTTP status
Auth Selector delta
Provider delta
Mock upstream delta
usage delta
audit event count/action/category/source
```

Required Host cases include marker-first/middle/last for Anthropic image,
OpenAI input image/audio/file, and Gemini inline data; safe and malicious
visible text; balanced/strict unknown multipart; mixed malicious prompt plus
unknown field; complete malicious prompt; and malicious file bytes with a safe
prompt.

## Method and restrictions

This round used repository source, public CPA v7.2.75 source contracts, and
visible development fixtures only. It did not run or inspect evaluation-v10,
retired holdout bodies, or a restricted audit bundle; did not run
`make holdout-test`, `make consumed-boundary-test`, `make release`, or an
`INDEPENDENT_HOLDOUT_V10=1` command; and did not start CPA locally, connect a
real account/model upstream, modify production, or create a Tag/Release. If the
pushed GitHub workflow later invokes an existing aggregate boundary gate, that
CI fact must be recorded separately rather than described as a local action.

## Short Leo rerun

Use only the authorized Tencent second-machine sandbox at
`/opt/cpa-v7272-test`, CPA v7.2.75, loopback `127.0.0.1:18317`, and the Mock
upstream. Install the exact CI Store artifact, verify every checksum and build
metadata commit first, run the documented Host matrix, query plugin audit, scan
temporary Host logs for privacy canaries, then destroy case-specific state.
Do not use a real account pool, provider, production traffic, Tag, or Release.

PENDING CI, ARTIFACT, AND CPA v7.2.75 ISOLATED HOST EVIDENCE
