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
implementation freeze / artifact source: 79aa4310457b2d5a4b4bf38022fe983ddfcdc72c
```

The evidence-document version is the commit containing this file, as identified
by Git/PR history; it is docs-only and must not be mistaken for the artifact
source above. The authorized Tencent CPA v7.2.75 Host/audit matrix remains
pending, so this is a development handoff and not production approval.

| Evidence field | Current value |
|---|---|
| evidence document HEAD | This file's docs-only commit in PR history |
| implementation freeze | `79aa4310457b2d5a4b4bf38022fe983ddfcdc72c` |
| artifact source commit | `79aa4310457b2d5a4b4bf38022fe983ddfcdc72c` |
| Draft PR | <https://github.com/yujianwudi/cyber-abuse-guard/pull/6> |
| CI runs | push <https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29366207032>; PR <https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29366210668> |
| CI conclusions | quality/artifacts, long fuzz, and reproducibility: PASS on both runs |
| artifact | `cyber-abuse-guard-linux-amd64-dirty`, GitHub artifact id `8324511321` |
| implementation diff | `origin/main@2d81ebd..79aa431`: 37 files, 2,916 insertions, 556 deletions |
| CPA v7.2.75 Store-installed CI Host | PASS; exact Store archive and standalone SO identity used |
| authorized Tencent isolated Host/audit | NOT RUN FOR THIS CANDIDATE |
| Leo independent result | NOT RUN |

## CI and artifact evidence

The existing workflow ran its consumed evaluation-v10 aggregate boundary gate.
That is recorded as a CI fact only; no restricted body was opened or executed
locally. All other quality steps, including explicit round-four regressions,
unit, race, vet, fuzz, benchmark, dependency scanning, Store-installed Host,
SBOM/package verification, artifact hashing, clean-tree, and reproducibility,
passed for artifact source `79aa431`.

The downloaded artifact was checked without loading the SO or opening the audit
bundle. All eight entries declared by `checksums.txt` matched the downloaded
files. Build metadata records version `0.1.2-dirty`, Go `1.26.4`, linux/amd64,
CGO enabled, commit `79aa4310457b2d5a4b4bf38022fe983ddfcdc72c`, ruleset
`1.0.7`, and ruleset SHA-256
`7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134`.

| File | Bytes | SHA-256 |
|---|---:|---|
| `build-metadata.json` | 400 | `b18b400d7d73416946da65832037c7ea0c621f9d058929f3f8fdde60f3ee728c` |
| `checksums.txt` | 768 | `4ae28b3b34dd72195677a9910ec40d6f6498f0ae89518a8c79c260accbc78abb` |
| `cyber-abuse-guard_0.1.2-dirty_linux_amd64.zip` | 3,444,191 | `73c8649739114960bf3be298a3a3bc0b092d4cbecc082991f52a0c99159e9f84` |
| `cyber-abuse-guard-v0.1.2-dirty.so` | 8,324,232 | `591805dafdf477080b728b14da04c8ca843926ca3b8483095995588c40626c9b` |
| `cyber-abuse-guard-v0.1.2-dirty.so.sha256` | 100 | `0363fa4a051b68cccbed8c6ab7972954e1508debd6ec3c7b292529279608b7ca` |
| `cyber-abuse-guard-v0.1.2-dirty-audit-bundle.zip` | 3,607,727 | `e16b188615b9b10897197e5aa4580f0c6a44b45cde7790a3568ff5063e106af4` |
| `ruleset.sha256` | 88 | `a8ff687340617dc18832047f841979a0bd06ff8c50a4bc3c15dd7da37b6fbee2` |
| `ruleset-manifest.json` | 1,475 | `486a4dfad49b4e96a600f908cbea47376baab5c8875324999ae50b6251f1af7e` |
| `sbom.cdx.json` | 5,919 | `7aa97543c1d920c5afae76838a6c4254dcd73aae6fe1f1d7b3869235f9196d50` |

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
