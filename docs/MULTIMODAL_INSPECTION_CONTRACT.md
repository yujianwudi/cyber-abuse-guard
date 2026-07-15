# Multimodal request inspection contract

Last updated: 2026-07-15 (Asia/Shanghai)

Status: fourth-round development contract. It is not production approval and
does not replace CPA v7.2.75 isolated-Host or Leo independent verification.

```text
base: 2d81ebdd5943c0334c484a146ce74f0069b1942f
CPA: v7.2.75 / e57416731aec87051ac00d0812df6aebd0e9d57a
classifier policy: classifier-policy-v2
classifier policy SHA-256: 6a0480acc63617b688484c81baf4991cad48b57ad4414b1a8aeab0f0d196c51c
fourth-round CI/artifact/Store-installed CI Host: PASS; authorized Tencent isolated Host/audit: PENDING
```

The earlier v7.2.72 multimodal and Host results remain historical evidence in
`ROUND2_LEO_REVIEW_HANDOFF.md`; they do not validate this candidate.

## State separation

`complete`, `incomplete_inspection`, `opaque_media`, and
`operational_failure` remain distinct. Opaque media is intentionally not
interpreted and does not by itself mean extraction failed. Incomplete content
takes precedence over any prefix classification. Operational failure retains
its separate runtime/CPA-aware policy and is not re-labelled as multipart or
JSON incompleteness.

## JSON media semantics

JSON object members are unordered. Media recognition therefore uses an
object-level transaction:

1. payload-adjacent values under `data`, `bytes`, `blob`, `binary`, `filename`,
   `format`, `detail`, `width`, `height`, and `duration` are retained only
   within fixed internal bounds;
2. a later media marker commits the object as opaque and discards those
   candidates without classification;
3. if the object closes without media evidence, candidates are committed as
   inspectable text;
4. candidate overflow retains no prefix. A final media object remains complete
   and opaque; a final non-media object becomes `deferred_text_candidate_limit`;
5. child `source` frames may move candidates to their owning media frame, but
   tool/tool-payload boundaries terminate inherited media meaning.

The same walker is used for `Parts` and role-aware `Segments`; marker-first,
marker-middle, and marker-last forms must not change either representation,
`TextBytesScanned`, completeness, or the stable `OpaqueMediaKinds` ordering.
Provider-native tool payload text such as
`{"data":"..."}` remains inspectable and cannot label itself as media merely
by adding `type=image`.

Opaque media payloads, data URLs, media URLs, and uploaded bytes do not enter
text decoding, do not consume the text budget, and are represented only by a
fixed media-kind enum. Real text fields such as caption, text, and prompt remain
inspectable.

## Multipart SourceProfile contract

Multipart text extraction is profile-bound. CPA v7.2.75's
`ModelRouteRequest` contains `SourceFormat`, headers, body, model and related
metadata, but no general HTTP path. CPA's image handler may parse and rebuild a
multipart request before the Router sees it. The Guard therefore maps only a
canonical `SourceFormat` to a fixed `SourceProfile`; it never guesses a schema
from a filename, model, field value, or endpoint path.

The current `openai-image` profile is:

| Class | Fields |
|---|---|
| inspectable text | `prompt`, `negative_prompt` (also the bounded spellings `negative-prompt` and `negative prompt`) |
| opaque file/media | `image`, `image[]`, `images`, `images[]`, `mask` |
| metadata/control | `model`, `stream`, `n`, `size`, `quality`, `response_format`, `output_format`, `background`, `style`, `user`, `seed`, `format`, `aspect_ratio`, `resolution`, `input_fidelity`, `moderation`, `output_compression`, `partial_images` |

Actual file evidence has precedence: filename/filename*, attachment disposition,
image/audio/video/multipart media types, octet-stream, PDF, or Office MIME.
However, an allowlisted text field carrying file evidence is not silently
complete; it becomes `multipart_text_field_type_mismatch` and its bytes are
discarded as opaque.

An unknown non-file field is never classifier text. It is discarded with a
fixed buffer, produces `multipart_unknown_field`, and neither its name nor value
may enter Parts, Segments, errors, Guard logs, metrics, or plugin audit. An
unknown profile treats every non-file field this way; explicit file evidence
can still be safely skipped. This statement does not extend to CPA's own raw
request/error logging boundary described below.

## Incomplete inspection disposition

Schema uncertainty is content incompleteness, not an operational failure.

| Mode | Unknown/type-mismatched multipart field |
|---|---|
| off | pass through |
| observe | pass through and observe |
| audit | pass through and audit |
| balanced | pass through and audit as `multipart_schema` |
| strict | local self-route block with `cyber_abuse_guard_multipart_schema` |

Incomplete inspection is primary. If a request contains both an apparently
malicious prompt and an unknown multipart field, no prefix score/rule IDs or
subject-risk update may be used: balanced allows+audits, strict blocks for the
fixed incomplete reason. A complete malicious prompt still follows ordinary
policy and blocks in enforcing modes.

Stable new reasons and counters are:

```text
multipart_unknown_field
multipart_text_field_type_mismatch
deferred_text_candidate_limit

incomplete_multipart_schema
incomplete_deferred_text_limit
```

## Privacy and resource boundary

The extractor does not create temporary files, fetch URLs, OCR, transcribe,
decompress, or inspect media bytes. Deferred candidates and multipart discard
buffers are fixed and bounded. Go's JSON decoder may still allocate the full
encoded JSON string transiently before the Guard can decide that it is media.

`RawBytesObserved` and `TextBytesScanned` are separate. Media Base64, data URLs,
remote media URLs, filenames, boundaries, MIME parameters, file bytes, metadata
fields, and unknown multipart values do not consume the text budget. Reaching a
raw/depth/token/node/part/header/text/deferred bound produces a fixed reason;
no untrusted field name, value, parser diagnostic, or payload fragment is used
as a counter label or persisted audit category.

These guarantees cover the Guard extractor, errors, metrics, and plugin audit.
They are not an end-to-end CPA logging guarantee. CPA v7.2.75 can temporarily
spool non-multipart request bodies in its request-logging middleware and can
persist a raw body in an HTTP error log. Isolated Host tests must use a temporary
log directory and Leo must review CPA commercial-mode, error-log retention, and
access controls before any production observation.

## Evidence boundary

Parser unit tests prove member-order and field-profile behavior for the payload
delivered to the plugin. Host tests separately prove CPA transformation,
pre-SSE blocking, and Auth/Provider/upstream/usage side effects. Neither class
of evidence substitutes for the other. The current CI run, artifact hashes,
Store-installed CPA v7.2.75 matrix, and audit/privacy scan are pending. No result
is `LEO PASS` or production approval until Leo independently repeats the frozen
artifact in the authorized CPA v7.2.75 sandbox.
