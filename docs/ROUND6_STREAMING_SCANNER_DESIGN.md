# Round 6 long-text streaming scanner design

Status: **BLOCKED / PENDING HOST AND INDEPENDENT AUDIT**. This is a Linux
amd64-only development candidate. Windows and macOS validation is outside this
round. See [ROUND6_DEVELOPMENT_HANDOFF.md](ROUND6_DEVELOPMENT_HANDOFF.md).

## Security objective

Round 5.2 treated `max_scan_bytes` as both a raw JSON prefix limit and a cumulative classifier limit. A valid request larger than 256 KiB could therefore become incomplete before its model-visible text reached the classifier. Balanced mode then allowed the request by design.

Round 6 separates envelope parsing, text coverage, classifier work, and transport disposition. A valid CPA-visible JSON request is no longer parsed as `body[:max_scan_bytes]`.

## Request path

```text
CPA model.route body
        |
        v
complete envelope validation and bounded structural planner
        |
        v
transactional shadow JSON + model-visible span selection
        |
        v
incremental JSON unescape / multipart UTF-8 replay
        |
        v
classifier ScanSession (bounded windows + derived overlap/carry)
        |
        v
single inspectionDisposition decision
        |
        +--> local block before provider/auth/usage
        +--> allow / observe / audit
```

The structural planner traverses the complete CPA-visible body and records only bounded metadata plus raw string spans. Long prompt strings are not copied into the plan. A compact shadow document is passed through the established provider/media/tool schema logic so marker-last media, metadata exclusion, tool controls, and role attribution remain transactional. Caller-controlled keys and semantic values collapse to closed representatives, metadata strings do not create spans, and span markers use a short base-36 form. Only spans proven to be model-visible are replayed.

CPA can retain `multipart/form-data` on an OpenAI image request after converting
the form into a complete JSON execution object. That transformed form uses a
separate top-level SourceProfile planner: approved `prompt` fields become raw
JSON string spans, metadata is skipped, file fields remain opaque, and unknown
or type-mismatched fields invalidate the transaction before any span is sent to
the classifier. It does not pass through legacy materialized `Parts`,
`MaxScanBytes`, `MaxMultipartTextBytes`, or `MaxMultipartTextPartBytes`; total
coverage is governed by `MaxTotalTextBytes`, `MaxTextParts`, and bounded
classification work. Binary controls retain the historical
`multipart_parse_error` category, while oversized encoded derived views retain
`multipart_text_limit`.

The shadow/index path is bounded but not constant-space: retained structural
metadata and decoder state still grow with JSON token/node and logical-field
counts under explicit hard limits. Final allocation and RSS evidence must come
from Linux amd64 CI and the authorized Linux sandbox.

## Streaming contract

The extractor calls a synchronous sink with serialized logical fields:

```go
type SegmentChunk struct {
    Role       Role
    Provenance SegmentProvenance
    FieldID    uint64
    Start      bool
    End        bool
    Text       []byte
}
```

`FieldID` is request-local and is never logged or persisted. Chunks for different fields cannot interleave. `Start` and `End` represent real logical field boundaries, not classifier-window boundaries. On malformed input or semantic incompleteness the extractor calls `Abort`, invalidating provisional classification.

JSON strings are decoded incrementally, including escapes, surrogate pairs, and UTF-8 boundaries. Existing bounded URL/HTML/Base64/data-text decoding remains part of the model-visible path. Oversized Base64 candidates use constant-memory full-stream syntax validation and incremental decoded-text signaling; a binary head sample cannot by itself hide a later printable encoded section, and malformed trailing bytes cannot erase an already proven strong printable prefix. Every actual UTF-8-safe chunk rechecks the classification-chunk hard limit before delivery. Opaque media classification is committed only after the complete containing structure proves media semantics. The transformed-multipart JSON planner validates the full top-level schema before replay, so a later unknown field cannot commit an earlier prompt prefix.

## Classifier windows and overlap

The classifier retains one configured window, a derived overlap/carry, and fixed-size role/proof summaries. It does not retain the complete prompt. The overlap is calculated from:

- the longest standard or compact matcher pattern;
- bounded intent lookback;
- negation reversal tail;
- meta-override association proof;
- Unicode normalization lookaround.

The compiled overlap must be smaller than the configured window and smaller than the conservative 4096-byte configuration reserve. The exact value is emitted by the Round 6 overlap test and management status.

Cross-window classification never merges different roles or unrelated fields as if they were one prompt. Role-aware reconstructions use complete, bounded logical-field summaries. Long fields continue through window scanning but are not copied into cross-field state. Inside one long logical field, fixed-size rule/outcome/semantic signal facts record whether different windows contributed distinct risk ingredients. If their aggregate reaches the balanced threshold while no individual window did, coverage becomes `classifier_window_incomplete` instead of being reported as complete allow.

Assistant/system quoted safety examples use a bounded provisional `Result`, not retained prompt text. A real closing quote discards that provisional result and exposes only the suffix to ordinary classification. If the logical field ends first, the provisional result is committed as ordinary content. Closing detection reads only newly consumed bytes, so an opener replayed in overlap cannot be mistaken for a close.

## Completeness and disposition

Envelope completeness and model-text coverage are independent:

- envelope `complete`: the complete CPA-visible structure was validated;
- text coverage `complete`: every model-visible decoded byte reached the classifier;
- text coverage `budget_exhausted`: a configured total-text or classification-work bound was reached;
- text coverage `unavailable`: parsing, decoding, schema, role attribution, or RPC visibility prevented safe completion.

The first Round 6 implementation does not enable the optional verified-hard-finding exception. If coverage is incomplete, partial score, category, rules, evidence, and behavior are cleared before policy or subject-state evaluation.

| Mode | Incomplete request |
|---|---|
| off | allow |
| observe | allow + observe event |
| audit | allow + audit |
| balanced | allow + audit |
| strict | local block + audit |

Incomplete requests never enter rolling subject risk.

## Resource bounds

Default effective limits are:

- raw CPA RPC envelope: 8 MiB;
- text window: legacy `max_scan_bytes` alias, clamped to 16 KiB–1 MiB;
- total model-visible text: 8 MiB;
- logical text fields: 512;
- classification work units: at least 2048 and automatically raised when configured limits require more;
- JSON depth: 32, with independent token/node bounds.

Traversal is O(raw bytes). Text classification is O(model-visible bytes plus bounded matching/reconstruction work). No request text is written to temporary files, audit rows, metrics labels, or logs.

## Audit and telemetry

Audit schema v3 adds fixed fields:

- `decision`;
- `coverage`;
- `incomplete_reason`;
- `scanner` (`streaming-scanner-v1`).

Counters are fixed and low-cardinality. `text_bytes_scanned_total` may exceed the legacy `max_scan_bytes`; peak retained text is bounded by the effective window plus fixed classifier state.

## Trust boundary

This design does not fetch remote media, call a model, select a provider, inspect production observe data, or execute third-party adversarial repositories. Host validation must use official CPA v7.2.81, v7.2.80, and v7.2.79 binaries, the exact Linux amd64 candidate, a Mock upstream, no real auth pool, and no real provider. All three Host runs are currently **NOT RUN / PENDING**.
