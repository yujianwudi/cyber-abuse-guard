# Multimodal request inspection contract

Last updated: 2026-07-14 (Asia/Shanghai)

Status: implementation contract for the second-round candidate. This document
does not grant production approval and does not replace isolated CPA Host or
Leo independent verification.

## Scope

The guard inspects request text before CPA provider/auth/usage/upstream work.
It supports bounded JSON and `multipart/form-data` inspection without fetching,
decoding, OCRing, transcribing, or classifying opaque media bytes.

The implementation baseline for behavioral comparison is:

```text
61536f9f02c47a4d79031a47dc8a284f040e41c1
```

The working branch starts from merge commit:

```text
9422087b5381bd06be9bc02a32ecdecffceef705
```

## Four distinct states

| State | Meaning | Examples |
|---|---|---|
| `complete` | All locally inspectable request text was extracted within every bound and classified normally. | Valid bounded JSON; valid bounded multipart prompt plus skipped files. |
| `incomplete_inspection` | The guard could not prove that all locally inspectable text was examined. | Malformed JSON, text budget, JSON depth/part limit, multipart boundary/header/part limit, unsupported media type, RPC body limit. |
| `opaque_media` | Media is intentionally not interpreted; this is not by itself an extraction failure. | Image/audio/video Base64, data URL, remote media URL, uploaded image/audio/file bytes. |
| `operational_failure` | Plugin/runtime execution failed independently of request-content completeness. | Panic, missing runtime, shutdown race, ABI callback failure, unavailable executor, Host fuse. |

These states must not share one `failClosed` or `Truncated` decision bit.
Operational failures retain their separate CPA-aware lifecycle policy.

## Mode disposition

### Complete inspection

| Mode | Safe text | Audit classification | Block classification |
|---|---|---|---|
| `off` | allow | allow | allow |
| `observe` | allow | observe | observe |
| `audit` | allow | audit | audit |
| `balanced` | allow | audit | local block |
| `strict` | allow or strict-policy result | audit or strict-policy result | local block |

### Incomplete inspection

| Mode | Route result | Primary decision/action |
|---|---|---|
| `off` | pass through | no persistence requirement |
| `observe` | pass through | observe/counter |
| `audit` | pass through | `audit` |
| `balanced` | pass through | `audit`, `allow_due_to_incomplete_inspection` |
| `strict` | local self-route | `block` |

Incomplete inspection takes precedence over any classification derived from a
prefix. In particular:

1. `balanced` never blocks from partially extracted text.
2. Incomplete requests do not update subject risk from a partial score.
3. `strict` may block the incomplete request without depending on its partial
   classification.
4. One request produces at most one primary incomplete-inspection audit event.

### Opaque media

The second-round validation configuration uses:

```yaml
opaque_media_policy: audit
```

Opaque media does not make an otherwise complete text inspection incomplete.
With the audit policy, media is passed through in every mode unless complete
malicious text independently requires a block. Only bounded media kind/count
metadata may cross the privacy boundary.

## Stable incomplete reasons

The implementation exposes a bounded, deduplicated, stable-order reason set.
At minimum it distinguishes:

```text
parse_error
scan_byte_limit
json_depth_limit
json_token_limit
text_part_limit
text_part_byte_limit
multipart_boundary_limit
multipart_part_limit
multipart_header_limit
multipart_text_limit
multipart_parse_error
unsupported_media_type
raw_body_limit
rpc_body_limit
```

Raw parser errors, Content-Type parameters, multipart boundaries, field names,
filenames, URLs, request fragments, and file bytes are never persisted or
logged.

## Request dispatch

The Router uses one request entry point and parses Content-Type with
`mime.ParseMediaType`.

| Content-Type | Inspection path |
|---|---|
| `application/json` | Provider-aware bounded JSON extraction. |
| `application/*+json` | Provider-aware bounded JSON extraction. |
| missing with an obvious JSON object/array body | Bounded JSON extraction. |
| `multipart/form-data` | Bounded multipart text extraction and file/media skipping. |
| unsupported or unsafe to interpret | Incomplete inspection; never reinterpret arbitrary bytes as text. |

The guard does not reserialize or replace the payload CPA will execute. It
observes the payload supplied to the plugin and returns only a route decision.

## Multipart field policy

Known text fields include:

```text
prompt
negative_prompt
input
instructions
message
messages
text
caption
```

Known file/media fields include:

```text
image
image[]
mask
file
audio
video
```

A part is treated as file/media when any of these hold:

- `filename` or `filename*` is present;
- the field name is a known file/media field;
- Content-Type is image, audio, video, application/octet-stream, or nested
  multipart;
- Content-Disposition identifies an attachment.

Once classified as file/media, its bytes are discarded under the raw request
bound and never added to text parts, even if they are valid UTF-8 or contain
classifier keywords. Known file field names take precedence over misleading
`text/plain`; binary Content-Type takes precedence over a misleading text field
name.

## Resource boundaries

The exact constants are tested and reported with the candidate. The design has
independent limits for:

| Resource | Required behavior |
|---|---|
| ABI/RPC request | Hard bounded by the native callback copy limit. |
| Raw body observed | Hard limit independent of text budget. |
| JSON semantic text | Charged to `max_scan_bytes`. |
| JSON nesting | Charged to `max_json_depth`. |
| JSON tokens/nodes | Fixed hard bound. |
| Text parts | Charged to `max_text_parts`. |
| Single text part | Fixed bounded chunk/field limit. |
| Multipart boundary | Fixed length bound; quoted legal boundaries supported. |
| Multipart parts | Fixed maximum count. |
| Part headers | Fixed header count and aggregate byte bounds. |
| Multipart text | Per-field and aggregate text limits. |
| File/media bytes | Skipped under the raw body bound; never charged to text. |

Reaching a bound sets an incomplete reason, does not panic, does not create a
temporary file, and does not retain the original body after the request call.

## Text and raw byte accounting

`RawBytesObserved` is bounded resource telemetry. `TextBytesScanned` counts
only text admitted to local text inspection. Uploaded media/file bytes, media
Base64, data URLs, remote URLs, filenames, MIME parameters, and boundaries do
not increase `TextBytesScanned`.

## Audit and counters

Incomplete inspection uses a canonical category derived from the stable reason
set. `balanced` records `action=audit`; `strict` records `action=block`.
Persistence may be disabled or degraded without changing the route decision,
while counters/health remain observable.

The audit schema must never store:

- raw prompt or request body;
- file or media bytes/Base64;
- raw URL or filename;
- Authorization, API key, cookie, OAuth token, or multipart boundary;
- raw parser error text.

## CPA transformation boundary

The plugin may receive CPA's execution payload after an endpoint handler has
already parsed or transformed ingress data. Therefore allow-path transparency
is tested as follows:

```text
same client input + same CPA configuration
guard enabled upstream payload/header hash
equals
guard disabled/control upstream payload/header hash
```

The evidence report must identify whether each endpoint exposes original
ingress bytes or CPA-transformed execution bytes to the plugin. A CPA
prevalidation 400/404 is `HOST_PREVALIDATION`, not a guard pass.

## Evidence labels

All results use one of:

```text
SOURCE REVIEW
UNIT TEST
HOST FIXTURE
REAL CPA ISOLATED HOST
GITHUB CI
LEO INDEPENDENT RERUN
```

No result is labelled `LEO PASS` before Leo performs the independent rerun.
No production deployment, real provider/account-pool call, release tag, or
GitHub Release is authorized by this contract.
