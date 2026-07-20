# Blocked-request review capture

The raw-capture facility exists only for operator review of false-positive
blocks. It is not general request logging and it does not preserve an exact,
unbounded copy of every prompt.

> [!WARNING]
> Captures contain user-supplied request content. Secret redaction is
> best-effort and cannot recognize every custom, encoded, or fragmented secret.
> Restrict the audit data directory to the CPA service account, protect the CPA
> Management Key, keep the management listener private, and use transport
> encryption whenever the query crosses a host boundary.

## Safety contract

- Default: disabled. If a prior audit database or WAL/SHM artifact exists,
  startup publishes a disabled-capture runtime only after that storage opens
  and the retained previews are purged. A purge/open failure rejects the new
  runtime instead of hiding old review text. A hot reconfiguration to disabled
  is accepted only after the old audit queue is drained, every preview is
  deleted, and the WAL truncation succeeds; otherwise the previous runtime
  remains active and the reconfiguration is reported as failed.
- Scope: only requests whose final Guard disposition prevents upstream routing
  (`block`, including subject `cooldown`).
  `only_blocked: false` is rejected.
- Redaction: mandatory. `redact_secrets: false` is rejected.
- Processing: common secret forms are replaced first; the resulting preview is
  then truncated on a valid UTF-8 boundary.
- Per-record bound: `max_bytes`, default 8192, allowed range 1..1048576.
- Lifetime: `ttl_hours`, default 72 and allowed range 1..87600. When capture is
  enabled it may not exceed `audit.retention_days * 24`.
- Storage: a separate audit-store record correlated to the ordinary block
  event. Ordinary audit events remain metadata-only.
- Legacy switch: `audit.log_original_text: true` remains invalid. There is no
  unrestricted full-request logging mode.

The preview is intended to answer "why was this request blocked?" while
placing a hard bound on retained content. It may be truncated and may contain
replacement markers, so it is not a byte-exact legal or billing record.

## Configuration

```yaml
audit:
  enabled: true
  retention_days: 30
  log_request_hash: true
  log_subject_hash: true
  log_original_text: false
  raw_capture:
    enabled: true
    only_blocked: true
    redact_secrets: true
    max_bytes: 8192
    ttl_hours: 72
```

Raw capture requires `audit.enabled: true`. A configuration outside the safety
contract is rejected rather than silently weakened.

## Authenticated query

CPA's management middleware verifies the configured Management Key before the
plugin handler runs. The plugin additionally rejects a callback with no
management credential header.

```bash
curl -H "X-Management-Key: $CPA_MANAGEMENT_KEY" \
  "http://127.0.0.1:8317/v0/management/plugins/cyber-abuse-guard/raw-captures?limit=20"
```

Supported query parameters are:

| Parameter | Meaning |
|---|---|
| `event_id` | Exact audit event UUID |
| `request_hash` | Exact `sha256:` request-correlation value from `/events` |
| `limit` | 1..100; defaults to 20 |

Parameters may be combined. Unknown, duplicate, malformed, or oversized
parameters return HTTP 400. A request body is not accepted.

Example correlation flow:

```bash
curl -H "X-Management-Key: $CPA_MANAGEMENT_KEY" \
  "http://127.0.0.1:8317/v0/management/plugins/cyber-abuse-guard/events?action=block&limit=20"

curl -H "X-Management-Key: $CPA_MANAGEMENT_KEY" \
  "http://127.0.0.1:8317/v0/management/plugins/cyber-abuse-guard/raw-captures?event_id=01234567-89ab-4def-8123-456789abcdef"
```

The response is JSON and is always sent with `Cache-Control: no-store`:

```json
{
  "enabled": true,
  "requested_limit": 20,
  "returned_count": 1,
  "response_truncated": false,
  "preview_bytes": 55,
  "encoded_preview_bytes": 63,
  "response_preview_budget_bytes": 8388608,
  "captures": [
    {
      "id": "capture-id",
      "event_id": "01234567-89ab-4def-8123-456789abcdef",
      "timestamp": "2026-07-21T00:00:00Z",
      "request_hash": "sha256:...",
      "subject_hash": "hmac-sha256:...",
      "action": "block",
      "decision": "block_malicious_text",
      "truncated": false,
      "redacted": true,
      "raw_preview": "{\"messages\":[{\"content\":\"...\"}]}",
      "raw_sha256": "sha256:..."
    }
  ]
}
```

The audit scanner enforces a fixed cumulative 8 MiB raw-preview budget and
scans at most one additional sentinel row, independent of both the accepted
query limit and the current `max_bytes` setting. This remains safe after a
configuration downgrade when the database still contains older 1 MiB rows: a
`limit=100` query cannot first materialize roughly 100 MiB of previews. The
management encoder separately enforces an 8 MiB budget over the JSON-encoded
`raw_preview` strings. The maximum single preview still fits that encoded
budget, so at least the newest matching record can be returned.

`returned_count` is the number of records in `captures`.
`response_truncated: true` means the requested result may contain more records
than were returned under the response budget or bounded fetch. `preview_bytes`
counts the returned UTF-8 preview bytes; `encoded_preview_bytes` counts their
JSON-encoded content bytes and is the value compared with
`response_preview_budget_bytes`. Callers must not assume that
`returned_count == requested_limit`.

`subject_hash` can be empty when subject correlation is unavailable or
disabled. `redacted` reports whether a replacement was actually made;
mandatory redaction can therefore be active while this field is `false` for a
record containing no recognized secret. `truncated` reports whether content
exceeded `max_bytes` after redaction. `raw_sha256` is the direct SHA-256 of the
complete original request bytes before redaction and truncation; it supports
integrity checks and deduplication but is not a substitute for the
domain-separated `request_hash` audit correlation value.

Expired captures are removed when the audit database opens and by the existing
periodic cleanup path (normally hourly). Deleting an ordinary audit event also
deletes its associated capture through the database relationship. TTL is a
retention ceiling evaluated by cleanup, not a promise that a row disappears at
the exact expiry nanosecond. SQLite `secure_delete` is enabled for every schema
v4 audit connection, including when capture is currently disabled. Disabling
capture deletes all preview rows and requests a truncating WAL checkpoint, but
these controls are not a forensic guarantee against storage-controller caches,
filesystem snapshots, external backups, or other copies.

If the entire `audit` subsystem is disabled before process startup, the plugin
does not open or mutate the configured audit database. Operators switching from
a prior capture-enabled deployment directly to `audit.enabled: false` across a
restart must securely remove or separately purge the old database and its
WAL/SHM files. A live reconfiguration from audit enabled to audit disabled does
perform the purge gate before the new runtime is published.

When capture is disabled and either audit is intentionally disabled or its
enabled store completed the startup/transition purge gate, the response is:

```json
{
  "enabled": false,
  "requested_limit": 20,
  "returned_count": 0,
  "response_truncated": false,
  "preview_bytes": 0,
  "encoded_preview_bytes": 0,
  "response_preview_budget_bytes": 8388608,
  "captures": []
}
```

If `audit.enabled: true` but the audit database never opened and no prior audit
artifact was present to trigger a hard startup rejection, this endpoint returns
HTTP 503 with `audit_unavailable`; it does not present an authoritative empty
capture list. This preserves enforcement availability without concealing an
unknown storage state.

No fallback reads a CPA request log, ordinary audit event, or in-memory request
body. Consequently, enabling this setting cannot recover requests that were
blocked before it was enabled.

## Operational review

For each reviewed block, compare `event_id` and `request_hash` with `/events`,
then record the disposition outside the capture database using an access-
controlled review system. Do not paste captured content into public issues,
GitHub Actions logs, chat rooms, or classifier test fixtures. If a capture
reveals a false positive, reduce it with a synthetic, repository-neutral
regression rather than copying customer text into the source tree.
