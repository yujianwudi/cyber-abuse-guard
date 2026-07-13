# Privacy Verification Report — v0.1.2 candidate

## Status

**PRE-PROMPT-INJECTION-CHANGE BASELINE — CURRENT-DIFF END-TO-END PRIVACY NOT
RUN.** Typed canary tests previously covered audit events, SQLite files,
management responses, parse failures, oversized routes, unknown source formats,
persistence, migration, candidate packaging, SBOM, strict archive verification,
and local-only network/proxy checks. Those results belong to an earlier
development artifact and were not rerun after the current classifier/extractor
changes. Current evidence is limited to the source-level checks in
`TEST_REPORT.md`. Methodologically valid evaluation v10 is `CONSUMED / FAIL`,
so no clean `v0.1.2` release tag or production artifact may be created.

## Privacy invariants

The plugin must never persist, log, or return through management APIs:

- raw Prompt, Messages, Instructions, Tool Arguments, or uploaded code;
- `Authorization` header or plaintext downstream API key;
- Cookie, OAuth token, refresh token, session token, or provider credential;
- plaintext subject/IP or HMAC secret;
- upstream auth/account identity;
- panic values that may contain attacker-controlled text.

`audit.log_original_text` exists only as a compatibility field. `true` must
reject initial configuration and hot reconfiguration. There is no debug,
trace, emergency, or test mode that overrides this rule.

Allowed audit fields are limited to time, disposition, mode, coarse category,
score, stable rule IDs, request SHA-256, subject HMAC, a domain-separated model
digest, a fixed canonical source-format enum, stream flag, scanned byte count,
and latency. Request SHA-256 is correlation metadata, not an encryption claim.
The prompt-injection overlay emits only fixed identifiers such as
`META-OVERRIDE-001` and `META-OVERRIDE-001:hierarchy`; it never returns or
persists the matched phrase, quoted prompt, tool payload, or protected prompt
content.

Optional subject persistence stores only:

- `hmac-sha256:<digest>` subject ID;
- score and bounded hit timestamps;
- cooldown/manual-block state;
- persistence version, saved timestamp, and a one-way HMAC key fingerprint.

The persistent Go type and SQLite schema cannot represent a plaintext key.
HMAC key mismatch is explicit; old state is not silently overwritten.
Schema/type/hash validation detects structural corruption, but schema v2 has no
keyed whole-snapshot MAC. It does not authenticate completeness against a local
SQLite writer; filesystem ownership and permissions are a documented trust
boundary.

## Network privacy

The v0.1.2 classifier is local deterministic rules. `classifier.enabled: true`
is rejected. The plugin does not upload requests to another classifier,
telemetry service, webhook, or remote log.

HTTPS image/media URLs are never fetched. Image/audio/video/document-attachment
bytes are not decoded. Bounded textual decoding performs no DNS lookup, redirect, network
request, decompression, archive expansion, or document parsing.

Allowed requests still follow CPA's configured upstream path. This privacy
claim applies to the guard's additional processing; it does not claim that CPA
or the chosen provider never receives an allowed request.

## Canary test method

Use unique synthetic values that cannot appear accidentally, for example:

```text
PROMPT_CANARY_CAG_V012_<random>
APIKEY_CANARY_CAG_V012_<random>
AUTH_CANARY_CAG_V012_<random>
COOKIE_CANARY_CAG_V012_<random>
OAUTH_CANARY_CAG_V012_<random>
HMACKEY_CANARY_CAG_V012_<random>
```

Never use a real production credential. Exercise allowed, blocked, parse-error,
truncated, opaque-media, management-test, panic-recovery, audit-degraded,
migration, persistence-save/restore, and shutdown paths against a disposable
local CPA + Mock Upstream.

After clean shutdown, search the complete artifact set:

1. SQLite main DB, WAL, and SHM;
2. pre-migration database backups;
3. CPA/plugin stdout/stderr and captured logs;
4. Management Status, Events, Stats, Test, Health Probe, Unblock, and Delete
   responses;
5. panic/recovery error envelopes and host log callbacks;
6. release `.so`, ZIP, `checksums.txt`, build metadata, ruleset manifest, SBOM,
   and release-test summary;
7. temporary integration/build directories before disposal.

Representative repository test command:

```bash
go test -tags=sqlite_omit_load_extension ./internal/audit ./internal/plugin \
  -run 'Privacy|Canary|OriginalText|Secret|Persistence' -count=1 -v
```

The exact final test names and output must be captured; the pattern above is a
review command, not evidence by itself.

For raw-file inspection, stop CPA first so WAL state is stable, then use a
binary-safe search tool. Do not print the canary values in shared CI logs; emit
only filename/category and PASS/FAIL. A match is a hard release failure until
explained and removed. Hashes of the canary strings must also be chosen so the
test does not mistake the intentionally stored request SHA-256 or subject HMAC
for plaintext leakage.

## Management response review

CPA Management Key middleware is the authentication authority. The final real-
host test must prove:

- missing key: 401;
- wrong key: 401;
- normal downstream client key: 401;
- correct Management Key: success;
- response bodies contain no raw prompt, plaintext subject/key, matched
  fragment, HMAC key, auth header, cookie, OAuth token, SQL error containing
  data, or filesystem secret content.

Status may expose only `hmac_stable`, initialized/degraded flags, and aggregate
counters. Persisted subject metadata may contain a domain-separated one-way key
identity for mismatch detection. Neither surface may expose the HMAC secret or
configured Management Key.

## Secret-file controls

Production uses `CYBER_ABUSE_GUARD_HMAC_KEY_FILE` pointing to a regular
mode-0600 non-symlink file. On Linux the plugin opens with `O_NOFOLLOW`, then
validates and reads through the same descriptor. The generator creates the file
atomically and prints only success/path metadata, never secret content.

The secret is excluded from Git, Docker build context, release ZIP, SBOM, and
logs. It should normally survive binary rollback/upgrade. Deleting it is an
explicit destructive operation that breaks correlation with retained HMAC
subject IDs.

## Final evidence table

| Surface | Canary scan | Final result |
|---|---|---|
| SQLite main DB | all synthetic canaries absent | **PASS** |
| WAL and SHM | all synthetic canaries absent | **PASS** |
| Migration backups | all raw canaries absent; only permitted digests/state | **PASS** |
| CPA/plugin logs | all synthetic canaries absent | **PASS** |
| Management responses | all synthetic canaries absent | **PASS** |
| Panic/recovery output | all synthetic canaries absent | **PASS** |
| Subject persistence | plaintext key/prompt absent; typed HMAC state only | **PASS** |
| `.so` and release ZIP | secret-like paths absent; strict allowlist/modes | **PASS (candidate artifact)** |
| Build metadata/rules manifest | no secret/request text | **PASS** |
| CycloneDX SBOM | no secret/request text | **PASS** |
| Network capture | no guard-originated classifier/media fetch | **PASS** |

```text
release_commit_tag_and_plugin_sha256: NOT CREATED — RELEASE BLOCKED
privacy_test_log_sha256: candidate evidence only; no formal tagged release log
canary_values: synthetic repository-only values; no production credential used
overall_privacy_gate: PASS PRE-CHANGE BASELINE; CURRENT DIFF NOT RUN; RELEASE GATE remains FAIL
```
