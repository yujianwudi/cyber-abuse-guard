# CPA Cyber Abuse Guard

Cyber Abuse Guard is a local, native security plugin for
[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) (CPA). It inspects
model requests before provider resolution and auth scheduling, blocks clearly
malicious operational cyber-abuse requests locally, and preserves legitimate
defensive research, remediation, CTF/lab, and authorized-testing workflows.

Plugin version `0.1.1` targets CPA `v7.2.67`, commit
`2075f77c8ebe9ec872759965661936fb1ac2931f`, Linux amd64, C ABI/RPC schema v1.
The published binary is compatible with the official Debian Bookworm CPA image,
requires glibc 2.34 or newer, and does not support musl/Alpine hosts.

> This plugin reduces risk. It cannot guarantee that an upstream account will
> never receive a policy warning, suspension, or deactivation. Upstream
> providers continue to apply their own independent policies.

## Security model

The plugin registers a CPA `ModelRouter` and a local executor. Safe requests
return `Handled: false` and continue through CPA unchanged. A blocked request
returns `Handled: true`, `TargetKind: self`; the local executor rejects it with
HTTP 403 and never calls a provider, host HTTP callback, or host model callback.

The classifier requires combinations of harmful intent, a dangerous object or
impact, and operational/target/evasion/scale evidence. It is not a one-keyword
blacklist. Bilingual ruleset `1.0.1` is embedded into the `.so`; the default
runtime does not send prompts to an auxiliary classifier or third party.
Requests the plugin allows still follow CPA's configured upstream path.

The plugin does **not**:

- rewrite client identity, model names, system prompts, or safety declarations;
- disguise malicious intent as education or research;
- read CPA auth/OAuth files;
- execute shell commands or user code;
- upload prompts, tokens, cookies, or API keys to an additional classifier or
  third party;
- replace upstream safety systems.

See [the design](docs/DESIGN.md), [threat model](docs/THREAT_MODEL.md), and
[known limitations](docs/LIMITATIONS.md). Future work is tracked in
[next-version recommendations](docs/NEXT_VERSION.md).
Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

Recorded acceptance evidence is available in the [test report](docs/reports/TEST_REPORT.md),
[performance report](docs/reports/PERFORMANCE.md), [corpus report](docs/reports/CORPUS_REPORT.md),
and [CPA v7.2.67 integration report](docs/reports/CPA_INTEGRATION.md). The final
Balanced corpus measured 0.00% false positives (0/142) and 100.00% malicious
recall (154/154); 10k local decisions measured P95 53.809 microseconds on the
documented test host.

## Build and test

Prerequisites: Linux amd64 with glibc 2.34 or newer, Go 1.26.0, a C compiler,
`make`, `file`, `zip`, `unzip`, and GNU `sha256sum`. Go and CPA must both be
built with cgo enabled for native plugin loading; musl/Alpine is unsupported.
If Go 1.26 is not on `PATH`, pass its executable explicitly, for example
`GO=/opt/go1.26/bin/go make test`.

```bash
make test
make race
make fuzz-smoke
make build-linux-amd64
make integration-test
make release
```

The release command writes:

```text
dist/cyber-abuse-guard-v0.1.1.so
dist/cyber-abuse-guard-v0.1.1.so.sha256
dist/cyber-abuse-guard_0.1.1_linux_amd64.zip
dist/checksums.txt
```

`make release` runs the pinned real-CPA integration suite before packaging.
`make verify-release` also rejects a binary whose imported glibc symbol version
is newer than `GLIBC_2.34`.

On Windows, run the commands inside an amd64 Linux WSL distribution. A Docker
test image is also provided:

```bash
docker build -f Dockerfile.test -t cyber-abuse-guard-test .
docker run --rm cyber-abuse-guard-test
```

## Install in Docker CPA

1. Verify the checksum:

   ```bash
   sha256sum -c cyber-abuse-guard-v0.1.1.so.sha256
   ```

2. Copy the library to the platform-specific plugin directory:

   ```bash
   mkdir -p ./plugins/linux/amd64
   install -m 0755 cyber-abuse-guard-v0.1.1.so \
     ./plugins/linux/amd64/cyber-abuse-guard-v0.1.1.so
   mkdir -p ./plugin-data/cyber-abuse-guard
   chmod 0700 ./plugin-data/cyber-abuse-guard
   ```

3. Mount both code and data:

   ```yaml
   services:
     cli-proxy-api:
       volumes:
         - ./plugins:/CLIProxyAPI/plugins:ro
         - ./plugin-data:/root/.cli-proxy-api/plugins
       environment:
         CYBER_ABUSE_GUARD_HMAC_KEY: ${CYBER_ABUSE_GUARD_HMAC_KEY}
   ```

4. Add [the example configuration](config.example.yaml) below
   `plugins.configs.cyber-abuse-guard`. Start with `mode: audit`, keep
   `subject_control.max_subjects: 10000`, verify decisions locally, and only
   then switch to `balanced`. Disable the obsolete identity-rewrite filter
   after verifying this plugin:

   ```yaml
   antigravity-coding-filter:
     enabled: false
   ```

5. Restart CPA and check its logs and management API:

   ```bash
   docker compose restart cli-proxy-api
   docker compose logs cli-proxy-api | grep -E 'plugin (loaded|registered)'
   curl -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
     http://127.0.0.1:8317/v0/management/plugins/cyber-abuse-guard/status
   ```

Detailed installation, upgrade, verification, and rollback commands are in
[docs/INSTALL_DOCKER.md](docs/INSTALL_DOCKER.md).

## Configuration

Production defaults use `mode: balanced`, a 256 KiB scan budget, a 60-point
block threshold, a 10,000-entry subject-state cap, conservative rolling subject
risk, and a 30-day audit retention. At capacity, the oldest non-manual risk
entry is evicted; manual blocks are protected, and a new risky subject fails
closed if no entry can be evicted. YAML keys are documented in
[config.example.yaml](config.example.yaml).

Modes:

| Mode | Behavior |
|---|---|
| `off` | No extraction, classification, event persistence, or blocking. |
| `observe` | In-memory aggregate statistics only; never blocks or persists per-request events. |
| `audit` | Minimal event persistence; never blocks. |
| `balanced` | Blocks clear operational abuse at the configured balanced threshold. |
| `strict` | Blocks at the audit threshold; v0.1.1 does not implement a challenge flow. |

`CYBER_ABUSE_GUARD_HMAC_KEY` should contain at least 32 bytes of high-entropy
secret material. The plugin never persists its plaintext value. If no stable
key is available, subject hashes use an ephemeral process key and status reports
degraded correlation across restarts.

The `classifier` and `trusted_proxy` activation switches are reserved for a
future CPA/plug-in revision. v0.1.1 rejects either switch when set to `true`
rather than silently providing incomplete protection.

## Management API

CPA authenticates these routes with its Management Key before invoking the
plugin:

```text
GET    /v0/management/plugins/cyber-abuse-guard/status
GET    /v0/management/plugins/cyber-abuse-guard/events
GET    /v0/management/plugins/cyber-abuse-guard/stats
POST   /v0/management/plugins/cyber-abuse-guard/test
POST   /v0/management/plugins/cyber-abuse-guard/subjects/unblock
DELETE /v0/management/plugins/cyber-abuse-guard/events
```

The status response distinguishes process lifetime (`started_at`) from the
latest successful configuration (`configured_at`). Compatible hot reload keeps
`started_at` unchanged. Its `subject_control` capacity snapshot contains
`subjects`, `max_subjects`, `manual_blocked`, `evicted`, and
`rejected_capacity`.

Unblock request body:

```json
{"subject_hash":"hmac-sha256:..."}
```

CPA v7.2.67 supports exact plugin management routes only, so the task-book
shape with `{hash}` in the URL is represented by this fixed route and JSON
body. No unauthenticated resource page is registered.

## Privacy

Audit events may contain timestamp, action, mode, coarse category, numeric
score, stable rule IDs, request SHA-256, subject HMAC, model, source format,
stream flag, scan byte count, and latency. They never contain the prompt,
messages, authorization header, plaintext key/IP, cookie, OAuth token, uploaded
code, or upstream account identity. A request rejected by the native no-copy
RPC size guard records only a minimal `scan_limit` event; it does not invent a
request hash, model, source format, or scanned-byte count that was unavailable.

## Rollback

Set `plugins.configs.cyber-abuse-guard.enabled: false`, restart CPA, confirm
`effective_enabled: false`, and then remove the `.so` if desired. Removing the
audit database is optional and must be an explicit operator decision. CPA does
not need to be reinstalled.
