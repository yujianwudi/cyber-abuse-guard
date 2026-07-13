# CPA Cyber Abuse Guard

CPA Cyber Abuse Guard is a local native security plugin for
[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) (CPA). It inspects
model requests before provider resolution and authentication scheduling, and
locally rejects clearly malicious operational cyber-abuse requests while
preserving legitimate defensive analysis, remediation, incident response,
CTF/lab, and authorized-testing workflows.

The v0.1.2 source targets CPA `v7.2.67` at commit
`2075f77c8ebe9ec872759965661936fb1ac2931f`, Linux amd64, glibc 2.34 or newer,
and CPA C ABI/RPC schema v1. musl/Alpine is not supported.

The repository root `go.mod` and the current development/runtime baseline remain
on CPA `v7.2.67`. An isolated source-contract module under
`integration/pluginstorecontract` pins CPA `v7.2.72` only so the official
`pluginstore.InstallArchive` implementation and official host-routing tests can
verify archive naming/layout/install behavior plus Router ordering and fallback
with opaque synthetic bytes. These source contracts do not load a plugin and
are not evidence that this project is compatible with, deployable on, or tested
against a CPA `v7.2.72` host.

> **Release status:** v0.1.2 is a **blocked candidate**, not a production
> release. Blind sets v1-v8 are retired or consumed failures; v9 is frozen as
> `CONSUMED / METHODOLOGY INVALID / FAIL` because the exact taxonomy-enum
> validator was missing. The first and only methodologically valid v10 run also
> failed: benign FP 28/320, policy blocked 49/320, and exact 33/320. v10 is
> consumed and `make holdout-test` now rejects a rerun. Do not create a
> `v0.1.2` tag or GitHub Release, and do not deploy this candidate. A future
> release attempt requires a new implementation and a newly, independently
> authored unseen set; it must not reuse v10.
>
> **Post-v10 development note:** the current development tree contains audit-driven
> hardening and dependency updates made after the recorded v10 implementation
> snapshot. These changes have engineering-test evidence only and do not
> inherit any v10 approval. A future candidate still requires a new independent
> unseen set.
>
> **Prompt-injection hardening status:** the current development tree adds the
> deterministic `META-OVERRIDE-001` control-plane overlay and bounded
> extraction fixes for ambiguous provider schemas, nested tool JSON, split
> encoded blocks, isolated-character fragmentation, and malicious safety-policy
> inversion. This is developer-visible engineering work only. **Server sandbox
> validation is PENDING / NOT RUN.** It does not change the consumed v10 failure
> or authorize deployment.

> **Risk statement:** this plugin can reduce the number of risky requests that
> reach upstream accounts. It cannot guarantee that any account will never be
> warned, suspended, rate-limited, or deactivated. Upstream providers continue
> to apply independent policies.

## Security path

The plugin registers a CPA `ModelRouter` and a local executor:

```text
downstream request
  -> CPA ModelRouter
    -> allowed: Handled=false; original request continues unchanged
    -> blocked: Handled=true, TargetKind=self
       -> execute / execute_stream / count_tokens return policy HTTP 403
       -> http_request remains unsupported and returns HTTP 405
       -> provider resolution, auth selection, usage, and upstream are skipped
```

The implementation never rewrites the requested model, client identity,
system prompt, or safety declarations. It does not disguise malicious intent,
read CPA auth/OAuth files, execute user code, or send request content to an
auxiliary public classifier. Allowed requests still follow CPA's configured
upstream path.

## Prompt-injection hardening (post-v10 development)

`META-OVERRIDE-001` combines independent bilingual evidence families for
instruction-hierarchy replacement, refusal suppression, unrestricted/developer
persona claims, direct-completion demands, sandbox/benchmark/placeholder
laundering, forced output or skipped authorization checks, explicit negative
authorization, and system/developer-prompt or hidden-reasoning disclosure. It
is not a lone-keyword blocklist.

When ordinary cyber-abuse evidence exists, the overlay raises that candidate
without replacing its original taxonomy. A strong standalone control-plane
attack is reported under the existing `defense_evasion` category. Prompt text
claiming CTF, lab, fictional scope, or authorization does not reduce this
overlay; quoted defensive analysis can reduce it only when an affirmative
analysis/mitigation purpose and a non-execution intent are present.

Tool provenance is inspected independently, supported provider bodies fall
back to a bounded untrusted walk when role proof fails, JSON-looking strings
inside tool payloads are recursively inspected within existing budgets, and
joined content blocks plus ordered tool-payload/output string fields are decoded
again. The classifier may combine linked
adjacent segments carried in one request, but it has no semantic memory across
independent API calls.

The embedded deterministic ruleset is `1.0.7`; its canonical embedded SHA-256
is `7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134`.
It requires combinations of
harmful intent, a dangerous object or impact, and operational, target, evasion,
or scale evidence. A lone keyword is not sufficient. Assertions such as
“education”, “CTF”, or “authorized” do not wash deployment-oriented credential
theft, phishing collection, ransomware, or data exfiltration.

The ruleset version and hash above identify the embedded YAML cyber-abuse
assets only. The complete post-v10 classifier policy — including
`META-OVERRIDE-001`, matcher/normalizer changes, role handling, and extraction
semantics — is not represented by that manifest. The containing Git/build
commit plus the YAML ruleset identity are required to identify this development
behavior. A release-eligible successor must add a separate classifier-policy
version/hash or bind all policy behavior to verified build provenance.

## CPA host fail-open boundary

The root development baseline is CPA v7.2.67. At the host boundary, CPA can
continue other Routers or native routing when this plugin is not loaded, fails
registration, is fused, returns a Router error, panics before a valid handled
result is accepted, returns an invalid/empty target, or self-routes to an
executor that is not ready. A higher-priority Router that handles the request
first also prevents this guard from seeing it. Routers at the same priority are
ordered by plugin ID ascending. The plugin reduces known in-process failure
risk with bounded parsing, panic recovery, mode-aware local handling for known
oversized RPCs, atomic reconfiguration, and health counters, but ABI v1 cannot
turn these host conditions into global fail-closed behavior.

Production operators must monitor `loaded`, `enforcement_ready`,
`router_errors`, `panics_recovered`, `audit_degraded`, `hmac_stable`,
`persistence_degraded`, `last_reconfigure_error`, and the build/ruleset
identity. Use the read-only watchdog:

`enforcement_ready` is only the plugin's internal runtime/readiness state. It
does not prove that CPA loaded and registered the binary, that the host has not
fused it, that Router ordering is favorable, or that CPA accepted the self
executor as ready for a particular request format.

```bash
CPA_MANAGEMENT_KEY_FILE=/run/secrets/cpa-management.key \
EXPECTED_MODE=balanced \
./scripts/check-production-health.sh
```

The watchdog accepts only a loopback CPA URL. It validates runtime/build/rules
identity and health, rejects router-error or recovered-panic deltas, reports
unknown source formats, and can enforce their probe-window delta with
`MAX_NEW_UNKNOWN_SOURCE_FORMATS`. Its benign and malicious probes
are built into the plugin and evaluated through authenticated management
routes; it does not send the probe text to `/v1`, an auth selector, a provider,
or an upstream account. It never changes CPA configuration, deletes an account,
or removes another plugin.

CPA ABI v1 also cannot enumerate router ordering or inspect the plugin
directory. Operators must manually confirm that no higher-priority router can
handle requests first, that `priority: 300` is effective, that the obsolete
`antigravity-coding-filter` is disabled, and that only one version of this
plugin `.so` is present. At equal priority, compare plugin IDs explicitly;
lexicographically smaller IDs execute first.

## Modes and staged rollout

| Mode | Request behavior | Event behavior |
|---|---|---|
| `off` | No extraction, classification, or blocking | No event persistence |
| `observe` | Classifies but never blocks | In-memory aggregates only |
| `audit` | Classifies but never blocks | Privacy-minimal events in SQLite |
| `balanced` | Blocks clear operational abuse at the balanced threshold | Minimal events and subject controls |
| `strict` | Blocks at the lower audit threshold | Most conservative; no challenge flow |

New deployments must use three stages:

1. **Observe, 24–48 hours.** Check classification counts, latency, CPU/memory,
   router errors, recovered panics, and HMAC/audit health without persisting
   request-level events.
2. **Audit, 24–48 hours.** Review privacy-minimal would-block events. Record
   every threshold or policy change. Do not send dangerous test traffic to a
   real provider.
3. **Balanced.** Check blocks, legitimate-user reports, CPA 5xx responses,
   audit health, plugin discovery, and watchdog deltas at least hourly during
   the initial window. Keep the disable rollback ready.

Do not deploy directly from absent/off to `strict`. Full rollout, promotion,
and abort criteria are in [Docker installation and operations](docs/INSTALL_DOCKER.md).

## Privacy

Raw prompts, messages, tool payloads, authorization headers, plaintext API
keys/IP addresses, cookies, OAuth tokens, uploaded code, and upstream account
identity are never written to the audit database or returned by management
APIs. `audit.log_original_text: true` is rejected; there is no debug override.

Stored audit fields are limited to timestamps, disposition, mode, coarse
category, score, stable rule IDs, request SHA-256, subject HMAC, a
domain-separated requested-model digest, the fixed canonical source enum
(`openai`, `openai-response`, `claude`, `gemini`, or `unknown`), stream flag,
scanned byte count, and latency. Subject persistence,
when enabled, stores only HMAC subject IDs and bounded risk/cooldown/manual-
block state. See [the privacy evidence plan](docs/reports/PRIVACY.md).

## Encoded text and opaque media

Text decoding is deliberately bounded: at most two layers and eight unique
variants, with a 128 KiB encoded-source cap and a 64 KiB aggregate decoded-text
cap. Supported textual envelopes are URL percent encoding, HTML entities,
inspectable Base64 text, textual data URLs, JSON escapes, and bounded nested
tool JSON. The plugin performs no decompression, archive expansion, or network
fetch. A complete but unrecognized/high-entropy string is still scanned as
literal text; it is not automatically blocked merely for looking encoded.
An incomplete recognized envelope sets truncation, so Balanced and Strict fail
closed. Encrypted or novel encodings remain a documented detection limit.

Image, audio, video, and document-attachment bytes are opaque. HTTPS media URLs
are never fetched.
`opaque_media_policy` may be `block`, `audit`, or `allow`; if omitted, the
mode-aware defaults are:

| Mode | Effective opaque-media policy |
|---|---|
| `off` | `allow` |
| `observe`, `audit`, `balanced` | `audit` |
| `strict` | `block` |

`audit` records only an opaque-media disposition, never media content or URL
contents. `allow` means the plugin cannot assess the opaque payload; it is not
a safety approval.

## HMAC identity and optional subject persistence

Use a stable secret file in production. Generate it without printing the key:

```bash
sudo install -d -m 0700 -o root -g root /opt/cliproxyapi/secrets
sudo ./scripts/generate-hmac-key.sh \
  /opt/cliproxyapi/secrets/cyber-abuse-guard-hmac.key
sudo chown root:root \
  /opt/cliproxyapi/secrets/cyber-abuse-guard-hmac.key
```

The generator requires a current-user-owned output directory with no symlinked
path component and no group/world write bit. It refuses overwrite, uses a
private temporary file, syncs the secret, publishes the mode-0600 regular file
with a no-overwrite identity check, and syncs the containing directory.

Mount that regular mode-0600 file read-only and set
`CYBER_ABUSE_GUARD_HMAC_KEY_FILE`. The key must never be committed, included in
an image, release archive, log, or status response. With no stable key,
restart-to-restart subject correlation is degraded.

`subject_control.persistence` is optional and defaults to `false`. When false,
risk, cooldown, and manual-block state is process-local and resets at CPA
restart. When true, audit storage must also be enabled, `max_subjects` cannot
exceed 10,000, and a stable HMAC key is required. State restoration applies
expiry, decay, and capacity limits. An HMAC key mismatch is explicit and
blocks persistence writes so the old snapshot is not silently replaced;
in-memory request enforcement continues.

v0.1.2 does not implement dual-key rotation. The documented rotation design is
to introduce an active key plus one read-only previous key, expose only their
fingerprints, restore old HMAC state into a bounded transition map, write only
active-key IDs, define a finite overlap deadline, and require an explicit
operator finalize step. Until that state machine exists, keep the current key
for ordinary upgrades. See [the design](docs/DESIGN.md).

## SQLite migration

The audit database has versioned `schema_version` and `migration_history`
tables. Schema v2 adds optional subject-state tables. Startup validates exact
table columns, order, types, constraints, indexes, the singleton schema row,
and the complete migration sequence. Migration is atomic. A
v0.1.1 database is detected as schema v1, optionally backed up with SQLite
`VACUUM INTO`, and migrated without rewriting event content. Backups are
read-only and bounded by `audit.max_migration_backups` (default 3).

Do not delete the old database or backup until the upgraded plugin has passed
local health checks. Downgrading a schema-v2 database to v0.1.1 is not claimed
to be supported; use the pre-migration backup for a binary-and-database
rollback.

## Build, test, and release

Targeted source tests can establish development regression evidence only. For
the current prompt-injection diff, no real-CPA integration, native loading,
deployment, formal Holdout, release verification, or release packaging was
performed locally; server sandbox validation remains pending.

Phase 0 adds source-level CPA store archive checks and aligns the local executor
method contract. It does not change the root CPA dependency from v7.2.67 and it
does not supply current-diff evidence for four-protocol HTTP behavior or zero
Auth Selector, Usage, Provider, and Mock Upstream calls. Those assertions remain
pending for the owner-operated server sandbox.
See [the Phase 0 CPA contract report](docs/reports/PHASE0_CPA_CONTRACT.md) for
the exact source-level evidence and remaining server matrix.

The release toolchain is pinned to Go `1.26.4`. Use Linux amd64 with cgo, GCC,
GNU binutils, `file`, `zip`, `unzip`, `sha256sum`, `jq`, CycloneDX GoMod
`v1.9.0`, and `govulncheck v1.6.0`.

The v9/v10 historical-provenance tests require a full Git clone containing the
recorded commit. A source `tar.gz` intentionally excludes `.git`; it is suitable
for source inspection and ordinary builds, but cannot satisfy or claim that
historical integrity gate. Run the complete test matrix from a full-history
clone.

```bash
make format-check git-diff-check module-verify
make test race vet fuzz-smoke corpus-regression
make benchmark integration-test
make vulncheck

# Historical-state check only: this intentionally fails because v10 is consumed.
make holdout-test
```

`make formal-release` is the complete local release entry point, but it must
not be run for the current blocked candidate. It is
intentionally blocked unless the worktree is clean, the source version matches,
and the real annotated tag `v0.1.2` points at `HEAD`. It runs the release gates,
strict verification and fault injection, two-clone reproducibility, source
packaging, and final evidence generation. Development builds may use
`ALLOW_DIRTY_BUILD=1`; their filenames and linked metadata include `-dirty` and
they are not formal release artifacts. Ordinary branch CI uses
`REPRODUCIBILITY_MODE=development`: both commit-bound builds stay in temporary
clones, use `-dirty` names, and never populate the repository `dist/` directory.

The formal release set is expected to include:

```text
dist/cyber-abuse-guard-v0.1.2.so
dist/cyber-abuse-guard-v0.1.2.so.sha256
dist/cyber-abuse-guard_0.1.2_linux_amd64.zip
dist/cyber-abuse-guard-v0.1.2-audit-bundle.zip
dist/build-metadata.json
dist/checksums.txt
dist/ruleset-manifest.json
dist/ruleset.sha256
dist/sbom.cdx.json
dist/release-test-summary.txt
dist/release-test-summary.txt.sha256
dist/release-evidence-final.md
dist/release-evidence-final.md.sha256
dist/cyber-abuse-guard-v0.1.2-source.tar.gz
dist/cyber-abuse-guard-v0.1.2-source.tar.gz.sha256
```

The two ZIP files have different contracts:

- `cyber-abuse-guard_<version>_linux_amd64.zip` is the CPA store installation
  ZIP. Its root contains exactly one regular executable `.so` and no nested
  documentation or second shared object.
- `cyber-abuse-guard-v<version>-audit-bundle.zip` is the separate documentation,
  metadata, SBOM, verification, and operator-material bundle. It is not a CPA
  store installation archive.

GitHub Repository/Release, source `tar.gz`, the CPA store ZIP, and the audit
bundle are the supported distribution channels. RAR is not a formal source or
binary release format.

The verifier treats a missing command, checksum mismatch, wrong ELF target,
missing ABI symbol, glibc version above 2.34, build identity mismatch, ruleset
mismatch, SBOM mismatch, unexpected ZIP entry, or incorrect file mode as a hard
non-zero failure. Formal reproducibility accepts only the real annotated release
tag and compares the published `.so`, store ZIP, audit bundle, and SBOM with two
clean clones of the same commit; it never synthesizes a tag or backfills missing
root artifacts.

Historical project-regression metrics are not a blind benchmark. v1-v8 are
retired or consumed failures, v9 is a consumed methodology-invalid failure,
and methodologically valid v10 is a consumed release-gate failure. Their frozen
aggregate reports are under `docs/reports/`; the current decision is summarized
in [RELEASE_EVIDENCE.md](docs/reports/RELEASE_EVIDENCE.md). None may be rerun or
used for row-specific tuning.

## Install, rollback, and cleanup

Use [docs/INSTALL_DOCKER.md](docs/INSTALL_DOCKER.md) for checksum verification,
single-version plugin installation, secret-file mounting, schema migration,
Observe → Audit → Balanced rollout, watchdog operation, rollback to a previous
`.so`, database restore, and explicit full cleanup.

The shortest safe disable rollback is:

```yaml
plugins:
  configs:
    cyber-abuse-guard:
      enabled: false
```

```bash
docker compose restart cli-proxy-api
```

Verify that the plugin is not loaded/registered, CPA is healthy, `/v1/models`
without a key still returns 401, New API can reach CPA, other plugins remain
normal, and auth-file counts are unchanged. Audit data and HMAC secrets are
retained unless the operator explicitly chooses to delete them.

## Management API

CPA protects the following exact routes with its Management Key before the
plugin handler runs:

```text
GET    /v0/management/plugins/cyber-abuse-guard/status
GET    /v0/management/plugins/cyber-abuse-guard/events
GET    /v0/management/plugins/cyber-abuse-guard/stats
POST   /v0/management/plugins/cyber-abuse-guard/test
POST   /v0/management/plugins/cyber-abuse-guard/health/probe
POST   /v0/management/plugins/cyber-abuse-guard/subjects/unblock
DELETE /v0/management/plugins/cyber-abuse-guard/events
```

CPA v7.2.67 plugin routes cannot safely use dynamic path parameters, so unblock
uses the fixed route and a bounded JSON body:

```json
{"subject_hash":"hmac-sha256:<64 lowercase hex characters>"}
```

Normal downstream API keys do not authorize these routes. Responses contain no
raw prompt or plaintext credential.

CPA currently calls `io.ReadAll` in `ServeManagementHTTP` before invoking the
plugin handler. The plugin's 1 MiB management-body limit and 2 MiB RPC-envelope
limit therefore do not cap host HTTP memory consumption. A deployment-facing
reverse proxy must enforce its own request-body limit (the Docker/Nginx example
uses `client_max_body_size 1m`) and the server sandbox must prove that an
oversized request receives HTTP 413 before it reaches CPA.

See also [DESIGN.md](docs/DESIGN.md), [RULES.md](docs/RULES.md),
[LIMITATIONS.md](docs/LIMITATIONS.md), [THREAT_MODEL.md](docs/THREAT_MODEL.md),
and [SECURITY.md](SECURITY.md).
