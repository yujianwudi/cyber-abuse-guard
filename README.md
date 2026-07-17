# CPA Cyber Abuse Guard

[![CI](https://github.com/yujianwudi/cyber-abuse-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/yujianwudi/cyber-abuse-guard/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.26.4-00ADD8?logo=go&logoColor=white)](go.mod)
[![Platform](https://img.shields.io/badge/platform-Linux%20amd64-lightgrey)](docs/ROUND6_LIMITATIONS.md)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-BLOCKED-critical)](docs/ROUND6_DEVELOPMENT_HANDOFF.md)

**A local, deterministic, pre-routing cyber-abuse request guard for
[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) (CPA).**

English | [简体中文](README_CN.md)

> [!WARNING]
> Round 6 is a development candidate only. Its status is
> **BLOCKED / PENDING HOST AND INDEPENDENT AUDIT**. It has not been merged into
> `main`, no Round 6 release has been created, and it must not be deployed to
> production. This round accepts evidence only from Linux amd64 CI and the
> authorized Linux sandbox. Windows and macOS build or test evidence is outside
> scope.

When CPA has loaded and registered the plugin, Router ordering reaches it, and
the self-executor is ready, the Guard inspects supported model requests before
provider selection, authentication scheduling, usage accounting, and upstream
work. Request content is evaluated in process and is not sent to a public
classifier.

## Current Round 6 status

| Item | State |
|---|---|
| Development branch | `agent/round6-long-text-streaming` |
| Round 5.2 base | `main@7a416df66a79218d73214084d4bf8a733268d894`, tree `63db7b7cb14a636f5ba9ff4453be4ebeef170b68` |
| Candidate commit and tree | Must be taken from the final PR head and Linux CI `build-metadata.json`; this README does not self-claim a future identity |
| Release decision | **BLOCKED / PENDING HOST AND INDEPENDENT AUDIT** |
| Merge and release | Not merged to `main`; no Round 6 tag or Release |
| Validation platform | Linux amd64 only; glibc 2.34 or newer is the documented build target |
| Out of scope | Windows, macOS, musl/Alpine, local deployment, production validation |
| CPA Host matrix | v7.2.83, v7.2.82, and v7.2.81 real Host + Mock-upstream runs are **NOT RUN / PENDING** |
| Production | Not accessed or modified; no production request, audit database, credential, HMAC key, account pool, or real Provider was used |
| Scanner identity | `streaming-scanner-v1` |
| Classifier policy | `classifier-policy-v3` / `ae6fb2c0bccec618bf91b6274d1cd9b9a483499703f21d068e5590f5255fc4bd` |
| Embedded YAML ruleset | `1.0.7` / `7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134` |
| Audit schema | v3 |

The historical v10 evaluation remains `CONSUMED / FAIL` and cannot be rerun or
used for tuning. Engineering checks do not override that methodology result or
authorize production enforcement.

## What Round 6 changes

- Removes production use of `body[:max_scan_bytes]`. Supported JSON requests
  are structurally traversed across the complete CPA-visible body.
- Changes legacy `max_scan_bytes` into a compatibility alias for the retained
  classifier window. It no longer means “inspect only the first 256 KiB”.
- Adds bounded `max_total_text_bytes` and
  `max_classification_chunks` limits so cumulative coverage and retained
  memory are separate controls.
- Streams JSON strings, multipart text, roles, provenance, and logical field
  boundaries into a bounded classifier session.
- Uses transactional media, metadata, tool-schema, and role decisions before
  committing text to classification. Unknown or ambiguous roles cannot
  impersonate a trusted user role.
- Preserves cross-window matching and bounded role-aware composition without
  retaining the full prompt.
- Adds audit schema v3 fields `decision`, `coverage`,
  `incomplete_reason`, and `scanner` plus fixed low-cardinality counters.
- Clears every partial category, score, rule, evidence, and behavior result
  when envelope or text coverage is incomplete.

The optional “verified local hard finding under incomplete coverage” exception
is deliberately disabled. Its counter remains for compatibility and is
expected to stay zero.

## Inspection and disposition contract

Envelope completeness and text coverage are separate:

- `complete`: the full visible structure and all model-visible decoded text
  were inspected;
- `budget_exhausted`: a configured cumulative text or classification-work
  bound was reached;
- `unavailable`: malformed input, unsupported encoding/schema, ambiguous role,
  or an RPC boundary prevented full coverage.

| Mode | Complete harmful request | Incomplete inspection |
|---|---|---|
| `off` | allow | allow |
| `observe` | observe only | allow + observe |
| `audit` | audit only | allow + audit |
| `balanced` | local block at the balanced threshold | allow + audit |
| `strict` | local block at the strict threshold | local block + audit |

Incomplete requests never update subject risk. A partial prefix cannot produce
a policy block in `balanced`.

## Effective default limits

| Control | Default / boundary |
|---|---|
| CPA-visible RPC envelope | 8 MiB |
| Retained classifier window | 256 KiB through the legacy alias; valid range 16 KiB–1 MiB |
| Total model-visible text | 8 MiB |
| Logical text fields | 512 |
| Classification work | computed minimum with a floor of 2048 chunks |
| JSON depth | 32 |
| Derived decoding | at most 2 layers, 8 variants, 128 KiB encoded source, and 64 KiB aggregate retained decoded text |

`text_bytes_scanned_total` is cumulative and may exceed
`max_scan_bytes`. Peak retained text is governed by the effective window and
bounded classifier state.

Dense encoded text whose derived view exceeds the 128 KiB encoded-source bound
still becomes incomplete. This is deliberate: long plain text is streamed, but
the implementation does not claim complete coverage for an oversized derived
decoded view.

The compact shadow planner retains closed semantic representatives, short
markers, and bounded span metadata rather than caller-controlled long keys or
semantic values. Residual allocation still grows with JSON token/node and
logical-field counts, under explicit hard limits. Allocation, RSS, and
concurrency claims remain pending authoritative Linux CI and sandbox evidence.

The legacy `ExtractText` API remains for source compatibility and preserves
its materialized `Parts` segmentation semantics. Production routing uses the
streaming request APIs and does not materialize the complete prompt.

See:

- [Streaming scanner design](docs/ROUND6_STREAMING_SCANNER_DESIGN.md)
- [Configuration migration](docs/ROUND6_CONFIG_MIGRATION.md)
- [Known limitations](docs/ROUND6_LIMITATIONS.md)
- [CI and blocked-prerelease gate](docs/ROUND6_RELEASE_GATE.md)
- [Development handoff](docs/ROUND6_DEVELOPMENT_HANDOFF.md)

## Supported request surfaces

The request path covers OpenAI Chat, OpenAI Responses, Interactions, Anthropic
Claude, Google Gemini, OpenAI image/video profiles, bounded
`multipart/form-data`, tool definitions and payloads, metadata exclusion, and
opaque media classification.

Images, audio, video, and documents are opaque. Their bytes are not decoded,
fetched, or sent elsewhere. `allow` for opaque media means “not inspected”, not
“safe”.

The deterministic policy covers credential theft, phishing, malware,
ransomware, exploitation, data exfiltration, service disruption, and defense
evasion. It is not a general content moderator or a replacement for provider
policy.

## Security and privacy boundary

- The Guard does not persist raw prompts, tool payloads, authorization headers,
  plaintext credentials, uploaded code, or provider account identity.
- Audit, metrics, and management status expose fixed fields, counters, and
  identities rather than prompt fragments or offsets.
- Media URLs are never fetched. No request-supplied code is executed.
- The Round 6 work did not connect to a real Provider or account pool and did
  not read production requests or audit data.
- The three public adversarial repositories were not executed and their raw
  payloads were not replayed.
- CPA can still fail open in Host conditions outside the plugin's control,
  including failed loading, Router fuse/error behavior, higher-priority
  Routers, invalid target handling, or an executor the Host does not consider
  ready. Real Host validation is therefore mandatory.

The Round 6 restricted-data disclosure is recorded in the
[development handoff](docs/ROUND6_DEVELOPMENT_HANDOFF.md). It does not claim
zero source-level contact where an over-broad search or mechanical build-tag
edit occurred, but no restricted corpus payload or production data was used
for implementation or conclusions.

## Verification and release gates

| Gate | Current state |
|---|---|
| Round 6 source and regression implementation | Present in the development worktree; final result depends on exact-source Linux CI |
| Linux amd64 format/module/vet/vulnerability/script gates | Pending final Linux CI |
| Linux amd64 unit/race/fuzz/benchmark evidence | Pending final Linux CI |
| Long-text tier matrix from 64 KiB through near the RPC limit | Test coverage is present; authoritative Linux result pending |
| CPA v7.2.83 Host + Mock upstream | **NOT RUN / PENDING** |
| CPA v7.2.82 Host + Mock upstream | **NOT RUN / PENDING** |
| CPA v7.2.81 Host + Mock upstream | **NOT RUN / PENDING** |
| Independent source/artifact/Host audit | **NOT RUN / PENDING** |
| Merge to `main` | Blocked |
| Round 6 Release | Blocked |

Windows and macOS are intentionally absent from this matrix. Their absence is
not a failed gate for this Linux-only round and must not be represented as test
coverage.

Safe Round 6 entry points are documented in
[ROUND6_RELEASE_GATE.md](docs/ROUND6_RELEASE_GATE.md). Do not replace the
allowlisted gates with broad `go test ./...` or `go vet ./...` commands that
could compile or open consumed evaluation packages.

Do not run `make formal-release`, `make release`, `make holdout-test`,
`make consumed-boundary-test`, or historical release/reproducibility packaging
for this candidate.

## Artifact contract

Any future admitted development artifact remains Linux amd64 and blocked:

| Artifact | Contract |
|---|---|
| `cyber-abuse-guard_<version>_linux_amd64.zip` | CPA Store ZIP with exactly one executable `.so` at the root |
| `cyber-abuse-guard-v<version>-audit-bundle.zip` | Documentation, metadata, SBOM, verification, and operator evidence; not Store-installable |
| `cyber-abuse-guard-v<version>-source.tar.gz` | Source review bundle; does not by itself prove Git provenance |

The manual Round 6 workflow must stay draft, prerelease, not latest, and named
`BLOCKED / PENDING HOST AND INDEPENDENT AUDIT`. It cannot be admitted until all
three CPA Host versions and the independent audit provide explicit PASS evidence
and the owner separately authorizes the blocked prerelease. All three Host records and the
independent audit must cite one exact candidate Linux SO SHA-256; the workflow
recomputes that hash immediately before attaching the rebuilt artifact.

## Repository map

| Path | Purpose |
|---|---|
| `cmd/cyber-abuse-guard/` | Native plugin entry point and CPA ABI bridge |
| `internal/classifier/` | Deterministic policy and streaming classifier |
| `internal/extract/` | Transactional request traversal, streaming text replay, decoding, roles, multipart, and media handling |
| `internal/plugin/` | Router, executor, disposition, management, health, and reconfiguration |
| `internal/audit/` | Privacy-minimal SQLite events, schema migrations, retention, and subject state |
| `integration/` | CPA source/compile and Host contract modules |
| `scripts/` | Safe gates, Linux build, packaging, verification, and reproducibility tooling |
| `docs/` | Design, migration, limitations, release gate, audit, and operations material |

Historical Round 5.2 evidence remains available in
[AUDIT_HANDOFF.md](docs/AUDIT_HANDOFF.md),
[TEST_REPORT.md](docs/reports/TEST_REPORT.md), and
[RELEASE_EVIDENCE.md](docs/reports/RELEASE_EVIDENCE.md). It does not validate
the Round 6 candidate.

## Security reporting

Follow [SECURITY.md](SECURITY.md). Do not include live credentials, private
prompts, OAuth material, production request content, or account identifiers in
an issue.

## License

[MIT](LICENSE)
