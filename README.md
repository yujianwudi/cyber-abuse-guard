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
> Version `0.15` and its formal tag `v0.15` remain
> **BLOCKED / PENDING HOST AND INDEPENDENT AUDIT**. The Round 6 implementation
> was merged by [PR #9](https://github.com/yujianwudi/cyber-abuse-guard/pull/9),
> and exact-main plus tag CI later passed. A public source-only
> [`v0.15-rc.1`](https://github.com/yujianwudi/cyber-abuse-guard/releases/tag/v0.15-rc.1)
> prerelease exists without attached release assets. The separate asset-bearing
> `v0.15-rc.2` prerelease is Linux amd64-only and is intended solely for owner-
> operated server sandbox validation; its binary, Store ZIP, metadata, SBOM,
> checksums, and RC manifest are not the private clean candidate, a formal
> release, or production deployment authorization. This
> round accepts evidence only from Linux amd64 CI and the authorized Linux
> sandbox. Windows and macOS build or test evidence is outside scope.

When CPA has loaded and registered the plugin, Router ordering reaches it, and
the self-executor is ready, the Guard inspects supported model requests before
provider selection, authentication scheduling, usage accounting, and upstream
work. Request content is evaluated in process and is not sent to a public
classifier.

## Current Round 6 status

| Item | State |
|---|---|
| Project version / intended formal tag | `0.15` / exact tag `v0.15` (never `v0.15.0`) |
| Merged Round 6 implementation | [PR #9](https://github.com/yujianwudi/cyber-abuse-guard/pull/9); `main@6782dfaffd4da3f09604113c7d38675f331dc759`, tree `a8edbe2e6d19fa725fb962cdd6aaad5b416d4b85` |
| Last fully verified pre-cleanup main baseline | `6782dfaffd4da3f09604113c7d38675f331dc759`, tree `a8edbe2e6d19fa725fb962cdd6aaad5b416d4b85`; main CI [29630844605](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29630844605) and tag CI [29630926354](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29630926354) passed |
| Release decision | **BLOCKED / PENDING HOST AND INDEPENDENT AUDIT** |
| Candidate bytes | Must be clean exact-source Linux amd64 bytes from the private untagged Actions candidate workflow; clean does not mean released |
| Merge and release | Round 6 is merged; formal `v0.15` is absent and blocked. Public `v0.15-rc.1` is source-only; `v0.15-rc.2` is an asset-bearing Linux server-sandbox prerelease and is not candidate or formal evidence |
| Validation platform | Linux amd64 only; emitted numeric GLIBC ABI versions must be `<= 2.34` |
| Out of scope | Windows, macOS, musl/Alpine, local deployment, production validation |
| CPA Host matrix | Active validation and the supported release target are limited to CPA v7.2.86; owner-operated isolated Host + Mock-upstream evidence is **NOT RUN / PENDING** |
| Production | Not accessed or modified; no production request, audit database, credential, HMAC key, account pool, or real Provider was used |
| Scanner identity | `streaming-scanner-v1` |
| Classifier policy | `classifier-policy-v3` / `99e0ce7f59d2e687ebb3e79e1a71300afee8bb56f723cd8ba3f478c71a64cfd2` |
| Embedded YAML ruleset | `1.0.7` / `7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134` |
| Audit schema | v3 |
| Code review | Automated review is advisory; no independent approval is claimed |

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
- This is a Guard-local guarantee, not an end-to-end Host guarantee. CPA may
  temporarily spool non-multipart request bodies and may persist raw bodies in
  Host HTTP error logs; see [Decision output and privacy](docs/RULES.md#decision-output-and-privacy).
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
| Round 6 implementation PR | [PR #9](https://github.com/yujianwudi/cyber-abuse-guard/pull/9) merged; its PR runner did not start because of the recorded GitHub billing limit, so it is not claimed as a PR-CI PASS |
| Exact post-merge `main` push CI | [29630844605](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29630844605) **SUCCESS** for `6782dfa` / tree `a8edbe2` |
| Source-only prerelease tag CI | [29630926354](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29630926354) **SUCCESS** for the same commit/tree |
| Private untagged clean candidate Actions artifact | **NOT CREATED / PENDING**; must bind one final commit/tree and emit `candidate-manifest.json` |
| CPA v7.2.86 Host + Mock upstream | **NOT RUN / PENDING** |
| Independent source/artifact/Host audit | **NOT RUN / PENDING** |
| Candidate-bound external evaluation-v11 or later | **NOT RUN / PENDING**; must be first-and-only `CONSUMED / PASS` for the exact candidate |
| Annotated `v0.15-dev.round6[.N]` prerelease | Optional and blocked until Host, independent audit, and candidate-level evaluation pass; never a formal release |
| Public source-only `v0.15-rc.1` prerelease | Exists with no attached assets; not the private candidate, Host evidence, or formal release |
| Asset-bearing `v0.15-rc.2` prerelease | Linux amd64 SO + CPA Store ZIP + checksums/SBOM/RC manifest for owner-operated server sandbox validation; not candidate or formal evidence |
| Annotated `v0.15` formal tag and verified draft | Blocked |
| Protected promotion of the unchanged draft | Blocked |

Windows and macOS are intentionally absent from this matrix. Their absence is
not a failed gate for this Linux-only round and must not be represented as test
coverage.

Safe Round 6 entry points are documented in
[ROUND6_RELEASE_GATE.md](docs/ROUND6_RELEASE_GATE.md). Do not replace the
allowlisted gates with broad `go test ./...` or `go vet ./...` commands that
could compile or open consumed evaluation packages.

Do not create `v0.15`, run the formal release path, rerun consumed v10, or use
historical release assets as current evidence. The candidate workflow must first
exist on the default branch, so candidate creation is restricted to a dispatch
from `main` after the final PR is merged and the exact main push CI succeeds.

## Artifact contract

The v0.15 evidence chain is intentionally split:

1. Freeze the final PR head, pass PR CI, merge it to `main`, and pass push CI on
   the exact resulting main commit/tree. Merge is a candidate prerequisite, not
   deployment or release approval.
2. A manual, private, **untagged** GitHub Actions dispatch from `main` builds clean exact-source
   Linux amd64 candidate bytes. Its artifact is not a GitHub Release and expires.
3. The CPA v7.2.86 Host + Mock record, the independent
   audit, and a candidate-bound external `evaluation-v11` or later
   `CONSUMED / PASS` report must all bind the same candidate identity.
4. If a durable development handoff is needed after those gates, an existing
   annotated `v0.15-dev.round6` (or numbered suffix) may produce a draft prerelease only
   after those external gates pass. It remains `BLOCKED / NOT A FORMAL RELEASE`.
5. Only that candidate-level external evaluation attestation may admit the
   annotated formal tag `v0.15`. Its workflow
   rebuilds and byte-compares the Host-tested candidate, emits
   `formal-release-attestation.json`, and creates a draft formal Release; a
   separate protected promotion publishes that unchanged draft.

The private candidate contains `cyber-abuse-guard-v0.15.so`, its sidecar,
`cyber-abuse-guard_0.15_linux_amd64.zip`, metadata, checksums, ruleset identity,
SBOM, and `candidate-manifest.json`. The Store ZIP contains exactly one root
`.so`. Audit bundles and source archives belong only to the later formal release
path and must exclude evaluation, Holdout, private, blind, and retired material.
They carry only the approved low-sensitivity attestation identities/hashes.
Clean candidate bytes are still unreleased and provide no deployment
authorization.

This source tree intentionally does not self-record future Host/audit PASS
hashes, merge identity, or Release state. Stable v0.15 eligibility is determined
only by external Round 6/formal attestation assets that bind the final source,
candidate workflow run, candidate bytes, Host records, independent audit, and
release evaluation.

Active CPA validation supports only v7.2.86. Legacy version-specific test
profiles and Make aliases have been removed; older observations remain only as
non-executable historical records and are not current release or Host evidence.

Historical evaluation-v10 remains `CONSUMED / FAIL`, cannot be rerun, and is
not accepted as a formal-build input.

The neutral source policy is [RELEASE_POLICY.md](docs/RELEASE_POLICY.md). The
external decision records are `round6-prerelease-attestation.json` and
`formal-release-attestation.json`; neither is self-authored as a future PASS by
this source tree.

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
