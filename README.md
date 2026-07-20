# CPA Cyber Abuse Guard

```text
current_classifier_policy_version: classifier-policy-v5
current_classifier_policy_sha256: 0e114d98862282d2492fb62e4300297b4746eeaf8165339603d02c48d11bd60b
```

[![CI](https://github.com/yujianwudi/cyber-abuse-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/yujianwudi/cyber-abuse-guard/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.26.4-00ADD8?logo=go&logoColor=white)](go.mod)
[![Platform](https://img.shields.io/badge/platform-Linux%20amd64-lightgrey)](docs/ROUND6_LIMITATIONS.md)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Prerelease](https://img.shields.io/badge/prerelease-v0.15--rc.3-orange)](https://github.com/yujianwudi/cyber-abuse-guard/releases/tag/v0.15-rc.3)
[![Formal release](https://img.shields.io/badge/formal_v0.15-BLOCKED-critical)](docs/ROUND6_RELEASE_GATE.md)

**A local, deterministic, pre-routing cyber-abuse request guard for
[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) (CPA).**

English | [简体中文](README_CN.md)

> [!WARNING]
> Version `0.15` and its formal tag `v0.15` remain
> **BLOCKED / PENDING HOST AND INDEPENDENT AUDIT**. The
> [`v0.15-rc.3`](https://github.com/yujianwudi/cyber-abuse-guard/releases/tag/v0.15-rc.3)
> side lane publishes only after exact-main CI, the complete internal Linux
> quality suite, CPA v7.2.88 source compatibility, RC-versioned integration, and
> two independent clean-clone rebuilds pass. Its 17 assets follow the formal
> package structure but carry RC-only evidence and no formal attestation.
> Therefore RC3 remains **SANDBOX ONLY / SERVER VALIDATION REQUIRED**, not a
> private clean candidate, formal release, production authorization, real CPA
> Host PASS, independent audit PASS, or independent evaluation PASS. Windows
> and macOS remain outside scope.

When CPA has loaded and registered the plugin, Router ordering reaches it, and
the self-executor is ready, the Guard inspects supported model requests before
provider selection, authentication scheduling, usage accounting, and upstream
work. Request content is evaluated in process and is not sent to a public
classifier.

## Current Round 6 status

| Item | State |
|---|---|
| Project version / intended formal tag | `0.15` / exact tag `v0.15` (never `v0.15.0`) |
| Current RC identity | Annotated `v0.15-rc.3` at the exact post-merge `main` commit/tree; the tag object, CI run, workflow run, and 17 asset hashes are bound in `rc-release-manifest.json` |
| Last fully verified pre-cleanup main baseline | `6782dfaffd4da3f09604113c7d38675f331dc759`, tree `a8edbe2e6d19fa725fb962cdd6aaad5b416d4b85`; main CI [29630844605](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29630844605) and tag CI [29630926354](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29630926354) passed |
| Release decision | **BLOCKED / PENDING HOST AND INDEPENDENT AUDIT** |
| Candidate bytes | Must be clean exact-source Linux amd64 bytes from the private untagged Actions candidate workflow; clean does not mean released |
| Merge and release | The active RC3 workflow creates a draft, re-downloads and byte-compares all 17 assets, then publishes `prerelease=true` and `latest=false`; formal `v0.15` remains absent and blocked |
| RC publication mode | `AUTOMATED / COMPLETE_INTERNAL_LINUX_GATES / TWO-CLEAN-CLONE_REPRODUCIBLE / SANDBOX_ONLY` |
| RC exact-main CI | Required and bound by run ID plus exact run attempt to the tagged `main` commit; the run URL and attempt are recorded in RC evidence and manifest |
| Validation platform | Linux amd64 only; emitted numeric GLIBC ABI versions must be `<= 2.34` |
| Out of scope | Windows, macOS, musl/Alpine, local deployment, production validation |
| CPA Host matrix | Active validation and the supported release target are pinned to CPA v7.2.88 (`93d74a890a44802f656d7f39a573916b2611896e`); owner-operated isolated Host + Mock-upstream evidence is **NOT RUN / PENDING** |
| Production | Not accessed or modified; no production request, audit database, credential, HMAC key, account pool, or real Provider was used |
| Scanner identity | `streaming-scanner-v1` |
| Classifier policy | `classifier-policy-v5` / `0e114d98862282d2492fb62e4300297b4746eeaf8165339603d02c48d11bd60b` |
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

The safe startup defaults are `mode: observe` and
`subject_control.enabled: false`. Observe updates bounded counters only: it
does not block, accumulate subject risk, persist per-request SQLite events, or
hash the full request body for audit correlation.

Incomplete requests never update subject risk. A partial prefix cannot produce
a policy block in `balanced`.
Subject accumulation also requires an explicit trusted-user attribution proof;
unknown/future fields and non-user or tool-originated text keep their direct
request disposition but cannot poison rolling subject state.
The proof is bound to the CPA `SourceFormat`: only a matching root provider
history or Responses scalar `input` can establish user authorship. Nested or
cross-provider histories, developer/system/tool content, unknown content types,
function responses, and opaque Responses reasoning state remain untrusted.
Nested history/content arrays, scalar members of provider content arrays, and
unknown or non-string Responses item `type` values are likewise scanned without
receiving trusted-user attribution. The exact Responses `type` discriminator is
transport metadata, not model-visible prompt text.

With audit enabled, a complete category-free wrapper-only finding attributed
to non-user or untrusted wrapper traffic stays visible through the bounded
`audited` and
`control_plane_meta_override` counters but does not create a per-request SQLite
event or request/subject correlation hash by default. Set
`audit.persist_wrapper_only: true` to restore those events. Cyber Abuse base
findings, trusted-user wrapper findings, blocks, incomplete inspections, and
opaque-media dispositions keep the full configured audit path.

Repository-neutral regressions derived from four public prompt-override source
pins cover high-authority `instructions`, Chat and Responses tool descriptions,
CPA v7.2.88 Codex Desktop `additional_tools`, assistant/tool history, defensive
domain catalogs, 1,397-17,166 decoded-byte templates, and the 16 KiB boundary
without adding repository-name signatures or complete third-party prompts. See the
[public jailbreak repository review](docs/reports/PUBLIC_JAILBREAK_REPOSITORY_REVIEW.md).

## Effective default limits

| Control | Default / boundary |
|---|---|
| Runtime mode | `observe` |
| Subject control | disabled; explicit opt-in |
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
- [CI, candidate, and release gates](docs/ROUND6_RELEASE_GATE.md)
- [Documentation and workflow index](docs/README.md)
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
- The four public adversarial repositories were not executed and their raw
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
| Last fully verified pre-cleanup `main` push CI | [29630844605](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29630844605) **SUCCESS** for `6782dfa` / tree `a8edbe2` |
| RC3 exact-main CI | Must be a completed successful `push` run of `ci.yml` for the exact tagged `main` commit and is revalidated before checkout |
| Source-only `v0.15-rc.1` tag CI | [29630926354](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29630926354) **SUCCESS** for `6782dfa` / tree `a8edbe2` |
| Private untagged clean candidate Actions artifact | **NOT CREATED / PENDING**; must bind one final commit/tree and emit `candidate-manifest.json` |
| CPA v7.2.88 Host + Mock upstream | **NOT RUN / PENDING** |
| Independent source/artifact/Host audit | **NOT RUN / PENDING** |
| Candidate-bound external evaluation-v11 or later | **NOT RUN / PENDING**; must be first-and-only `CONSUMED / PASS` for the exact candidate |
| Annotated `v0.15-dev.round6[.N]` prerelease | Optional and blocked until Host, independent audit, and candidate-level evaluation pass; never a formal release |
| Public source-only `v0.15-rc.1` prerelease | Exists with no attached assets; not the private candidate, Host evidence, or formal release |
| Historical asset-bearing `v0.15-rc.2` prerelease | **PUBLIC / PRERELEASE / SANDBOX ONLY**; ten Linux amd64 assets were published by direct owner override with tests skipped |
| Formal-structure `v0.15-rc.3` prerelease | Exactly 17 Linux amd64 assets; internal gates and reproducibility must pass, while real CPA Host, independent audit/evaluation, formal release, and production authorization remain absent |
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
3. The CPA v7.2.88 Host + Mock record, the independent
   audit, and a candidate-bound external `evaluation-v11` or later
   `CONSUMED / PASS` report must all bind the same candidate identity.
   The Host identity and evidence hash are carried by attestation schema v2 as
   `cpa_version`, `cpa_commit`, and `cpa_host_sha256`.
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

Active release and Host validation is pinned to CPA v7.2.88 at
`93d74a890a44802f656d7f39a573916b2611896e`. Later upstream CPA versions do
not automatically change the supported, tested, or release-admitted target. Legacy version-specific test
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
| [`docs/README.md`](docs/README.md) | Documentation index for architecture, operations, policy, current release handoff, and historical reports |

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
