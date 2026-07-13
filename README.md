# CPA Cyber Abuse Guard

[![CI](https://github.com/yujianwudi/cyber-abuse-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/yujianwudi/cyber-abuse-guard/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.26.4-00ADD8?logo=go&logoColor=white)](go.mod)
[![Platform](https://img.shields.io/badge/platform-Linux%20amd64-lightgrey)](docs/LIMITATIONS.md)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-BLOCKED-critical)](docs/reports/RELEASE_EVIDENCE.md)

**A local, deterministic, pre-routing cyber-abuse request guard for
[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) (CPA).**

English | [简体中文](README_CN.md)

> [!WARNING]
> This repository is an **unreleased development candidate**. The v0.1.2
> release decision is **BLOCKED**, the only methodologically valid v10
> evaluation is `CONSUMED / FAIL`, and server-sandbox validation for the
> current tree has not been completed. Do not create a v0.1.2 tag or GitHub
> Release, and do not deploy this candidate to production.

When CPA has loaded and registered the plugin, Router ordering reaches it, and
the self-executor is ready, CPA Cyber Abuse Guard inspects supported model
requests before provider resolution and authentication scheduling. It is
designed to locally refuse clearly operational cyber-abuse requests while
preserving defensive analysis, remediation, incident response, CTF/lab work,
and explicitly authorized testing. Request content is evaluated in process and
is not sent to a public classifier.

## Current status

| Item | Current state |
|---|---|
| Repository state | Unreleased post-v10 development tree; candidate lineage v0.1.2 |
| Release decision | **BLOCKED / NOT PRODUCTION-READY** |
| Formal evaluation | v10 `CONSUMED / FAIL`: benign FP 28/320, policy blocked 49/320, exact 33/320 |
| Runtime baseline | CPA `v7.2.67`, commit `2075f77c8ebe9ec872759965661936fb1ac2931f` |
| CPA v7.2.72 usage | Isolated source-contract tests only; no host compatibility claim |
| Documented build target | Linux amd64, glibc 2.34 or newer, CPA C ABI/RPC schema v1 |
| Unsupported platform | musl/Alpine |
| Embedded YAML ruleset | `1.0.7`, SHA-256 `7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134` |
| Current validation | Source/CI and Phase 0 contract evidence available; owner-operated server sandbox still required |

The root `go.mod` remains pinned to CPA v7.2.67. The isolated module under
`integration/pluginstorecontract` pins CPA v7.2.72 only to exercise official
source contracts. The archive tests pass opaque synthetic plugin bytes through
`pluginstore.InstallArchive`; the host-routing tests run CPA's official
in-memory fakes. Neither path loads this plugin or proves that this repository
runs on a CPA v7.2.72 host.

## What this project is

- A CPA-native `ModelRouter` plus local self-executor.
- A deterministic, bilingual, rules-based classifier for operational
  cyber-abuse evidence.
- When CPA accepts the self route and executor readiness, a pre-provider
  control that can stop a refused request before provider, authentication,
  usage, and upstream work begins.
- A privacy-minimal audit and operator-control surface with bounded local
  SQLite persistence.
- An engineering and audit project with explicit evidence, packaging, and
  reproducibility contracts.

## What this project is not

- A general-purpose content, NSFW, copyright, or software-licensing moderator.
- An account scheduler, quota manager, OAuth manager, provider proxy, or 429
  recovery component.
- A replacement for upstream provider policies.
- A guarantee that an upstream account will never be warned, limited,
  suspended, or deactivated.
- A remote AI classifier, telemetry collector, URL fetcher, media scanner, or
  user-code execution environment.
- A production-ready release in its current state.

The post-v10 tree includes a narrow `META-OVERRIDE-001` control-plane overlay
for malicious instruction-hierarchy inversion and safety-policy suppression.
A strong standalone control-plane attack can currently be reported as
`defense_evasion`; this is a known scope extension in development code, not a
claim that the plugin is a complete general model-safety filter.

## How it works

```text
downstream request
  -> CPA ModelRouter
    -> allowed: Handled=false
       -> original CPA provider/auth/upstream path continues unchanged
    -> blocked: Handled=true, TargetKind=self
       -> if CPA accepts the self route and executor readiness:
          -> execute / execute_stream / count_tokens emit RPC error envelopes
             requesting HTTP status 403
          -> http_request emits an unsupported-method envelope requesting 405
          -> provider resolution, auth selection, usage, and upstream are skipped
```

The implementation does not rewrite the requested model, client identity,
system prompt, safety declarations, or allowed request content. It does not
read CPA Auth/OAuth files, disguise malicious intent, execute request-supplied
code, or send prompts to an auxiliary public classifier.

## Detection scope

The embedded policy covers eight operational cyber-abuse families:

- credential theft;
- phishing;
- malware;
- ransomware;
- exploitation;
- data exfiltration;
- service disruption;
- defense evasion.

A lone keyword is not sufficient. The classifier combines harmful intent,
dangerous object or impact, and operational, target, evasion, or scale
evidence. Labels such as “education”, “CTF”, “benchmark”, or “authorized” do
not automatically wash deployment-oriented abuse, while affirmative defensive
analysis and non-execution intent can preserve legitimate work.

Supported source extractors cover OpenAI Chat, OpenAI Responses, Anthropic
Claude, and Google Gemini request shapes. The current repository has source
tests for these paths, but the four-protocol HTTP and zero-downstream-call
matrix still requires owner-operated server-sandbox validation.

Text handling is deliberately bounded:

- at most two decoding layers and eight unique variants;
- 128 KiB encoded-source and 64 KiB aggregate decoded-text limits;
- URL percent, HTML entity, inspectable Base64, textual data URL, JSON escape,
  and bounded nested tool-JSON handling;
- no decompression, archive expansion, network fetch, or cross-request semantic
  memory.

Images, audio, video, and document attachments are opaque. Their policy can be
`block`, `audit`, or `allow`; `allow` means “not inspected”, not “safe”.

## Modes

| Mode | Request behavior | Event behavior |
|---|---|---|
| `off` | No extraction, classification, or blocking | No event persistence |
| `observe` | Classifies but never blocks | In-memory aggregates only |
| `audit` | Classifies but never blocks | Privacy-minimal SQLite events |
| `balanced` | Blocks clear operational abuse | Minimal events and subject controls |
| `strict` | Uses the lower enforcement threshold | Most conservative; no challenge flow |

These modes describe implemented behavior, not deployment authorization. The
current candidate must not be installed in production. The staged rollout and
rollback material in [INSTALL_DOCKER.md](docs/INSTALL_DOCKER.md) is retained
for future, release-eligible builds and controlled server-sandbox work.

## Security and privacy invariants

- Raw prompts, messages, tool payloads, authorization headers, plaintext API
  keys/IP addresses, cookies, OAuth tokens, uploaded code, and upstream account
  identity are not written to the audit database or returned by management
  APIs.
- `audit.log_original_text: true` is rejected; there is no debug bypass.
- Stable subject identity uses HMAC. Subject persistence is optional, bounded,
  and requires a stable secret file.
- Media URLs are never fetched and request content is not sent to a public
  classification service.
- Audit, subject, query, body, decoding, and RPC paths use explicit size and
  capacity limits.

CPA's host boundary remains fail-open in conditions the plugin cannot control.
CPA may continue another Router or native routing if this plugin is not loaded,
is fused, errors, panics before an accepted handled result, returns an invalid
target, or self-routes to an executor the host does not consider ready. A
higher-priority Router can also handle the request first; equal-priority
Routers are ordered by plugin ID ascending.

`loaded` and `enforcement_ready` report only plugin-internal state through a
management callback that CPA has already dispatched. They do not independently
prove host discovery, registration, Router ordering, fuse state, duplicate
libraries, or per-format executor readiness. Operators must verify those host
conditions separately.
See [LIMITATIONS.md](docs/LIMITATIONS.md) and
[THREAT_MODEL.md](docs/THREAT_MODEL.md).

The audited CPA v7.2.72 management source calls `io.ReadAll` before invoking
the plugin handler. The deployment-facing reverse proxy must therefore enforce
its own body limit; the server sandbox must prove oversized requests receive
HTTP 413 before reaching CPA.

## Verification status

| Evidence | Status |
|---|---|
| Root unit, race, vet, fuzz-smoke, regression, build, and packaging workflows | Implemented in CI |
| CPA Store ZIP naming/layout/install source contract | Implemented against official CPA v7.2.72 source |
| CPA Router ordering/fallback source contract | Implemented against official CPA v7.2.72 source |
| Local executor refusal contract | RPC error envelopes request 403 for `execute`, `execute_stream`, and `count_tokens`; `http_request` requests 405 |
| Native plugin loading on the current server diff | Not run locally |
| OpenAI Chat / Responses / Claude / Gemini server matrix | Server sandbox required |
| Zero Auth Selector / Usage / Provider / upstream calls on blocked requests | Server sandbox required |
| Independent release evaluation | v10 consumed and failed; a new unseen set is required |
| Production release | Blocked |

Phase 0 evidence and remaining server cases are recorded in
[PHASE0_CPA_CONTRACT.md](docs/reports/PHASE0_CPA_CONTRACT.md). Historical
evaluation datasets are frozen evidence. Do not rerun or tune against
individual v10 rows.

## Developer and auditor checks

The following checks are source-only; they do not deploy CPA or load a
`.so`:

```bash
make format-check git-diff-check module-verify
make test vet race fuzz-smoke corpus-regression
make script-test

# Explicit source-only CPA v7.2.72 store and host contracts.
go -C integration/pluginstorecontract test ./... -count=1
```

The release toolchain expects Go `1.26.4`. Linux-native build, integration,
SBOM, vulnerability, artifact, and reproducibility commands are documented in
[TEST_REPORT.md](docs/reports/TEST_REPORT.md) and
[RELEASE_EVIDENCE.md](docs/reports/RELEASE_EVIDENCE.md).

`make holdout-test` is not a routine developer check. The v10 dataset is
consumed, and its gate deliberately refuses a rerun. `make formal-release`
must not be run for the current blocked candidate.

## Artifact contracts

Development CI may build dirty-suffixed evidence artifacts. No formal v0.1.2
release artifact exists.

| Artifact | Contract |
|---|---|
| `cyber-abuse-guard_<version>_linux_amd64.zip` | CPA Store ZIP; exactly one regular executable `.so` at the ZIP root |
| `cyber-abuse-guard-v<version>-audit-bundle.zip` | Separate documentation, metadata, SBOM, verification, and operator bundle; not installable by the CPA Store |
| `cyber-abuse-guard-v<version>-source.tar.gz` | Source review/build bundle; excludes `.git` and therefore cannot satisfy historical Git-provenance gates |

RAR is not a supported source or binary release format.

## Repository map

| Path | Purpose |
|---|---|
| `cmd/cyber-abuse-guard/` | Native plugin entry point and CPA ABI bridge |
| `internal/classifier/` | Deterministic policy evaluation and historical gates |
| `internal/extract/` | Provider-aware, bounded request extraction and decoding |
| `internal/plugin/` | Router, executor, management, runtime health, and reconfiguration |
| `internal/audit/` | Privacy-minimal SQLite events, migrations, retention, and subject state |
| `rules/` | Embedded versioned YAML cyber-abuse policy assets |
| `integration/` | CPA integration and isolated official-source contract modules |
| `scripts/` | Build, package, verify, reproduce, health-check, and release tooling |
| `testdata/` | Regression and frozen evaluation evidence; not a tuning dataset |
| `docs/` | Design, operations, limitations, threat model, audit handoff, and reports |

Ignored local `dist/`, `coverage.out`, databases, logs, and secret files are
not repository source or formal release evidence.

## Documentation

| Audience | Start here |
|---|---|
| Project evaluator | [Design](docs/DESIGN.md), [Limitations](docs/LIMITATIONS.md), [Threat model](docs/THREAT_MODEL.md) |
| Security auditor | [Audit handoff](docs/AUDIT_HANDOFF.md), [Release evidence](docs/reports/RELEASE_EVIDENCE.md), [Test report](docs/reports/TEST_REPORT.md) |
| CPA integrator | [CPA integration](docs/reports/CPA_INTEGRATION.md), [Phase 0 contract](docs/reports/PHASE0_CPA_CONTRACT.md), [Docker operations](docs/INSTALL_DOCKER.md) |
| Policy reviewer | [Rules](docs/RULES.md), [Privacy](docs/reports/PRIVACY.md), [Prompt-injection review](docs/reports/PROMPT_INJECTION_REVIEW.md) |
| Future maintainer | [Next-version recommendations](docs/NEXT_VERSION.md), [Changelog](CHANGELOG.md) |

## Security reporting

Please follow [SECURITY.md](SECURITY.md). Do not include live credentials,
private prompts, OAuth material, or production account identifiers in an issue.

## License

[MIT](LICENSE)
