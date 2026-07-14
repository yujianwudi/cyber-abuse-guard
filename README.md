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
> evaluation is `CONSUMED / FAIL`. The fourth-round candidate targets CPA
> v7.2.75; its new GitHub CI artifact, isolated Host matrix, and Leo verification
> remain pending. Do not create a v0.1.2 tag or GitHub Release, and do not deploy
> this candidate to production.

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
| Runtime baseline | CPA `v7.2.75`, commit `e57416731aec87051ac00d0812df6aebd0e9d57a`, C ABI/RPC schema v1 |
| CPA v7.2.75 checksums | module `h1:WcCCeENtQ5F2bT86FVIOZJJbWCkPqrp3idl8kyZqARM=`; go.mod `h1:f4pcyAej8RoeRhIxJfm+OUMkCKaApiA8WzxR2XVlBh8=` |
| Documented build target | Linux amd64, glibc 2.34 or newer, CPA C ABI/RPC schema v1 |
| Unsupported platform | musl/Alpine |
| Embedded YAML ruleset | `1.0.7`, SHA-256 `7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134` |
| Classifier policy identity | `classifier-policy-v2`, SHA-256 `6a0480acc63617b688484c81baf4991cad48b57ad4414b1a8aeab0f0d196c51c` |
| Current validation | Fourth-round JSON/multipart unit regressions pass locally; CPA v7.2.75 CI artifact and isolated Host evidence are pending; status remains **PARTIAL / NOT PRODUCTION-READY** |

The root `go.mod` and `integration/pluginstorecontract` module both pin CPA
v7.2.75. Source contracts enumerate and run 16 exact official Host tests, while
the native harness installs the real Store ZIP, loads the real Guard `.so`, and
uses a pure-C second Router/executor fixture. Source or compile-only results do
not prove native compatibility: the fourth-round GitHub CI Linux run, artifact,
and CPA v7.2.75 isolated-Host matrix are still pending, and Leo must repeat the
frozen result independently in isolation.

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

The post-v10 tree treats `META-OVERRIDE-001` as wrapper/control evidence, not a
standalone Cyber Abuse category. Wrapper-only text may be allowed or audited,
but cannot independently block or synthesize `defense_evasion`. When an
independent dangerous behavior exists, the wrapper may amplify that candidate
without replacing its taxonomy. This is not a complete general model-safety
filter.

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
          -> http_request emits an unsupported-method RPC error carrying status
             405; the official adapter returns nil plus that status error, and
             no current official public route maps it to final client HTTP 405
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

Every non-trivial result can carry a privacy-safe `BehaviorGraph`: stable
dimensions and relations for requester, action, object, target, destination,
execution, credential/access, persistence, evasion, exfiltration, impact,
scale, authorization/defensive scope, wrapper/amplifier, role scope, carrier,
composition mode, and reason codes. It contains no prompt fragments.

Supported request inspection covers OpenAI Chat, OpenAI Responses, Anthropic
Claude, Google Gemini, and OpenAI image request shapes. JSON and bounded
`multipart/form-data` use one Content-Type-aware entry point. JSON media
semantics are independent of object-member order: payload-adjacent values such
as `data`, `bytes`, `blob`, `binary`, `filename`, `format`, `detail`, `width`,
`height`, and `duration` are deferred until their object is known to be media
or ordinary text. Media candidates never enter `Parts`, role-aware `Segments`,
decoding, or the text budget; tool-payload `data` and non-media `data` remain
inspectable. Multipart text is selected by a fixed `SourceProfile`, not a
denylist or HTTP path. The current `openai-image` profile admits only `prompt`
and `negative_prompt` (including its two bounded spelling variants), skips
reviewed metadata and file fields, and treats every unknown non-file field as
incomplete schema rather than classifier text.

The earlier v7.2.72 four-protocol HTTP and zero-downstream-call matrix remains
historical evidence for implementation freeze `61536f9`. It does not validate
the fourth-round CPA v7.2.75 candidate; its CI artifact, real-Host matrix, audit
privacy check, and Leo isolated verification are separate pending gates.

Recognized roles keep system safety policy and assistant refusals separate from
user intent. User-authored adjacent turns and one explicitly linked bounded
three-turn plan can compose; provider-native tool payloads are scanned
independently; unknown role shapes use the conservative fallback. Placeholders
such as `<target>`, `${host}`, and `VICTIM_IP` matter only when nearby text binds
them to a dangerous object or real target.

Text handling is deliberately bounded:

- at most two decoding layers and eight unique variants;
- 128 KiB encoded-source and 64 KiB aggregate decoded-text limits;
- URL percent, HTML entity, inspectable Base64, textual data URL, JSON escape,
  and bounded nested tool-JSON handling;
- provider-aware role, content-part, tool-argument, and tool-output carriers;
- object-level deferred media candidates with fixed count/byte bounds and
  stable opaque-kind ordering across JSON member permutations;
- independent raw-request and extracted-text budgets, so uploaded media does
  not consume the ordinary text-classification budget;
- SourceFormat-bound multipart field allowlists plus bounded boundary, part,
  header, field, and aggregate-text limits, with no Guard-created temporary
  files and no remote media fetch;
- no decompression, archive expansion, network fetch, or cross-request semantic
  memory.

Images, audio, video, and document attachments are opaque. Their policy can be
`block`, `audit`, or `allow`; `allow` means “not inspected”, not “safe”.

Content inspection completeness is a separate policy input. Malformed JSON,
scan/depth/part limits, unsupported Content-Type, multipart resource limits,
deferred-text candidate overflow, multipart unknown/type-mismatched fields, and
plugin RPC body limits are `incomplete_inspection`, not runtime crashes.
`balanced` passes such requests through and emits an audit decision; `strict`
locally blocks them. A partially inspected prefix can never trigger a
`balanced` block, update subject risk, or persist partial rule IDs. See
[MULTIMODAL_INSPECTION_CONTRACT.md](docs/MULTIMODAL_INSPECTION_CONTRACT.md).

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

Wrapper-only control evidence is a deliberate exception to the ordinary strict
score matrix: it remains allow/observe/audit and never directly becomes a Cyber
Abuse block. Strict blocking still requires an independently established base
behavior.

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
- Authenticated status exposes both the YAML ruleset identity and the complete
  classifier-policy version/hash without exposing request text.

These no-plaintext and no-tempfile claims apply to the Guard extractor,
management surfaces, metrics, and plugin audit. They are not an end-to-end CPA
logging guarantee.

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

The audited CPA v7.2.75 Host still buffers management bodies before invoking
the plugin handler, so a deployment-facing reverse proxy must enforce its own
body limit and prove HTTP 413 before CPA. CPA v7.2.75 request logging may also
spool a non-multipart body temporarily and persist a raw body for an HTTP error.
The isolated sandbox must use a temporary log directory, and production review
must separately cover commercial mode, retention, permissions, and deletion.

## Verification status

| Evidence | Status |
|---|---|
| Fourth-round JSON order, multipart profile, race/vet/fuzz/benchmark, artifact, and CPA v7.2.75 Host gates | **PENDING** — no fourth-round CI run, artifact hash, implementation freeze, or isolated-Host conclusion is recorded yet |
| Historical safe unit/race boundary, vet, fuzz-smoke, regression, build, packaging, and reproducibility workflows | **GITHUB CI PASS** on earlier implementation freeze `61536f9`; push run [29312969925](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29312969925) and PR run [29312971717](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29312971717); not fourth-round evidence |
| Safe Go development scripts | `test`, `race`, and `boundary` **DEVELOPMENT SELF-CHECK PASS** on the pre-review implementation tree, WSL Ubuntu 26.04 / Go 1.26.4; exact-freeze coverage is provided by GitHub CI |
| CPA Store ZIP naming/layout/install source contract | Updated to official CPA v7.2.75 source; fourth-round CI execution pending |
| CPA Router ordering/fallback source contract | Updated to official CPA v7.2.75 source; fourth-round CI execution pending |
| Local executor refusal contract | RPC error envelopes request 403 for `execute`, `execute_stream`, and `count_tokens`; `http_request` has a SOURCE/ADAPTER status-error 405 check with no response only |
| Historical native plugin loading | **GITHUB CI PASS** for the earlier v7.2.72 freeze; current CPA v7.2.75 Store artifact/load is **PENDING** |
| Historical OpenAI Chat / Responses / Claude / Gemini server matrix | **GITHUB CI PASS** on the earlier v7.2.72 freeze; fourth-round order/profile cases are pending |
| Historical zero Auth Selector / Usage / Provider / upstream calls on blocked requests | **GITHUB CI PASS** on the earlier freeze; current exact-artifact proof is pending |
| Historical Multi-Router/fail-open and management proxy 413 matrices | **GITHUB CI PASS** on the earlier freeze — 15 native Router scenarios and proxy rejection before the counted CPA handler |
| Final official CPA client HTTP 405 for `executor.http_request` | **NOT AVAILABLE / NOT RUN** — `/v1/alpha/search` is provider-specific, normally selects `codex`, and maps every executor error to 502; no current official route maps Guard's 405 error to final 405 |
| Independent release evaluation | v10 consumed and failed; a new unseen set is required |
| Production release | Blocked |

Three WSL commands were mistakenly run outside the authorized evidence path:

```text
make cpa-router-fixture-blackbox
make cpa-v7272-host-blackbox
scripts/management-proxy-413-test.sh
```

They used random loopback ports and Mock components only, contacted no real
provider or production service, and cleanup left no fixture process running.
Their status is strictly:

```text
LOCAL MIS-EXECUTION RECORDED / EXCLUDED; NOT AUTHORITATIVE
```

No result from those local commands is a delivery PASS.
The separately authorized GitHub CI results above are the applicable remote
evidence; Leo's independent verification remains not run.

A separate methodology incident involved three incorrectly scoped WSL
source-search commands that unexpectedly emitted several rows from the retired
`testdata/holdout-v3` corpus. All three searches were stopped immediately; the
rows were not analyzed or used for tuning or conclusions, and evaluation v10 content
was not accessed. The retired holdout-v3 corpus is no longer eligible as
independent evidence, and this incident independently keeps the handoff status
`BLOCKED FOR HANDOFF`.

Historical v7.2.72 source/native evidence boundaries are recorded in
[CPA_INTEGRATION.md](docs/reports/CPA_INTEGRATION.md) and
[LEO_VERIFICATION_HANDOFF.md](docs/LEO_VERIFICATION_HANDOFF.md). The older
[PHASE0_CPA_CONTRACT.md](docs/reports/PHASE0_CPA_CONTRACT.md) remains historical
Phase 0 evidence. The current candidate is tracked separately in
[ROUND4_LEO_REVIEW_HANDOFF.md](docs/ROUND4_LEO_REVIEW_HANDOFF.md), whose status
remains pending. Historical evaluation datasets are frozen; do not rerun or
tune against individual v10 rows.

## Developer and auditor checks

The following checks are source-only/safe development gates; they do not deploy
CPA, load a `.so`, or open consumed evaluation samples:

```bash
make format-check git-diff-check module-verify
./scripts/go-safe-development-test.sh test
./scripts/go-safe-development-test.sh race
./scripts/go-safe-development-test.sh boundary
make vet fuzz-smoke corpus-regression script-test

# Visible development-only adversarial corpus; never a future Holdout.
go test ./cmd/development-adversarial-v11-prep-validator \
  -run '^TestDevelopmentAdversarialV11PrepCorpus$' -count=1

# Explicit source-only CPA v7.2.75 store and host contracts.
go -C integration/pluginstorecontract test ./... -count=1
```

The safe script is the required broad Go gate. `make unit-test`, `make race`,
and `make consumed-boundary-test` resolve to those safe modes. Do not replace
them with a broad invocation that can open retired or consumed evaluation
fixtures.

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
| `cmd/development-adversarial-v11-prep-validator/` | Strict validator for the visible development-only adversarial corpus |
| `internal/classifier/` | Deterministic policy evaluation and historical gates |
| `internal/extract/` | Provider-aware, bounded request extraction and decoding |
| `internal/plugin/` | Router, executor, management, runtime health, and reconfiguration |
| `internal/audit/` | Privacy-minimal SQLite events, migrations, retention, and subject state |
| `rules/` | Embedded versioned YAML cyber-abuse policy assets |
| `integration/` | CPA integration and isolated official-source contract modules |
| `scripts/` | Build, package, verify, reproduce, health-check, and release tooling |
| `testdata/` | Regression data, explicitly development-only adversarial data, and frozen historical evaluation evidence; development data is never a future Holdout |
| `docs/` | Design, operations, limitations, threat model, audit handoff, and reports |

Ignored local `dist/`, `coverage.out`, databases, logs, and secret files are
not repository source or formal release evidence.

## Documentation

| Audience | Start here |
|---|---|
| Project evaluator | [Design](docs/DESIGN.md), [Limitations](docs/LIMITATIONS.md), [Threat model](docs/THREAT_MODEL.md) |
| Security auditor | [Round-four handoff](docs/ROUND4_LEO_REVIEW_HANDOFF.md), [Audit handoff](docs/AUDIT_HANDOFF.md), [Release evidence](docs/reports/RELEASE_EVIDENCE.md), [Test report](docs/reports/TEST_REPORT.md) |
| CPA integrator | [CPA integration](docs/reports/CPA_INTEGRATION.md), [Phase 0 contract](docs/reports/PHASE0_CPA_CONTRACT.md), [Docker operations](docs/INSTALL_DOCKER.md) |
| Policy reviewer | [Rules](docs/RULES.md), [Classifier redesign baseline](docs/reports/CLASSIFIER_REDESIGN_BASELINE.md), [Privacy](docs/reports/PRIVACY.md), [Prompt-injection review](docs/reports/PROMPT_INJECTION_REVIEW.md) |
| Future maintainer | [Next-version recommendations](docs/NEXT_VERSION.md), [Changelog](CHANGELOG.md) |

## Security reporting

Please follow [SECURITY.md](SECURITY.md). Do not include live credentials,
private prompts, OAuth material, or production account identifiers in an issue.

## License

[MIT](LICENSE)
