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
> This source tree carries the **round5.2 source-freeze / pre-merge record**.
> It records only evidence that can be fixed before merge: source identity,
> safe local gates, exact-source branch push CI, the PR synthetic merge-result
> gate, and review state. Post-merge main CI, the exact-main artifact, tag,
> release flags, and release asset hashes are authoritative only through GitHub
> API metadata; the corresponding Release notes link those records, list the
> per-asset hashes, and preserve every incomplete gate. The historical
> `v0.1.2-dev.round5.1` prerelease is `BLOCKED / NOT FOR DEPLOYMENT`; its tag
> points to `89b62b341278073e7b6518b85e41cd7f7c6b682c` and must never be moved or
> reused. The stable v0.1.2 release decision remains **BLOCKED**, and the only
> methodologically valid v10 evaluation remains `CONSUMED / FAIL`. Do not deploy
> either candidate to production. Engineering success is not production
> admission, and the recorded methodology incidents independently keep handoff
> blocked.

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
| Repository state | Round5.2 source-freeze/pre-merge record on `agent/post-release-reaudit-fixes`, based on historical `main@89b62b341278073e7b6518b85e41cd7f7c6b682c`; pending pre-merge fields must be backfilled without guessing future values |
| Release decision | **BLOCKED / NOT PRODUCTION-READY** |
| Formal evaluation | v10 `CONSUMED / FAIL`: benign FP 28/320, policy blocked 49/320, exact 33/320 |
| Historical development prerelease | [`v0.1.2-dev.round5.1`](https://github.com/yujianwudi/cyber-abuse-guard/releases/tag/v0.1.2-dev.round5.1), `prerelease=true`, `latest=false`, tag target `89b62b341278073e7b6518b85e41cd7f7c6b682c`; project-policy historical snapshot, while GitHub reports `isImmutable=false`; not production approval |
| Round5.2 pre-merge evidence | Safe local gates and CPA latest compatibility **PASS**; PR [#8](https://github.com/yujianwudi/cyber-abuse-guard/pull/8) is open; CodeRabbit CLI `0.6.5` raised 0 issues on the final uncommitted diff; source-freeze commit and exact-source branch/PR CI remain **PENDING PRE-MERGE BACKFILL** |
| Round5.2 post-merge evidence | Main CI, exact-main artifact, tag, release flags, and release asset hashes are **EXTERNAL EVIDENCE — GITHUB API METADATA + LINKED RELEASE NOTES** |
| Runtime baseline | CPA `v7.2.75`, commit `e57416731aec87051ac00d0812df6aebd0e9d57a`, C ABI/RPC schema v1 |
| CPA v7.2.75 checksums | module `h1:WcCCeENtQ5F2bT86FVIOZJJbWCkPqrp3idl8kyZqARM=`; go.mod `h1:f4pcyAej8RoeRhIxJfm+OUMkCKaApiA8WzxR2XVlBh8=` |
| Latest CPA source/compile lane | CPA `v7.2.80`, commit `09da52ad509e2c18e7b9540db3b98c2214c280aa`; module `h1:QIa5T/KYvJACHVPPRzXcRwq/HLpbwWYJYpZAC1eY2WA=`; go.mod `h1:ytvZNWbCv7PrAyR80+RKsDJPODsdL6qxyFaXDBNZdqs=`; `CPA_LATEST_VERIFY_REMOTE=1 make cpa-latest-compat` verified `releases/latest` and Tag-to-Commit; pinned checksums, compile-only, Router, and fail-open checks also passed; source-freeze branch CI pending; no Host start or `.so` load |
| Documented build target | Linux amd64, glibc 2.34 or newer, CPA C ABI/RPC schema v1 |
| Unsupported platform | musl/Alpine |
| Embedded YAML ruleset | `1.0.7`, SHA-256 `7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134` |
| Round5.2 source-bound classifier policy | `classifier-policy-v2`, SHA-256 `e9b87f7e2635495bdbceae469ef89e696b419f0a9a6fd129558a20bc4be947ec`; exact source-freeze commit remains a separate pre-merge field |
| Round5.2 re-audit blockers | Development self-checks closed classifier reversal/performance defects, the Balanced proof-budget downgrade, a large-request top-level tool-definition blind spot, and missing native `interactions` format registration; exact-source CI remains pending |
| Historical round5.1 classifier policy | `classifier-policy-v2`, SHA-256 `c2092d0949fcaa1d0f085dfe31a668d45cc4d14efc10427d0f3ebcf3e821a112` |
| Round5.2 source-freeze validation | **LOCAL SAFE GATES PASS; SOURCE-FREEZE COMMIT/CI PENDING**. Historical round5.1 evidence is retained below and must not be presented as validation of round5.2. |

## Fifth-round boundary and review status

- The Router sees only the request delivered by CPA. It cannot attest to the
  path, owner, mode, SHA-256/signature, reload history, or contents of a local
  `model_instructions_file`, `AGENTS.md`, remote instruction template, or other
  client-side high-priority configuration loaded before the request reaches
  CPA. The host must enforce path allowlists, owner/mode checks, immutable hash
  or signature binding, reload-time verification, and audited template changes.
- Provider controls such as `safetySettings`, `generationConfig`, and `options`
  are not prompt text and are not safely governed by keyword matching. The host
  must apply a versioned schema allowlist and reject or forcibly overwrite
  unsafe values before routing.
- The only fifth-round key-only mapping is explicitly activated by
  `cag_control_schema=meta_override_control/v1` inside an established
  tool/tool-payload object. The same key outside tool provenance does not
  activate semantic mapping, and arbitrary business JSON keys are never
  promoted to prompt text.
- Embedded ruleset `1.0.7` identifies only the YAML Cyber Abuse assets. It does
  **not** include the Go-level `META-OVERRIDE-001` overlay, extraction semantics,
  tool-schema mappings, or control-plane telemetry. The classifier-policy
  identity and exact Git commit are required alongside the ruleset identity.
- The visible `development-public-jailbreak-patterns-v1` corpus contains 36
  sanitized cases (18 allow / 18 audit), five protocols, 13 carriers, 19
  transforms, and five abstract source contexts. The added evidence covers
  mixed system/developer/tool composition, local instruction and managed
  `AGENTS` contexts, Skill/MCP payloads, semantic aliases, concealed overrides,
  boundary-split continuation, HTML-comment modules, and long benign padding.
  It remains development-only, contains no live payloads, and is permanently
  ineligible for a future blind Holdout. `source_context` is test metadata, not
  proof that runtime text came from a named repository or local file.
- Ordinary CI no longer invokes any evaluation-v10 boundary target. The manual
  `consumed-boundary-test` target remains only for separately authorized audit
  work and is not a routine development or CI gate.
- Role-aware classification deliberately does not compose a base Cyber Abuse
  taxonomy from system/assistant text into a later user message. This prevents
  provider policy examples and refusals from becoming user intent, but means
  the host must authenticate every high-priority instruction source and enforce
  its owner, mode, hash/signature, and reload policy before the request reaches
  CPA.
- `Segments` are currently derived by a second bounded JSON parse after the
  primary extractor walk. Differential, race, fuzz, and scalar-media tests have
  not reproduced semantic leakage, but a future refactor should emit Parts and
  Segments from one semantic parse product to remove parser-drift risk.
- The base-to-freeze history contains one composite fifth-round implementation
  commit. Exact post-fix regressions are green, but no independently preserved
  pre-fix red-test commit or command log exists. The task-book requirement to
  prove both HIGH cases red before the fix remains an independent audit item.
- During this fifth-round review, one over-broad read-only `git grep`
  unexpectedly emitted content from the restricted
  `testdata/holdout/malicious-operational.jsonl` file. No holdout test ran; the
  output was not redirected, copied into source/tests/docs, analyzed, or used
  for tuning or conclusions. During the later release audit, one classifier
  source search also unintentionally matched historical holdout gate-test source
  lines; it did not open any `testdata` corpus or run any holdout/evaluation
  test, and that output was not used for implementation decisions. All remaining
  commands are explicitly scoped away from holdout/evaluation paths. These
  incidents mean the round cannot truthfully claim zero restricted-corpus access
  and independently keep handoff blocked.
- During the post-release round5.2 re-audit, a case-insensitive path exclusion
  failed and a read-only status search printed exactly one status line from each
  of `EVALUATION_V5_REPORT.md` through `EVALUATION_V10_REPORT.md`. No evaluation
  corpus or sample row was opened, printed, classified, extracted, or used for
  any source, test, documentation, or release decision. This additional
  disclosure does not change the frozen v10 `CONSUMED / FAIL` result and keeps
  methodology handoff blocked.
- During the same re-audit, a classifier sub-agent mistakenly started
  `go test -shuffle=on -count=20 ./...`. The root process interrupted it after
  about 23 seconds and sent `TERM` to PID `265343`. The same command then
  reappeared as PID `266741` with WSL `/init` as its parent, consistent with an
  orphaned CodeRabbit/tool session. The root interrupted the classifier agent
  again, terminated every matching process, and verified that none remained.
  It is not known whether any consumed evaluation or Holdout test selected or
  read a restricted fixture before termination. The command and every partial
  result are permanently excluded and were not used for source, tests,
  documentation, or release decisions. Subsequent validation is restricted to
  the explicit safe allowlist. The round cannot claim no restricted access;
  v10 remains `CONSUMED / FAIL`, and handoff remains blocked.
- During the final independent diff audit, one overly broad read-only
  `cmd/**/*.go` search printed snippets from evaluation/holdout author source
  and a few synthetic examples. It did not open `testdata` restricted corpora,
  run an author/evaluation/holdout tool, or inform any implementation, test,
  documentation, or release conclusion. The output is permanently excluded;
  this additional disclosure keeps the methodology claim blocked.

The root `go.mod` and `integration/pluginstorecontract` module both pin CPA
v7.2.75. Source contracts enumerate and run 16 exact official Host tests, while
the native harness installs the real Store ZIP, loads the real Guard `.so`, and
uses a pure-C second Router/executor fixture. Source or compile-only results do
not prove native compatibility: fifth-round ordinary CI executes bounded
source-contract tests and compiles the integration-tagged package without
starting CPA or loading the `.so`. The canonical exact-source artifact has been
statically verified, but the Tencent Cloud CPA v7.2.75 isolated-Host matrix and
independent review are still not run.

An independent `integration/cpalatestcontract` module and
`scripts/cpa-latest-compat.sh` pin CPA v7.2.80 separately from that runtime
baseline. They compile the Guard and integration packages through a temporary
modfile, run the real Guard registration and role-routing probes, list and run
17 official Host routing/status tests plus 11 official Interactions
route/handler tests, and apply three checksum-pinned ephemeral overlays for
Host fail-open, Interactions handler/translator, and direct executor-format
behavior. This proves source/compile compatibility only. It does not start CPA,
load a Guard `.so`, install from Store, or validate end-to-end request
reconstruction and upstream-isolation behavior on v7.2.80.

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
historical evidence for implementation freeze `61536f9`. Historical round5.1
merged as `89b62b341278073e7b6518b85e41cd7f7c6b682c` and has exact-main CI and a
statically verified dirty development artifact. It still has no CPA v7.2.75
real-Host matrix or independent verification. Round5.2 source-freeze and
pre-merge evidence belongs in this source tree; its post-merge evidence belongs
in GitHub API metadata, with links, per-asset hashes, and remaining blocks
summarized in the corresponding Release notes.

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
| Round5.2 source-freeze, local gates, branch push CI, PR merge-result CI, PR, and review | **PENDING PRE-MERGE BACKFILL**; no historical round5.1 SHA, run, or artifact may be substituted |
| Round5.2 post-merge main CI, exact-main artifact, tag, and release | **EXTERNAL EVIDENCE — GITHUB API METADATA + LINKED RELEASE NOTES**; this source tree does not self-reference future merge/release identities |
| Historical round5.1 merge and development prerelease | Merge/tag commit `89b62b341278073e7b6518b85e41cd7f7c6b682c`; main run [29409182748](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29409182748) attempt 1 failed at a fuzz timer boundary and attempt 2 passed all jobs; artifact ID `8340894661`, container digest `sha256:7419fcf0c0745472728d6e9c73d99aa01737930ccf25e26501e17ae4d453db61`, SO SHA-256 `3176d2af23963a2768672034af02fc1ca9ebe0c3f29a3654aa802ce0f822b6be`; historical prerelease only |
| Fifth-round CPA v7.2.75 isolated Host and independent review | **NOT RUN / PENDING** — ordinary CI is source-contract plus integration compile-only; no CPA process was started and no `.so` was loaded |
| CPA v7.2.80 latest source/compile compatibility | **DEVELOPMENT SELF-CHECK PASS; EXACT-SOURCE GITHUB CI PENDING** — `CPA_LATEST_VERIFY_REMOTE=1 make cpa-latest-compat` verified GitHub `releases/latest` and Tag-to-Commit; pinned module checksums, Guard/integration compile probes, real Guard registration/route tests, 17 official Host routing/status tests, 11 official Interactions route/handler tests, and three checksum-pinned overlays also passed; not native Host evidence |
| Historical safe unit/race boundary, vet, fuzz-smoke, regression, build, packaging, and reproducibility workflows | **GITHUB CI PASS** on earlier implementation freeze `61536f9`; push run [29312969925](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29312969925) and PR run [29312971717](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29312971717); not fifth-round evidence |
| Safe Go development scripts | `test`, `race`, and bounded development gates **DEVELOPMENT SELF-CHECK PASS**; the implementation freeze is also covered by exact-source push CI and PR merge validation |
| CPA Store ZIP naming/layout/install source contract | **GITHUB CI PASS** against official CPA v7.2.75 source; this is not a real Store install or native Host load |
| CPA Router ordering/fallback source contract | **GITHUB CI PASS** against official CPA v7.2.75 source; this is not the isolated Host matrix |
| Local executor refusal contract | RPC error envelopes request 403 for `execute`, `execute_stream`, and `count_tokens`; `http_request` has a SOURCE/ADAPTER status-error 405 check with no response only |
| Historical native plugin loading | **GITHUB CI PASS** for the earlier v7.2.72 freeze; current CPA v7.2.75 Store artifact/load is **PENDING** |
| Historical OpenAI Chat / Responses / Claude / Gemini server matrix | **GITHUB CI PASS** on the earlier v7.2.72 freeze; fifth-round Host cases are pending and ordinary CI is compile-only |
| Historical zero Auth Selector / Usage / Provider / upstream calls on blocked requests | **GITHUB CI PASS** on the earlier freeze; the fifth-round exact artifact's real-Host zero-side-effect proof is not run |
| Historical Multi-Router/fail-open and management proxy 413 matrices | **GITHUB CI PASS** on the earlier freeze — 15 native Router scenarios and proxy rejection before the counted CPA handler |
| Final official CPA client HTTP 405 for `executor.http_request` | **NOT AVAILABLE / NOT RUN** — `/v1/alpha/search` is provider-specific, normally selects `codex`, and maps every executor error to 502; no current official route maps Guard's 405 error to final 405 |
| Historical PR #7 CodeRabbit evidence | A local CLI follow-up recorded 0 issues, but the GitHub bot comment later ended with `Review failed — pull request is closed`; no CodeRabbit approval is claimed |
| Round5.2 CodeRabbit review | **PENDING / NOT RUN** |
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

An additional, distinct fifth-round incident occurred later: one over-broad
read-only `git grep` unexpectedly emitted content from the restricted
`testdata/holdout/malicious-operational.jsonl` file. It did not run a holdout
test, redirect or retain a separate output file, feed any source/test/document,
or influence tuning or conclusions. Nevertheless, this round must not state
that no restricted corpus was accessed, and its methodological handoff remains
blocked even if all engineering gates pass.

Historical v7.2.72 source/native evidence boundaries are recorded in
[CPA_INTEGRATION.md](docs/reports/CPA_INTEGRATION.md) and
[LEO_VERIFICATION_HANDOFF.md](docs/LEO_VERIFICATION_HANDOFF.md). The older
[PHASE0_CPA_CONTRACT.md](docs/reports/PHASE0_CPA_CONTRACT.md) remains historical
Phase 0 evidence, and
[ROUND4_LEO_REVIEW_HANDOFF.md](docs/ROUND4_LEO_REVIEW_HANDOFF.md) is a historical
round-four handoff. [PR #7](https://github.com/yujianwudi/cyber-abuse-guard/pull/7)
and `v0.1.2-dev.round5.1` are treated as historical round5.1 snapshots by
project policy; GitHub currently reports `isImmutable=false`, so API metadata
and hashes are point-in-time evidence rather than platform-enforced immutability. The
round5.2 source-freeze/pre-merge record is tracked by
[AUDIT_HANDOFF.md](docs/AUDIT_HANDOFF.md),
[TEST_REPORT.md](docs/reports/TEST_REPORT.md), and
[RELEASE_EVIDENCE.md](docs/reports/RELEASE_EVIDENCE.md); post-merge evidence is
tracked by GitHub API metadata and linked from its Release notes. Historical evaluation
datasets are frozen; do not rerun or tune against individual v10 rows.

## Developer and auditor checks

The following checks are source-only/safe development gates; they do not deploy
CPA, load a `.so`, or open consumed evaluation samples:

```bash
make format-check git-diff-check module-verify
./scripts/go-safe-development-test.sh test
./scripts/go-safe-development-test.sh race
make vet fuzz-smoke corpus-regression script-test
make round4-regression round5-regression
make development-public-jailbreak-corpus

# Visible development-only adversarial corpus; never a future Holdout.
go test ./cmd/development-adversarial-v11-prep-validator \
  -run '^TestDevelopmentAdversarialV11PrepCorpus$' -count=1

go test ./cmd/development-public-jailbreak-patterns-v1-validator \
  -run '^TestDevelopmentPublicJailbreakPatternsV1Corpus$' -count=1

# Explicit source-only CPA v7.2.75 store and host contracts.
go -C integration/pluginstorecontract test ./... -count=1

# Latest CPA v7.2.80 source/compile lane; no Host process or .so load.
make cpa-latest-compat

# Ordinary CI compiles integration-tagged code but does not start CPA.
make integration-compile
```

The safe script is the required broad Go gate. `make unit-test` and `make race`
resolve to its sample-safe modes. Do not replace them with a broad invocation
that can open retired or consumed evaluation fixtures. The separately named
`make consumed-boundary-test` target is intentionally absent from ordinary CI
and must not be run without explicit evaluation-boundary authorization.

Ordinary fifth-round CI uses `make integration-compile`; it does not call
`make integration-test` or either Host blackbox target. Real `.so` loading and
the Host matrix are reserved for the later authorized Tencent Cloud CPA
v7.2.75 + Mock-upstream sandbox, not local development validation.

The release toolchain expects Go `1.26.4`. Linux-native build, integration,
SBOM, vulnerability, artifact, and reproducibility commands are documented in
[TEST_REPORT.md](docs/reports/TEST_REPORT.md) and
[RELEASE_EVIDENCE.md](docs/reports/RELEASE_EVIDENCE.md).

`make holdout-test` is not a routine developer check. The v10 dataset is
consumed, and its gate deliberately refuses a rerun. `make formal-release`
must not be run for the current blocked candidate.

## Artifact contracts

Development CI may build dirty-suffixed evidence artifacts. No formal stable
v0.1.2 release artifact exists. The historical `v0.1.2-dev.round5.1`
prerelease attached only dirty, non-production assets and must remain bound to
its existing tag; it must not be moved to later source.

The historical round5.1 exact-main artifact is
`cyber-abuse-guard-linux-amd64-dirty`, ID `8340894661`, size `10691298` bytes,
container digest
`sha256:7419fcf0c0745472728d6e9c73d99aa01737930ccf25e26501e17ae4d453db61`,
expiring `2026-10-13T10:54:12Z`. Its build metadata binds merge commit
`89b62b341278073e7b6518b85e41cd7f7c6b682c`; the SO SHA-256 is
`3176d2af23963a2768672034af02fc1ca9ebe0c3f29a3654aa802ce0f822b6be`.
Release assets were hashed individually; the Actions artifact is recorded only
by its container digest, without a retained member-to-asset equivalence map.
This is historical development evidence, not validation of round5.2. Any
round5.2 exact-main artifact and release asset hashes are intentionally recorded
in GitHub API metadata and linked/summarized in the corresponding Release notes
rather than self-claimed here.

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
| `cmd/development-public-jailbreak-patterns-v1-validator/` | Strict validator for sanitized, public-taxonomy-derived development canaries |
| `internal/classifier/` | Deterministic policy evaluation and historical gates |
| `internal/extract/` | Provider-aware, bounded request extraction and decoding |
| `internal/plugin/` | Router, executor, management, runtime health, and reconfiguration |
| `internal/audit/` | Privacy-minimal SQLite events, migrations, retention, and subject state |
| `rules/` | Embedded versioned YAML cyber-abuse policy assets |
| `integration/` | CPA integration and isolated official-source contract modules |
| `scripts/` | Build, package, verify, reproduce, health-check, and release tooling |
| `testdata/` | Regression data, explicitly development-only adversarial/canary data, and frozen historical evaluation evidence; development data is never a future Holdout |
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
