# Threat Model

## Protected assets

- upstream OpenAI/Codex and other provider accounts behind CPA;
- downstream API credentials and authenticated identities;
- request privacy, including prompts, uploaded code, cookies, and tokens;
- CPA availability and correct routing/accounting behavior;
- structural integrity and operational availability of audit and subject-control state.

## Trust boundaries

The plugin is trusted in-process native code. Downstream request bodies,
headers, tool arguments, plugin YAML configuration, optional rule data, and
management test input are untrusted. CPA's Plugin Host and authenticated
management middleware are trusted. No upstream or external classifier is
trusted with request text.

The root dependency is CPA v7.2.75 at upstream tag commit
`e57416731aec87051ac00d0812df6aebd0e9d57a`. Source overlays, developer tests,
authorized GitHub CI, and Leo's isolated real-Host run are separate evidence
classes. A source implementation, local WSL run, or older PASS is never treated
as proof for the implementation freeze. The fourth-round CI artifact and CPA
v7.2.75 isolated-Host matrix are currently pending.

## Principal threats and controls

| Threat | Control |
|---|---|
| Explicit malicious request reaches an upstream account | ModelRouter runs before provider/auth selection; handled decisions target only the local executor. The historical v7.2.72 harness counted Auth Selector, Provider, Usage, and Mock Upstream calls independently for four protocols, but does not validate this candidate. The fourth-round v7.2.75 artifact/Host matrix and Leo independent verification are pending. |
| Another router handles the request first | Install at priority 300, verify effective ordering, disable the obsolete identity-rewrite filter, and document that any higher-priority handled Router can bypass this guard. At equal priority CPA orders by plugin ID ascending, so a lexicographically earlier handled Router can also win. |
| Plugin is absent, registration fails, it is fused, or its self executor is unusable | Treat load/registration/fuse state, Router errors or pre-result panics, invalid/empty targets, and executor-not-ready as CPA host fail-open conditions that may continue other Routers or native routing. `enforcement_ready` is internal plugin state only; external load/order/readiness monitoring remains required. |
| Keyword-only false positive blocks legitimate security work | Base behavior requires related action/object plus operationalization, target, evasion, impact, or scale evidence; defensive/lab/remediation scope is explicit and wrapper evidence cannot manufacture a taxonomy. |
| Instruction-hierarchy or unrestricted-persona replacement controls the model | Multi-family `META-OVERRIDE-001` is wrapper/amplifier evidence only. Wrapper-only requests allow or audit; a wrapper can increase confidence only after an independent dangerous behavior relation exists. |
| Refusal/safety-disable inversion is presented as a safety policy | Policy wording that negates refusal, blocking, filtering, guardrails, or safety checks is treated as hostile control rather than benign policy suppression. |
| Fake sandbox, benchmark, placeholder, or authorization scope washes a real target | Prompt-derived CTF/lab/fictional/authorization claims do not reduce the meta-override overlay; explicit negative authorization increases risk. |
| System/developer prompt or hidden-reasoning disclosure is forced through exact-output controls | Protected-disclosure evidence composes with hierarchy/output-control signals and emits only fixed evidence IDs, never the requested secret text. |
| Caller hides intent with casing, spaces, punctuation, zero-width characters, light leetspeak, URL/HTML/Base64/text-data encoding, or nested tool JSON | Bounded Unicode normalization, compact matching, at most two decode layers/eight variants, and explicit byte budgets; no claim of resistance to arbitrary adversarial encoding. |
| Supported `SourceFormat` carries a forged or future schema | Failure to prove a recognized role envelope triggers the bounded untrusted-text walker instead of trusting the source label. |
| Tool output or a double-stringified payload carries an indirect instruction | Tool provenance is inspected separately and valid JSON-looking strings inside established tool payloads recurse under the shared budget. |
| A media marker placed after `source.data` turns opaque bytes into classifier text | Payload-adjacent `data`/`bytes`/`blob`/`binary`/`filename`/`format`/`detail`/`width`/`height`/`duration` values are bounded object-level candidates. A later media marker discards them before Parts, Segments, decoding, or text-budget accounting; a final non-media object commits them as text. Candidate propagation is restricted to media-style ownership, tool boundaries cut inherited media meaning, and opaque kinds have fixed ordering. |
| An attacker labels executable tool data as media to suppress inspection | Provider-native tool/tool-payload boundaries retain text semantics. Tool `data` remains inspectable and cannot make itself opaque merely by adding `type=image` outside a reviewed media container. |
| An unknown multipart field injects text into classification or creates a partial-score block | Multipart text is selected only by a fixed SourceFormat profile. `openai-image` admits prompt/negative-prompt text; unknown non-file fields and text/file type mismatches become fixed incomplete schema without retaining name/value. Balanced allows+audits, Strict blocks for the incomplete reason, and neither uses partial rule IDs, score, or subject state. |
| Parser tests are mistaken for real ingress/Host proof | CPA v7.2.75 `ModelRouteRequest` has no general HTTP path and the image handler may rebuild multipart before routing. Parser tests prove only the plugin-input contract; exact-artifact Host tests must separately prove CPA reconstruction, pre-SSE behavior, and Auth/Provider/Usage/upstream deltas. |
| Base64 or high-risk words are split across provider blocks, ordered tool fields, or isolated characters | Same-message content and ordered tool-payload/output strings are re-decoded after pristine joining, and a tightly bounded isolated-character reconstruction path closes simple fragmentation. |
| Public adversarial material contaminates later evaluation | External repositories are reviewed read-only, sanitized into mechanism-level development tests, never executed, and never reused as a blind Holdout. |
| JSON/decode/media resource exhaustion | Token walk, depth/part/byte budgets, 128 KiB encoded-source and 64 KiB decoded-variant caps, no decompression/archive expansion/network fetch, separate opaque-media policy, fuzz tests. |
| Artificial scan boundary inside a JSON escape or UTF-8 sequence becomes a router-error bypass | Boundary decode errors are classified as truncation rather than malformed complete JSON; enforcing modes fail closed, with escape and multibyte regression tests. |
| Base64-expanded plugin RPC exceeds the native copy cap before extraction | The native boundary recognizes oversized model-route/executor methods without copying the payload; Balanced/Strict self-route to a local scan-limit 403, and the real CPA test proves zero auth selection/upstream usage for a raw request above 6 MiB. |
| Token counting or HTTP forwarding bypasses a policy self-route | `executor.execute`, `executor.execute_stream`, and `executor.count_tokens` share the policy 403 path. `executor.http_request` has a SOURCE/ADAPTER status-error 405 check: the official adapter returns `nil,error`. CPA's public `/v1/alpha/search` consumer normally selects `codex` and maps every executor error to 502, so no current official route yields Guard's final client 405. The project wrapper is not official Host evidence; final 405 is `NOT AVAILABLE / NOT RUN` and blocks handoff. |
| Tool input hides abuse under a metadata-named key or reordered Anthropic block | Transport metadata remains excluded, but all textual fields inside tool payloads, including order-independent `tool_use.input` and `name`/`url`/`type`/`model`, are scanned under the shared budget. |
| Appended history or forged role labels hide earlier abuse | Standard role segments are each classified independently plus adjacent user follow-ups; role-less shapes use a conservative part fallback, unsupported roles fail closed, and history-cap truncation is never silent. |
| Router and executor retries count one logical request multiple times | Subject risk uses a domain-separated request digest and bounded idempotency receipts. The same subject/request pair is counted once across execute, stream, token count, retry, concurrency, pending-cache miss/expiry, enabled reconfigure, and shutdown races. Receipts persist with optional subject snapshots. |
| Regex denial of service | Default rules use normalized literal terms; validation rejects unsupported/oversized rule constructs. |
| Prompt or secret leakage through Guard audit | Fixed minimal event schema; SHA-256/HMAC correlation; tests search the DB for canary prompt/key/unknown-field values. This does not cover CPA Host request/error logs. |
| CPA Host logging persists request bodies outside the Guard audit boundary | CPA v7.2.75 may temporarily spool non-multipart bodies and persist a raw body in an HTTP error log. Sandbox tests use a temporary log directory and must review commercial mode, retention, permissions, canary absence/presence, and cleanup before any production observation. |
| Subject hash reversal/correlation or secret-file path swap | HMAC-SHA256 with a production mode-0600 regular-file secret; Linux uses `O_NOFOLLOW` and validates/reads the same descriptor; no plaintext subjects; status exposes no secret. |
| Persisted subject state leaks plaintext or is restored under a different key | Typed HMAC-only schema, bounded atomic snapshots, one-way key ID, explicit key mismatch with writes blocked, expiry/decay/capacity on restore. |
| Forged `X-Forwarded-For` | CPA v7.2.75 exposes no trusted peer address to ModelRouter, so v0.1.2 rejects trusted-proxy activation and never accepts the header as identity. |
| High-cardinality subject IDs exhaust memory or displace manual blocks | `max_subjects` defaults to 10,000; least-recent-risk non-manual entries are evicted, manual blocks are protected, and new risky subjects fail closed if no entry is evictable. |
| Audit DB lock/corruption takes CPA down or path swap changes another file | Busy timeout, bounded queue, fail-open audit path, deadline-bounded close, rate-limited diagnostics, exact schema/index/history validation, rejection of writable/final-symlink directories and DB/WAL/SHM symlinks, and visible runtime permission degradation. Enforcement continues while audit/persistence degrades. |
| A local DB writer deletes valid persisted subjects | Filesystem ownership/mode is the trust boundary. Schema v2 detects malformed or inconsistent rows but has no keyed whole-snapshot MAC and does not claim adversarial completeness. |
| v0.1.1 database upgrade is partial, exposes a temporary copy, or destroys the old store | Explicit schema version/history, transactional v1→v2 migration, private mode-0700 staging, mode-0400 sync-before-publish backup, bounded backup count, and failure rollback tests. |
| Invalid hot reload weakens policy or erases enforcement history | Parse/compile/validate full state before atomic swap; last valid state is retained; compatible enabled-to-enabled changes preserve subject risk, cooldown, and manual blocks; unsafe capacity shrink is rejected. |
| Plugin panic crashes CPA or bypasses enforcement | ABI entrypoints recover. A recovered `model.route` panic self-routes in a validated Balanced/Strict runtime and increments counters; other methods preserve a non-zero ABI failure signal. CPA may still fuse a plugin, so monitoring remains required. |
| Router error silently weakens enforcement | Known scan-boundary, oversized-RPC, recovered panic, and guarded Router failures self-route in enforcing modes. Status exposes readiness/error/panic counters; the watchdog alarms on deltas. CPA v7.2.75 still owns a host-level fail-open policy that the plugin cannot change. |
| Management test/unblock exposed to normal API keys | Routes registered exclusively through CPA Management API; no public resource routes. |
| Oversized management HTTP body is fully buffered by CPA before plugin limits run | CPA currently uses `io.ReadAll` in `ServeManagementHTTP`, so plugin 1 MiB body / 2 MiB envelope checks are not a host memory ceiling. The deployment proxy sets `client_max_body_size 1m`; the server sandbox must prove Nginx returns 413 before CPA receives the request. |
| CPA store rejects or misinstalls the release archive | Keep the store ZIP separate from the audit bundle. CI must require real `.so`/ZIP/metadata/checksums, use `InstallManifest` for first install and Host load, then verify same-Dist repeat-skip/tamper-repair with `TestPublishedStoreArchive`. Synthetic fallback is source evidence only. |
| SSRF or prompt/media exfiltration via classifier or URL inspection | v0.1.2 rejects classifier activation, never fetches media URLs, and performs no outbound classification/telemetry call. |
| Identity spoofing to evade upstream policy | Plugin never changes model, system prompt, client name, headers that claim identity, or upstream safety declarations. |

## Abuse cases intentionally still blocked

An assertion of authorization does not by itself permit deployment-oriented
credential theft, phishing collection, ransomware, or data exfiltration. A
request for static analysis, detection, containment, or remediation can still
be allowed when those defensive signals dominate and no deployment intent is
present.

## Residual risk

Deterministic local rules cannot infer intent perfectly, can be evaded by novel
language or encoding, and can produce false positives/negatives. Decoding is
bounded, images/audio/video are not semantically inspected, and public media
URLs are never fetched. `observe` and `audit` deliberately do not block. CPA or
upstream behavior outside the pinned ABI may change. The repository root now
targets CPA v7.2.75, but only the pending authorized GitHub CI artifact plus
Leo's independent real-Host run against the implementation freeze can establish
compatibility. CPA retains the host-level Router fail-open conditions described
above. Holdout/evaluation generations v1-v9 are
retired, consumed, or methodology-invalid history; methodologically valid v10
was consumed and failed. Any future release attempt requires a new
independently authored unseen set for a materially new implementation and must
not reuse v10 or the visible 35-case
`development-adversarial-v11-prep` corpus. Upstream providers independently enforce their own policies.
Therefore the plugin reduces risk but cannot guarantee that an account will
never be warned, suspended, or deactivated.

The classifier remains stateless across separate API calls, cannot attest to
the owner, permissions, or hash of a local instruction file before a request
reaches CPA, and does not claim arbitrary-transform or opaque-media semantic
coverage. Local WSL Host/Router/proxy commands were mistakenly executed with
loopback/Mock components and cleaned up without residual processes, but are
excluded from evidence. Historical results are reported in
`reports/TEST_REPORT.md` and `LEO_VERIFICATION_HANDOFF.md`; the current pending
candidate is in `ROUND4_LEO_REVIEW_HANDOFF.md`. Any missing final-commit Host,
GitHub CI, artifact, or proxy result is **NOT RUN** or **BLOCKED**, never an
inferred PASS.
