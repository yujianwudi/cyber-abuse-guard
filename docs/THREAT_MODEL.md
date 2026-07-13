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

## Principal threats and controls

| Threat | Control |
|---|---|
| Explicit malicious request reaches an upstream account | ModelRouter runs before provider/auth selection; handled decisions target only the local executor; integration test asserts mock call count remains zero. |
| Another router handles the request first | Install at priority 300, verify effective ordering, disable the obsolete identity-rewrite filter, and document that any higher-priority handled router can bypass this guard. |
| Keyword-only false positive blocks legitimate security work | Multi-evidence rules, explicit defensive/lab/remediation contexts, bilingual benign corpus, balanced threshold. |
| Caller hides intent with casing, spaces, punctuation, zero-width characters, light leetspeak, URL/HTML/Base64/text-data encoding, or nested tool JSON | Bounded Unicode normalization, compact matching, at most two decode layers/eight variants, and explicit byte budgets; no claim of resistance to arbitrary adversarial encoding. |
| JSON/decode/media resource exhaustion | Token walk, depth/part/byte budgets, 128 KiB encoded-source and 64 KiB decoded-variant caps, no decompression/archive expansion/network fetch, separate opaque-media policy, fuzz tests. |
| Artificial scan boundary inside a JSON escape or UTF-8 sequence becomes a router-error bypass | Boundary decode errors are classified as truncation rather than malformed complete JSON; enforcing modes fail closed, with escape and multibyte regression tests. |
| Base64-expanded plugin RPC exceeds the native copy cap before extraction | The native boundary recognizes oversized model-route/executor methods without copying the payload; Balanced/Strict self-route to a local scan-limit 403, and the real CPA test proves zero auth selection/upstream usage for a raw request above 6 MiB. |
| Tool input hides abuse under a metadata-named key or reordered Anthropic block | Transport metadata remains excluded, but all textual fields inside tool payloads, including order-independent `tool_use.input` and `name`/`url`/`type`/`model`, are scanned under the shared budget. |
| Appended history or forged role labels hide earlier abuse | Standard role segments are each classified independently plus adjacent user follow-ups; role-less shapes use a conservative part fallback, unsupported roles fail closed, and history-cap truncation is never silent. |
| Regex denial of service | Default rules use normalized literal terms; validation rejects unsupported/oversized rule constructs. |
| Prompt or secret leakage through audit | Fixed minimal event schema; SHA-256/HMAC correlation; tests search the DB for canary prompt/key values. |
| Subject hash reversal/correlation or secret-file path swap | HMAC-SHA256 with a production mode-0600 regular-file secret; Linux uses `O_NOFOLLOW` and validates/reads the same descriptor; no plaintext subjects; status exposes no secret. |
| Persisted subject state leaks plaintext or is restored under a different key | Typed HMAC-only schema, bounded atomic snapshots, one-way key ID, explicit key mismatch with writes blocked, expiry/decay/capacity on restore. |
| Forged `X-Forwarded-For` | CPA v7.2.67 exposes no trusted peer address to ModelRouter, so v0.1.2 rejects trusted-proxy activation and never accepts the header as identity. |
| High-cardinality subject IDs exhaust memory or displace manual blocks | `max_subjects` defaults to 10,000; least-recent-risk non-manual entries are evicted, manual blocks are protected, and new risky subjects fail closed if no entry is evictable. |
| Audit DB lock/corruption takes CPA down or path swap changes another file | Busy timeout, bounded queue, fail-open audit path, deadline-bounded close, rate-limited diagnostics, exact schema/index/history validation, rejection of writable/final-symlink directories and DB/WAL/SHM symlinks, and visible runtime permission degradation. Enforcement continues while audit/persistence degrades. |
| A local DB writer deletes valid persisted subjects | Filesystem ownership/mode is the trust boundary. Schema v2 detects malformed or inconsistent rows but has no keyed whole-snapshot MAC and does not claim adversarial completeness. |
| v0.1.1 database upgrade is partial, exposes a temporary copy, or destroys the old store | Explicit schema version/history, transactional v1→v2 migration, private mode-0700 staging, mode-0400 sync-before-publish backup, bounded backup count, and failure rollback tests. |
| Invalid hot reload weakens policy or erases enforcement history | Parse/compile/validate full state before atomic swap; last valid state is retained; compatible enabled-to-enabled changes preserve subject risk, cooldown, and manual blocks; unsafe capacity shrink is rejected. |
| Plugin panic crashes CPA or bypasses enforcement | ABI entrypoints recover. A recovered `model.route` panic self-routes in a validated Balanced/Strict runtime and increments counters; other methods preserve a non-zero ABI failure signal. CPA may still fuse a plugin, so monitoring remains required. |
| Router error silently weakens enforcement | Known scan-boundary, oversized-RPC, recovered panic, and guarded Router failures self-route in enforcing modes. Status exposes readiness/error/panic counters; the watchdog alarms on deltas. CPA v7.2.67 still owns a host-level fail-open policy that the plugin cannot change. |
| Management test/unblock exposed to normal API keys | Routes registered exclusively through CPA Management API; no public resource routes. |
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
upstream behavior outside the pinned ABI may change, and CPA v7.2.67 retains a
host-level Router fail-open boundary. Holdout v1 and v2 are consumed historical
evidence; the separately authored blind v3 is required before release. Upstream
providers independently enforce their own policies. Therefore the plugin
reduces risk but cannot guarantee that an account will never be warned,
suspended, or deactivated.
