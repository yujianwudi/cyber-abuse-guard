# CPA Cyber Abuse Guard v0.1.0 Design

## Scope and invariants

Cyber Abuse Guard is an in-process CPA C-ABI v1 plugin for CLIProxyAPI v7.2.67
(`2075f77c8ebe9ec872759965661936fb1ac2931f`). It reduces the chance that a
downstream caller sends clearly malicious, operational cyber-abuse requests to
an upstream account. It cannot guarantee that an account will not receive a
warning or be deactivated.

The implementation has three non-negotiable invariants:

1. A blocked request is routed by `ModelRouter` to the plugin's own executor
   before provider resolution and auth scheduling. The executor never invokes a
   host HTTP or host model callback.
2. A single keyword is never sufficient to block. Decisions require a harmful
   action/object combination plus operational, target, evasion, or scale
   evidence, with defensive and lab context applied explicitly.
3. The plugin never rewrites the requested model, client identity, or system
   prompt, and never sends request content to a classifier or third party.

## CPA ABI path

The shared object exports `cliproxy_plugin_init` and returns ABI version 1. The
JSON RPC capabilities are:

- `model_router`: inspect `ModelRouteRequest` before provider/auth selection;
- `executor`: terminate blocked non-streaming and streaming requests locally;
- `management_api`: expose management-key-protected status, event, stats, test,
  unblock, and delete routes.

The canonical CPA formats `openai`, `openai-response`, and `claude` are
declared as executor input and output formats. `gemini` is also declared and is
covered when the installed CPA handler routes that entry protocol through the
standard model-router path.

For an allowed request, `model.route` returns `Handled: false`. For a blocked
request, it returns `Handled: true`, `TargetKind: self`. The executor returns an
RPC error envelope with HTTP status 403 and the stable marker
`cyber_abuse_guard_blocked`. CPA v7.2.67 turns that error into the native error
shape for the entry protocol.

CPA v7.2.67's `ExecutorResponse` has payload and headers but no HTTP status.
Consequently, ABI v1 cannot simultaneously return an arbitrary plugin-owned
JSON body and a non-200 status from `executor.execute`. v0.1.0 favors the
security property and correct 403 status, using CPA's protocol error wrapper.
The stable marker and coarse category remain in the message; rule IDs and
bypass details do not.

## Request extraction

The extractor is format-tolerant and walks JSON tokens with bounded work:

- maximum JSON depth, text parts, and scanned text bytes are configurable;
- common text-bearing fields (`system`, `instructions`, `input`, `content`,
  `text`, and tool `arguments`) are collected across nested arrays/objects;
- role, model, identifiers, URLs, image fields, and known binary fields are not
  treated as prompt text;
- recognized media payloads and data URLs are omitted and marked truncated;
- unknown fields (including a tool argument named `data`) remain inspectable;
  long base64-like unknown strings are retained as text and marked truncated,
  so they cannot become a silent bypass;
- nested JSON inside tool arguments is scanned using the same shared budget;
- malformed JSON is a parse error, not automatically malicious;
- over-limit input is marked truncated without panicking.

The original request byte slice is used only during the call. It is never
stored in events or risk-control state.

## Deterministic classifier

Rules are versioned YAML embedded into the shared object. Startup compiles and
validates them once. Rules use literal normalized terms rather than runtime
regular expressions, eliminating catastrophic-backtracking risk.

Text is normalized with Unicode NFKC, lower-casing, removal of zero-width
format characters, whitespace folding, and a conservative adjacent-letter
leet normalization. Matching also uses a punctuation/space-compacted view for
light obfuscation.

Each category uses evidence groups:

- harmful action and dangerous object establish intent;
- operational detail, a real target, credential/data access, evasion, and
  scale/automation add risk;
- defensive analysis, remediation, static analysis, incident response,
  CTF/lab, explicit authorization, and high-level-only context subtract risk;
- an authorization statement alone does not override credential theft,
  phishing deployment, ransomware deployment, or data exfiltration.

The result contains only category, score, action, evidence IDs, and aggregate
context flags. It never contains matched prompt fragments.

Mode semantics are:

- `off`: skip extraction, classification, audit, and risk accumulation;
- `observe`: classify and update counters only; never block or persist events;
- `audit`: classify and persist minimal events; never block;
- `balanced`: block at `balanced_block` (default 60);
- `strict`: block at `audit` (default 35).

The mode definitions intentionally take precedence over the task book's
non-binding suggested statement that a score of 80 blocks every non-off mode;
otherwise `observe` and `audit` would not mean "never block".

## Subject risk control

Subject selection is ordered:

1. the downstream bearer/API key on the CPA-authenticated request, immediately
   HMACed in memory;
2. an anonymous bucket.

CPA v7.2.67 does not supply a distinct authenticated principal/key-policy ID or
a trustworthy direct-peer address to ModelRouter. v0.1.0 therefore rejects
`trusted_proxy.enabled: true`; forwarded headers alone are spoofable and are
never accepted as identity.

Plain API keys and IP addresses are never stored. The HMAC key comes from
`CYBER_ABUSE_GUARD_HMAC_KEY` or an explicitly configured mode-0600 secret file.
If no key is available, process-random key material is used and status reports
that hashes will not be stable across restarts.

Risk entries are in-memory rolling windows with time decay. Risk is added only
for results at or above the audit threshold. Repeat hits receive a bounded
multiplier. Cooldown/manual-block state applies only to new risky requests;
ordinary safe requests are not permanently denied. Manual blocks can be
cleared through the authenticated management API.

## Audit store

When enabled, SQLite stores only the minimal event schema. The database uses
WAL, a busy timeout, parameterized SQL, bounded asynchronous writes, retention
cleanup, and a configured maximum size. A database open/write failure degrades
to in-memory counters and rate-limited diagnostics; classification continues.

No prompt, message, authorization header, plaintext subject, token, cookie,
OAuth material, user code, or upstream account identity is persisted. Request
correlation uses SHA-256 of the raw body. Subject correlation uses HMAC-SHA256.

Reconfiguration builds and validates a complete immutable runtime state before
an atomic swap. Invalid configuration leaves the last valid state active. This
requires a CPA-specific behavior: `plugin.reconfigure` still returns the valid
registration envelope after a rejected update, because returning an RPC error
would make CPA omit the plugin from its next active snapshot. Status exposes
the rejected update as `last_config_error` and the plugin logs it through the
host logging callback.

## Management routes

Only CPA management routes are registered; no unauthenticated resource page is
exposed in v0.1.0.

- `GET /plugins/cyber-abuse-guard/status`
- `GET /plugins/cyber-abuse-guard/events`
- `GET /plugins/cyber-abuse-guard/stats`
- `POST /plugins/cyber-abuse-guard/test`
- `POST /plugins/cyber-abuse-guard/subjects/unblock` with
  `{"subject_hash":"..."}`
- `DELETE /plugins/cyber-abuse-guard/events`

CPA mounts these below `/v0/management` and enforces its Management Key before
the plugin handler runs. The test route does not persist its input.

CPA v7.2.67 management routes are exact matches and reject `:` or `*`, so the
task book's suggested `{hash}` path parameter cannot be registered safely.

## Failure behavior

- invalid initial config: plugin registration fails visibly;
- invalid reconfigure: keep the previous state, expose/log the error, and return
  the current valid registration so CPA keeps the plugin active;
- rule load/validation failure: registration/reconfigure fails;
- malformed request: allow and optionally audit `parse_error` outside `off`;
- audit failure: continue classifying and blocking;
- panic at the ABI boundary: recover and return an internal plugin error;
- optional classifier: interface reserved but not implemented in v0.1.0.

## Verification strategy

Unit tests cover extraction limits, scoring, modes, bilingual and obfuscated
inputs, hard-block exceptions, subject decay/cooldown, config rollback, SQLite
privacy, management handlers, and ABI envelopes. Separate corpora contain at
least 100 benign security prompts and 100 clearly malicious operational
prompts. Benchmarks report classifier latency and allocations.

The integration harness builds the `.so`, builds CPA at the pinned commit,
starts a local mock OpenAI-compatible upstream, and starts CPA with the plugin.
It asserts that a safe request increments the mock counter while blocked
requests across supported entry protocols return 403 and leave the counter
unchanged. A public CPA auth-selector probe directly verifies zero auth
selection for blocks, and the usage queue remains empty. It also verifies safe
model/body preservation, authenticated management access, reconfiguration,
stream termination, and disabled-plugin recovery.

For streaming blocks, the executor returns the 403 error before a stream is
established. CPA closes the request promptly with a protocol-compatible regular
error response. ABI v1 cannot simultaneously send HTTP 403 and establish an
SSE stream with terminal frames; returning successful chunks would force HTTP
200, so v0.1.0 chooses the genuine pre-stream 403.
