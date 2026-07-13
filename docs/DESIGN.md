# CPA Cyber Abuse Guard v0.1.2 Design

## Scope and invariants

Cyber Abuse Guard is an in-process CPA C-ABI v1 plugin for CLIProxyAPI v7.2.67
(`2075f77c8ebe9ec872759965661936fb1ac2931f`). It reduces the chance that a
downstream caller sends clearly malicious, operational cyber-abuse requests to
an upstream account. It cannot guarantee that an account will not receive a
warning or be deactivated.

The root module and runtime baseline remain on CPA v7.2.67. The isolated
`integration/pluginstorecontract` module pins CPA v7.2.72 only to execute the
official store-installer and host-routing source contracts without loading a
shared library. Those source tests do not establish native-host compatibility.

This document describes the v0.1.2 candidate implementation, not an approved
release. The methodologically valid v10 evaluation failed its first and only
formal run (28/320 benign false positives, 49/320 policy blocks, 33/320 exact),
so the release is blocked. No v0.1.2 tag, GitHub Release, or production
deployment may be created. A future attempt requires implementation changes
followed by a newly and independently authored unseen evaluation; v10 cannot be
rerun.

The implementation has three non-negotiable invariants:

1. A blocked request is routed by `ModelRouter` to the plugin's own executor
   before provider resolution and auth scheduling. The executor never invokes a
   host HTTP or host model callback.
2. A single keyword is never sufficient to block. Decisions require a harmful
   action/object combination plus operational, target, evasion, or scale
   evidence, with defensive and lab context applied explicitly.
3. The plugin never rewrites the requested model, client identity, or system
   prompt, and never sends request content to an auxiliary classifier or third
   party. Requests it allows still follow CPA's configured upstream path.

## CPA ABI path

The shared object exports `cliproxy_plugin_init` and returns ABI version 1. The
JSON RPC capabilities are:

- `model_router`: inspect `ModelRouteRequest` before provider/auth selection;
- `executor`: terminate blocked non-streaming, streaming, and token-count
  requests locally; HTTP forwarding remains explicitly unsupported;
- `management_api`: expose management-key-protected status, event, stats, test,
  unblock, and delete routes.

The canonical CPA formats `openai`, `openai-response`, and `claude` are
declared as executor input and output formats. `gemini` is also declared and is
covered when the installed CPA handler routes that entry protocol through the
standard model-router path.

For an unknown `SourceFormat`, Strict self-routes before interpretation.
Balanced, Audit, and Observe still run a bounded generic untrusted-text walk so
a new label is not a silent bypass; a counter and watchdog delta make it
visible. This fallback cannot know every future provider's metadata semantics,
so a new CPA/provider shape requires review and an explicit canonical mapping.

For an allowed request, `model.route` returns `Handled: false`. For a blocked
request, it returns `Handled: true`, `TargetKind: self`. The executor returns an
RPC error envelope with HTTP status 403 and the stable marker
`cyber_abuse_guard_blocked`. CPA v7.2.67 turns that error into the native error
shape for the entry protocol.

`executor.execute`, `executor.execute_stream`, and `executor.count_tokens` use
this same policy-403 path. `executor.http_request` is not implemented and
returns HTTP 405. The real four-protocol HTTP/SSE and zero
Auth/Usage/Provider/Upstream matrix for the current diff remains a server-
sandbox requirement.

CPA v7.2.67's `ExecutorResponse` has payload and headers but no HTTP status.
Consequently, ABI v1 cannot simultaneously return an arbitrary plugin-owned
JSON body and a non-200 status from `executor.execute`. v0.1.2 favors the
security property and correct 403 status, using CPA's protocol error wrapper.
The stable marker and coarse category remain in the message; rule IDs and
bypass details do not.

CPA serializes request bodies as Base64 inside `ModelRouteRequest`, so a raw
request slightly above 6 MiB can exceed the native 8 MiB RPC copy budget.
Returning a router error there would make CPA continue upstream. The native
boundary therefore detects an oversized `model.route` before `C.GoBytes` and
uses a no-copy, mode-aware path: `balanced`/`strict` self-route to the local
executor with `scan_limit`; `off`/`observe`/`audit` retain their documented
non-enforcing behavior. An oversized executor RPC returns the local 403 policy
refusal and cannot fall back to a provider.

## Request extraction

The extractor is format-tolerant and walks JSON tokens with bounded work:

- maximum JSON depth, text parts, and scanned text bytes are configurable;
- common text-bearing fields (`system`, `instructions`, `input`, `content`,
  `text`, and tool `arguments`) are collected across nested arrays/objects;
- role, model, identifiers, URLs, image fields, and known binary fields are not
  treated as prompt text at transport/message level; metadata-named keys such
  as `name`, `url`, `type`, and `model` remain inspectable inside tool payloads;
- recognized image/audio/video/document-attachment payloads are omitted and marked as opaque media,
  independently from incomplete text scanning;
- HTTPS media URLs are metadata and are never fetched;
- unknown fields (including a tool argument named `data`) remain inspectable;
  text decoding recognizes bounded URL escapes, HTML entities, Base64 text,
  textual data URLs, JSON escapes, and nested tool JSON;
- nested JSON inside tool arguments is scanned using the same shared budget;
- Anthropic `tool_use.input` and equivalent nested `input` payloads are scanned
  as tool data regardless of whether the sibling `type` field appears before
  or after `input`;
- standard OpenAI/Anthropic/Gemini histories are also indexed into bounded
  `system`/`user`/`assistant`/`tool` segments. Role-less standard items use a
  conservative legacy-plus-per-part fallback; explicit unsupported roles fail
  closed, and discarding history at the 64-segment cap sets `truncated`;
- malformed complete JSON is a parse error, not automatically malicious;
- an artificial scan boundary inside an escape or UTF-8 sequence is treated as
  truncation, not a parse error, so `balanced` and `strict` fail closed;
- over-limit input is marked truncated without panicking.

The original request byte slice is used only during the call. It is never
stored in events or risk-control state.

### Bounded decoding and opaque media

Encoded text is inspected without entering unbounded recursive decoding. At
most two decode layers and eight unique variants are retained. Encoded input is
capped at 128 KiB and decoded variants share a 64 KiB retained-byte budget.
Only valid UTF-8, printable textual results are added. An incomplete recognized
text envelope sets the ordinary truncation signal, which enforcing modes treat
conservatively. There is no decompression, archive expansion, document parser,
binary-media decoder, redirect handling, DNS resolution, or network fetch.
Complete unknown or merely high-entropy strings remain literal classifier input
and do not become an automatic block signal. This avoids treating arbitrary
tokens, hashes, and compressed-looking identifiers as malicious, while leaving
encrypted and novel encodings as an explicit detection limitation.

Opaque image/audio/video/document attachment is a separate signal controlled by
`opaque_media_policy`. An explicit `block`, `audit`, or `allow` wins. If the
field is omitted, Off allows, Observe/Audit/Balanced audit, and Strict blocks.
Auditing records only a coarse disposition and counters, not media bytes. An
allow decision means “not inspectable by this plugin,” not “known safe.” Pure
text behavior does not depend on this policy.

## Deterministic classifier

Ruleset `1.0.7` is versioned YAML embedded into the shared object. Its current
canonical embedded SHA-256 is
`7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134`. Startup
compiles and validates it once. Rules use literal normalized terms rather than
runtime regular expressions, eliminating catastrophic-backtracking risk.

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

Negation and prohibition cues are scoped to nearby evidence in the same clause.
They can preserve a genuine request to avoid or prohibit abuse, but an unrelated
prefix such as "do not add comments" cannot suppress a later implementation
request, and a prior negated policy statement cannot poison a follow-up segment.

For recognized role histories, each retained segment is classified on its own,
so old explicit abuse cannot be hidden by appending benign turns. Adjacent user
turns are additionally classified as a pair to preserve follow-up semantics
across an intervening assistant refusal. Non-user text is never combined with
user evidence, but an explicitly abusive system, assistant, or tool segment is
still blocked. Ambiguous/role-less envelopes retain a joint legacy decision and
also classify every part and adjacent pair, with the same bounded fail-closed
capacity marker.

The result contains only category, score, action, evidence IDs, and aggregate
context flags. It never contains matched prompt fragments.

### Post-v10 meta-override layer

The development tree adds `META-OVERRIDE-001` after ordinary category
assessment. It compiles bounded bilingual evidence families for hierarchy
replacement, refusal suppression, unrestricted persona, direct completion,
scope laundering, forced output/authorization bypass, protected-prompt
disclosure, and explicit negative authorization. Independent families must
compose; it is not a single-keyword bypass detector.

If ordinary cyber-abuse evidence exists, the layer raises the score while
preserving the original taxonomy. A strong standalone control-plane attack is
reported under `defense_evasion`. Prompt-derived CTF/lab/authorization claims
cannot reduce the layer. Defensive quoted analysis is discounted only with an
affirmative non-execution purpose and no contradictory continuation.

Role proof failure on a supported provider body causes a bounded conservative
re-extraction. Tool provenance is inspected independently, nested valid JSON
strings recurse only inside an established tool payload, joined content blocks
are decoded again, and isolated single-character fragmentation has a narrow
reconstruction path. These mechanisms remain stateless across independent API
calls and do not attest to local instruction-file integrity.

Ruleset `1.0.7` identifies the embedded YAML assets only. The complete
code-level policy also includes the meta layer, matcher/normalizer behavior,
role handling, and extraction semantics. The containing Git/build commit plus
the YAML identity are required to identify this development behavior; a future
release must add a separate policy identity or fully bind it to verified build
provenance.

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
a trustworthy direct-peer address to ModelRouter. v0.1.2 therefore rejects
`trusted_proxy.enabled: true`; forwarded headers alone are spoofable and are
never accepted as identity.

Plain API keys and IP addresses are never stored. The HMAC key comes from
`CYBER_ABUSE_GUARD_HMAC_KEY` or an explicitly configured mode-0600 secret file.
If no key is available, process-random key material is used and status reports
that hashes will not be stable across restarts. On Linux, a configured secret
file is opened with `O_NOFOLLOW`; its type, permissions, size, and contents are
validated through that same descriptor to prevent final-component symlink and
path-swap races.

Risk entries are in-memory rolling windows with time decay. Risk is added only
for results at or above the audit threshold. Repeat hits receive a bounded
multiplier. Cooldown/manual-block state applies only to new risky requests;
ordinary safe requests are not permanently denied. Manual blocks can be
cleared through the authenticated management API.

`subject_control.max_subjects` bounds state cardinality and defaults to 10,000.
The controller keeps non-manual entries in least-recent-risk order and evicts
the oldest when capacity is needed. Manual blocks are never capacity-evicted;
if they consume all capacity, a new risky subject is blocked with
`subject_capacity` rather than admitted without state. Status exposes current
capacity through `subject_control`: `subjects`, `max_subjects`,
`manual_blocked`, `evicted`, and `rejected_capacity`.

### Optional subject persistence

Persistence defaults to disabled. With `subject_control.persistence: false`,
all risk, cooldown, and manual-block state is process-local and intentionally
resets on CPA restart. Enabling persistence requires subject control, audit
storage, a stable HMAC secret, and `max_subjects <= 10000`.

The persistent type can represent only an HMAC subject, score/hit timestamps,
cooldown, and manual state. It cannot represent a plaintext credential. A
bounded snapshot replaces prior subject-state rows atomically. Restoration
validates schema and key fingerprint, rejects duplicate or malformed hashes,
applies expiry and time decay, then enforces the current capacity. Expired and
over-capacity rows are counted in status.

The loader detects schema/type/version errors, malformed or duplicate HMAC
subject IDs, row/payload mismatches, and invalid bounded state. The snapshot is
not protected by a separate keyed whole-snapshot MAC, so it does not prove
completeness or authenticity against an actor who can write the SQLite file.
Such an actor can delete otherwise valid rows. Production filesystem ownership
and mode controls therefore remain part of the persistence trust boundary.

Writes are debounced and periodic, and a bounded shutdown save is attempted.
Database failure degrades persistence while in-memory rule enforcement
continues. A different HMAC key produces an explicit key-mismatch state and
blocks persistence writes, preserving the old snapshot for operator review
instead of silently replacing uncorrelatable identities.

### Dual-key rotation design (not implemented)

v0.1.2 supports one active HMAC key only. A future safe rotation mechanism must
be an explicit state machine:

1. configure one active key and at most one previous read-only key;
2. expose only domain-separated key fingerprints in authenticated status;
3. accept old persisted subjects only during a finite, operator-configured
   overlap window and keep them in a bounded transition map;
4. compute every new subject ID and persistence write with the active key;
5. never compare plaintext credentials across keys or log either key;
6. finalize rotation explicitly, remove the previous key, and atomically drop
   unmigrated old-key state after an operator-reviewed backup.

Until that mechanism exists, normal upgrades must preserve the current key.
Changing it is a correlation reset, not a transparent rotation.

## Audit store

When enabled, SQLite stores only the minimal event schema. The database uses
WAL, a busy timeout, parameterized SQL, bounded asynchronous writes, retention
cleanup, and a configured maximum size. A database open/write failure degrades
to in-memory counters and rate-limited host-error diagnostics; classification
continues. Shutdown has a five-second runtime budget so a locked SQLite writer
cannot indefinitely stall plugin reconfiguration or shutdown.

New database directories are created with mode 0700, but the plugin never
changes permissions on an existing operator-owned directory. Database, WAL,
and shared-memory files are restricted to mode 0600. Existing directories with
group/world write bits, final database-directory symlinks, and database/WAL/SHM
symlinks are rejected; runtime permission failures make audit status visibly
degraded. Operator-selected ancestor paths remain part of the deployment trust
boundary.

Pre-migration `VACUUM INTO` output is first created below a same-filesystem
mode-0700 staging directory, changed to mode 0400, synced, and only then
published through a no-overwrite hard link. A complete backup is therefore not
temporarily exposed with SQLite's default creation mode in a 0755 data
directory.

An RPC rejected by the native no-copy size guard has no safely available body,
model, source format, or request hash. When audit is enabled, the plugin records
a minimal `scan_limit` event with `text_bytes_scanned: 0` and does not invent
those unavailable fields.

No prompt, message, authorization header, plaintext subject, token, cookie,
OAuth material, user code, or upstream account identity is persisted. Request
correlation uses SHA-256 of the raw body. Subject correlation uses HMAC-SHA256.
Requested models use a separate `cyber-abuse-guard/audit/model/v1` hash domain
and `sha256-model-v1:` prefix. Source format is restricted to the canonical
`openai`, `openai-response`, `claude`, `gemini`, or `unknown` enum. Legacy
database reads are sanitized before query or CSV output.

The database schema is versioned. `schema_version` records the active schema;
`migration_history` records every applied version. A v0.1.1 event database with
no metadata is recognized as schema v1. The schema-v2 migration adds optional
subject-state tables inside a transaction. On failure, the old schema remains
intact. When `audit.backup_before_migration` is enabled, SQLite `VACUUM INTO`
creates a consistent mode-0400 pre-migration copy before the transaction.
Backups are capped by `audit.max_migration_backups` and are never placed in a
release archive.

Existing schema objects are accepted only after exact column name/order/type/
nullability/primary-key, required CHECK fragment, index column/direction,
singleton version-row, and contiguous migration-history validation. This is a
structural contract, not a keyed proof that no otherwise valid row was deleted.

`audit.log_original_text` remains in the compatibility schema only to reject
unsafe input. A value of `true` prevents activation or reconfiguration. There
is no debug or emergency mode that persists raw request text.

Reconfiguration builds and validates a complete immutable runtime state before
an atomic swap. Invalid configuration leaves the last valid state active. This
requires a CPA-specific behavior: `plugin.reconfigure` still returns the valid
registration envelope after a rejected update, because returning an RPC error
would make CPA omit the plugin from its next active snapshot. Status exposes
the rejected update as `last_config_error` and the plugin logs it through the
host logging callback.

Compatible enabled-to-enabled reconfiguration reuses the subject controller,
preserving rolling risk, cooldowns, and manual blocks. Capacity shrink evicts
only non-manual entries and is rejected atomically if the requested limit is
below the number of protected manual blocks. Disabling subject control clears
its process-local state. `started_at` remains the original process-runtime
timestamp across compatible hot reload, while `configured_at` records the most
recent successful configuration.

## Management routes

Only CPA management routes are registered; no unauthenticated resource page is
exposed in v0.1.2.

- `GET /plugins/cyber-abuse-guard/status`
- `GET /plugins/cyber-abuse-guard/events`
- `GET /plugins/cyber-abuse-guard/stats`
- `POST /plugins/cyber-abuse-guard/test`
- `POST /plugins/cyber-abuse-guard/health/probe`
- `POST /plugins/cyber-abuse-guard/subjects/unblock` with
  `{"subject_hash":"..."}`
- `DELETE /plugins/cyber-abuse-guard/events`

CPA mounts these below `/v0/management` and enforces its Management Key before
the plugin handler runs. The test route does not persist its input.

CPA v7.2.67 management routes are exact matches and reject `:` or `*`, so the
task book's suggested `{hash}` path parameter cannot be registered safely.

CPA's Management Key middleware is the authentication authority. The plugin
adds bounded body/query/method guards but cannot independently compare the
configured Management Key because ABI v1 does not expose it. A normal client
key therefore cannot authorize these routes, and deployment tests must verify
the host's 401 behavior. Responses never include prompt text or plaintext
subjects.

The plugin rejects a management body above 1 MiB and a serialized RPC envelope
above 2 MiB. These are plugin-side limits only: CPA currently calls `io.ReadAll`
inside `ServeManagementHTTP` before invoking the plugin. A reverse proxy must
therefore enforce the HTTP request-body ceiling, and the server sandbox must
prove that an oversized request receives 413 before CPA reads it.

## Failure behavior

- invalid initial config: plugin registration fails visibly;
- invalid reconfigure: keep the previous state, expose/log the error, and return
  the current valid registration so CPA keeps the plugin active;
- rule load/validation failure: registration/reconfigure fails;
- malformed request: allow and optionally audit `parse_error` outside `off`;
- RPC beyond the native copy budget: no-copy local refusal in Balanced/Strict;
  allow in Off/Observe/Audit, with a minimal event in audit-capable modes;
- audit failure: continue classifying and blocking;
- panic in `model.route`: increment counters and, when a validated
  Balanced/Strict runtime is active, return a successful local self-route so
  CPA cannot fall through to auth/provider selection; non-enforcing/no-runtime
  cases still expose the error because they deliberately do not enforce;
- panic in another ABI method: recover, return a parseable internal error, and
  retain the non-zero ABI failure signal;
- optional classifier: interface reserved but not implemented in v0.1.2.

CPA owns the host fail-open policy. A plugin that is absent, fails registration,
is fused, returns a Router error, panics before an accepted handled result,
returns an invalid/empty target, or self-routes to an executor that is not ready
can be skipped while later Routers or native routing continue. A higher-priority
handled Router wins; equal priority is ordered by plugin ID ascending. No in-
process plugin can prove that every host or ABI failure will be fail-closed.
The authenticated status exposes `loaded`, `enforcement_ready`,
`router_errors`, `panics_recovered`, audit/HMAC/persistence degradation,
reconfigure error, and build/ruleset identity. The read-only production
watchdog checks those fields and runs built-in local-only probes. ABI v1 cannot
enumerate router ordering or scan the plugin directory, so higher-priority
router conflicts and duplicate `.so` versions remain mandatory operator checks.
`enforcement_ready` reflects plugin-internal runtime state only; it does not
prove host load/registration, non-fused state, ordering, or per-request executor
readiness.

## Verification strategy

Unit tests cover extraction limits, scoring, modes, bilingual and obfuscated
inputs, hard-block exceptions, subject decay/cooldown, config rollback, SQLite
privacy, management handlers, and ABI envelopes. Separate corpora contain at
least 100 benign security prompts and 100 clearly malicious operational
prompts. Benchmarks report classifier latency and allocations.

The isolated CPA v7.2.72 contract module calls the official
`pluginstore.InstallArchive` with opaque bytes and runs the official
`TestHostRouteModel*` and Router-sorting tests. It verifies store naming,
root-only library layout, checksum, installed path/bytes, repeat installation,
nested-layout rejection, priority ordering, and documented host fallback. It
does not load the Guard `.so`.

The integration harness builds the `.so`, builds CPA at the pinned commit,
starts a local mock OpenAI-compatible upstream, and starts CPA with the plugin.
It asserts that a safe request increments the mock counter while blocked
requests across supported entry protocols return 403 and leave the counter
unchanged. A public CPA auth-selector probe directly verifies zero auth
selection for blocks, and the usage queue remains empty. It also verifies safe
model/body preservation, authenticated management access, reconfiguration,
stream termination, role-aware follow-ups, metadata-named OpenAI and Anthropic
tool payloads, a Base64-expanded RPC above 8 MiB, and disabled-plugin recovery.

`make release` depends on this real-CPA integration suite before packaging.
For the current Phase 0 diff that real-host suite was deliberately not run
locally; server-sandbox evidence is still required.
Release verification inspects the ELF and rejects a binary whose imported glibc
symbol version exceeds `GLIBC_2.34`. The published artifact therefore requires
glibc 2.34 or newer, is compatible with the official Debian Bookworm CPA image,
and does not support musl/Alpine runtimes.

For streaming blocks, the executor returns the 403 error before a stream is
established. CPA closes the request promptly with a protocol-compatible regular
error response. ABI v1 cannot simultaneously send HTTP 403 and establish an
SSE stream with terminal frames; returning successful chunks would force HTTP
200, so v0.1.2 chooses the genuine pre-stream 403.

## Build identity and release reproducibility

Release builds link immutable version, full commit SHA, ruleset version,
canonical ruleset SHA-256, and dirty state. Authenticated status exposes the
same values. Formal release scripts require a clean worktree and annotated
`v0.1.2` tag at `HEAD`; `ALLOW_DIRTY_BUILD=1` produces clearly marked
development artifacts only.

`SOURCE_DATE_EPOCH` derives from the commit timestamp unless explicitly fixed.
Builds use `-trimpath`, a pinned Go toolchain, deterministic ZIP ordering and
timestamps, strict file allowlists, and a canonical ruleset manifest. The CPA
store ZIP contains exactly one root mode-0755 `.so`; documentation, metadata,
SBOM, and operational material live in a separately named audit bundle.
CycloneDX SBOM and checksums are verified against source and cover both ZIPs.
The reproducibility gate builds in two clean clones and byte-compares the `.so`,
store ZIP, audit bundle, and SBOM.

These mechanisms make evidence reproducible; they do not turn a failed safety
gate into a release. v1-v8 are retired or consumed failures, v9 is a consumed
methodology-invalid failure, and methodologically valid v10 is a consumed
formal failure. The v0.1.2 release is therefore blocked permanently on this
implementation/evaluation pairing.
