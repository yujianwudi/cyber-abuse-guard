# CPA Cyber Abuse Guard v0.15 Design

## Scope and invariants

Cyber Abuse Guard is an in-process CPA C-ABI v1 plugin for CLIProxyAPI. Exact
project version is `0.15`; the only formal tag name is `v0.15` (never
`v0.15.0`). It reduces the chance that a
downstream caller sends clearly malicious, operational cyber-abuse requests to
an upstream account. It cannot guarantee that an account will not receive a
warning or be deactivated.

The root ABI build dependency is CPA v7.2.88 at
`93d74a890a44802f656d7f39a573916b2611896e`. Its pinned module checksum is
`h1:YfLBYPvkasjqFLzdht+UrEgRLsU3HcM0WDMurNEjIDo=` and its `go.mod` checksum is
`h1:ytvZNWbCv7PrAyR80+RKsDJPODsdL6qxyFaXDBNZdqs=`.

The current Round 6 compatibility and required Host gate is a separate layer:
the isolated `integration/cpalatestcontract` module and
`make cpa-latest-compat` pin CPA v7.2.88
(`93d74a890a44802f656d7f39a573916b2611896e`). The gate compiles the Guard
and integration packages, runs the real Guard registration/role-routing probes,
18 official Host routing/status/metadata-sanitization tests and 11 official Interactions
route/handler tests, and applies three checksum-pinned ephemeral overlays.
Remote verification checks the fixed tag, commit, module origin, and checksums
without GitHub REST Release metadata or a repository token. Later upstream CPA
versions do not automatically retarget the supported source/Host identity. Historical commit
`21ceb57e6b6030e56d7820c9a67a8eecd068c669` passed push and PR CI with
the then-current v7.2.83 latest-source gate as a
**pre-version-migration checkpoint**. It does not constitute a
v7.2.88 native Host/Store load and is not the final v0.15
candidate identity.

Earlier v7.2.85/v7.2.84/v7.2.83/v7.2.82/v7.2.81 source/compile profiles remain historical non-gating
engineering evidence and are not current release targets.

The repository work began from historical baseline
`a121a444cb0d82cba4e27754914a1f88258e1d7b`. The root module,
`integration/cpalatestcontract`, and `integration/pluginstorecontract` now pin
CPA v7.2.88. The plugin-store module covers Store/source behavior while the
compatibility module covers the broader current pinned source/compile contract. Source
contracts, a real shared-object Host harness, and a second Router/executor
fixture are distinct evidence layers; implementing a harness is not the same as
executing it. The current v0.15 candidate must be produced as a private,
untagged, clean exact-source Linux amd64 Actions artifact and then tested against
CPA v7.2.88 with Mock upstream. Historical Round 5 evidence remains in the
explicitly marked sections of `reports/TEST_REPORT.md` and Git history; the
legacy CPA-version-specific handoff files have been removed from the active
source tree.

This document describes a post-v10 v0.15 development handoff, not an approved
release. The methodologically valid v10 evaluation failed its first and only
formal run (28/320 benign false positives, 49/320 policy blocks, 33/320 exact),
so the formal release is blocked. No formal `v0.15` tag, formal Release, or
production deployment may be created. The public source-only `v0.15-rc.1`
prerelease has no attached assets and does not change that decision. The
evidence order is: final PR head and PR CI,
merge to `main`, exact post-merge main push CI, private untagged clean candidate
dispatched from `refs/heads/main`, v7.2.88 Host evidence, independent
audit, a candidate-bound external `evaluation-v11` or later first-and-only
`CONSUMED / PASS` attestation, optional annotated development prerelease, then
the annotated formal `v0.15` tag and verified draft, followed by protected
promotion of that unchanged draft. v10 cannot be rerun and is not a formal
input.

The neutral source admission policy is [RELEASE_POLICY.md](RELEASE_POLICY.md).
Future Host/audit and formal decisions are externalized in
`round6-prerelease-attestation.json` and `formal-release-attestation.json`.

The implementation has three non-negotiable invariants:

1. A blocked request is routed by `ModelRouter` to the plugin's own executor
   before provider resolution and auth scheduling. The executor never invokes a
   host HTTP or host model callback.
2. A single keyword or wrapper is never sufficient to block. Decisions require
   an independently established harmful behavior relation plus operational,
   target, evasion, impact, or scale evidence, with defensive and lab context
   applied explicitly. Wrapper evidence may amplify that base behavior but
   cannot synthesize a Cyber Abuse category.
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

The canonical CPA formats `openai`, `openai-response`, `interactions`,
`openai-image`, `openai-video`, `claude`, and `gemini` are declared as executor input and output
formats. The real-Host harness retains separate allow/block, stream,
token-count, and native error-shape assertions for the four original entry
protocols; the image/profile and native Interactions matrices are distinct
pending Host gates. Interactions is a known format but intentionally uses the
conservative untrusted-text extractor until a fixed role schema is proven.

For an unknown non-multipart `SourceFormat`, Strict self-routes before
interpretation. Balanced, Audit, and Observe still run a bounded generic
untrusted-text walk so a new label is not a silent bypass; a counter and
watchdog delta make it visible. Unknown multipart is different: every non-file
field becomes schema-incomplete, Balanced allows+audits, and Strict blocks for
the fixed incomplete reason. Neither path guesses future provider semantics;
a new CPA/provider shape requires review and an explicit canonical mapping.

For an allowed request, `model.route` returns `Handled: false`. For a blocked
request, it returns `Handled: true`, `TargetKind: self`. The executor returns an
RPC error envelope with HTTP status 403 and the stable marker
`cyber_abuse_guard_blocked`. The root CPA v7.2.88 ABI contract turns that error
into the native error shape for the entry protocol; the current v7.2.88
Host matrix must reverify the exact client shapes.

`executor.execute`, `executor.execute_stream`, and `executor.count_tokens` use
this same policy-403 path. `executor.http_request` produces an unsupported-method
RPC error whose `StatusCode()` is 405; the official adapter returns `(nil,
error)`. This is a SOURCE/ADAPTER check, not a final client HTTP result. The
audited root CPA contract exposes the provider-specific public consumer
`POST /v1/alpha/search`, but ordinary selection is fixed to `codex` and the
handler maps every `HttpRequest` error to HTTP 502. The project's
`httptest.Server` manually maps the status error and cannot establish official
Host HTTP 405. No current official public route maps Guard's error to final
client 405, so the result is `NOT AVAILABLE / NOT RUN` and remains a handoff
blocker that current CI cannot solve. The real four-protocol HTTP/SSE and zero
Auth/Usage/Provider/Upstream matrix must be executed against the exact private
v0.15 candidate on CPA v7.2.88 before it becomes Host
evidence.

CPA ABI v1 `ExecutorResponse` has payload and headers but no HTTP status.
Consequently, ABI v1 cannot simultaneously return an arbitrary plugin-owned
JSON body and a non-200 status from `executor.execute`. v0.15 favors the
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
- adjacent user turns and one explicitly linked bounded three-turn plan can
  compose behavior evidence across an assistant refusal, while non-user safety
  text cannot supply user intent;
- provider-native tool payloads retain tool provenance and are scanned
  independently; placeholders and renamed variables are ordinary text until a
  nearby definition binds them to a dangerous object, asset, or target;
- malformed complete JSON is a parse error, not automatically malicious;
- an artificial scan boundary inside an escape or UTF-8 sequence is treated as
  truncation, not a parse error; `balanced` allows+audits without a prefix
  score, while `strict` blocks for the fixed incomplete reason;
- over-limit input is marked truncated without panicking.

The original request byte slice is used only during the call. It is never
stored in events or risk-control state.

### Order-independent JSON media and schema-bound multipart

JSON object members are unordered. Values under the payload-adjacent keys
`data`, `bytes`, `blob`, `binary`, `filename`, `format`, `detail`, `width`,
`height`, and `duration` are therefore held as bounded object-level candidates
until their media meaning is known. A later media marker discards
the candidates without adding `Parts`, `Segments`, decode variants, or
`TextBytesScanned`; a final non-media object commits them as inspectable text.
Candidate overflow retains and classifies no prefix: a final media object stays
complete/opaque, while a final non-media object gets the fixed
`deferred_text_candidate_limit` reason. Candidate propagation is limited to
media-style ownership such as `source`, and crossing a tool/tool-payload
boundary cuts inherited media meaning. Consequently, tool argument/output
`data` remains inspectable and cannot hide itself merely by adding a sibling
`type=image`. Opaque media kinds are deduplicated in a fixed order so equivalent
member permutations have identical telemetry.

Multipart extraction is selected by a fixed `RequestProfile` derived from the
canonical `SourceFormat`. CPA ABI v1 `ModelRouteRequest` has no general HTTP
path, and the official image handler may parse and rebuild multipart before the
Router receives it, so endpoint-path inference is neither available nor valid.
For `openai-image`, inspectable text is limited to `prompt` and
`negative_prompt` (plus `negative-prompt` and `negative prompt`); reviewed
metadata/control fields are discarded, and `image`, `image[]`, `images`,
`images[]`, and `mask` are opaque files. File evidence has precedence. An
allowlisted text field carrying file evidence becomes
`multipart_text_field_type_mismatch`; every unknown non-file field becomes
`multipart_unknown_field`. Neither name nor value is classified or persisted.

Both schema reasons are incomplete inspection. No partial classification or
subject-risk update is used: Balanced allows+audits as `multipart_schema`,
Strict self-routes with `cyber_abuse_guard_multipart_schema`, and a complete
malicious prompt still follows ordinary policy. Parser unit tests prove the
payload delivered to the plugin; only the CPA v7.2.88 exact-candidate Host matrix can prove
pre-Router reconstruction and Auth/Provider/Usage/upstream side effects.

The original-body statement above is a Guard boundary, not an end-to-end Host
logging guarantee. CPA request logging may temporarily spool a
non-multipart body and persist a raw body in an HTTP error log. Host validation
must isolate and inspect that log path, commercial-mode behavior, retention,
permissions, and cleanup.

### Bounded decoding and opaque media

Encoded text is inspected without entering unbounded recursive decoding. At
most two decode layers and eight unique variants are retained. Encoded input is
capped at 128 KiB and decoded variants share a 64 KiB retained-byte budget.
Only valid UTF-8, printable textual results are added. An incomplete recognized
text envelope sets the ordinary truncation signal, which enforcing modes treat
conservatively. There is no decompression, archive expansion, document parser,
binary-media decoder, redirect handling, DNS resolution, or network fetch.
Strings with an unknown encoding shape or merely high entropy remain literal
classifier input when their schema and role provenance are otherwise supported;
they do not become an automatic block signal. This is not a promise that an
arbitrarily long `RoleUnknown` field can participate in exact cross-field text
reconstruction: once the bounded summary cannot retain it, the streaming
classifier keeps only fixed risk facts and may report
`classifier_window_incomplete`. The distinction avoids treating arbitrary
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

The result contains only category, score, action, evidence IDs, aggregate
context flags, the ruleset version, the classifier-policy identity, and a privacy-safe
`BehaviorGraph`. It never contains matched prompt fragments.

### Wrapper/amplifier separation and behavior graph

The development tree adds `META-OVERRIDE-001` after ordinary category
assessment. It compiles bounded bilingual evidence families for hierarchy
replacement, refusal suppression, unrestricted persona, direct completion,
scope laundering, forced output/authorization bypass, protected-prompt
disclosure, and explicit negative authorization. Independent families must
compose; it is not a single-keyword bypass detector.

Wrapper/control evidence is structurally separate from base behavior. If an
ordinary Cyber Abuse candidate exists, the layer may raise its score while
preserving the original taxonomy and records an amplifier relation. Without a
base candidate, wrapper-only text never produces `defense_evasion` or another
Cyber Abuse category: weak combinations allow, while strong combinations are
capped at the configured audit boundary and remain observe/audit even in
classifier Strict mode. Defensive quoted analysis is discounted only with an
affirmative non-execution purpose and no contradictory continuation.

`BehaviorGraph` is the deterministic relation model behind the result. It uses
stable booleans and edges for requester, action, object, target, destination,
technique, delivery/execution, credential/access, persistence, evasion,
exfiltration, impact, scale, authorization/defensive purpose,
wrapper/amplifier, role scope, carrier, composition mode, and reason codes.
No node or edge contains a prompt span. Rule-local candidates, same-category
composition, and bounded semantic windows all emit through this common model.

Role proof failure on a supported provider body causes a bounded conservative
re-extraction. Tool provenance is inspected independently, nested valid JSON
strings recurse only inside an established tool payload, joined content blocks
are decoded again, and isolated single-character fragmentation has a narrow
reconstruction path. Adjacent user turns and an explicitly linked three-turn
plan may compose; placeholder bindings remain local to the supplied request.
These mechanisms remain stateless across independent API calls and do not
attest to local instruction-file integrity.

Ruleset `1.0.7` identifies the embedded YAML assets only. The complete
code-level behavior is separately identified as `classifier-policy-v4`,
SHA-256
`2763f10e2565dce2ffcf700f5d6566e9fbac68f3fedd08fcce20bceff450b4c8`.
Its tested source list binds the classifier, matcher, normalizer, role logic,
wrapper assessment, behavior graph, semantic composition, bounded extractor,
rule loader/schema, embedded YAML assets, and module dependency locks. The
identity is returned in classifier results and exposed by authenticated status.

Mode semantics are:

- `off`: skip extraction, classification, audit, and risk accumulation;
- `observe`: classify and update counters only; never block or persist events;
- `audit`: classify and persist minimal events; never block;
- `balanced`: block at `balanced_block` (default 60);
- `strict`: block at `audit` (default 35).

These ordinary thresholds apply to established base behaviors. Wrapper-only
control evidence uses the separate non-blocking observe/audit path described
above.

The mode definitions intentionally take precedence over the task book's
non-binding suggested statement that a score of 80 blocks every non-off mode;
otherwise `observe` and `audit` would not mean "never block".

## Subject risk control

Subject selection is ordered:

1. the downstream bearer/API key on the CPA-authenticated request, immediately
   HMACed in memory;
2. an anonymous bucket.

The anonymous identity is never admitted to rolling subject state. Anonymous
requests still receive the same direct classifier/transport disposition, but
cannot allocate a shared bucket or accumulate cross-request risk across users.

CPA ABI v1 does not supply a distinct authenticated principal/key-policy ID or
a trustworthy direct-peer address to ModelRouter. v0.15 therefore rejects
`trusted_proxy.enabled: true`; forwarded headers alone are spoofable and are
never accepted as identity.

Plain API keys and IP addresses are never stored. The HMAC key comes from
`CYBER_ABUSE_GUARD_HMAC_KEY` or an explicitly configured mode-0600 secret file.
If no key is available, process-random key material is used and status reports
that hashes will not be stable across restarts. On Linux, a configured secret
file is opened with `O_NOFOLLOW`; its type, permissions, size, and contents are
validated through that same descriptor to prevent final-component symlink and
path-swap races.

Subject control is disabled by default and the Router does not enter the
identifier/controller path unless `subject_control.enabled: true` is explicit.
The domain-separated request digest is computed lazily only for an enabled
subject evaluation, a final block pending key, or a persisted audit event whose
configuration includes `log_request_hash: true`.

Risk entries are in-memory rolling windows with time decay. A hit, request
receipt, and repeat multiplier are added only when every admission condition is
true: the identity is authenticated rather than anonymous; extractor and
classifier coverage are complete; finding confidence is
`FindingCompleteRequest`; the winning finding origin is the closed,
text-free `user_content` value; the behavior graph contains `BaseBehavior`;
the classifier directly returned `ActionBlock`; and the score is at or above
the configured `hard_block` threshold. System, assistant, tool, tool-payload,
roleless, unknown, mixed-role, or lower-confidence findings retain their direct
request disposition but cannot accumulate subject risk.

Non-accumulating observations never allocate state or add a hit, receipt, or
multiplier. A non-accumulating risky candidate at or above the audit threshold
may read an already active cooldown/manual-block disposition, while an ordinary
score below the audit threshold remains safe even for a previously cooling or
manually blocked subject. Expired inactive state is pruned during this lookup.
Manual blocks can be cleared through the authenticated management API.

Risk accounting is idempotent per subject and domain-separated request digest.
The same logical request crossing Router and executor methods, retrying, racing
concurrently, missing or expiring from the pending cache, or surviving an
enabled-to-enabled reconfigure contributes at most one risk hit inside the risk
window. Receipt metadata is bounded with the hit window and can be restored
from the optional subject snapshot; older snapshots without receipts remain
readable. If the bounded receipt capacity is exhausted, the controller refuses
to evict a still-live receipt merely to count a retry again.

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

v0.15 supports one active HMAC key only. A future safe rotation mechanism must
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
`openai`, `openai-response`, `interactions`, `openai-image`, `openai-video`,
`claude`, `gemini`, or `unknown` enum. Legacy
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
exposed in v0.15.

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

The audited CPA ABI management routes are exact matches and reject `:` or `*`, so the
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
- optional classifier: interface reserved but not implemented in v0.15.

CPA owns the host fail-open policy. A plugin that is absent, fails registration,
is fused, returns a Router error, panics before an accepted handled result,
returns an invalid/empty target, or self-routes to an executor that is not ready
can be skipped while later Routers or native routing continue. A higher-priority
handled Router wins; equal priority is ordered by plugin ID ascending. No in-
process plugin can prove that every host or ABI failure will be fail-closed.
The authenticated status exposes `loaded`, `enforcement_ready`,
`router_errors`, `panics_recovered`, audit/HMAC/persistence degradation,
reconfigure error, build/ruleset identity, and the classifier-policy
version/hash. The read-only production watchdog checks those fields and runs
built-in local-only probes. ABI v1 cannot
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

The visible `testdata/development-adversarial-v11-prep` corpus adds 35
development cases: 16 block, 14 allow, 2 audit, and 3 resource-boundary
fixtures. It covers all eight taxonomies, four provider protocols, English,
Chinese, mixed language, role-aware and untrusted extraction, wrapper-only and
wrapper-plus-behavior, multi-turn/refusal continuation, tool payload/output,
bounded encodings, placeholders, and scan/part boundaries. Its validator checks
schema, taxonomy, IDs, duplicates/near-duplicates, balance, coverage,
production extraction, recovered semantics, and action/category. It is marked
development-only and must never be reused as a future Holdout.

The safe broad Go gate uses `scripts/go-safe-development-test.sh` in `test`,
`race`, and `boundary` modes so routine development verification does not open
consumed v4-v9 fixtures. Broad `go test ./...` is not an acceptable substitute.

The current CPA v7.2.88 plugin-store/source-contract module first proves that
17 exact upstream Host tests still exist, then runs those names precisely
instead of relying on a broad
wildcard. It also calls the official `pluginstore.InstallArchive` for both
synthetic bytes and, when supplied, the real build artifact. These checks cover
store naming, root-only library layout, checksum, installed path/bytes, repeat
installation, tamper repair, priority ordering, and documented Host fallback.
They remain historical source/installer evidence. Current admission requires
the v7.2.88 compatibility lane and exact-candidate real-Host run plus independent
verification.

The integration harness builds the `.so`, builds CPA at the pinned commit,
starts a local mock OpenAI-compatible upstream, and starts CPA with the plugin.
It installs the real store ZIP, loads the installed Guard, and asserts that safe
requests increment Auth Selector, Provider, Usage, and Mock Upstream counters
while blocked requests leave all four at zero. It covers OpenAI Chat, OpenAI
Responses, Anthropic, and Gemini non-streaming/streaming paths, pre-SSE 403,
token-count 403 where exposed, adapter-level nil-response/status-error 405 for `http_request`, safe model/body
and tool preservation, management authentication, reconfiguration, role-aware
follow-ups, encoded tool payloads, a Base64-expanded RPC above 8 MiB, and
disabled-plugin recovery.

A separately compiled minimal Router/executor fixture exercises priority
preemption, equal-priority plugin-ID ordering, invalid targets, missing or
disabled Guard state, registration failure, route error, and executor
identifier/format/scope readiness. Host fuse and pre-result panic remain pinned
to official source-overlay tests; the fixture does not use a process crash as a
false substitute for a recoverable plugin panic.

Historically, the Host/Router targets and management-proxy fixture were mistakenly executed
once in WSL outside the authorized evidence path. They used loopback/Mock
components only and cleanup left no fixture process, but the results are
excluded: `LOCAL MIS-EXECUTION RECORDED / EXCLUDED; CI REQUIRED / NOT YET
AUTHORITATIVE`. Separately, an earlier CPA v7.2.72 exact-freeze GitHub CI passed
the historical Host/Router/proxy matrix. Neither result validates v0.15. The
current CPA v7.2.88 exact-candidate Host matrix and independent
verification remain not run.

The authorized v0.15 artifact lifecycle is one chain over the same identity:
the final PR head passes PR CI, merges to `main`, and the exact resulting main
commit/tree passes push CI without producing a release; the private untagged
candidate workflow is then dispatched from `refs/heads/main` and produces clean
SO/Store ZIP bytes plus `candidate-manifest.json`; the CPA v7.2.88 Host record
and the independent audit bind that SO SHA-256. Attestation schema v2 records
the Host identity and evidence hash as `cpa_version`, `cpa_commit`, and
`cpa_host_sha256`; an
annotated development prerelease is optional; the annotated formal `v0.15` tag
and verified draft remain separate; and protected promotion may publish only
that unchanged draft. `InstallManifest` must prove first install and real Host
load, while `TestPublishedStoreArchive` verifies repeat-skip and tamper-repair.
Missing `.so`, Store ZIP, metadata, checksums, or candidate manifest must fail;
synthetic fallback cannot satisfy Host evidence.

Whether the authorized sandbox and independent auditor ran the suite against the
exact private candidate is an evidence field, not an architectural property;
consult the current Round 6 handoff and reports.
Release verification inspects the ELF and rejects a binary whose imported glibc
symbol version exceeds `GLIBC_2.34`. The published artifact therefore requires
glibc 2.34 or newer, is compatible with the official Debian Bookworm CPA image,
and does not support musl/Alpine runtimes.

For streaming blocks, the executor returns the 403 error before a stream is
established. CPA closes the request promptly with a protocol-compatible regular
error response. ABI v1 cannot simultaneously send HTTP 403 and establish an
SSE stream with terminal frames; returning successful chunks would force HTTP
200, so v0.15 chooses the genuine pre-stream 403.

## Build identity and release reproducibility

Builds link immutable version, full commit SHA, ruleset version/hash,
`classifier-policy-v4` /
`2763f10e2565dce2ffcf700f5d6566e9fbac68f3fedd08fcce20bceff450b4c8`,
streaming-scanner identity, and dirty state. Build metadata and the verifier bind
these identities. Candidate mode requires a clean worktree, exact expected
commit/tree, the commit timestamp, an absent formal `v0.15` tag, and forbids
formal operations. Formal release scripts require a clean worktree and annotated
`v0.15` tag at `HEAD`. `ALLOW_DIRTY_BUILD=1` remains development-only and cannot
produce the Host-test candidate.

`SOURCE_DATE_EPOCH` derives from the commit timestamp; clean candidate and formal
builds reject a different override.
Builds use `-trimpath`, a pinned Go toolchain, deterministic ZIP ordering and
timestamps, strict file allowlists, and a canonical ruleset manifest. The CPA
store ZIP contains exactly one root mode-0755 `.so`; documentation, metadata,
SBOM, and operational material live in a separately named audit bundle.
CycloneDX SBOM and checksums are verified against source and cover both ZIPs.
The candidate reproducibility gate builds in two clean clones and byte-compares
the `.so`, Store ZIP, metadata, ruleset identity, and SBOM without packaging an
audit bundle. The formal gate separately covers the audit bundle and source
archive.

Formal source and audit bundles exclude evaluation, Holdout, private, blind,
and retired material. Only low-sensitivity external evaluation identity/hash and
release-attestation files cross that packaging boundary.

These mechanisms make evidence reproducible; they do not turn a failed safety
gate into a release. v1-v8 are retired or consumed failures, v9 is a consumed
methodology-invalid failure, and methodologically valid v10 is a consumed
formal failure. Historical 0.1.2 evidence remains frozen. The formal v0.15
release is blocked until the exact candidate has an external `evaluation-v11`
or later first-and-only `CONSUMED / PASS` attestation; v10 cannot be rerun,
renamed, or supplied to the formal build.
