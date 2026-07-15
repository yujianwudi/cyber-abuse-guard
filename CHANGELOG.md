# Changelog

## 0.1.2 — Unreleased candidate

Release status: **blocked candidate; not production-ready**. Blind generations
v1-v8 are retired or consumed failures. v9 is frozen as
`CONSUMED / METHODOLOGY INVALID / FAIL` because the exact taxonomy-enum
validator was missing. The first and only methodologically valid v10 run failed
with 28/320 benign false positives, 49/320 policy blocks, and 33/320 exact
  classifications. v10 is consumed and cannot be rerun. No stable `v0.1.2` tag,
  production release, or production deployment may be created from this
  candidate. The repository owner may publish an explicitly marked development
  prerelease snapshot such as `v0.1.2-dev.round5.1`; it is not release admission,
  must not be marked latest, and may contain only dirty development artifacts.
  A future stable release attempt requires a new implementation and a newly
  authored independent unseen set.

- Complete the Phase 0 CPA contract alignment without changing the root runtime
  baseline from CPA v7.2.67. Local `execute`, `execute_stream`, and
  `count_tokens` refusals now emit policy RPC error envelopes requesting HTTP
  403, while unsupported `http_request` remains an envelope requesting 405.
- Split the CPA Store archive from the audit/operator bundle. The Store ZIP
  contains exactly one executable `.so` at its root; documentation, build
  metadata, SBOM, and verification material are packaged separately in the
  Audit Bundle. The root `checksums.txt` remains a separate release asset that
  covers both the Store ZIP and Audit Bundle.
- Add an isolated CPA v7.2.72 source-contract module for the official
  `pluginstore.InstallArchive` naming/layout/install behavior and official
  Host Router ordering/fallback tests. These tests do not load this plugin and
  are not CPA v7.2.72 runtime-compatibility evidence.
- Document that the audited CPA v7.2.72 management path calls `io.ReadAll`
  before the plugin handler, so plugin body limits are not host HTTP memory
  limits and an external reverse-proxy limit still requires server evidence.

- Add the development-only deterministic `META-OVERRIDE-001` classifier
  overlay for instruction-hierarchy inversion, refusal suppression,
  unrestricted persona claims, sandbox/placeholder laundering, forced-output
  controls, explicit negative authorization, and system/developer-prompt or
  hidden-reasoning disclosure. It requires independent evidence families; a
  lone `jailbreak`, `benchmark`, or `developer` token is not a block rule.
- Re-extract supported-provider bodies conservatively when role proof fails;
  recursively inspect JSON-looking strings inside established tool payloads;
  re-decode content joined from split provider blocks; reconstruct tightly
  bounded isolated-character fragments; extend the reviewed homoglyph map; and
  reject malicious policy wording that negates refusal or filtering rather
  than the abusive action.
- Record this work as post-v10 developer-visible engineering evidence only.
  The targeted source package tests, vet, module verification, and diff checks
  are recorded in `docs/reports/TEST_REPORT.md`. Server sandbox validation,
  current-diff real-CPA integration, native loading, deployment, and formal
  Holdout remain pending, not run, or prohibited. A development prerelease may
  be published only as a blocked audit snapshot; the v10 release failure is
  unchanged.
- Document that ruleset `1.0.7` and its canonical SHA-256 identify only the
  embedded YAML cyber-abuse assets. The complete post-v10 classifier policy —
  including the meta overlay plus matcher, normalizer, role, and extractor
  semantics — is identified only by the containing source/build commit, not by
  the ruleset manifest; a future release must add a separately versioned policy
  identity or bind all behavior to verified build provenance.

- Harden the post-v10 development tree after independent review. Carrier
  authors now prove that production extraction recovers the authored semantic
  text; validators fail on schema, duplication, extraction, overlap, taxonomy,
  scale, distribution, and frozen prior-corpus inventory errors; snapshot globs
  must all match; and one shared fixture publisher keeps incomplete staging
  private before a no-replace atomic rename. Files and Unix directory metadata
  are synced; non-Unix directory sync is explicitly best-effort. Unix tests
  now assert that the destination name stays absent throughout staging.
  Windows uses native `MoveFileEx` without replace semantics and is exercised
  against existing files, symlinks, and concurrent publishers.
- Preserve v9/v10 corpus and historical implementation hashes without forcing
  later development HEADs to equal consumed-run snapshots. Full-history CI now
  binds the recorded hashes to commit `0f1d68717daadfd5dfc514ff2174cfb641a5d845`
  and tree `df878c537bca9fd71256b1c81ced18e72b583cf3`, then recomputes them from Git
  blobs. The frozen v9/v10 corpus and formal report blobs are bound to the same
  commit so changing current files and constants together cannot rewrite the
  consumed record. Missing Git metadata or shallow history fails this gate
  closed instead of silently passing. Current source remains unevaluated until
  a new independent unseen set exists.
- Harden malformed and permissively decoded Base64 handling, including
  horizontal whitespace and valid padded prefixes followed by ignored suffix
  bytes. Also harden atomic no-follow HMAC secret opening across Unix, callback
  synchronization tests, decimal watchdog budgets, and portable HMAC-key
  publication synchronization.
- Update `golang.org/x/crypto` to `v0.52.0` and `golang.org/x/net` to `v0.55.0`
  plus their required `x/text`, `x/sync`, and `x/sys` versions, meeting the
  minimum patched versions for all 14 alerts against the prior module graph.

- Add bounded textual decoding for URL percent escapes, HTML entities,
  inspectable Base64, textual data URLs, JSON escapes, and nested tool JSON.
  Decoding is limited to two layers, eight variants, a 128 KiB encoded source,
  and 64 KiB retained decoded text; no decompression, archive expansion, or
  network fetch is performed.
- Separate opaque image/audio/video handling from text truncation. Add
  `opaque_media_policy: block|audit|allow` with mode-aware defaults: Off allows,
  Observe/Audit/Balanced audit, and Strict blocks. Public media URLs are never
  fetched.
- Publish embedded ruleset `1.0.7` and expose linked version plus canonical
  ruleset SHA-256 through build metadata and authenticated status.
- Add router error and recovered-panic counters, `enforcement_ready`, explicit
  audit/HMAC/persistence degradation, build identity, reconfigure error, and
  ABI conflict-detection limitations to management status.
- Add a read-only production health checker. Its benign and fixed-malicious
  probes are evaluated locally through authenticated management routes and
  never reach `/v1`, CPA auth selection, usage accounting, or an upstream.
- Bound and harden management request bodies, query parameters, pagination,
  method handling, delete/unblock inputs, and database-degraded responses. CPA
  Management Key middleware remains the authentication authority; ordinary
  downstream keys cannot authorize plugin management routes.
- Keep `audit.log_original_text` only as a rejected compatibility field.
  `true` fails configuration; no debug mode persists raw prompt/request text.
- Introduce atomic SQLite schema migrations with `schema_version` and
  `migration_history`. Schema v2 adds optional subject-state storage. Optional
  pre-migration `VACUUM INTO` backups are mode 0400 and retention-bounded.
- Add optional `subject_control.persistence`. It stores only HMAC subject IDs
  and bounded risk/cooldown/manual-block state, applies expiry/decay/capacity on
  restore, requires a stable HMAC key, and explicitly degrades on key mismatch
  without overwriting the old snapshot. In-memory enforcement remains active.
- Add a race-resistant HMAC secret-file generator that does not print secret
  material. Document a future active/previous dual-key rotation state machine;
  dual-key rotation is not implemented in v0.1.2.
- Add a versioned build identity (`version`, commit, ruleset version/hash,
  dirty state), clean-tag preflight, deterministic timestamps, strict
  verification failure, ruleset manifest, CycloneDX SBOM, pinned
  `govulncheck`, and two-clean-clone reproducibility comparison.
- Refactor CI into explicit format, diff, module, unit, race, vet, fuzz,
  regression, Holdout, benchmark, vulnerability, build, real-CPA integration,
  verification-fault, artifact-hash, clean-tree, and reproducibility gates.
  Format checking includes tracked and untracked Go files and exits cleanly
  when a repository contains none.
- Add production operations documentation for Observe → Audit → Balanced
  rollout, watchdog alarms, router-order/duplicate-binary manual checks,
  binary/database rollback, HMAC retention, and opt-in complete cleanup.
- Add evidence templates for tests, performance, CPA integration, privacy, and
  release provenance. Missing formal artifacts are labelled `NOT CREATED —
  RELEASE BLOCKED`; no v0.1.1 result is presented as v0.1.2 evidence.

## 0.1.1 — 2026-07-12

- Treat artificial scan boundaries inside JSON escapes or UTF-8 sequences as
  truncation instead of parse errors, so enforcing modes fail closed rather
  than surfacing a CPA router-error fail-open path.
- Scan metadata-named fields such as `name`, `url`, `type`, and `model` when
  they occur inside tool payloads, including order-independent Anthropic
  `tool_use.input`, while continuing to skip transport metadata.
- Add role-aware standard OpenAI/Anthropic/Gemini conversation extraction.
  Classify every retained segment independently, join adjacent user turns for
  follow-ups, use a conservative fallback for role-less provider items, and
  fail closed instead of silently discarding over-capacity history.
- Handle over-8-MiB Base64-expanded model-route RPCs without copying the giant
  payload: Balanced/Strict self-route to a local scan-limit refusal, while
  non-enforcing modes retain their documented behavior. Record a privacy-
  minimal scan-limit event without inventing unavailable request metadata.
- Scope negation and prohibition cues to nearby evidence so unrelated prefixes
  cannot suppress a later operational-abuse request.
- Publish embedded ruleset `1.0.1`, including targeted indirect
  data-exfiltration coverage for corpus cases `M128` and `M150`.
- Bound subject state with `subject_control.max_subjects` (default 10,000), LRU
  eviction of non-manual entries, protected manual blocks, capacity counters,
  and fail-closed handling when protected entries consume all capacity.
- Preserve risk, cooldown, and manual-block state across compatible enabled-to-
  enabled hot reconfiguration; reject unsafe capacity shrink atomically, keep
  `started_at` stable, and expose the latest `configured_at` plus capacity
  counters in status.
- Leave safe existing audit-directory permissions unchanged; reject writable
  directories plus database/sidecar symlinks; surface runtime permission
  failures; add deadline-bounded shutdown and reentrant, rate-limited audit
  degradation logs.
- Harden Linux HMAC secret loading with `O_NOFOLLOW` and validate/read from the
  same opened file descriptor.
- Require the release path to pass the pinned real-CPA integration suite and
  reject binaries importing glibc symbol versions newer than `GLIBC_2.34`.
- Reduce ordinary classifier latency/allocation and remove the two retained
  exfiltration misses: the locked Balanced corpus now measures 0/142 false
  positives and 154/154 malicious exact-category recall.

## 0.1.0 — 2026-07-12

- Initial CPA v7.2.67 C-ABI v1 plugin.
- Pre-auth ModelRouter and local 403 executor.
- Embedded bilingual deterministic rules across eight abuse categories.
- Bounded multi-protocol text extraction and fuzz coverage.
- Balanced/strict enforcement plus observe/audit modes.
- HMAC subject correlation, decay, cooldown, and manual unblock.
- Minimal SQLite audit events and authenticated management API.
- Linux amd64 reproducible build, checksums, release ZIP, and real-host test.
