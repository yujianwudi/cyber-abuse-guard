# Changelog

## 0.1.2 — Unreleased candidate

Release status: **blocked candidate; not production-ready**. Blind generations
v1-v8 are retired or consumed failures. v9 is frozen as
`CONSUMED / METHODOLOGY INVALID / FAIL` because the exact taxonomy-enum
validator was missing. The first and only methodologically valid v10 run failed
with 28/320 benign false positives, 49/320 policy blocks, and 33/320 exact
classifications. v10 is consumed and cannot be rerun. No `v0.1.2` tag, GitHub
Release, or production deployment may be created from this candidate. A future
release attempt requires a new implementation and a new independently authored
unseen set.

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
