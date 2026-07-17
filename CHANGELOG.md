# Changelog

## 0.1.2 — Unreleased candidate

Release status: **BLOCKED / PENDING HOST AND INDEPENDENT AUDIT**. Round 6 is an
unmerged development candidate based on
`main@7a416df66a79218d73214084d4bf8a733268d894`. No Round 6 tag or Release has
been created, and production deployment or an `observe -> balanced` change is
not authorized. The only validation platform in this round is Linux amd64;
Windows and macOS are outside scope. The historical v10 result remains
`CONSUMED / FAIL` and cannot be rerun or used for tuning. A future stable
release still requires a newly authored independent unseen set.

### Round 6 long-text streaming candidate

- Remove production parsing of `body[:max_scan_bytes]`. Supported JSON requests
  now traverse the complete CPA-visible envelope and replay proven
  model-visible string spans incrementally.
- Migrate legacy `max_scan_bytes` into a compatibility alias for the retained
  classifier window. Add bounded `max_total_text_bytes` and
  `max_classification_chunks` controls so cumulative coverage and retained
  memory are independent.
- Add a streaming classifier session with derived overlap/carry, logical field
  boundaries, role/provenance isolation, bounded cross-window reconstruction,
  and fixed coverage states.
- Retain only bounded classifier signal facts inside each logical field. If
  independently safe-looking windows contribute different risk ingredients
  whose aggregate reaches the balanced threshold, report classifier-window
  coverage as unavailable instead of incorrectly returning complete allow.
- Treat assistant/system safety quotes as provisional until a real closing
  delimiter is observed. Closed quotations discard their bounded provisional
  result; an unclosed logical field commits it as ordinary content, including
  later-window and cross-window malicious text.
- Inspect oversized Base64 candidates with a constant-memory full-stream syntax
  and decoded-text signal so a binary first sample cannot hide printable text
  near the end, malformed trailing bytes cannot erase an already proven strong
  printable Base64 prefix, and high-density text cannot evade detection by
  inserting a control byte before every 32-byte run. Enforce `max_classification_chunks`
  before every actual emitted UTF-8-safe chunk rather than relying only on a
  byte-length estimate.
- Keep media, metadata, tool-schema, multipart, and role decisions
  transactional. Add `RoleUnknown` so unknown schema cannot impersonate proven
  user text.
- Replace the CPA-transformed OpenAI image multipart JSON legacy collector with
  a schema-bound raw-span streaming planner. Approved 270 KiB and 1 MiB prompts
  now receive complete classification in balanced/strict mode, while unknown
  fields, non-string prompts, opaque files, binary controls, and oversized
  encoded views retain their fixed multipart contracts.
- Neutralize every partial finding when envelope or text coverage is
  incomplete. The optional verified-local-hard exception remains disabled:
  `balanced` allows plus audits, `strict` blocks plus audits, and incomplete
  input never updates subject risk.
- Add audit schema v3 fields `decision`, `coverage`,
  `incomplete_reason`, and `scanner`, scanner identity
  `streaming-scanner-v1`, effective-limit status, and fixed low-cardinality
  counters.
- Publish classifier identity `classifier-policy-v3` /
  `2c8c85a913c7ee68db4ec1d63502cbe81d0162e9314c7a36df54a27c93ad7645`.
- Compact the transactional shadow plan by collapsing caller-controlled keys
  and semantic values to closed representatives, skipping metadata spans, and
  using short base-36 markers. Residual allocation remains bounded by structural
  token/node/field limits and awaits authoritative Linux memory evidence.
- Add Linux long-text coverage tiers at 64 KiB, 255 KiB, 256 KiB,
  256 KiB + 1, 270 KiB, 512 KiB, 1 MiB, 4 MiB, and near the effective RPC
  boundary, plus classifier/extractor fuzz and scaling benchmarks. Final
  results remain pending exact-source Linux CI.
- Isolate consumed evaluation/Holdout gate tests behind the
  `consumed_evaluation` build tag and restrict ordinary Round 6 CI to explicit
  safe targets and sparse source checkout.
- Make the Linux build itself audit the complete `readelf --version-info` set,
  reject non-numeric GLIBC ABI tags and numeric versions above 2.34, and make
  the long-JSON benchmark fail if its exact extract-package benchmark name is
  absent instead of accepting a zero-match run.
- Bind the manual blocked prerelease to an exact candidate SO SHA-256 cited by
  both CPA Host records and the independent audit. Split the gate into exact
  `admission -> verify -> publish` jobs: verify rebuilds and uploads one
  commit-named artifact with read-only non-persisted checkout credentials,
  publish downloads and reverifies it without a checkout, and the final
  GH-token-bearing step peels the annotated tag through the GitHub API before
  running the locked draft/prerelease/not-latest GH CLI command.
- Preserve two deliberate compatibility boundaries: dense encoded derived
  views beyond the 128 KiB source / 64 KiB retained decoded budget are
  incomplete, and legacy `ExtractText` keeps materialized `Parts` segmentation
  semantics while production routing uses streaming APIs.
- Target CPA v7.2.80 and v7.2.79 source/compile lanes, but leave both real
  Linux Host + Mock-upstream matrices **NOT RUN / PENDING**. Do not merge to
  `main` or create a Release before those Host gates and independent audit pass.
- Add the Round 6 design, configuration migration, limitations, release-gate,
  and development-handoff documents.

### Earlier 0.1.2 development history

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
