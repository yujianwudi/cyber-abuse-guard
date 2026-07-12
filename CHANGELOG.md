# Changelog

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
