# Next-Version Recommendations

These items remain after the v0.1.2 candidate work. They are not claims about
implemented behavior.

1. Propose a CPA ABI-v2 block result carrying HTTP status, headers, and a
   protocol-native body so cooldown responses can include `Retry-After`, a
   blocked stream can have an explicit terminal event without HTTP 200, and the
   host can offer a true fail-closed Router policy.
2. Ask CPA to expose authenticated downstream principal/key-policy ID, verified
   direct-peer address, loaded Router ordering, and active plugin binary
   inventory. Only then enable trusted-proxy subjects and in-process conflict/
   duplicate-version checks.
3. Implement the documented dual-key HMAC rotation state machine: one active
   and one previous read-only key, one-way fingerprints, bounded transition
   state, finite overlap, active-key-only writes, and explicit finalization.
4. Add an authenticated operator action for deliberately archiving/resetting a
   key-mismatched subject snapshot. It must not expose raw subjects or silently
   overwrite state.
5. Establish an independent blind-Holdout generation and review pipeline outside
   the rule-development loop. Each release should freeze new SHA-256 inputs,
   emit aggregate-only results, and prevent row-level access before the gate.
6. Extend role/provenance support with provider-versioned quotation and citation
   markers while preserving conservative unsupported-role and history-cap
   behavior.
7. Add signed, licensed external rule bundles only if they are restricted to a
   trusted plugin-data directory, permission checked, signature/hash verified,
   atomically activated, offline by default, and backed by the embedded rules.
   Never auto-download rules.
8. If a local model classifier is added, require explicit loopback/private
   endpoint allowlists, address pinning per connection, redirect rejection,
   bounded request/response sizes, rules-only fallback, and privacy canaries.
   Public endpoints must remain unsupported by default.
9. Add an authenticated management UI mechanism only after CPA offers a safe
   private resource route. CPA v7.2.67 public resource routes must never carry
   audit or subject data.
10. Replace whole-buffer rune normalization with a streaming/byte-oriented
    matcher to bring near-budget allocation below 1,000,000 bytes/op without
    reducing scan, decode, history, or rule coverage.
11. Add long-running nightly fuzz, soak, migration-fault, and memory-leak jobs,
    signed provenance/attestation, and reproducibility comparison across two
    independent Linux builders rather than two local clones only.
12. Qualify newer CPA releases and architectures one at a time with the full
    Mock Upstream/Auth Selector/Usage isolation suite. Do not infer compatibility
    from ABI numbers alone.
