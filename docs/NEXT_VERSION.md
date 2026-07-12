# Next-Version Recommendations

1. Propose a CPA ABI-v2 block result carrying HTTP status, headers, and a
   protocol-native body so cooldown responses can include `Retry-After` and a
   blocked stream can have an explicit terminal event without forcing HTTP 200.
2. Extend the v0.1.1 role-aware standard envelopes with provider-specific
   quotation/provenance markers and a versioned compatibility corpus, without
   weakening the conservative fallback or history-cap fail-closed behavior.
3. Add signed, licensed external rule bundles restricted to the plugin data
   directory, with checksum verification, atomic activation, rollback, and a
   rule-development corpus separate from the locked acceptance set.
4. If a local classifier is implemented, require an explicit endpoint
   allowlist, pin resolved addresses, reject redirects, enforce loopback/private
   transport on every connection, bound payload/response size, and retain
   rules-only timeout behavior. Never enable public endpoints by default.
5. Ask CPA to expose a verified direct-peer address and authenticated downstream
   principal/key ID in `ModelRouteRequest`; only then enable trusted-proxy IP
   subject buckets.
6. Add dual-key HMAC rotation and optional encrypted persistence for subject
   cooldown/manual-block state across restarts.
7. Add an authenticated management UI mechanism. CPA v7.2.67 resource routes
   are public and must not carry audit or subject data.
8. Expand real-host coverage to safe/streaming Gemini variants and every
   production plugin ordering combination. The current suite already includes
   an observable auth-scheduler probe, usage-queue spy, role/tool regressions,
   and a no-copy oversized-RPC case.
9. Add a long-running nightly fuzz/leak job, signed SBOM/provenance, and
   reproducible-build comparison across two clean Linux builders.
10. Replace whole-buffer rune normalization with a streaming/byte-oriented
    matcher to reduce the current roughly 1.05 MB worst-case allocation without
    regressing the benign corpus.
