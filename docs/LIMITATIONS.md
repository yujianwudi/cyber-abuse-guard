# Known Limitations — v0.1.0

1. **No guarantee against account action.** The plugin reduces the number of
   clearly risky requests reaching upstream. It cannot guarantee that an
   upstream account will never be warned, suspended, or deactivated.
2. **Deterministic language rules are imperfect.** Novel wording, arbitrary
   encoding, images, audio, encrypted content, and sufficiently adversarial
   obfuscation may evade classification. False positives and negatives remain
   possible.
3. **Truncated content cannot be fully classified.** Inputs beyond configured
   budgets are marked truncated. Operators must not treat an unscanned suffix
   as proven safe; strict handling is documented in status and reports.
4. **Role provenance is limited.** CPA provides a raw body. The extractor
   retains text parts but v0.1.0 does not build a full trust model for quoted
   policy text versus user instructions in every vendor-specific extension.
5. **403 versus SSE is an ABI-v1 tradeoff.** CPA v7.2.67's executor result has
   no status field. A blocked streaming request returns a genuine HTTP 403
   before SSE is established and closes promptly. ABI v1 cannot return both a
   403 and an already-established SSE terminal frame; a successful stream
   would force HTTP 200.
6. **Protocol-specific error shape.** OpenAI-compatible handlers can preserve a
   structured JSON error message. Anthropic normalizes plugin errors and may
   drop the custom code/category. CPA discards the plugin error code and keeps
   only message and HTTP status at the executor adapter boundary.
7. **No `Retry-After` on executor errors.** ABI-v1 RPC errors cannot attach
   downstream response headers.
8. **Exact management routes only.** CPA v7.2.67 rejects dynamic `:`/`*` plugin
   routes. Subject unblock therefore uses a fixed path and JSON body.
9. **No trusted remote address in `ModelRouteRequest`.** Key-based subjects are
   HMACed from inbound auth headers after CPA request authentication. CPA
   v7.2.67 exposes neither a separate authenticated principal/key-policy ID nor
   the direct peer needed to validate a forwarded header, so v0.1.0 rejects
   `trusted_proxy.enabled: true` and otherwise uses an anonymous bucket.
10. **Router ordering matters.** The first handled router wins. A higher-
    priority router can bypass this plugin. Verify priority 300 ordering and
    disable the old identity-rewrite filter.
11. **CPA router failures are fail-open.** A router error is logged and routing
    continues; a panic fuses the plugin. CPA v7.2.67 has no host-level
    fail-closed router mode. Monitor plugin status/logs.
12. **No external/local model classifier in v0.1.0.** The configuration shape is
    reserved and validated, but the plugin makes no classifier network call.
13. **No management UI in v0.1.0.** CPA resource routes are unauthenticated.
    This release exposes audit/subject data only through authenticated
    management API routes.
14. **No custom rule override in v0.1.0.** Rules are embedded for reproducible
    builds. Signed external rules, safe path constraints, license metadata, and
    atomic rollback need a later design.
15. **No challenge workflow.** Strict mode blocks; the task book does not define
    a portable challenge protocol or state machine.
16. **HMAC rotation is manual.** Changing the key breaks correlation with old
    subject hashes. A dual-key migration mechanism is not implemented.
17. **Target pin.** Only CPA v7.2.67/ABI v1 is integration-tested. Re-run the
    full host suite before using a newer CPA release.
18. **Subject state is process-local.** Risk scores, cooldowns, and manual-block
    flags reset when CPA restarts. Events remain in SQLite, but v0.1.0 does not
    reconstruct enforcement state from audit history.
19. **Worst-case normalization exceeds the aspirational 1 MiB allocation
    goal.** Ordinary decisions allocate about 3.4 KiB, but deliberately large
    near-budget inputs allocate about 1.3–1.6 MiB. Scan/rune/depth/part limits
    keep the work bounded; a streaming matcher is planned for a later version.
20. **Two known evaluation misses remain.** The v0.1.0 Balanced corpus misses
    two indirect data-exfiltration paraphrases (`M128` and `M150`) while still
    exceeding the overall recall target. Exact results are recorded in
    `reports/CORPUS_REPORT.md`.
21. **Opaque embedded media fails closed in enforcing modes.** Image/audio
    bytes and data URLs are not decoded. Their presence sets `truncated`, so
    Balanced/Strict reject the request; Observe/Audit only record the condition.
    HTTPS media URLs are metadata and are not fetched or inspected. This favors
    upstream-safety isolation over transparent multimodal support in v0.1.0.
