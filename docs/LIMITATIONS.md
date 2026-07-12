# Known Limitations — v0.1.1

1. **No guarantee against account action.** The plugin reduces the number of
   clearly risky requests reaching upstream. It cannot guarantee that an
   upstream account will never be warned, suspended, or deactivated.
2. **Deterministic language rules are imperfect.** Novel wording, arbitrary
   encoding, images, audio, encrypted content, and sufficiently adversarial
   obfuscation may evade classification. False positives and negatives remain
   possible.
3. **Truncated content cannot be fully classified.** Inputs beyond configured
   budgets, including an artificial boundary inside an escape or UTF-8
   sequence, are marked truncated. `balanced` and `strict` fail closed;
   `observe` and `audit` can only report the condition. For an RPC above the
   native no-copy boundary, the minimal event cannot contain a request hash,
   model, source format, or body-derived byte count because none is copied.
4. **Role provenance is bounded, not universal.** Standard OpenAI, Anthropic,
   and Gemini envelopes are segmented as system/user/assistant/tool. Role-less
   provider items use conservative per-part and adjacent-part classification;
   explicit unsupported roles and over-64-segment histories fail closed in
   enforcing modes. Vendor-specific quotation and provenance extensions that
   do not use these standard fields still lack a complete trust model. Evidence
   deliberately split across multiple non-adjacent turns may remain outside the
   deterministic follow-up window.
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
   the direct peer needed to validate a forwarded header, so v0.1.1 rejects
   `trusted_proxy.enabled: true` and otherwise uses an anonymous bucket.
10. **Router ordering matters.** The first handled router wins. A higher-
    priority router can bypass this plugin. Verify priority 300 ordering and
    disable the old identity-rewrite filter.
11. **CPA router failures are fail-open.** A router error is logged and routing
    continues; a panic fuses the plugin. CPA v7.2.67 has no host-level
    fail-closed router mode. Monitor plugin status/logs.
12. **No external/local model classifier in v0.1.1.** The configuration shape is
    reserved and validated, but the plugin makes no classifier network call.
13. **No management UI in v0.1.1.** CPA resource routes are unauthenticated.
    This release exposes audit/subject data only through authenticated
    management API routes.
14. **No custom rule override in v0.1.1.** Rules are embedded for reproducible
    builds. Signed external rules, safe path constraints, license metadata, and
    atomic rollback need a later design.
15. **No challenge workflow.** Strict mode blocks; the task book does not define
    a portable challenge protocol or state machine.
16. **HMAC rotation is manual.** Changing the key breaks correlation with old
    subject hashes. A dual-key migration mechanism is not implemented.
17. **Target and runtime pin.** Only CPA v7.2.67/ABI v1 is integration-tested.
    Re-run the full host suite before using a newer CPA release. The published
    Linux amd64 binary is compatible with the official Debian Bookworm CPA
    image, requires glibc 2.34 or newer, and does not support musl/Alpine.
18. **Subject state is process-local.** Risk scores, cooldowns, and manual-block
    flags reset when CPA restarts. Events remain in SQLite, but v0.1.1 does not
    reconstruct enforcement state from audit history.
19. **Worst-case normalization remains just above the aspirational 1 MB
    allocation goal.** Ordinary decisions allocate about 3.27 KiB, while
    deliberately large near-budget inputs allocate about 1,050,144 bytes (about
    1.05 MB / 1.00 MiB). Scan/rune/depth/part limits keep work bounded; a
    streaming matcher is planned for a later version.
20. **Opaque embedded media fails closed in enforcing modes.** Image/audio
    bytes and data URLs are not decoded. Their presence sets `truncated`, so
    Balanced/Strict reject the request; Observe/Audit only record the condition.
    HTTPS media URLs are metadata and are not fetched or inspected. This favors
    upstream-safety isolation over transparent multimodal support in v0.1.1.
21. **Audit paths require a trusted directory chain.** The final data directory
    must not be group/world writable; final database-directory and DB/WAL/SHM
    symlinks are rejected. The plugin does not implement a fully `openat`-
    anchored walk of every ancestor, so operators must not place `data_dir`
    beneath an attacker-controlled or same-user-mutated ancestor.
22. **Host logging is a trust assumption.** Error callbacks are rate-limited,
    panic-contained, and invoked outside store locks so shutdown keeps its
    deadline. A host logger that blocks forever may leave one audit worker and
    its background finalizer pending even though plugin shutdown returns.
23. **Non-Linux secret-file hardening is weaker.** The published target is
    Linux, where `O_NOFOLLOW` plus same-descriptor validation closes the final-
    component swap. Other build targets retain an `Lstat`/open fallback and are
    not release-supported.
24. **Capacity shrink is a logical bound, not an immediate heap compactor.** A
    hot shrink evicts entries immediately, but Go may retain now-empty map
    buckets until a later garbage collection or controller replacement. The new
    entry limit is still enforced for every request.
