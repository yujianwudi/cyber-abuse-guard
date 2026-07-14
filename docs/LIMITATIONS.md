# Known Limitations — v0.1.2 candidate

1. **No guarantee against account action.** The plugin reduces the number of
   clearly risky requests that reach upstream. It cannot guarantee that an
   account will never be warned, rate-limited, suspended, or deactivated.

2. **The current candidate failed the formal release gate.** v1-v8 are retired
   or consumed failures. v9 is a consumed methodology-invalid failure because
   the exact taxonomy-enum validator was missing. The methodologically valid
   v10 first-and-only run failed with 28/320 benign false positives, 49/320
   policy blocks, and 33/320 exact classifications. v10 cannot be rerun. No
   `v0.1.2` tag, GitHub Release, or production deployment may be created; a
   future attempt requires a new implementation and a new independent unseen
   set.

3. **Deterministic language rules are imperfect.** Novel phrasing, languages,
   slang, semantic indirection, encrypted content, unknown encodings, and
   sufficiently adversarial obfuscation may evade detection. False positives
   and false negatives remain possible.

4. **Decoding is intentionally bounded.** URL escapes, HTML entities,
   inspectable Base64, textual data URLs, JSON escapes, and nested tool JSON are
   limited to two decode layers, eight variants, 128 KiB source, and 64 KiB
   retained decoded text. The plugin does not decompress, expand archives, or
   parse arbitrary documents. An incomplete recognized text envelope is
   conservative in enforcing modes. Complete unknown/high-entropy strings are
   scanned literally and are not blocked solely because they appear encoded;
   encrypted or novel encodings can therefore evade semantic detection.

5. **Opaque media is not inspected.** Image/audio/video/document-attachment
   bytes and their meaning are unavailable to the classifier. The plugin never fetches HTTPS media
   URLs. Mode-aware defaults audit opaque media in Observe/Audit/Balanced and
   block it in Strict; operators may explicitly choose `block`, `audit`, or
   `allow`. `allow` is uninspected pass-through, not a safety determination.

6. **Truncated content cannot be fully classified.** Inputs beyond byte, part,
   depth, segment, native RPC, or decode budgets are marked incomplete.
   Balanced/Strict fail closed for ordinary truncation; Observe/Audit can only
   report it. A no-copy oversized RPC event cannot include a request hash,
   model, source format, or body-derived byte count because the body is not
   copied into Go.

7. **Role provenance is bounded, not universal.** Standard OpenAI, Anthropic,
   and Gemini envelopes use role-aware segments. Unsupported explicit roles and
   over-capacity histories are conservative in enforcing modes. Vendor-specific
   quotation/provenance extensions and deliberately split non-adjacent evidence
   can remain outside the deterministic follow-up window.

8. **CPA router failures are host-level fail-open.** The root development
   dependency is CPA v7.2.72. CPA may continue other Routers or native routing if
   the plugin is not loaded, registration fails, it is fused, the Router returns
   an error, a panic occurs before the host accepts a valid handled result, the
   target is invalid/empty, or the self executor is not ready. The plugin
   self-routes known failures and recovered ModelRouter panics in an active
   Balanced/Strict runtime, but it cannot alter CPA's host policy or prove
   fail-closed behavior for every host/ABI failure. `enforcement_ready` reports
   only internal plugin state and does not prove host load, registration,
   ordering, fuse state, or per-request executor readiness. Watchdog and
   counter-delta monitoring remain mandatory.

9. **Router ordering cannot be enumerated.** The first handled Router wins. ABI
   v1 does not expose loaded Router ordering, so a higher-priority plugin can
   bypass this guard. Use priority 300, inspect deployment configuration, and
   disable the old `antigravity-coding-filter`. Routers at the same priority are
   ordered by plugin ID ascending; a lexicographically earlier ID can still
   handle the request first.

10. **Duplicate plugin binaries cannot be detected in-process.** ABI v1 does
    not expose the plugin directory. The operator must ensure only one
    `cyber-abuse-guard` `.so` version is installed before restart.

11. **403 versus SSE is an ABI-v1 tradeoff.** `ExecutorResponse` has no status
    field. A blocked stream returns a genuine HTTP 403 before SSE is
    established. ABI v1 cannot return both a 403 and a successful terminal SSE
    frame; successful chunks would force HTTP 200. The policy executor routes
    `execute`, `execute_stream`, and `count_tokens` to the same policy HTTP 403;
    `http_request` returns an unsupported-method RPC error whose `StatusCode()`
    is 405; the official adapter returns `(nil, error)`. CPA v7.2.72's public
    `/v1/alpha/search` consumer normally selects `codex` and maps every executor
    error to HTTP 502. The project-owned `httptest.Server` manually maps the
    status error, so final official CPA client HTTP 405 is `NOT AVAILABLE / NOT
    RUN` and remains a handoff blocker until an official route can map Guard's
    error to a final 405.

12. **Protocol-specific error shapes differ.** OpenAI-compatible handlers can
    retain a stable marker. Anthropic may normalize plugin errors and drop
    custom code/category fields. CPA's executor adapter controls the final
    protocol envelope.

13. **No `Retry-After` on executor errors.** ABI-v1 RPC errors cannot attach
    arbitrary downstream response headers.

14. **Exact management routes only.** CPA v7.2.72 rejects dynamic `:`/`*`
    plugin routes, so subject unblock uses a fixed path and bounded JSON body.
    CPA host middleware, not the plugin, is the Management Key verification
    authority; ABI v1 does not reveal the configured key to the plugin. Host
    401 behavior must be integration-tested. CPA currently executes
    `io.ReadAll` in `ServeManagementHTTP` before calling the plugin, so the
    plugin's 1 MiB body and 2 MiB RPC-envelope limits are not a host HTTP memory
    ceiling. Deployments need an upstream body limit such as Nginx
    `client_max_body_size 1m`, with a server test proving HTTP 413 occurs before
    CPA receives the request.

15. **No trustworthy remote address in `ModelRouteRequest`.** CPA exposes
    neither a verified direct peer nor a separate authenticated principal/key
    policy ID. `trusted_proxy.enabled: true` is rejected; forwarded headers are
    not trusted. Subjects are HMACed from the authenticated downstream key or
    use an anonymous bucket.

16. **No external/local model classifier.** The configuration shape is
    reserved, but `classifier.enabled: true` is rejected. The plugin makes no
    classifier network request and does not upload prompts to a third party.

17. **No authenticated management UI.** CPA v7.2.72 resource routes are not a
    safe place for audit/subject data. This version exposes exact authenticated
    management API routes only.

18. **No external rule override.** Rules remain embedded for deterministic,
    auditable builds. Signed external rules, path constraints, atomic rollback,
    and license metadata require a later version. No rule is downloaded at
    runtime.

19. **No challenge workflow.** Strict mode blocks. ABI v1 and this release do
    not define a portable challenge/approval state machine.

20. **HMAC dual-key rotation is not implemented.** Changing the key breaks
    correlation with stored subject IDs. A future active/previous-key design is
    documented, but v0.1.2 accepts one active key. Preserve the current key for
    normal upgrades or explicitly treat the change as a state reset.

21. **Subject persistence is optional, not universal.** With persistence off
    (the default), restart clears risk, cooldown, and manual blocks. With it on,
    a stable HMAC key, audit DB, and `max_subjects <= 10000` are required. A key
    mismatch blocks persistence writes and reports degradation; the operator
    must deliberately retain, archive, or reset the old snapshot.

22. **Persisted-state completeness is not cryptographically authenticated.**
    The loader rejects malformed types, hashes, rows, versions, and key
    mismatches, but schema v2 has no keyed whole-snapshot MAC. An actor who can
    write the SQLite file can delete otherwise valid subject rows without that
    deletion being distinguishable from a legitimate smaller snapshot. Keep
    the DB below a trusted, non-writable path and treat local DB writers as
    trusted for persistence completeness.

23. **Schema downgrade is not promised.** v0.1.2 migrates a v0.1.1 event DB to
    schema v2 atomically and can create bounded pre-migration backups. v0.1.1 is
    not claimed to understand schema v2. A full rollback should restore the
    matching pre-migration database backup. Before publishing a backup or
    migrating, legacy `request_hash`, `subject_hash`, `model`, and
    `source_format` must already satisfy digest/fixed-provider privacy contracts.
    A nonconforming value fails closed: no backup is published, no migration
    occurs, and the original DB is retained for operator repair. The plugin does
    not automatically sanitize a legacy plaintext database.

24. **Audit path ancestors are a trust boundary.** The final data directory
    must not be group/world writable; final DB/WAL/SHM symlinks are rejected.
    The plugin does not provide a fully `openat`-anchored walk of every ancestor,
    so do not place `data_dir` below an attacker-controlled path.

25. **Audit availability is not enforcement availability.** SQLite lock,
    permission, queue, migration, or write failures degrade audit/persistence
    while local classification and blocking continue. This avoids making the
    database an availability dependency, but means events may be dropped. Treat
    any degradation as an operational alarm.

26. **Host logging is trusted to return.** Error callbacks are rate-limited,
    panic-contained, and invoked outside store locks. A host logger that blocks
    forever may leave a background finalizer pending even after bounded plugin
    shutdown returns.

27. **Non-Linux secret-file hardening is weaker and unsupported for release.**
    Linux uses `O_NOFOLLOW` and same-descriptor validation. Other targets use a
    weaker fallback and are not release platforms.

28. **Capacity shrink does not immediately compact Go map buckets.** Hot shrink
    evicts logical entries immediately, but heap buckets may remain until later
    garbage collection. The new logical limit is enforced for every request.

29. **Only one host/runtime target is in scope.** The root `go.mod` pins CPA
    v7.2.72 at tag commit
    `6279bb8a4c2835ff6ed99c6b85083b2afbefa681`, Linux amd64, and glibc 2.34+.
    musl/Alpine is unsupported. Source-contract and Windows compile checks do
    not establish native compatibility. Authoritative evidence requires the
    authorized GitHub CI Linux job and Leo's independent isolated real-Host run
    against the implementation freeze, plus final artifact verification. A
    newer CPA or ABI requires a complete new integration run.

30. **Performance evidence is host-specific and cannot override the failed
    release gate.** Same-machine Windows development medians improved from
    baseline `a121a44` to classifier commit `a1be19f` in all five measured
    latency cases, including 165,552→103,190 ns/op for the ordinary classifier
    and 119,484,917→97,126,983 ns/op for candidate-rich max-parts. Small,
    role-aware, and semantic-graph allocations increased. Pending-cache and
    duplicate-request microbenchmarks are separate WSL/Windows self-checks.
    These results are `DEVELOPMENT SELF-CHECK / NOT FINAL EVIDENCE` and require
    final-commit reruns by Leo.

31. **Unknown provider shapes are only generically understood.** Strict blocks
    an unknown `SourceFormat` before interpretation. Balanced/Audit/Observe use
    a bounded all-nonmetadata-string fallback and expose a counter/Watchdog
    delta, but a future provider may encode semantics under fields the generic
    walker cannot identify. Every new CPA/provider source label still requires
    compatibility review and an explicit canonical mapping.

32. **Prompt-injection detection remains heuristic.** The post-v10
    `META-OVERRIDE-001` overlay requires combinations of reviewed control-plane
    evidence, but cannot guarantee coverage of every persona, hierarchy
    inversion, language, steganographic form, or future jailbreak technique.

33. **Cross-request continuation remains stateless.** The classifier can use
    adjacent segments and history present in the current request body. It does
    not retain prompt fragments or semantic flags across independent API calls;
    callers that omit relevant history can therefore remove context the plugin
    never received.

34. **Local instruction-file integrity is outside the plugin boundary.** The
    router cannot prove the owner, mode, allowlist membership, or hash of a
    local `model_instructions_file` before CPA serializes a request. That
    control belongs to the launcher/deployment environment.

35. **Control-plane signals have no standalone Cyber Abuse taxonomy.** Wrapper-
    only text is allowed or audited and cannot synthesize `defense_evasion` or
    another Cyber Abuse category. When an independent dangerous behavior is
    present, wrapper evidence retains and amplifies that behavior's taxonomy.
    Operators needing a distinct prompt-injection reporting taxonomy must add a
    separate non-Cyber-Abuse control-plane event model in a future version.

36. **Local Host execution is not authoritative evidence.** The four-protocol
    harness, real store install, zero Auth Selector/Provider/Usage/Mock Upstream
    counters, Router fixture, and proxy-413 fixture were mistakenly executed in
    WSL using loopback/Mock components and cleaned up without residual fixture
    processes. Those local results are excluded. Authorized GitHub CI passed the
    implementation-freeze Host/Router/proxy matrix; Leo independent verification
    remains not run. No Host result can reverse the frozen v10 failure.

37. **Classifier-policy identity is source-bound but not yet artifact-bound.**
    The Go-level behavior is identified as `classifier-policy-v2` / SHA-256
    `bd55065bc3f1fd350148ad8f2f440c8f606aeb02fabd0024d7a350fe23ee4585`,
    while ruleset `1.0.7` separately identifies YAML assets. A digest test binds
    the reviewed source list, and authenticated status exposes the policy
    identity. Current build metadata and artifact verification do not yet carry
    that identity, so the full Git commit remains required for provenance.

38. **Provider safety-control semantics are not enforced.** Recognized
    transport/configuration containers such as `safetySettings`,
    `generationConfig`, and generic `options` are not interpreted as model
    policy. The plugin scans model-visible text and tool data; it does not prove
    that a client or CPA configuration kept every provider-side safety option
    enabled. Enforce those controls with a server-side allowlist and verify them
    in the owner-operated sandbox.

39. **Tool JSON property names are not standalone instructions.** Text values
    inside established tool payloads are scanned recursively, but a property
    name whose value is only a boolean, number, or `null` is not promoted to
    prompt text. A key-only control such as `reveal_system_prompt: true` can
    therefore remain outside semantic classification unless equivalent text is
    present in a value. Provider/tool schemas should reject unapproved control
    keys before they reach the model or executor.

40. **The CPA store ZIP is not the audit bundle.**
    `cyber-abuse-guard_<version>_linux_amd64.zip` must contain exactly one root
    `.so`; CPA's official store installer rejects the former nested
    `plugins/linux/amd64/...` layout. Documentation, SBOM, build metadata,
    reports, and operator scripts belong in the separate
    `cyber-abuse-guard-v<version>-audit-bundle.zip`. Neither artifact exists as
    an approved v0.1.2 release because the release gate remains blocked.

41. **The visible 35-case development corpus is not independent evidence.**
    `testdata/development-adversarial-v11-prep` is deliberately visible,
    implementation-facing, and marked `future_holdout_eligible=false`. Its
    validator can prove schema, coverage, extraction, and expected regression
    behavior only. Leo must not reuse any case or derived wording as a future
    blind v11; quality generalization remains unknown until a new isolated set
    is authored outside the development loop.

42. **Synthetic Store tests cannot close the artifact lifecycle.** Authorized
    CI must require the real `.so`, Store ZIP, metadata, and checksums; use
    `InstallManifest` for first install and Host load; and run
    `TestPublishedStoreArchive` against the same Dist identity for repeat-skip
    and tamper-repair. Missing artifacts must fail rather than falling back to
    synthetic bytes.
