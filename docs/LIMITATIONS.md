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
   baseline is CPA v7.2.67. CPA may continue other Routers or native routing if
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
    `http_request` remains unsupported with HTTP 405. Current-diff real-host
    behavior across OpenAI Chat, OpenAI Responses, Claude, and Gemini remains a
    server-sandbox requirement.

12. **Protocol-specific error shapes differ.** OpenAI-compatible handlers can
    retain a stable marker. Anthropic may normalize plugin errors and drop
    custom code/category fields. CPA's executor adapter controls the final
    protocol envelope.

13. **No `Retry-After` on executor errors.** ABI-v1 RPC errors cannot attach
    arbitrary downstream response headers.

14. **Exact management routes only.** CPA v7.2.67 rejects dynamic `:`/`*`
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

17. **No authenticated management UI.** CPA v7.2.67 resource routes are not a
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
    matching pre-migration database backup.

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

29. **Only one host/runtime target is qualified.** The repository root `go.mod`
    and development/runtime baseline remain CPA v7.2.67 at the pinned commit,
    Linux amd64, and glibc 2.34+. musl/Alpine is unsupported. The isolated
    v7.2.72 source-contract module verifies the official archive/install logic
    and official host Router ordering/fallback tests with synthetic bytes; it
    does not establish Guard native-host, ABI, executor, management, stream, or
    deployment compatibility. A newer CPA or ABI still requires a complete new
    integration run.

30. **Performance evidence is host-specific and cannot override the failed
    release gate.** The current development candidate measured approximately
    76.296/124.682/216.869 microseconds at ordinary P50/P95/P99,
    78.335194 ms for candidate-rich acceptance (76.693716-80.439013 ms in raw
    benchmarks, 78,360 B/op and 174 allocs/op), and 14.970291 ms / 293,906 B/op
    near budget. These are useful engineering regressions only, not production
    approval.

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

35. **Control-plane taxonomy is coarse.** A strong standalone meta override is
    currently reported as `defense_evasion`, not a dedicated prompt-injection
    category. When ordinary abuse is present, the original abuse taxonomy is
    retained and amplified.

36. **Server sandbox validation is pending.** The current prompt-injection
    and Phase 0 changes have source-level evidence only unless separately listed
    in the test report. They have not been deployed, natively loaded, or
    exercised through a current-diff real CPA integration locally. In
    particular, the four-protocol 403 matrix and zero Auth Selector, Provider,
    Usage, and Mock Upstream calls remain **PENDING / NOT RUN** in the
    owner-operated server sandbox and cannot reverse the v10 release failure.

37. **Classifier-policy identity is not yet independently versioned.**
    Ruleset `1.0.7` and its canonical hash identify the embedded YAML
    cyber-abuse assets, not the complete Go-level policy. The meta overlay,
    matcher/normalizer mappings, role handling, and extraction semantics all
    affect decisions. The containing Git/build commit plus the YAML identity
    are required for this development tree. A future release must add a policy
    version/hash or fully bind these semantics to verified build provenance.

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
