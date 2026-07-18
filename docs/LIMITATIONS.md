# Known Limitations — v0.15 Round 6 development candidate

1. **No guarantee against account action.** The plugin reduces the number of
   clearly risky requests that reach upstream. It cannot guarantee that an
   account will never be warned, rate-limited, suspended, or deactivated.

2. **The current v0.15 candidate remains blocked by the formal release gate.**
   Exact project version is `0.15`; the only formal tag is `v0.15`, never
   `v0.15.0`. v1-v8
   are retired or consumed failures. v9 is a consumed methodology-invalid failure because
   the exact taxonomy-enum validator was missing. The methodologically valid
   v10 first-and-only run failed with 28/320 benign false positives, 49/320
   policy blocks, and 33/320 exact classifications. v10 is `CONSUMED / FAIL`
   and cannot be rerun. No `v0.15` tag, production release, or production
   deployment may be created. A future formal attempt requires a candidate-bound
   external `evaluation-v11` or later first-and-only `CONSUMED / PASS`
   attestation. Historical development prerelease
   `v0.1.2-dev.round5.1` exists only as `BLOCKED / NOT FOR DEPLOYMENT`
   evidence at immutable tag target
   `89b62b341278073e7b6518b85e41cd7f7c6b682c`; it must not be moved or reused.
   Round 5 hashes and tags remain frozen historical evidence and cannot be
   relabeled as v0.15.

3. **Deterministic language rules are imperfect.** Novel phrasing, languages,
   slang, semantic indirection, encrypted content, unknown encodings, and
   sufficiently adversarial obfuscation may evade detection. False positives
   and false negatives remain possible.

4. **Decoding is intentionally bounded.** URL escapes, HTML entities,
   inspectable Base64, textual data URLs, JSON escapes, and nested tool JSON are
   limited to two decode layers, eight variants, 128 KiB source, and 64 KiB
   retained decoded text. The plugin does not decompress, expand archives, or
   parse arbitrary documents. An incomplete recognized text envelope follows
   the fixed incomplete-inspection mode contract. Strings with an unknown
   encoding shape or high entropy are scanned literally when their schema and
   role provenance remain supported, and are not blocked solely because they
   appear encoded. This does not make arbitrarily long `RoleUnknown` fields
   exactly reconstructable across fields; bounded streaming proof loss may
   instead yield `classifier_window_incomplete`. Encrypted or novel encodings
   can therefore still evade semantic detection.

5. **Opaque media is not inspected.** Image/audio/video/document-attachment
   bytes and their meaning are unavailable to the classifier. The plugin never fetches HTTPS media
   URLs. Mode-aware defaults audit opaque media in Observe/Audit/Balanced and
   block it in Strict; operators may explicitly choose `block`, `audit`, or
   `allow`. `allow` is uninspected pass-through, not a safety determination.

6. **Truncated content cannot be fully classified.** Inputs beyond byte, part,
   depth, segment, native RPC, or decode budgets are marked incomplete.
   Balanced allows and audits incomplete inspection; Strict self-routes and
   blocks for the fixed incomplete reason. Neither mode may enforce a partial
   classification or update subject risk from a prefix. A no-copy oversized RPC
   event cannot include a request hash, model, source format, or body-derived
   byte count because the body is not copied into Go.

7. **Role provenance is bounded, not universal.** Standard OpenAI, Anthropic,
   and Gemini envelopes use role-aware segments. Unsupported explicit roles and
   over-capacity histories are conservative in enforcing modes. Vendor-specific
   quotation/provenance extensions and deliberately split non-adjacent evidence
   can remain outside the deterministic follow-up window.

8. **CPA router failures are host-level fail-open.** The current required Host
   target is CPA v7.2.88 only. CPA may continue other Routers or native routing if
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
    is 405; the official adapter returns `(nil, error)`. CPA v7.2.88's public
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

14. **Exact management routes only.** CPA v7.2.88 rejects dynamic `:`/`*`
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

17. **No authenticated management UI.** CPA v7.2.88 resource routes are not a
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
    documented, but v0.15 accepts one active key. Preserve the current key for
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

23. **Schema downgrade is not promised.** v0.15 migrates supported legacy event
    databases to schema v3 atomically and can create bounded pre-migration
    backups. Older binaries are not claimed to understand schema v3. A full rollback should restore the
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

29. **Only one platform and one CPA Host version are in scope.** The release
    platform is Linux amd64 with glibc 2.34+; musl/Alpine is unsupported. The
    root `go.mod` and current compatibility contract pin CPA v7.2.88, but
    source/compile success is not runtime admission. Exact-candidate Host
    evidence is required for CPA v7.2.88.
    Earlier v7.2.85/v7.2.84/v7.2.83/v7.2.82/v7.2.81 checks are historical and non-gating.
    Windows/macOS checks and source contracts do
    not establish native compatibility.

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
    an unknown non-multipart `SourceFormat` before interpretation.
    Balanced/Audit/Observe use a bounded all-nonmetadata-string fallback and
    expose a counter/Watchdog delta, but a future provider may encode semantics
    under fields the generic walker cannot identify. Unknown multipart never
    guesses text fields: every non-file field is schema-incomplete, Balanced
    allows+audits, and Strict blocks for the fixed reason. Every new
    CPA/provider source label still requires compatibility review and an
    explicit canonical mapping.

32. **Prompt-injection detection remains heuristic.** The post-v10
    `META-OVERRIDE-001` overlay requires combinations of reviewed control-plane
    evidence, but cannot guarantee coverage of every persona, hierarchy
    inversion, language, steganographic form, or future jailbreak technique.

33. **Cross-request continuation remains stateless.** The classifier can use
    adjacent segments and history present in the current request body. It does
    not retain prompt fragments or semantic flags across independent API calls;
    callers that omit relevant history can therefore remove context the plugin
    never received.

34. **Local instruction-file and remote-template integrity are outside the
    plugin boundary.** The Router cannot prove the path, owner, mode, allowlist
    membership, hash/signature, or reload history of a local
    `model_instructions_file`, `AGENTS.md`, remote instruction template, or
    other high-priority client configuration loaded before CPA serializes a
    request. The launcher/deployment environment must enforce a path allowlist,
    non-business-user ownership and write restrictions, SHA-256 or signature
    binding, verification at startup and every reload, fixed configuration
    audit, and human-approved remote templates pinned to a commit/hash.

35. **Control-plane signals have no standalone Cyber Abuse taxonomy.** Wrapper-
    only text is allowed or audited and cannot synthesize `defense_evasion` or
    another Cyber Abuse category. When an independent dangerous behavior is
    present, wrapper evidence retains and amplifies that behavior's taxonomy.
    Operators needing a distinct prompt-injection reporting taxonomy must add a
    separate non-Cyber-Abuse control-plane event model in a future version.

36. **Local and historical Host execution is not current evidence.** The
    four-protocol harness, real store install, zero
    Auth Selector/Provider/Usage/Mock Upstream counters, Router fixture, and
    proxy-413 fixture were mistakenly executed in WSL using loopback/Mock
    components and cleaned up without residual fixture processes. Those local
    results are excluded. Earlier CPA v7.2.72 and Round 5 v7.2.75 records remain
    frozen historical evidence only. Current v0.15 requires a private untagged
    clean candidate and one external v7.2.88 Host record,
    followed by independent verification. It has not run, and no Host result can
    reverse the frozen v10 failure.

37. **Classifier-policy identity is source- and artifact-bound, but still not
    independent approval.** The current identity is `classifier-policy-v3` /
    SHA-256
    `1294c6fd587522829d07220d5a6f4214092eba6ce1837636da5b3e3d461ba2a3`.
    Build metadata and artifact verification carry it. The historical
    round5.2 value was `classifier-policy-v2` /
    `e9b87f7e2635495bdbceae469ef89e696b419f0a9a6fd129558a20bc4be947ec`,
    and the historical round5.1 value was `classifier-policy-v2` /
    `c2092d0949fcaa1d0f085dfe31a668d45cc4d14efc10427d0f3ebcf3e821a112`.
    Ruleset `1.0.7` separately identifies YAML assets and
    does **not** include the Go-level `META-OVERRIDE-001` overlay, extractor
    semantics, approved tool-schema mappings, or control-plane telemetry. A
    digest test binds the reviewed source list, and authenticated status exposes
    the policy identity. The full Git commit/tree and candidate workflow run
    remain required for provenance.

38. **Provider safety-control semantics are not enforced.** Recognized
    transport/configuration containers such as `safetySettings`,
    `generationConfig`, and generic `options` are not interpreted as model
    policy. The plugin scans model-visible text and tool data; it does not prove
    that a client or CPA configuration kept every provider-side safety option
    enabled. Enforce those controls with a versioned server-side schema
    allowlist and reject or forcibly overwrite unsafe values before routing;
    verify the effective values independently in the owner-operated sandbox.

39. **Key-only tool controls are schema-specific, not globally scanned.** Text
    values inside established tool payloads are scanned recursively. Only an
    explicitly approved, versioned tool schema may map a boolean/numeric/null
    property to a fixed low-cardinality semantic signal; unknown control keys
    in that known schema become fixed `tool_schema` incomplete inspection,
    following the existing Balanced allow+audit / Strict local-block contract
    without classification.
    The fifth-round mapping is activated only by
    `cag_control_schema=meta_override_control/v1` inside established
    tool/tool-payload provenance; the same marker elsewhere is inert. Ordinary
    business JSON property names never become prompt text. Provider
    configuration keys remain a host schema-policy responsibility rather than
    classifier guesses.

40. **The CPA store ZIP is not the audit bundle.**
    `cyber-abuse-guard_<version>_linux_amd64.zip` must contain exactly one root
    `.so`; CPA's official store installer rejects the former nested
    `plugins/linux/amd64/...` layout. Documentation, SBOM, build metadata,
    reports, and operator scripts belong in the separate
    `cyber-abuse-guard-v<version>-audit-bundle.zip`. Historical round5.1 dirty
    versions of these files exist on a blocked development prerelease, but
    neither is an approved stable v0.15 release artifact. Current v0.15 Host
    evidence must use the private untagged clean candidate, not a historical
    Round 5 asset.

41. **Visible development corpora are not independent evidence.**
    `testdata/development-adversarial-v11-prep` is deliberately visible,
    implementation-facing, and marked `future_holdout_eligible=false`. Its
    validator can prove schema, coverage, extraction, and expected regression
    behavior only. Leo must not reuse any case or derived wording as a future
    blind v11. The fifth-round
    `testdata/development-public-jailbreak-patterns-v1` corpus is likewise
    sanitized, `development_only=true`, `future_holdout_eligible=false`,
    derived only from public adversarial taxonomy, and declares
    `contains_live_payloads=false`. Neither corpus nor derived wording is
    independent evidence; quality generalization remains unknown until a new
    isolated set is authored outside the development loop.

42. **Synthetic Store tests cannot close the artifact lifecycle.** Authorized
    CI must require the real `.so`, Store ZIP, metadata, and checksums; use
    `InstallManifest` for first install and Host load; and run
    `TestPublishedStoreArchive` against the same Dist identity for repeat-skip
    and tamper-repair. Missing artifacts must fail rather than falling back to
    synthetic bytes.

43. **JSON media suppression cannot avoid the decoder's initial string
    allocation.** Deferred media candidates have fixed retained bounds and do
    not classify a prefix. Candidate overflow remains complete only if later
    evidence proves media; a final non-media object becomes
    `deferred_text_candidate_limit`. Go's token decoder can still allocate the
    full encoded string transiently before a later member proves that it is
    media. Raw-body limits remain the outer memory control.

44. **Multipart schemas are intentionally incomplete by default.** Only the
    reviewed `openai-image` profile admits `prompt` and `negative_prompt` (plus
    its two bounded spelling variants) as text. Unknown profiles and unknown
    non-file fields become fixed incomplete inspection; adding a future
    provider or field requires source evidence, tests, and a policy-identity
    refresh.

45. **No-tempfile and no-raw-prompt claims stop at the Guard boundary.** The
    extractor and plugin audit do not create temp files or persist prompt/media
    content. CPA request logging can spool non-multipart bodies and can
    persist raw bodies for HTTP error responses. Deployment must separately
    control CPA commercial mode, log directory, retention, and access.

46. **Parser evidence is not Host evidence.** CPA ABI v1 does not provide a
    general HTTP path in `ModelRouteRequest`, and its image handler can parse and
    rebuild multipart before the Router sees it. Unit tests prove the payload
    delivered to the Guard; they cannot prove ingress boundary/header order,
    CPA reconstruction, pre-SSE behavior, or Auth/Provider/Usage/upstream side
    effects. Those claims require the exact CI artifact in the authorized
    isolated Host matrix.

47. **Unit tests and GitHub CI are not production admission.** Passing source,
    unit, race, vet, fuzz, benchmark, privacy, packaging, or reproducibility
    gates shows only that the named command passed on the named commit and
    environment. It cannot replace artifact inspection, the authorized CPA
    v7.2.88 + Mock-upstream Host matrix, or independent
    review, and it cannot reverse the frozen v10 failure.

48. **The Round 6 deployment decision is still blocked.** Historical
    `v0.1.2-dev.round5.1` is a prerelease and is not production admission.
    The current source tree cannot self-record future Host/audit PASS hashes,
    merge identity, tag, or Release state. Stable v0.15 eligibility must be
    determined only from external Round 6/formal attestation assets that bind
    the final source and candidate bytes. Host validation, independent
    source/artifact review, and production observation remain separate gates.
    Even after all source and artifact gates
    pass, the strongest permitted status is
    `READY FOR INDEPENDENT SOURCE/ARTIFACT REVIEW`; it is never
    `PRODUCTION APPROVED`.

49. **Role-aware cross-source composition is intentionally incomplete.** To
    avoid treating a system policy example or assistant refusal as user intent,
    the classifier does not combine base Cyber Abuse taxonomy evidence from a
    system/assistant segment with a later user segment. It may combine bounded
    control-plane/meta-override evidence, but high-priority instruction source,
    owner, mode, hash/signature, and reload integrity remain mandatory host
    gates. A compromised high-priority source can therefore create semantics the
    plugin cannot independently authenticate.

50. **Parts and Segments do not yet share one semantic parse product.** The
    primary token walk creates `Parts`; recognized role envelopes then undergo
    a second bounded JSON parse to create `Segments`, reusing the same bounded
    extraction helpers. Differential, race, fuzz, and fifth-round media tests
    have not reproduced a leak, but two parses retain a parser-drift risk. A
    future refactor should emit both views from one immutable semantic result.

51. **The fifth-round restricted-corpus access claim is not clean.** One
    over-broad read-only `git grep` unexpectedly emitted content from restricted
    `testdata/holdout/malicious-operational.jsonl`. No holdout test ran, no
    output was redirected or copied into implementation artifacts, and it was
    not analyzed or used for tuning or conclusions. Nevertheless, this round
    must not claim zero restricted-corpus access, and the incident independently
    keeps methodological handoff blocked.

52. **The round5.2 evaluation-report exclusion was not case-insensitive.** A
    read-only status search used an exclusion that failed under case variation
    and printed exactly one status line from each of
    `EVALUATION_V5_REPORT.md` through `EVALUATION_V10_REPORT.md`. It did not open
    or print evaluation corpus rows or sample content, run an evaluation test,
    classify or extract the corpus, or influence any source, test,
    documentation, or release decision. This disclosure does not change the
    frozen v10 `CONSUMED / FAIL` result and independently keeps methodology
    handoff blocked.

53. **A broad recursive Go test was started and forcibly terminated.** A
    classifier sub-agent mistakenly launched
    `go test -shuffle=on -count=20 ./...`. The root process interrupted it after
    about 23 seconds and sent `TERM` to PID `265343`. The same command then
    reappeared as PID `266741` with WSL `/init` as its parent, consistent with
    an orphaned CodeRabbit/tool session. The root interrupted the classifier
    agent again, terminated every matching process, and verified that none
    remained. It is unknown whether any consumed evaluation or Holdout test
    selected or read a restricted fixture before termination. The command and
    all partial results are permanently inadmissible and did not inform source,
    tests, documentation, or release decisions. Subsequent validation is
    restricted to the explicit safe allowlist. The project cannot claim no
    restricted access; v10 remains `CONSUMED / FAIL`, and methodology handoff
    remains blocked.

54. **CPA v7.2.88 compatibility is source/compile evidence only.** The separate
    `integration/cpalatestcontract` module pins current target v7.2.88 at commit
    `93d74a890a44802f656d7f39a573916b2611896e`. Earlier v7.2.85/v7.2.84/v7.2.83/v7.2.82/v7.2.81
    profiles and their checksums are retained only as historical development
    evidence, not current release requirements.
    The primary compatibility lane compiles the Guard and integration packages, runs
    the real Guard registration/role-routing probes, 18 official Host
    routing/status tests, 11 official Interactions route/handler tests, and
    three checksum-pinned overlays in ephemeral official-source copies. It does not start CPA, load a
    Guard `.so`, install through Store, or prove request reconstruction,
    logging, Auth/Provider/Usage isolation, and upstream behavior on v7.2.88.
    No current runtime baseline is admitted until the owner runs the authorized
    v7.2.88 server sandbox matrix against the exact candidate SO. Later upstream
    CPA versions do not automatically change this pinned Host requirement.

55. **The public-reference corpus cannot attribute attack origin.** Its 36
    sanitized cases cover visible mechanism families and abstract source
    contexts, including local instructions, managed `AGENTS`, Skill/MCP,
    aliases, concealment, segmented continuation, and HTML-comment modules.
    `source_context` is test metadata, not a runtime security signal. The Guard
    cannot infer that text came from a particular GitHub repository, inspect
    content available only through a URL, `file_id`, archive, encryption,
    compression, or opaque media, stop a local program from modifying config,
    or correlate fragments omitted across independent requests.

56. **The final diff audit exposed author-source snippets.** One overly broad
    read-only `cmd/**/*.go` search printed evaluation/holdout author-source
    snippets and a few synthetic examples. It did not open restricted
    `testdata`, execute an author/evaluation/holdout tool, or inform source,
    tests, documentation, or release conclusions. The output is permanently
    excluded, but the event must remain disclosed and independently prevents a
    clean restricted-access methodology claim.

57. **Native CPA Interactions remains without exact-artifact Host evidence.**
    The Guard now registers `interactions` directly, retains it in the fixed
    audit enum, and scans its mixed schema conservatively without role trust.
    Source contracts can prove handler/Router field visibility and direct
    executor-format readiness, but they do not load the release `.so`. On CPA
    v7.2.80, an `agent` request that the Guard self-routes is rejected by CPA's
    native-Interactions validator with HTTP 400 before the Guard executor runs;
    a uniform Guard 403 would require an upstream CPA change. The owner-operated
    sandbox must recheck that behavior on v7.2.88 and
    separately verify model/agent, stream/non-stream, exact status
    shapes, first-byte behavior, and zero Auth/Provider/Usage/upstream effects.

58. **Clean candidate bytes are not released bytes.** Commit
    `21ceb57e6b6030e56d7820c9a67a8eecd068c669` passed push and PR CI as a
    pre-version-migration checkpoint, not final v0.15 evidence. The final
    PR head must pass PR CI, merge to `main`, and the exact resulting main
    commit/tree must pass push CI before the private untagged candidate workflow
    is dispatched from `refs/heads/main`. That workflow binds the post-merge
    main commit/tree and hashes in `candidate-manifest.json`. Only after the
    v7.2.88 Host record, independent audit, and candidate-bound external
    evaluation-v11+ `CONSUMED / PASS` report bind that same candidate may an
    optional annotated `v0.15-dev.round6[.N]` draft prerelease be created. The
    annotated formal `v0.15` tag and verified draft remain a later, separate
    gate, followed by protected promotion of that unchanged draft.
    The neutral policy is [RELEASE_POLICY.md](RELEASE_POLICY.md); external
    decisions are `round6-prerelease-attestation.json` and
    `formal-release-attestation.json`.
    Historical v10 is not a formal-build input. Formal source/audit bundles
    exclude evaluation, Holdout, private, blind, and retired material.

59. **Automated review is not independent approval.** The final PR head must
    have no unresolved, non-outdated actionable review threads before merge.
    That does not replace independent source, artifact, and Host review.
