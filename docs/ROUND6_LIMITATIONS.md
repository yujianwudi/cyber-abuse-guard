# Round 6 known limitations and release blockers

Status: **BLOCKED / PENDING HOST AND INDEPENDENT AUDIT**.

This document describes a Linux amd64-only development candidate, not a
production approval. Windows and macOS validation is outside this round. See
[ROUND6_DEVELOPMENT_HANDOFF.md](ROUND6_DEVELOPMENT_HANDOFF.md).

## Release blockers

- Official CPA v7.2.80 and v7.2.79 source/compile compatibility is a CI gate, but real Host + Mock-upstream validation must be performed by the user in the authorized server sandbox.
- No Los Angeles production host may be accessed or modified by this task.
- A new release must remain `BLOCKED / PENDING HOST AND INDEPENDENT AUDIT` and must not be marked latest.
- Production `observe -> balanced` is outside this task and requires a later explicit approval.
- The ordinary CI and manual release boundary is documented in [ROUND6_RELEASE_GATE.md](ROUND6_RELEASE_GATE.md). The manual workflow defaults to blocked and cannot create a draft prerelease without explicit PASS inputs for both CPA Host versions, an independent audit PASS, and a separate authorization boolean.
- The workflow's exact run/environment hashes, clean execution environment,
  canonical checksums, and ZIP-contained identity checks reduce runner and
  transfer ambiguity but do not replace GitHub Environment reviewers,
  immutable release-tag rules, exact-source Linux CI, real CPA Host evidence,
  or independent artifact review.

## Deliberate safety behavior

- The verified-local-hard-block-under-incomplete exception is disabled. Any incomplete request has neutralized classifier findings and follows the mode table.
- Model-visible text above 8 MiB is incomplete: balanced allows with audit; strict blocks.
- Opaque image/audio/video/document content is not decoded or fetched. Only surrounding model-visible text is classified.
- Unknown multipart schema, ambiguous roles, unsupported encodings, and unavailable full RPC bodies are incomplete rather than guessed.
- Audit and status contain fixed enums, counters, digests, and bounded timing only; no prompt windows or offsets are persisted.
- Dense encoded derived views beyond 128 KiB of encoded source or the 64 KiB
  aggregate retained decoded-text budget remain incomplete. Long plain text is
  streamed, but oversized derived views are not reported as fully covered.

## Compatibility boundaries

- The CPA ABI limits the complete RPC envelope to 8 MiB. Because a `[]byte` body is represented inside the RPC envelope, the largest model request body visible to a particular Host can be smaller than 8 MiB. Host evidence must report the actual accepted body size.
- Legacy `ExtractText` returns materialized `Parts` for source compatibility
  and preserves its old part-splitting and compatibility-limit semantics.
  Production routing uses the streaming sink and does not materialize the full
  prompt.
- Transformed multipart JSON is schema-bound to the currently proven
  `openai-image` top-level field allowlist. Its approved long prompt fields are
  streamed, but unknown fields or non-string prompt values remain incomplete;
  the scanner does not guess future transformed schemas.
- The streaming classifier preserves bounded cross-role and cross-message proofs. It intentionally does not join arbitrary distant messages or unrelated roles into a hard finding.
- If actionable classifier evidence is distributed across multiple windows of
  one logical field, the scanner conservatively reports classifier-window
  incompleteness rather than reconstructing or retaining the full field.
  Balanced mode therefore allows with audit and strict mode blocks, following
  the existing incomplete-inspection policy.
- The compact shadow/index path no longer copies arbitrary long keys or semantic
  values, but structural metadata and decoder allocations still grow with
  bounded JSON token/node and logical-field counts. Linux allocation and RSS
  evidence is still required at the near-envelope tier.

## Independent validation still required

The external auditor should independently verify:

1. the Linux size ladder at 64 KiB, 255 KiB, 256 KiB, 256 KiB + 1,
   270 KiB, 512 KiB, 1 MiB, 4 MiB, and near the effective RPC limit, including
   benign text and malicious text at start, middle, end, and a window boundary;
2. benign and negated neighbors;
3. system, user, tool, Responses, Claude, Gemini, Interactions, raw multipart,
   and CPA-transformed multipart JSON paths;
4. zero Auth Selector, provider, Mock upstream, and usage deltas for every local block;
5. SQLite `quick_check`, schema migration backup, privacy canaries, race, fuzz, allocation, RSS, and reproducible artifact hashes;
6. rollback to the prior candidate without touching production request or audit data.

CPA v7.2.80 and v7.2.79 real Host + Mock-upstream results are both
**NOT RUN / PENDING**. Source/compile checks cannot substitute for these gates.
