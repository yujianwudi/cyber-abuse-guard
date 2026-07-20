# Public jailbreak repository review

```text
current_classifier_policy_version: classifier-policy-v6
current_classifier_policy_sha256: ece497210db938528cb166a34f2ce3013324b792a7eedf276a96fa5d256001d4
```

## Scope and safety boundary

This review covers public prompt-override projects that can change the high-authority
instructions seen by CPA-routed model requests. The repositories were inspected as
untrusted text only. No repository code, script, dependency, binary, or embedded
instruction was executed.

Pinned sources:

| Repository | Exact commit |
|---|---|
| `Jia-Ethan/codex-keysmith` | `f699b9bd2cb59eb0d54e69139c68f7808d869b6d` |
| `MDX-Tom/gpt-5.6-instruct` | `5f469e43ef66f540cadb475039fd9ed469aef654` |
| `yynxxxxx/Codex-X` | `7d0e0064d54f860d4bf12b557fd9f8c489043a35` |
| `yynxxxxx/Codex-5.5-codex-instruct-5.5` | `ed0b6dc37d1994e93788d92f7af63f58bf0b9e2d` |

The production rule set does not contain repository names, release names, file
hashes, or complete third-party prompts. Tests use repository-neutral, disarmed
surrogates so a renamed or lightly edited template does not bypass the Guard and
ordinary discussion of these projects is not treated as abuse.

## CPA-visible attack surfaces

The common CPA-visible carriers are:

1. OpenAI Responses root `instructions`;
2. chat `system`, `developer`, `assistant`, or `tool` messages;
3. Chat/Responses function and custom-tool descriptions, including legacy
   `functions[]`;
4. CPA v7.2.88 Codex Desktop `input[].type="additional_tools"`, including
   namespace-nested MCP/custom tools;
5. persisted model-instruction or managed `AGENTS.md` content;
6. function/custom call arguments and tool output;
7. user text containing role-tag forgery, adjacent fragments, or encoded wrappers.

The source material also contains candidate-rich 1,397-17,166 decoded-byte
templates. Several templates enumerate many cyber domains in one fixed instruction
block. Classifying
that catalog as the user's current credential, malware, phishing, exploitation, or
evasion intent would block every benign request that carries the template and could
poison subject risk.

## Disposition contract

- A wrapper-only request with a harmless or benign current task is at most an
  audit finding and must remain HTTP 200.
- A proven current user explicitly requesting persistent instruction-file
  override remains a local hard block; non-persistent wrapper-only controls do
  not become cyber-abuse taxonomy by themselves.
- A wrapper plus an independent, complete malicious cyber request from a proven
  current user is blocked locally and may accumulate subject risk.
- A complete malicious system, developer, assistant, tool, or unknown payload may
  still be blocked directly, but it never accumulates subject risk.
- Quotation, static review, incident analysis, explanation, detection, and explicit
  non-execution requests remain allowed.
- Repository names, a single mode label, or a single security-domain word are never
  sufficient block evidence.

## Repository-neutral coverage

The regression matrix covers these observed control families without copying a
live prompt:

- instruction-hierarchy replacement and default-constraint override;
- refusal suppression and disabled-filter claims;
- safety-priority inversion and authorization laundering;
- concealment of the active mode or instruction source;
- fixed prefixes, continuation markers, classification-boundary splits, and
  neutral padding;
- maximum-permission personas and unapproved autonomous tool execution;
- persistent instruction-file changes;
- defensive quotation and benign near-neighbors.

Each of the four active control families is routed through 17 exact non-user
carrier shapes: Responses instructions; Chat system/developer/assistant/tool;
Chat assistant tool calls; Chat nested and legacy function descriptions;
Responses function/custom descriptions; CPA `additional_tools` function and
namespace/custom definitions; Responses assistant history; function/custom calls;
and function/custom outputs. Every carrier verifies both wrapper + benign user
allow/audit behavior and wrapper + independent malicious trusted-user blocking.

Decoded-text coverage includes 1,397, 1,743, 4,575, 5,137, 7,899, 10,198, 13,641,
16,383, 16,384, 16,385, and 17,166 bytes. Existing Round6 tests separately cover
32 KiB role windows, the 256 KiB compatibility boundary, multi-megabyte fields,
and more than 64 logical role segments.

## Attribution hardening

User-origin subject risk now requires a closed provider-aware proof:

- only a SourceProfile-matched root history container can establish a trusted
  user role;
- OpenAI Responses root scalar `input` is a trusted user carrier;
- exact CPA v7.2.88 Codex Responses Lite `additional_tools` items, including the
  official `role: developer` sibling, are system-originated and untrusted, while
  a following exact Responses user message remains trusted;
- type-derived Responses call/output/reasoning/additional-tools items cannot add
  an explicit `role: user`; the conflict makes role attribution incomplete;
- root `instructions`, valid provider system fields, developer messages, tool
  payloads, function responses, unknown content types, cross-provider envelopes,
  and nested histories remain non-user or untrusted;
- a failed role-aware parse clears all tentative user attribution;
- compatibility scanning beyond 64 segments preserves attribution;
- an independent trusted-user hard winner wins an otherwise exact result tie, so
  a preceding non-user catalog cannot suppress subject accountability.

Sanitized repository material frequently appears inside a safety review. That
review can make exactly one closed quote inert only while its unsafe assessment
and final non-execution boundary remain intact. A later affirmative user
follow-up such as `execute it`, `proceed`, or `go ahead` reclassifies the quoted
referent alone and cannot borrow wrapper signals. Explanations, questions,
negation, remediation, and non-user review carriers remain inert. Long-field
state retains no quoted text; unprovable cross-window linkage becomes
`classifier_window_incomplete`, and the additional classification remains bound
by `MaxChunks`. Common governors such as `just`, `simply`, `let's`, and `let us`
remain active. Only positively proven analytical, safety, or negated speech acts
suppress the incomplete-prior fallback; wrapper-stripped adjacent heads/tails
are not reclassified when either field already proved an inert quote.

## Performance work and acceptance

The hot path avoids request hashing when subject accumulation is ineligible,
skips subject HMAC derivation and controller locking for complete clean allows,
avoids per-request Observe-event persistence by default, skips unnecessary
cross-window risk aggregation, bounds short JSON buffers to actual content, and
uses a zero-copy decode path for valid unescaped JSON strings.

Final acceptance is Linux-only:

1. GitHub CI on Ubuntu 24.04, including race, vet, fuzz smoke, corpus, benchmarks,
   CPA v7.2.88 pinned-source compatibility, and Linux amd64 artifact build;
2. exact-head SO verification in the isolated CPA v7.2.88 sandbox;
3. zero benign blocks across the repository-neutral matrix;
4. all independent malicious-user links blocked before Mock upstream;
5. zero subject growth from non-user carriers and a clean same-auth follow-up;
6. repeated off/observe/balanced A/B measurements for throughput, latency, CPU,
   RSS, coverage, and error counters.

Static review and unit fixtures do not by themselves claim real-CPA compatibility
or performance. Those claims require the exact Linux artifact and sandbox evidence.
