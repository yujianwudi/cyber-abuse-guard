# Threat Model

## Protected assets

- upstream OpenAI/Codex and other provider accounts behind CPA;
- downstream API credentials and authenticated identities;
- request privacy, including prompts, uploaded code, cookies, and tokens;
- CPA availability and correct routing/accounting behavior;
- integrity of audit and subject-control state.

## Trust boundaries

The plugin is trusted in-process native code. Downstream request bodies,
headers, tool arguments, plugin YAML configuration, optional rule data, and
management test input are untrusted. CPA's Plugin Host and authenticated
management middleware are trusted. No upstream or external classifier is
trusted with request text.

## Principal threats and controls

| Threat | Control |
|---|---|
| Explicit malicious request reaches an upstream account | ModelRouter runs before provider/auth selection; handled decisions target only the local executor; integration test asserts mock call count remains zero. |
| Another router handles the request first | Install at priority 300, verify effective ordering, disable the obsolete identity-rewrite filter, and document that any higher-priority handled router can bypass this guard. |
| Keyword-only false positive blocks legitimate security work | Multi-evidence rules, explicit defensive/lab/remediation contexts, bilingual benign corpus, balanced threshold. |
| Caller hides intent with casing, spaces, punctuation, zero-width characters, or light leetspeak | Bounded Unicode normalization and compact matching; no claim of resistance to arbitrary adversarial encoding. |
| JSON/depth/base64 resource exhaustion | Token walk, depth/part/byte budgets, binary/data-URL skipping, truncation markers, fuzz tests. |
| Regex denial of service | Default rules use normalized literal terms; validation rejects unsupported/oversized rule constructs. |
| Prompt or secret leakage through audit | Fixed minimal event schema; SHA-256/HMAC correlation; tests search the DB for canary prompt/key values. |
| Subject hash reversal/correlation | HMAC-SHA256 with environment or mode-0600 secret; no plaintext subjects. |
| Forged `X-Forwarded-For` | CPA v7.2.67 exposes no trusted peer address to ModelRouter, so v0.1.0 rejects trusted-proxy activation and never accepts the header as identity. |
| Audit DB lock/corruption takes CPA down | Busy timeout, bounded queue, fail-open audit path, rate-limited diagnostics. |
| Invalid hot reload weakens policy | Parse/compile/validate full state before atomic swap; last valid state retained. |
| Plugin panic crashes CPA | ABI entrypoint recovers; CPA Plugin Host also fuses panicking plugins. |
| Router error silently weakens enforcement | Status and logs expose the error; CPA v7.2.67 itself fails open on router errors/panics, so monitoring is required and this residual host limitation is documented. |
| Management test/unblock exposed to normal API keys | Routes registered exclusively through CPA Management API; no public resource routes. |
| SSRF or prompt exfiltration via classifier | v0.1.0 has no network classifier implementation and makes no outbound calls. |
| Identity spoofing to evade upstream policy | Plugin never changes model, system prompt, client name, headers that claim identity, or upstream safety declarations. |

## Abuse cases intentionally still blocked

An assertion of authorization does not by itself permit deployment-oriented
credential theft, phishing collection, ransomware, or data exfiltration. A
request for static analysis, detection, containment, or remediation can still
be allowed when those defensive signals dominate and no deployment intent is
present.

## Residual risk

Deterministic local rules cannot infer intent perfectly, can be evaded by novel
language or encoding, and can produce false positives/negatives. The plugin
does not inspect images or decode arbitrary binary attachments. `observe` and
`audit` modes deliberately do not block. CPA or upstream behavior outside the
pinned ABI may change. Upstream providers independently enforce their own
policies. Therefore the plugin reduces risk but cannot guarantee that an
account will never be warned, suspended, or deactivated.
