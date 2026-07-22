# Documentation index

```text
current_classifier_policy_version: classifier-policy-v7
current_classifier_policy_sha256: ea8c4dcfacacc6478f86fd2ca5de96d667ae98f2fc6ff0c83d8e6092e9f6a82d
```

The root [English README](../README.md) and [Chinese README](../README_CN.md)
are the shortest current-status entry points. `v0.15` is the manually published
[historical stable release](https://github.com/yujianwudi/cyber-abuse-guard/releases/tag/v0.15).
The current publication target is the Linux-only `v0.16-rc.2` prerelease. It
uses the single CPA v7.2.95 pin. Independent audit and
counted-Mock Host validation remain required, production approval has not been
granted, and no stable `v0.16` exists.

This cleanup adds navigation without relocating frozen evaluation or Holdout
evidence. Those files keep their existing paths so historical hashes and
references remain stable.

## Current v0.16 documents

Use these files for the current implementation and evidence state:

- [Blocked-request review capture operator guide](RAW_CAPTURE.md)
- [v0.16 release admission policy](RELEASE_POLICY.md)
- [Round 8 v0.16-rc.2 release readiness](reports/ROUND8_RELEASE_READINESS.md)
- [Round 8 synthetic score calibration](reports/ROUND8_CALIBRATION.md) —
  development-only 336 benign / 336 paired-malicious histogram and threshold
  analysis; not blind or Holdout evidence
- [Round 8 Linux Host runner and counted-Mock contract](ROUND8_HOST_RUNNER.md)
- [Current test status and exact-main CI failures](reports/TEST_REPORT.md)
- [Local-package and publication evidence](reports/RELEASE_EVIDENCE.md)
- [Historical performance evidence and v0.16 acceptance table](reports/PERFORMANCE.md)
- [Privacy boundary](reports/PRIVACY.md)
- [Repository security-support policy](../SECURITY.md)

The local package manifest and checksums are delivery artifacts under the
ignored local `dist/` path, not tracked documentation and not GitHub release
evidence.

## Architecture and security model

- [Design](DESIGN.md)
- [Threat model](THREAT_MODEL.md)
- [Rule system](RULES.md)
- [Round 6 streaming scanner design](ROUND6_STREAMING_SCANNER_DESIGN.md)

## Operations and configuration

- [Docker installation, rollout, rollback, and cleanup](INSTALL_DOCKER.md)
- [Blocked-request review capture](RAW_CAPTURE.md)
- [General known limitations](LIMITATIONS.md)
- [Round 6 configuration migration](ROUND6_CONFIG_MIGRATION.md)
- [Round 6 limitations and blockers](ROUND6_LIMITATIONS.md)

## Release policy and workflow boundaries

- [Release admission policy](RELEASE_POLICY.md)
- [Round 6 CI, candidate, and release gate](ROUND6_RELEASE_GATE.md)
- [Repository governance and desired `main` protection](REPOSITORY_GOVERNANCE.md)
- [Contribution guide](../CONTRIBUTING.md)
- [Security policy](../SECURITY.md)

The repository-governance document records desired GitHub settings, not proof
that they are already enabled. The `main` controls are applied and API-verified
only after the current hardening pull request and all named checks are green.

Current GitHub Actions entry points are intentionally limited to:

- `.github/workflows/ci.yml` for ordinary verification;
- `.github/workflows/codeql.yml` for minimal-permission Linux Go static
  analysis within the reviewed sparse source boundary;
- `.github/workflows/candidate.yml` for private unreleased candidate bytes;
- `.github/workflows/attested-prerelease.yml` for the externally attested
  development prerelease gate;
- `.github/workflows/release-rc.yml` for the exact-main, Linux-only
  `v0.16-rc.2` formal-structure sandbox prerelease;
- `.github/workflows/release.yml` and
  `.github/workflows/release-promote.yml` for the formal draft and its
  protected promotion.

CodeQL creates code-scanning evidence only. It does not create package bytes or
authorize publication. Only the RC workflow has been migrated to v0.16-rc.2.
Candidate, attestation, formal, and promotion workflows remain version-locked
historical v0.15 machinery and do not authorize a stable v0.16 publication.

The retired attempted `v0.15-rc.2` workflow definition is archived under
[`archive/workflows/`](archive/workflows/) and cannot be dispatched by GitHub
Actions. Its recorded runs failed and did not produce the public RC, which was
published separately through the disclosed direct owner override. It remains
historical evidence and is separate from the active v0.16-rc.2 workflow.

The protected `v0.15-rc.3` tag is separate failed evidence. Workflow run
29728286559 passed admission, failed before packaging, published no Actions
artifact, and created no GitHub Release. It is not moved or reused by RC4.

## Historical v0.15 / Round 6 handoff

- [Independent-audit handoff](AUDIT_HANDOFF.md)
- [Round 6 development handoff](ROUND6_DEVELOPMENT_HANDOFF.md)

These handoff documents contain point-in-time evidence. They remain at their
original paths for audit continuity and must not be read as current v0.16
release evidence. Use the root READMEs and the current-document list above for
the active state.

## Engineering and historical evidence reports

Project baselines and engineering evidence:

- [Classifier redesign baseline](reports/CLASSIFIER_REDESIGN_BASELINE.md)
- [Regression corpus report](reports/CORPUS_REPORT.md)
- [CPA integration report](reports/CPA_INTEGRATION.md)
- [CPA packaging and contract baseline](reports/PHASE0_CPA_CONTRACT.md)
- [Performance report and v0.16 acceptance table](reports/PERFORMANCE.md)
- [Privacy report](reports/PRIVACY.md)
- [Prompt-injection defensive review](reports/PROMPT_INJECTION_REVIEW.md)
- [Public jailbreak repository review](reports/PUBLIC_JAILBREAK_REPOSITORY_REVIEW.md)
- [Release evidence](reports/RELEASE_EVIDENCE.md) — current v0.16 section plus
  retained historical records
- [Test report](reports/TEST_REPORT.md) — current v0.16 section plus retained
  historical records

Frozen evaluation reports:

- [Evaluation v4](reports/EVALUATION_V4_REPORT.md)
- [Evaluation v5](reports/EVALUATION_V5_REPORT.md)
- [Evaluation v6](reports/EVALUATION_V6_REPORT.md)
- [Evaluation v7](reports/EVALUATION_V7_REPORT.md)
- [Evaluation v8](reports/EVALUATION_V8_REPORT.md)
- [Evaluation v9](reports/EVALUATION_V9_REPORT.md)
- [Evaluation v10](reports/EVALUATION_V10_REPORT.md)

Retired or historical Holdout reports:

- [Holdout v1](reports/HOLDOUT_REPORT.md)
- [Holdout v2](reports/HOLDOUT_V2_REPORT.md)
- [Holdout v3](reports/HOLDOUT_V3_REPORT.md)

## Archive

- [Retired workflow evidence](archive/workflows/) - retained outside the
  executable GitHub Actions directory.

- [v0.1.2 next-version recommendations](archive/v0.1.2/NEXT_VERSION.md) —
  retained for historical context; it is not the current v0.15 roadmap.
