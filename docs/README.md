# Documentation index

```text
current_classifier_policy_version: classifier-policy-v5
current_classifier_policy_sha256: 0e114d98862282d2492fb62e4300297b4746eeaf8165339603d02c48d11bd60b
```

The root [English README](../README.md) and [Chinese README](../README_CN.md)
are the shortest current-status entry points. The public
[`v0.15-rc.2` prerelease](https://github.com/yujianwudi/cyber-abuse-guard/releases/tag/v0.15-rc.2)
is Linux amd64 sandbox-only; formal `v0.15` remains blocked.

This cleanup adds navigation without relocating frozen evaluation or Holdout
evidence. Those files keep their existing paths so historical hashes and
references remain stable.

## Architecture and security model

- [Design](DESIGN.md)
- [Threat model](THREAT_MODEL.md)
- [Rule system](RULES.md)
- [Round 6 streaming scanner design](ROUND6_STREAMING_SCANNER_DESIGN.md)

## Operations and configuration

- [Docker installation, rollout, rollback, and cleanup](INSTALL_DOCKER.md)
- [General known limitations](LIMITATIONS.md)
- [Round 6 configuration migration](ROUND6_CONFIG_MIGRATION.md)
- [Round 6 limitations and blockers](ROUND6_LIMITATIONS.md)

## Release policy and gates

- [Release admission policy](RELEASE_POLICY.md)
- [Round 6 CI, candidate, and release gate](ROUND6_RELEASE_GATE.md)

Current GitHub Actions entry points are intentionally limited to:

- `.github/workflows/ci.yml` for ordinary verification;
- `.github/workflows/candidate.yml` for private unreleased candidate bytes;
- `.github/workflows/attested-prerelease.yml` for the externally attested
  development prerelease gate;
- `.github/workflows/release.yml` and
  `.github/workflows/release-promote.yml` for the formal draft and its
  protected promotion.

The retired attempted `v0.15-rc.2` workflow definition is archived under
[`archive/workflows/`](archive/workflows/) and cannot be dispatched by GitHub
Actions. Its recorded runs failed and did not produce the public RC, which was
published separately through the disclosed direct owner override.

## Current v0.15 / Round 6 handoff

- [Independent-audit handoff](AUDIT_HANDOFF.md)
- [Round 6 development handoff](ROUND6_DEVELOPMENT_HANDOFF.md)

These handoff documents contain point-in-time evidence. Use the root READMEs
and the GitHub prerelease page above for the latest publication status.

## Historical and evidence reports

Project baselines and engineering evidence:

- [Classifier redesign baseline](reports/CLASSIFIER_REDESIGN_BASELINE.md)
- [Regression corpus report](reports/CORPUS_REPORT.md)
- [CPA integration report](reports/CPA_INTEGRATION.md)
- [CPA packaging and contract baseline](reports/PHASE0_CPA_CONTRACT.md)
- [Performance report](reports/PERFORMANCE.md)
- [Privacy report](reports/PRIVACY.md)
- [Prompt-injection defensive review](reports/PROMPT_INJECTION_REVIEW.md)
- [Public jailbreak repository review](reports/PUBLIC_JAILBREAK_REPOSITORY_REVIEW.md)
- [Release evidence](reports/RELEASE_EVIDENCE.md)
- [Test report](reports/TEST_REPORT.md)

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
