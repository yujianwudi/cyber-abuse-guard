# GitHub Actions workflows

Seven YAML files in this directory are active workflows. Verification, static
analysis, candidate construction, attestation, and publication are separated
by trust boundary; a successful build or CodeQL scan is not by itself
permission to publish.

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | Pull requests to `main`; pushes to `main` | Core quality, long fuzzing, Linux artifacts, fixed CPA v7.2.88 source compatibility, and reproducibility |
| `codeql.yml` | Pull requests and pushes to `main`; weekly schedule; manual dispatch | Minimal-permission CodeQL analysis for Go on Ubuntu, using the same sparse restricted-data boundary as CI; produces code-scanning results only |
| `candidate.yml` | Manual dispatch from exact `main` | Produce a private clean candidate artifact; never creates a GitHub Release |
| `attested-prerelease.yml` | Manual dispatch from annotated `v0.15-dev.round6[.N]` | Bind candidate, Host, audit, and evaluation attestations into a blocked prerelease |
| `release-rc.yml` | Manual dispatch from annotated exact-main `v0.15-rc.4` | Run complete Linux internal gates, create the 17-asset formal-structure RC package, byte-check a draft, and publish a non-latest prerelease |
| `release.yml` | Exact `v0.15` tag | Rebuild and verify the formal bytes, then create a draft Release |
| `release-promote.yml` | Manual dispatch from exact `v0.15` | Publish the already verified, unchanged formal draft |

`codeql.yml` grants `contents: read` globally and `security-events: write` only
to its analysis job. It does not receive `contents: write`, does not build or
upload release artifacts, and is not a substitute for the exact-main CI,
external Host evidence, or release admission. Repository branch protection and
required-status settings remain external GitHub configuration; adding this file
does not enable them automatically.

The exact-main v0.16 CI run
[`29799561002`](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29799561002)
failed twice on 2026-07-21. Attempt 1 failed in `fuzz-smoke` when
`FuzzExtractText` exceeded its context deadline. Attempt 2 passed that fuzz
step, then failed in `operational-script-security` because the Round 6 document
consistency fixture rejected an unreviewed document mutation. Both attempts
created zero Actions artifacts. This is current failure evidence, not an absent
workflow run and not release authorization.

The retired one-off `v0.15-rc.2` workflow definition is retained under
[`docs/archive/workflows/`](../../docs/archive/workflows/) and is not executable
by GitHub Actions. Its recorded runs failed; the public RC was an explicitly
disclosed direct owner-authorized release and was not produced by a successful
run of that workflow. The protected `v0.15-rc.3` tag is also retained as failed,
unpublished evidence: run 29728286559 passed admission, failed before packaging,
published no Actions artifact, and created no GitHub Release. The active
`release-rc.yml` is independently hashed, fixed to RC4 and CPA v7.2.88, and
does not reuse or mutate the archived RC2 file.

When changing a release workflow, update its path/name bindings, manifest
validators, release documentation, and `scripts/round6_safe_gate_contract.py`
in the same pull request. The fail-closed identity checks intentionally reject
partial renames.
