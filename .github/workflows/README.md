# GitHub Actions workflows

Only the five YAML files in this directory are active workflows. Release
workflows are deliberately separated by trust boundary; a successful build is
not by itself permission to publish.

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | Pull requests to `main`; pushes to `main` | Core quality, long fuzzing, Linux artifacts, CPA v7.2.86 source compatibility, and reproducibility |
| `candidate.yml` | Manual dispatch from exact `main` | Produce a private clean candidate artifact; never creates a GitHub Release |
| `attested-prerelease.yml` | Manual dispatch from an existing development tag | Bind candidate, Host, audit, and evaluation attestations into a blocked prerelease |
| `release.yml` | Exact `v0.15` tag | Rebuild and verify the formal bytes, then create a draft Release |
| `release-promote.yml` | Manual dispatch | Publish the already verified, unchanged formal draft |

The retired one-off `v0.15-rc.2` workflow definition is retained under
[`docs/archive/workflows/`](../../docs/archive/workflows/) and is not executable
by GitHub Actions. Its recorded runs failed; the public RC was an explicitly
disclosed direct owner-authorized release and was not produced by a successful
run of that workflow.

When changing a release workflow, update its path/name bindings, manifest
validators, release documentation, and `scripts/round6_safe_gate_contract.py`
in the same pull request. The fail-closed identity checks intentionally reject
partial renames.
