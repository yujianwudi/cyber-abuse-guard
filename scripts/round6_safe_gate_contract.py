#!/usr/bin/env python3
"""Fail closed when Round6 entrypoints escape the privacy-safe command graph.

The checker audits workflow run blocks, reachable Make recipes, shell scripts,
and Python scripts. It validates names and paths before opening files and never
reads restricted evaluation, holdout, private, blind, retired, or consumed data.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import re
import shlex
import sys
from collections import defaultdict
from pathlib import Path

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
from yaml.tokens import (
    AliasToken,
    AnchorToken,
    DirectiveToken,
    DocumentEndToken,
    DocumentStartToken,
    FlowMappingStartToken,
    FlowSequenceStartToken,
    KeyToken,
    TagToken,
)


RESTRICTED_PATH_MARKERS = (
    "consumed",
    "evaluation",
    "holdout",
    "private",
    "blind",
    "retired",
)
FORBIDDEN_TARGETS = {
    "consumed-boundary-test",
    "formal-release",
    "format-check",
    "git-diff-check",
    "holdout-test",
    "module-verify",
    "package-release",
    "package-source-release",
    "release",
    "release-doc-consistency",
    "release-doc-consistency-test",
    "release-evidence",
    "release-preflight",
    "reproducibility-test",
    "script-test",
    "verification-fault-test",
    "verify-release",
    "vet",
    "vulncheck",
}
FORBIDDEN_SCRIPT_NAME = re.compile(
    r"^(?:formal-release|generate-release-evidence|package-release|"
    r"package-source-release|release-doc-consistency|release-preflight|"
    r"release-verification-fault-test|reproducibility-test|verify-release)\.sh$",
    re.IGNORECASE,
)
FORBIDDEN_TARGET_NAME = re.compile(
    r"(?:consumed|evaluation|holdout|private|blind|retired)", re.IGNORECASE
)
TARGET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.%/-]*$")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
SCRIPT_REFERENCE = re.compile(
    r"(?:^|[^A-Za-z0-9_.-])(scripts/[A-Za-z0-9_./-]+\.(?:sh|py))"
)
SHELL_OPERATORS = {"&&", "||", ";", "|", "&"}
SAFE_DYNAMIC_TOOL_VARIABLES = {"go_bin", "cyclonedx"}
BLOCKED_PRERELEASE_MARKER = "BLOCKED / PENDING HOST AND INDEPENDENT AUDIT"
BLOCKED_PRERELEASE_INPUT_ORDER = (
    "tag",
    "expected_commit",
    "expected_tree",
    "ci_run_id",
    "candidate_run_id",
    "expected_so_sha256",
    "expected_store_zip_sha256",
    "host_v7286_validation",
    "host_v7286_evidence_sha256",
    "independent_audit_validation",
    "independent_audit_sha256",
    "independent_evaluation_validation",
    "independent_evaluation_id",
    "independent_evaluation_sha256",
    "authorize_blocked_prerelease",
)
BLOCKED_PRERELEASE_INPUTS = set(BLOCKED_PRERELEASE_INPUT_ORDER)
BLOCKED_PRERELEASE_IF_LINES = (
    "if: >-",
    "inputs.host_v7286_validation == 'PASS' &&",
    "inputs.independent_audit_validation == 'PASS' &&",
    "inputs.independent_evaluation_validation == 'PASS' &&",
    "inputs.authorize_blocked_prerelease == true",
)
ADMISSION_INPUT_ENV = (
    "TAG: ${{ inputs.tag }}",
    "EXPECTED_COMMIT: ${{ inputs.expected_commit }}",
    "EXPECTED_TREE: ${{ inputs.expected_tree }}",
    "CI_RUN_ID: ${{ inputs.ci_run_id }}",
    "CANDIDATE_RUN_ID: ${{ inputs.candidate_run_id }}",
    "EXPECTED_SO_SHA256: ${{ inputs.expected_so_sha256 }}",
    "EXPECTED_STORE_ZIP_SHA256: ${{ inputs.expected_store_zip_sha256 }}",
    "DISPATCH_REF: ${{ github.ref }}",
    "DISPATCH_SHA: ${{ github.sha }}",
    "WORKFLOW_REF: ${{ github.workflow_ref }}",
    "WORKFLOW_SHA: ${{ github.workflow_sha }}",
    "HOST_V7286: ${{ inputs.host_v7286_validation }}",
    "HOST_V7286_SHA256: ${{ inputs.host_v7286_evidence_sha256 }}",
    "INDEPENDENT_AUDIT: ${{ inputs.independent_audit_validation }}",
    "INDEPENDENT_AUDIT_SHA256: ${{ inputs.independent_audit_sha256 }}",
    "INDEPENDENT_EVALUATION: ${{ inputs.independent_evaluation_validation }}",
    "INDEPENDENT_EVALUATION_ID: ${{ inputs.independent_evaluation_id }}",
    "INDEPENDENT_EVALUATION_SHA256: ${{ inputs.independent_evaluation_sha256 }}",
    "AUTHORIZED: ${{ inputs.authorize_blocked_prerelease }}",
)
ADMISSION_INPUT_COMMANDS = (
    '[[ "$TAG" =~ ^v0\\.15-dev\\.round6([.][0-9]+)?$ ]]',
    '[[ "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]]',
    '[[ "$EXPECTED_TREE" =~ ^[0-9a-f]{40}$ ]]',
    '[[ "$CI_RUN_ID" =~ ^[1-9][0-9]*$ ]]',
    '[[ "$CANDIDATE_RUN_ID" =~ ^[1-9][0-9]*$ ]]',
    '[[ "$EXPECTED_SO_SHA256" =~ ^[0-9a-f]{64}$ ]]',
    '[[ "$EXPECTED_STORE_ZIP_SHA256" =~ ^[0-9a-f]{64}$ ]]',
    '[[ "$DISPATCH_REF" == "refs/tags/$TAG" ]]',
    '[[ "$DISPATCH_SHA" == "$EXPECTED_COMMIT" ]]',
    '[[ "$WORKFLOW_SHA" == "$EXPECTED_COMMIT" ]]',
    '[[ "$WORKFLOW_REF" == "${GITHUB_REPOSITORY}/.github/workflows/round6-blocked-prerelease.yml@refs/tags/$TAG" ]]',
    '[[ "$HOST_V7286" == PASS ]]',
    '[[ "$INDEPENDENT_AUDIT" == PASS ]]',
    '[[ "$INDEPENDENT_EVALUATION" == PASS ]]',
    '[[ "$AUTHORIZED" == true ]]',
    '[[ "$HOST_V7286_SHA256" =~ ^[0-9a-f]{64}$ ]]',
    '[[ "$INDEPENDENT_AUDIT_SHA256" =~ ^[0-9a-f]{64}$ ]]',
    '[[ "$INDEPENDENT_EVALUATION_ID" =~ ^evaluation-v(1[1-9]|[2-9][0-9]|[1-9][0-9]{2,})$ ]]',
    '[[ "$INDEPENDENT_EVALUATION_SHA256" =~ ^[0-9a-f]{64}$ ]]',
)
ADMISSION_CI_ENV = (
    "CI_RUN_ID: ${{ inputs.ci_run_id }}",
    "EXPECTED_COMMIT: ${{ inputs.expected_commit }}",
    "GH_TOKEN: ${{ github.token }}",
)
ADMISSION_CI_COMMANDS = (
    'response="$(mktemp)"',
    'trap \'rm -f -- "$response"\' EXIT',
    "curl --fail-with-body --silent --show-error --location \\",
    "  --header 'Accept: application/vnd.github+json' \\",
    '  --header "Authorization: Bearer $GH_TOKEN" \\',
    "  --header 'X-GitHub-Api-Version: 2022-11-28' \\",
    '  "${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}/actions/runs/${CI_RUN_ID}" \\',
    '  --output "$response"',
    "jq -e \\",
    '  --arg run_id "$CI_RUN_ID" \\',
    '  --arg repository "$GITHUB_REPOSITORY" \\',
    '  --arg expected_commit "$EXPECTED_COMMIT" \\',
    "  '(.id | tostring) == $run_id and",
    '   .name == "CI" and',
    '   .path == ".github/workflows/ci.yml" and',
    '   .event == "push" and',
    '   .head_sha == $expected_commit and',
    '   .status == "completed" and',
    '   .conclusion == "success" and',
    "   .repository.full_name == $repository' \\",
    '  "$response" >/dev/null',
)
CANDIDATE_ADMISSION_ENV = (
    "CANDIDATE_RUN_ID: ${{ inputs.candidate_run_id }}",
    "EXPECTED_COMMIT: ${{ inputs.expected_commit }}",
    "GH_TOKEN: ${{ github.token }}",
)
CANDIDATE_ADMISSION_COMMANDS = (
    'response="$(mktemp)"',
    'trap \'rm -f -- "$response"\' EXIT',
    "curl --fail-with-body --silent --show-error --location \\",
    "  --header 'Accept: application/vnd.github+json' \\",
    '  --header "Authorization: Bearer $GH_TOKEN" \\',
    "  --header 'X-GitHub-Api-Version: 2022-11-28' \\",
    '  "${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}/actions/runs/${CANDIDATE_RUN_ID}" \\',
    '  --output "$response"',
    "jq -e \\",
    '  --arg run_id "$CANDIDATE_RUN_ID" \\',
    '  --arg repository "$GITHUB_REPOSITORY" \\',
    '  --arg expected_commit "$EXPECTED_COMMIT" \\',
    "  '(.id | tostring) == $run_id and",
    '   .name == "Round6 clean candidate - NOT A RELEASE" and',
    '   .path == ".github/workflows/round6-candidate.yml" and',
    '   .event == "workflow_dispatch" and',
    '   .head_sha == $expected_commit and',
    '   .status == "completed" and',
    '   .conclusion == "success" and',
    "   .repository.full_name == $repository' \\",
    '  "$response" >/dev/null',
)
SAFE_GATE_COMMANDS = (
    "python3 -B scripts/round6_safe_gate_contract_test.py",
    "python3 -B scripts/round6_safe_gate_contract.py --root .",
)
SAFE_WORKFLOW_ENV_LINES = {
    "GO_VERSION: '1.26.4'",
    "VERSION: '0.15'",
    "CYCLONEDX_GOMOD_VERSION: 'v1.9.0'",
    "GOVULNCHECK_VERSION: 'v1.6.0'",
}
SAFE_WORKFLOW_ENV = {
    "GO_VERSION": "1.26.4",
    "VERSION": "0.15",
    "CYCLONEDX_GOMOD_VERSION": "v1.9.0",
    "GOVULNCHECK_VERSION": "v1.6.0",
}
DANGEROUS_WORKFLOW_ENV = re.compile(
    r"^(?:BASH_ENV|ENV|PATH|CDPATH|GLOBIGNORE|PROMPT_COMMAND|SHELLOPTS|BASHOPTS|"
    r"LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT|PYTHONPATH|PYTHONHOME|PERL5OPT|RUBYOPT|"
    r"NODE_OPTIONS|GIT_CONFIG_[A-Z0-9_]+)$"
)
CLEAN_EXECUTION_ENV = (
    ("BASH_ENV", ""),
    ("ENV", ""),
    ("PATH", "/usr/bin:/bin"),
    ("CDPATH", ""),
    ("GLOBIGNORE", ""),
    ("PROMPT_COMMAND", ""),
    ("LD_PRELOAD", ""),
    ("LD_LIBRARY_PATH", ""),
    ("LD_AUDIT", ""),
    ("PYTHONPATH", ""),
    ("PYTHONHOME", ""),
    ("PERL5OPT", ""),
    ("RUBYOPT", ""),
    ("NODE_OPTIONS", ""),
    ("NODE_PATH", ""),
    ("GIT_CONFIG_COUNT", "0"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_SYSTEM", "/dev/null"),
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_TERMINAL_PROMPT", "0"),
    ("GIT_ASKPASS", "/bin/false"),
    ("SSH_ASKPASS", "/bin/false"),
    ("GIT_SSH_COMMAND", "/bin/false"),
    ("CURL_HOME", "/nonexistent"),
    ("GH_CONFIG_DIR", "/nonexistent"),
    ("HTTP_PROXY", ""),
    ("HTTPS_PROXY", ""),
    ("ALL_PROXY", ""),
)
CLEAN_EXECUTION_ENV_MAP = dict(CLEAN_EXECUTION_ENV)
CLEAN_EXECUTION_ENV_PATHS = {
    "jobs.verify.steps[12].env",
    "jobs.verify.steps[13].env",
}
BLOCKED_TOP_LEVEL_KEYS = (
    "name",
    "on",
    "permissions",
    "concurrency",
    "env",
    "jobs",
)
BLOCKED_JOB_KEYS = {
    "admission": ("runs-on", "timeout-minutes", "steps"),
    "verify": ("needs", "permissions", "runs-on", "timeout-minutes", "steps"),
    "publish": (
        "needs",
        "environment",
        "if",
        "permissions",
        "runs-on",
        "timeout-minutes",
        "steps",
    ),
}
BLOCKED_STEP_CONTRACTS = {
    "admission": (
        (
            "Fail closed unless every external gate and authorization is explicit",
            ("name", "env", "run"),
            None,
        ),
        (
            "Bind admission to a successful CI run for the exact commit",
            ("name", "env", "run"),
            None,
        ),
        (
            "Bind admission to the successful clean-candidate run",
            ("name", "env", "run"),
            None,
        ),
    ),
    "verify": (
        (
            "Checkout the explicitly supplied existing tag",
            ("name", "uses", "with"),
            "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        ),
        ("Recheck the Round6 restricted-data boundary", ("name", "run"), None),
        (
            "Verify immutable source identity and annotated tag",
            ("name", "env", "run"),
            None,
        ),
        (
            "Set up pinned Go",
            ("name", "uses", "with"),
            "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16",
        ),
        ("Install bounded build dependencies", ("name", "run"), None),
        (
            "Download the exact Host-tested clean candidate artifact",
            ("name", "uses", "with"),
            "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131",
        ),
        (
            "Verify candidate manifest and Host-tested artifact bytes",
            ("name", "env", "run"),
            None,
        ),
        ("Run source and Round6 regression gates", ("name", "run"), None),
        (
            "Verify current CPA v7.2.86 source compatibility",
            ("name", "env", "run"),
            None,
        ),
        (
            "Rebuild the exact clean Host-tested candidate",
            ("name", "env", "run"),
            None,
        ),
        (
            "Prove clean candidate reproducibility against root artifacts",
            ("name", "env", "run"),
            None,
        ),
        ("Recheck source cleanliness", ("name", "run"), None),
        (
            "Reverify source and artifact identity before transfer",
            ("name", "env", "run"),
            None,
        ),
        (
            "Upload exact verified blocked-development artifacts",
            ("name", "uses", "env", "with"),
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        ),
    ),
    "publish": (
        (
            "Download exact verified blocked-development artifacts",
            ("name", "uses", "with"),
            "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131",
        ),
        (
            "Reverify transferred artifact identity without a repository token",
            ("name", "env", "run"),
            None,
        ),
        (
            "Upload immutable blocked-attestation artifact for the formal workflow",
            ("name", "uses", "with"),
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        ),
        (
            "Recheck immutable tag and create draft blocked prerelease",
            ("name", "env", "run"),
            None,
        ),
    ),
}
BLOCKED_ALLOWED_GITHUB_TOKEN_PATHS = {
    "jobs.admission.steps[1].env.GH_TOKEN",
    "jobs.admission.steps[2].env.GH_TOKEN",
    "jobs.verify.steps[5].with.github-token",
    "jobs.publish.steps[3].env.GH_TOKEN",
}
BLOCKED_ALLOWED_GITHUB_IDENTITY_EXPRESSIONS = {
    "jobs.admission.steps[0].env.DISPATCH_REF": "${{ github.ref }}",
    "jobs.admission.steps[0].env.DISPATCH_SHA": "${{ github.sha }}",
    "jobs.admission.steps[0].env.WORKFLOW_REF": "${{ github.workflow_ref }}",
    "jobs.admission.steps[0].env.WORKFLOW_SHA": "${{ github.workflow_sha }}",
    "jobs.verify.steps[5].with.repository": "${{ github.repository }}",
    "jobs.publish.steps[1].env.WORKFLOW_SHA": "${{ github.workflow_sha }}",
}
GITHUB_EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
SENSITIVE_EXPRESSION_CONTEXT = re.compile(r"(?i)(?<![A-Za-z0-9_])(?:github|secrets)(?![A-Za-z0-9_])")
ROUND6_SPARSE_PATTERNS = (
    "/*",
    "!/cmd/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*",
    "!/cmd/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*",
    "!/cmd/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*",
    "!/cmd/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*",
    "!/cmd/**/*[Bb][Ll][Ii][Nn][Dd]*",
    "!/cmd/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*",
    "!/docs/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*",
    "!/docs/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*",
    "!/docs/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]_[Rr][Ee][Pp][Oo][Rr][Tt].[Mm][Dd]",
    "!/docs/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*",
    "!/docs/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*",
    "!/docs/**/*[Bb][Ll][Ii][Nn][Dd]*",
    "!/docs/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*",
    "!/internal/classifier/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*",
    "!/internal/classifier/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*",
    "!/internal/classifier/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*",
    "!/internal/classifier/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*",
    "!/internal/classifier/**/*[Bb][Ll][Ii][Nn][Dd]*",
    "!/internal/classifier/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*",
    "!/testdata/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*",
    "!/testdata/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*",
    "!/testdata/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*",
    "!/testdata/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*",
    "!/testdata/**/*[Bb][Ll][Ii][Nn][Dd]*",
    "!/testdata/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*",
)
CONSUMED_BOUNDARY_LINES = {
    ".gitattributes": (
        "/cmd/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]* export-ignore",
        "/docs/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]* export-ignore",
        "/internal/classifier/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]* export-ignore",
        "/testdata/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]* export-ignore",
    ),
    "scripts/release-common.sh": (
        '  local path="${1,,}"',
        '  case "$path" in',
        "    cmd/*evaluation*|cmd/*holdout*|cmd/*consumed*|cmd/*private*|cmd/*blind*|cmd/*retired*|\\",
        "    docs/*consumed*|docs/*private*|docs/*blind*|docs/*retired*|\\",
        "    internal/classifier/*consumed*|internal/classifier/*private*|internal/classifier/*blind*|internal/classifier/*retired*|\\",
        "    testdata/*evaluation*|testdata/*holdout*|testdata/*consumed*|testdata/*private*|testdata/*blind*|testdata/*retired*)",
    ),
    "scripts/package-source-release.sh": (
        "  ':(exclude,glob,icase)cmd/**/*consumed*'",
        "  ':(exclude,glob,icase)docs/**/*consumed*'",
        "  ':(exclude,glob,icase)internal/classifier/**/*consumed*'",
        "  ':(exclude,glob,icase)testdata/**/*consumed*'",
        "if grep -Eiq '(^|/)[^/]*(evaluation|holdout|consumed|private|blind|retired)[^/]*($|/)' <<<\"$listing\"; then",
    ),
    "Makefile": (
        "\t\t':(exclude,glob,icase)cmd/**/*consumed*' \\",
        "\t\t':(exclude,glob,icase)docs/**/*consumed*' \\",
        "\t\t':(exclude,glob,icase)internal/classifier/**/*consumed*' \\",
        "\t\t':(exclude,glob,icase)testdata/**/*consumed*' \\",
    ),
    "scripts/source-release-exclusion-contract-test.sh": (
        "  cmd/safe/nested-consumed",
        "  cmd/safe/nested-Consumed",
        "  cmd/safe/nested-Evaluation/payload.go",
        "  cmd/safe/nested-Consumed/payload.go",
        "  cmd/safe/nested-HoldOut/payload.go",
        "  docs/safe/nested-Private/report.md",
        "  internal/classifier/safe/nested-Blind/payload.go",
        "  testdata/safe/nested-Retired/payload.json",
        "  '!/cmd/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*'",
        "  '!/internal/classifier/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*'",
        "  '!/testdata/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*'",
        'git -C "$sparse_fixture" sparse-checkout set --no-cone "${sparse_patterns[@]}"',
        "if grep -Eiq '(^|/)[^/]*(evaluation|holdout|consumed|private|blind|retired)[^/]*($|/)' <<<\"$listing\"; then",
    ),
    "scripts/round6-safe-go-files.sh": (
        '  case "${file,,}" in',
        "    internal/classifier/*evaluation*|internal/classifier/*holdout*|internal/classifier/*consumed*|internal/classifier/*private*|internal/classifier/*retired*|internal/classifier/*blind*)",
    ),
}
ROUND6_REPRODUCIBILITY_SCRIPT_SHA256 = (
    "f801b8b3f530fe00fe7b354fa8726e33fcfdf7bddf70e4b9ee32ac785e09d273"
)
ROUND6_REPRODUCIBILITY_ENTRY_MODE_CONTRACT = """reproducibility_mode="${ROUND6_REPRODUCIBILITY_MODE:-release}"
case "$reproducibility_mode" in
  development)
    [[ "${RELEASE_CANDIDATE_BUILD:-0}" == 0 ]] || \\
      release_die "development reproducibility mode cannot enable candidate builds"
    ALLOW_DIRTY_BUILD=1
    ;;
  release) ;;
  *) release_die "ROUND6_REPRODUCIBILITY_MODE must be release or development" ;;
esac"""
ROUND6_REPRODUCIBILITY_MODE_CONTRACT = """case "$RELEASE_BUILD_KIND" in
  candidate)
    release_assert_candidate_build
    clone_dirty_build=0
    clone_candidate_build=1
    artifact_version="$RELEASE_SOURCE_VERSION"
    ;;
  formal)
    release_assert_tag
    release_assert_formal_build
    clone_dirty_build=0
    artifact_version="$RELEASE_SOURCE_VERSION"
    ;;
  development) ;;
  *) release_die "unsupported Round6 reproducibility build kind: $RELEASE_BUILD_KIND" ;;
esac"""
ROUND6_REPRODUCIBILITY_FORMAL_PACKAGE_COMMAND = (
    '    env "${common_env[@]}" "$clone/scripts/package-release.sh"'
)
ROUND6_REPRODUCIBILITY_PACKAGE_BRANCH_CONTRACT = """  if [[ "$RELEASE_BUILD_KIND" == formal ]]; then
    env "${common_env[@]}" "$clone/scripts/package-release.sh"
  else
    PLUGIN_BINARY="$clone/dist/$so" \\
      STORE_ARCHIVE="$clone/dist/$store_zip" \\
      SOURCE_DATE_EPOCH="$RELEASE_SOURCE_DATE_EPOCH" \\
      "$clone/scripts/create-store-archive.sh"
  fi"""
ROUND6_REPRODUCIBILITY_CHECKSUMS_CONTRACT = (
    '        sbom.cdx.json >checksums.txt',
    '      sha256sum -c checksums.txt',
    'compare_artifact "checksums manifest" checksums.txt',
    '  for relative in "$so" "$so.sha256" "$store_zip" build-metadata.json checksums.txt \\',
)
BLOCKED_STEP_RUN_SHA256 = {
    ("admission", 0): "4830e3f84435dda74c87216010d4ca5021d7c75935a95997acf1e416e3ef47fe",
    ("admission", 1): "7f1817ec7b567df4be63fafd9ee2b2347ac37e01982e41ee3338f64c79cae81a",
    ("admission", 2): "5a315540eb55c2663caeba1fa2f77a80df0f4d2fd6c786c656149d22f638c2f2",
    ("verify", 1): "b38e1f3a74567d8390bde6390c75c7e96a3bd0d5bc13de0e6a7dbbcfeec0a2fe",
    ("verify", 2): "3427df1bdbbcd38976514b679706f45fe6331981e750168beffd9bfdd1efdea1",
    ("verify", 4): "378f0a3b53f59937e4646b34b7b69f16c839ffb03edf54331fea149479f9c8b9",
    ("verify", 6): "f44c21af46cc092437d61120ad9f5d9c7984d3013d224ce3c189b32610ed82ba",
    ("verify", 7): "feb84636bac16fb6245913190b0803f0644ee094423c531ad4e59c752e6bc9fd",
    ("verify", 8): "fa50af5a75fcdd76f7a5c0900c3f983b2ee285220229e1746c35671713cba7b7",
    ("verify", 9): "eabde1048cd0f10bfc3540f427c3674b3cf8d5fc0206bebc58e695a328dbb0cb",
    ("verify", 10): "d6bd0b9f43ef190a6545893891fe514928b3e354a438f357602e2d3a89565bd0",
    ("verify", 11): "72ba08821693dcb100be3d4dcfaac32d485191186d46fa22119ae7a7b60990b9",
    ("verify", 12): "25116143b78146e257b7eb89c5466266132755433249c07664c0cdbf01944c7d",
    ("publish", 1): "f0b4e25161a56a18cbe2379e048d0151e537eb80d504673f20c8cd2adf4bfbb5",
    ("publish", 3): "f5d984d926b1ff4cb197863446457871abf2abfc662847024a1cbcf3a51984ff",
}
BLOCKED_STEP_RUN_STYLE = {
    ("admission", 0): "|",
    ("admission", 1): "|",
    ("admission", 2): "|",
    ("verify", 1): "|",
    ("verify", 2): "|",
    ("verify", 4): "|",
    ("verify", 6): "|",
    ("verify", 7): "|",
    ("verify", 8): None,
    ("verify", 9): None,
    ("verify", 10): None,
    ("verify", 11): None,
    ("verify", 12): "|",
    ("publish", 1): "|",
    ("publish", 3): "|",
}
BLOCKED_STEP_ENV = {
    ("admission", 0): (
        ("TAG", "${{ inputs.tag }}"),
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("CI_RUN_ID", "${{ inputs.ci_run_id }}"),
        ("CANDIDATE_RUN_ID", "${{ inputs.candidate_run_id }}"),
        ("EXPECTED_SO_SHA256", "${{ inputs.expected_so_sha256 }}"),
        ("EXPECTED_STORE_ZIP_SHA256", "${{ inputs.expected_store_zip_sha256 }}"),
        ("DISPATCH_REF", "${{ github.ref }}"),
        ("DISPATCH_SHA", "${{ github.sha }}"),
        ("WORKFLOW_REF", "${{ github.workflow_ref }}"),
        ("WORKFLOW_SHA", "${{ github.workflow_sha }}"),
        ("HOST_V7286", "${{ inputs.host_v7286_validation }}"),
        ("HOST_V7286_SHA256", "${{ inputs.host_v7286_evidence_sha256 }}"),
        ("INDEPENDENT_AUDIT", "${{ inputs.independent_audit_validation }}"),
        ("INDEPENDENT_AUDIT_SHA256", "${{ inputs.independent_audit_sha256 }}"),
        ("INDEPENDENT_EVALUATION", "${{ inputs.independent_evaluation_validation }}"),
        ("INDEPENDENT_EVALUATION_ID", "${{ inputs.independent_evaluation_id }}"),
        ("INDEPENDENT_EVALUATION_SHA256", "${{ inputs.independent_evaluation_sha256 }}"),
        ("AUTHORIZED", "${{ inputs.authorize_blocked_prerelease }}"),
    ),
    ("admission", 1): (
        ("CI_RUN_ID", "${{ inputs.ci_run_id }}"),
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("GH_TOKEN", "${{ github.token }}"),
    ),
    ("admission", 2): (
        ("CANDIDATE_RUN_ID", "${{ inputs.candidate_run_id }}"),
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("GH_TOKEN", "${{ github.token }}"),
    ),
    ("verify", 2): (
        ("TAG", "${{ inputs.tag }}"),
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
    ),
    ("verify", 6): (
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("CANDIDATE_RUN_ID", "${{ inputs.candidate_run_id }}"),
        ("EXPECTED_SO_SHA256", "${{ inputs.expected_so_sha256 }}"),
        ("EXPECTED_STORE_ZIP_SHA256", "${{ inputs.expected_store_zip_sha256 }}"),
    ),
    ("verify", 8): (("CPA_COMPAT_VERIFY_REMOTE", "1"),),
    ("verify", 9): (
        ("RELEASE_CANDIDATE_BUILD", "1"),
        ("RELEASE_CANDIDATE_EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("RELEASE_CANDIDATE_EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("ROUND6_SAFE_SPARSE_BUILD", "1"),
        ("REQUIRE_DIST_ARTIFACTS", "1"),
    ),
    ("verify", 10): (
        ("RELEASE_CANDIDATE_BUILD", "1"),
        ("RELEASE_CANDIDATE_EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("RELEASE_CANDIDATE_EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("ROUND6_SAFE_SPARSE_BUILD", "1"),
    ),
    ("verify", 12): (
        ("TAG", "${{ inputs.tag }}"),
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("EXPECTED_SO_SHA256", "${{ inputs.expected_so_sha256 }}"),
        ("EXPECTED_STORE_ZIP_SHA256", "${{ inputs.expected_store_zip_sha256 }}"),
    )
    + CLEAN_EXECUTION_ENV,
    ("verify", 13): CLEAN_EXECUTION_ENV,
    ("publish", 1): (
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("EXPECTED_SO_SHA256", "${{ inputs.expected_so_sha256 }}"),
        ("EXPECTED_STORE_ZIP_SHA256", "${{ inputs.expected_store_zip_sha256 }}"),
        ("TAG", "${{ inputs.tag }}"),
        ("CI_RUN_ID", "${{ inputs.ci_run_id }}"),
        ("CANDIDATE_RUN_ID", "${{ inputs.candidate_run_id }}"),
        ("HOST_V7286_SHA256", "${{ inputs.host_v7286_evidence_sha256 }}"),
        ("INDEPENDENT_AUDIT_SHA256", "${{ inputs.independent_audit_sha256 }}"),
        ("INDEPENDENT_EVALUATION_ID", "${{ inputs.independent_evaluation_id }}"),
        ("INDEPENDENT_EVALUATION_SHA256", "${{ inputs.independent_evaluation_sha256 }}"),
        ("WORKFLOW_SHA", "${{ github.workflow_sha }}"),
    ),
    ("publish", 3): (
        ("GH_TOKEN", "${{ github.token }}"),
        ("TAG", "${{ inputs.tag }}"),
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("EXPECTED_SO_SHA256", "${{ inputs.expected_so_sha256 }}"),
        ("EXPECTED_STORE_ZIP_SHA256", "${{ inputs.expected_store_zip_sha256 }}"),
        ("CI_RUN_ID", "${{ inputs.ci_run_id }}"),
        ("CANDIDATE_RUN_ID", "${{ inputs.candidate_run_id }}"),
        ("HOST_V7286_SHA256", "${{ inputs.host_v7286_evidence_sha256 }}"),
        ("INDEPENDENT_AUDIT_SHA256", "${{ inputs.independent_audit_sha256 }}"),
        ("INDEPENDENT_EVALUATION_ID", "${{ inputs.independent_evaluation_id }}"),
        ("INDEPENDENT_EVALUATION_SHA256", "${{ inputs.independent_evaluation_sha256 }}"),
    ),
}

CANDIDATE_WORKFLOW_NAME = "Round6 clean candidate - NOT A RELEASE"
CANDIDATE_INPUT_ORDER = (
    "expected_commit",
    "expected_tree",
    "ci_run_id",
    "authorize_clean_candidate",
)
CANDIDATE_TOP_LEVEL_KEYS = (
    "name",
    "on",
    "permissions",
    "concurrency",
    "env",
    "jobs",
)
CANDIDATE_JOB_KEYS = {
    "admission": ("runs-on", "timeout-minutes", "steps"),
    "build": ("needs", "permissions", "runs-on", "timeout-minutes", "steps"),
}
CANDIDATE_STEP_CONTRACTS = {
    "admission": (
        (
            "Bind dispatch to the exact main tip and candidate workflow",
            ("name", "env", "run"),
            None,
        ),
        (
            "Bind candidate admission to successful exact-head push CI",
            ("name", "env", "run"),
            None,
        ),
    ),
    "build": (
        (
            "Checkout exact Round6-safe source",
            ("name", "uses", "with"),
            "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        ),
        ("Recheck restricted-data and workflow contracts", ("name", "run"), None),
        ("Verify immutable source identity", ("name", "env", "run"), None),
        (
            "Set up pinned Go",
            ("name", "uses", "with"),
            "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16",
        ),
        ("Install bounded candidate dependencies", ("name", "run"), None),
        (
            "Recheck source, regressions, and latest CPA v7.2.86 contract",
            ("name", "env", "run"),
            None,
        ),
        (
            "Build exact clean unreleased Host-test assets",
            ("name", "env", "run"),
            None,
        ),
        (
            "Rebuild candidate in two clean clones and compare bytes",
            ("name", "env", "run"),
            None,
        ),
        (
            "Reverify candidate identity and source cleanliness",
            ("name", "env", "run"),
            None,
        ),
        (
            "Upload private exact-commit candidate",
            ("name", "uses", "with"),
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        ),
    ),
}
CANDIDATE_STEP_RUN_SHA256 = {
    ("admission", 0): "1010c71654565731433ae574c6ac875b36bcd7c164bbab8aed6fb9d56932108b",
    ("admission", 1): "7f1817ec7b567df4be63fafd9ee2b2347ac37e01982e41ee3338f64c79cae81a",
    ("build", 1): "b38e1f3a74567d8390bde6390c75c7e96a3bd0d5bc13de0e6a7dbbcfeec0a2fe",
    ("build", 2): "8966c407a8e05f9a88182c2130b24b907e58dd1d874d55fe4f86c9bfedef6457",
    ("build", 4): "e94a8d7e6ec6ca9c30a512aa4f6bd8eb93dd3412b406ea2f64a7d2b91e75022f",
    ("build", 5): "43a1e2b51527edd141c9b4c53ac0c11775f0b8b9948054e5d2f329221a555e60",
    ("build", 6): "f99bfc855f5afa25f227afce3800b41093b1858f9ae4b8027378ebf530470cf8",
    ("build", 7): "d6bd0b9f43ef190a6545893891fe514928b3e354a438f357602e2d3a89565bd0",
    ("build", 8): "841d631459baa6ee68b3021816c7d9da6310be1527d4c01a66a546210e288289",
}
CANDIDATE_STEP_RUN_STYLE = {
    ("admission", 0): "|",
    ("admission", 1): "|",
    ("build", 1): "|",
    ("build", 2): "|",
    ("build", 4): "|",
    ("build", 5): "|",
    ("build", 6): None,
    ("build", 7): None,
    ("build", 8): "|",
}
CANDIDATE_STEP_ENV = {
    ("admission", 0): (
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("CI_RUN_ID", "${{ inputs.ci_run_id }}"),
        ("AUTHORIZED", "${{ inputs.authorize_clean_candidate }}"),
        ("DISPATCH_REF", "${{ github.ref }}"),
        ("DISPATCH_SHA", "${{ github.sha }}"),
        ("WORKFLOW_REF", "${{ github.workflow_ref }}"),
        ("WORKFLOW_SHA", "${{ github.workflow_sha }}"),
    ),
    ("admission", 1): (
        ("CI_RUN_ID", "${{ inputs.ci_run_id }}"),
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("GH_TOKEN", "${{ github.token }}"),
    ),
    ("build", 2): (
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
    ),
    ("build", 5): (("CPA_COMPAT_VERIFY_REMOTE", "1"),),
    ("build", 6): (
        ("RELEASE_CANDIDATE_BUILD", "1"),
        ("RELEASE_CANDIDATE_EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("RELEASE_CANDIDATE_EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("RELEASE_CANDIDATE_WORKFLOW_SHA", "${{ github.workflow_sha }}"),
        ("ROUND6_SAFE_SPARSE_BUILD", "1"),
        ("REQUIRE_DIST_ARTIFACTS", "1"),
    ),
    ("build", 7): (
        ("RELEASE_CANDIDATE_BUILD", "1"),
        ("RELEASE_CANDIDATE_EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("RELEASE_CANDIDATE_EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("ROUND6_SAFE_SPARSE_BUILD", "1"),
    ),
    ("build", 8): (
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
    ),
}
CANDIDATE_ALLOWED_GITHUB_TOKEN_PATHS = {
    "jobs.admission.steps[1].env.GH_TOKEN",
}
CANDIDATE_ALLOWED_GITHUB_IDENTITY_EXPRESSIONS = {
    "jobs.admission.steps[0].env.DISPATCH_REF": "${{ github.ref }}",
    "jobs.admission.steps[0].env.DISPATCH_SHA": "${{ github.sha }}",
    "jobs.admission.steps[0].env.WORKFLOW_REF": "${{ github.workflow_ref }}",
    "jobs.admission.steps[0].env.WORKFLOW_SHA": "${{ github.workflow_sha }}",
    "jobs.build.steps[6].env.RELEASE_CANDIDATE_WORKFLOW_SHA": "${{ github.workflow_sha }}",
}
CANDIDATE_ARTIFACTS = (
    "dist/cyber-abuse-guard-v0.15.so",
    "dist/cyber-abuse-guard-v0.15.so.sha256",
    "dist/cyber-abuse-guard_0.15_linux_amd64.zip",
    "dist/build-metadata.json",
    "dist/checksums.txt",
    "dist/ruleset-manifest.json",
    "dist/ruleset.sha256",
    "dist/sbom.cdx.json",
    "dist/candidate-manifest.json",
)
CANDIDATE_SCRIPT_SHA256 = {
    "round6-candidate-artifacts.sh": "11a2a358c3154bd8665f6b5ae27d84c6f97fd33763f9cc602b38425c93bce659",
    "release-candidate-contract-test.sh": "82879ce86da1a0424c1ba688d33635176411e2a646449e355dc705ba7d982a69",
}
RC_RELEASE_SCRIPT_SHA256 = "30d349c1f6d7e78b3b66d78042b493e1e17f14a5bc89bad2abaf16958f7521fd"
RC_RELEASE_WORKFLOW_SHA256 = "d5bef4b54cedc6e67fab70e29250f83af9c9311add28188c5d2d7d0d5f6e1289"
FORMAL_OPERATION_SCRIPTS = (
    "formal-release.sh",
    "generate-release-evidence.sh",
    "package-release.sh",
    "package-source-release.sh",
    "release-preflight.sh",
    "verify-release.sh",
)
FORMAL_RELEASE_ARTIFACTS = (
    "dist/cyber-abuse-guard-v0.15.so",
    "dist/cyber-abuse-guard-v0.15.so.sha256",
    "dist/cyber-abuse-guard_0.15_linux_amd64.zip",
    "dist/cyber-abuse-guard-v0.15-audit-bundle.zip",
    "dist/build-metadata.json",
    "dist/checksums.txt",
    "dist/ruleset-manifest.json",
    "dist/ruleset.sha256",
    "dist/sbom.cdx.json",
    "dist/release-test-summary.txt",
    "dist/release-test-summary.txt.sha256",
    "dist/release-evidence-final.md",
    "dist/release-evidence-final.md.sha256",
    "dist/cyber-abuse-guard-v0.15-source.tar.gz",
    "dist/cyber-abuse-guard-v0.15-source.tar.gz.sha256",
    "dist/round6-prerelease-attestation.json",
    "dist/round6-prerelease-attestation.json.sha256",
    "dist/formal-release-attestation.json",
    "dist/formal-release-attestation.json.sha256",
)
FORMAL_RELEASE_STEP_RUN_SHA256 = {
    ("admission", 0): "dd00f8c8f9a1a732ce9d923f203c83052c953556510bf1015cc2567a596a665b",
    ("build-and-verify", 2): "5bc38a90928a7309be0be55b3834ebf28c2eee7c2fd290ef19bf6d3a8dd3857d",
    ("build-and-verify", 3): "3177c58474d2bd9ee7246a79c02d77fc4afac7b26e13f3193cd456f9cadbb2dd",
    ("build-and-verify", 4): "e2194c0fb1cc2681adff35d6c0a12e10540e17bb7495597ac1f3ccb992bbc53f",
    ("build-and-verify", 5): "16f59f25d193f0098efe4009bb21dbb52a387fb00b7581a6e800e65907efb51c",
    ("build-and-verify", 7): "2ecb4e3db81c81773248547deb2121bd998a7c1aeae69036485603c1760c53e2",
    ("build-and-verify", 8): "2824c61aa8a13293fe96c4a6f7586466ca90eb0f527182265f9be7df66586ccf",
    ("build-and-verify", 9): "85ab9b21007e3d06b5c4720274e1fe5753a3634b5611185736e4fc83b738dc38",
    ("build-and-verify", 10): "59019f683072911ccdd1638400fd5af145c9c6cbd8be29d8c75960b2fc888fbc",
    ("publish", 1): "ca29fccccf8950a2ddfa783c8420bc8be1b32dd75f790837c825af84b43eee0c",
    ("publish", 2): "1574a0d0ac458f3e12ab6052955d1027955a8cfad76f5773547da4d4bcb85fb2",
}
PROMOTE_STEP_RUN_SHA256 = {
    ("verify", 0): "23790f44480f0b622850f051f03c2d50fe343e5bbed41b8bdf7a94ac3f4a9af1",
    ("verify", 2): "81f3c306c6e57ff95c598cb10fcc9c9bd185361a1bb753ab98de0e4e4a8df813",
    ("promote", 0): "d04544c3a61f3bae7810179742dbd326ae291aa02791347eb4f2ebb5dfccd4b1",
}
REPRODUCIBILITY_WRAPPER_SCRIPT = "scripts/reproducibility-test.sh"
REPRODUCIBILITY_WRAPPER_SCRIPT_SHA256 = (
    "29bf44be67be80aea19f37acbbda01bba247b2319f32626b0f562ce9fda78824"
)
FROZEN_EVALUATION_TREE_SCRIPT = "scripts/verify-frozen-evaluation-v10-tree.sh"
FROZEN_EVALUATION_TREE_SCRIPT_SHA256 = (
    "eda0524cfc297095edc018b710fc18a98312914112968dba2d094f0e8a03aac2"
)
FROZEN_EVALUATION_STATUS_COMMAND = (
    'status="$(git -C "$root" status --porcelain=v1 --untracked-files=all -- "${paths[@]}")"'
)
ROUND6_DOC_FIXTURE_WRAPPER_SCRIPT = "scripts/round6-doc-consistency-fixture-test.sh"
ROUND6_DOC_FIXTURE_WRAPPER_SCRIPT_SHA256 = (
    "43a27e7616b3b9007de336818e27e78a9260406b86b5da55983fb99d4758b46d"
)
ROUND6_DOC_FIXTURE_DEPENDENCY_SHA256 = {
    "scripts/release-doc-consistency-test.sh": "e1ee5204237668125a5da3b7c025f72f6c568ec0cad7a7c0bb581168e84c9fd8",
    "scripts/release-doc-consistency.sh": "bb16e34ebec34f4fdb5329e6db9a773104fedeb236b28ce759b686eed0cce0f2",
}
ROUND6_PRIVACY_FIXTURE_SCRIPT = "scripts/release-evidence-privacy-test.sh"
ROUND6_PRIVACY_FIXTURE_SCRIPT_SHA256 = (
    "6306a733095173425ad735bea5d986de21ae2b3f4e6f053dee970d7436f9f762"
)
CPA_COMPAT_SCRIPT = "scripts/cpa-latest-compat.sh"
CPA_COMPAT_SCRIPT_SHA256 = (
    "4a86b16a36786957bde70b9b4885430f0409e62e16cf8224263e8f0162517650"
)
CPA_COMPAT_FINAL_OUTPUT_CONTRACT = """if [[ "$verify_remote" == 1 ]]; then
  printf 'CPA latest source/compile compatibility PASS: profile=%s\\n' "${profiles[*]}"
else
  printf 'CPA source/compile compatibility PASS: profile=%s remote_release_checks=SKIPPED\\n' "${profiles[*]}"
fi"""
EXTERNAL_ATTESTATION_SCRIPT_SHA256 = {
    "verify-external-release-attestation.sh": "17d79149b779b01f2e3e733d0deb529927bfe0c6d50b8125abd8b556fd95d476",
    "verify-external-release-attestation-test.sh": "07683ce09cbdef7c15f8d6b31ff1308380ad21c920d8bc745c9b4599f4555aba",
}
GENERATE_RELEASE_EVIDENCE_SCRIPT_SHA256 = "22317f7596fadf7ea39a35b8df1ed5ac22c8f46608cbacf5ba2a25222cc92c1c"


class ContractError(RuntimeError):
    pass


def validate_consumed_boundary_files(root: Path) -> None:
    for relative, required_lines in CONSUMED_BOUNDARY_LINES.items():
        source = root / relative
        lines = read_regular_text(source, root).splitlines()
        for required in required_lines:
            if lines.count(required) != 1:
                raise ContractError(
                    f"consumed exclusion boundary differs from the reviewed contract: {relative}"
                )


def yaml_location(node: Node | None, source: Path) -> str:
    if node is None:
        return f"{source}:missing"
    return f"{source}:{node.start_mark.line + 1}:{node.start_mark.column + 1}"


def validate_yaml_mapping_tree(node: Node, source: Path, path: str = "workflow") -> None:
    if isinstance(node, MappingNode):
        seen: set[str] = set()
        for key_node, value_node in node.value:
            if not isinstance(key_node, ScalarNode):
                raise ContractError(
                    f"workflow mapping keys must be plain scalars at {yaml_location(key_node, source)}"
                )
            if key_node.style is not None:
                raise ContractError(
                    f"workflow mapping keys may not be quoted or block-scalars at {yaml_location(key_node, source)}"
                )
            key = key_node.value
            if key in seen:
                raise ContractError(
                    f"workflow contains duplicate semantic key {key!r} at {yaml_location(key_node, source)}"
                )
            seen.add(key)
            validate_yaml_mapping_tree(value_node, source, f"{path}.{key}")
    elif isinstance(node, SequenceNode):
        for index, child in enumerate(node.value):
            validate_yaml_mapping_tree(child, source, f"{path}[{index}]")


def parse_workflow_yaml(text: str, source: Path) -> MappingNode:
    forbidden_tokens = (
        AliasToken,
        AnchorToken,
        DirectiveToken,
        DocumentEndToken,
        DocumentStartToken,
        FlowMappingStartToken,
        FlowSequenceStartToken,
        TagToken,
    )
    try:
        for token in yaml.scan(text, Loader=yaml.SafeLoader):
            if isinstance(token, forbidden_tokens):
                raise ContractError(
                    "workflow may not use YAML anchors, aliases, tags, directives, "
                    f"document markers, or flow collections at {source}:"
                    f"{token.start_mark.line + 1}:{token.start_mark.column + 1}"
                )
            if isinstance(token, KeyToken) and token.end_mark.index > token.start_mark.index:
                raise ContractError(
                    f"workflow may not use explicit YAML mapping keys at {source}:"
                    f"{token.start_mark.line + 1}:{token.start_mark.column + 1}"
                )
        document = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as exc:
        raise ContractError(f"workflow is not valid fail-closed YAML: {source}: {exc}") from exc
    if not isinstance(document, MappingNode):
        raise ContractError(f"workflow root must be one YAML mapping: {source}")
    validate_yaml_mapping_tree(document, source)
    return document


def yaml_mapping(node: Node | None, source: Path, path: str) -> dict[str, Node]:
    if not isinstance(node, MappingNode):
        raise ContractError(f"workflow {path} must be a mapping at {yaml_location(node, source)}")
    return {key.value: value for key, value in node.value}


def yaml_mapping_keys(node: Node | None, source: Path, path: str) -> tuple[str, ...]:
    if not isinstance(node, MappingNode):
        raise ContractError(f"workflow {path} must be a mapping at {yaml_location(node, source)}")
    return tuple(key.value for key, _ in node.value)


def require_yaml_keys(
    node: Node | None, expected: tuple[str, ...], source: Path, path: str
) -> dict[str, Node]:
    actual = yaml_mapping_keys(node, source, path)
    if actual != expected:
        raise ContractError(
            f"workflow {path} keys/order changed: expected {expected}, got {actual}"
        )
    return yaml_mapping(node, source, path)


def yaml_sequence(node: Node | None, source: Path, path: str) -> list[Node]:
    if not isinstance(node, SequenceNode):
        raise ContractError(f"workflow {path} must be a sequence at {yaml_location(node, source)}")
    return list(node.value)


def yaml_scalar(node: Node | None, source: Path, path: str) -> str:
    if not isinstance(node, ScalarNode):
        raise ContractError(f"workflow {path} must be a scalar at {yaml_location(node, source)}")
    return node.value


def require_yaml_scalar(
    node: Node | None, expected: str, source: Path, path: str, *, tag: str | None = None
) -> None:
    actual = yaml_scalar(node, source, path)
    if actual != expected or (tag is not None and node.tag != tag):
        raise ContractError(
            f"workflow {path} must be exact scalar {expected!r}"
        )


def iter_yaml_scalars(node: Node, path: str = ""):
    if isinstance(node, MappingNode):
        for key_node, value_node in node.value:
            child_path = f"{path}.{key_node.value}" if path else key_node.value
            yield from iter_yaml_scalars(value_node, child_path)
    elif isinstance(node, SequenceNode):
        for index, child in enumerate(node.value):
            yield from iter_yaml_scalars(child, f"{path}[{index}]")
    elif isinstance(node, ScalarNode):
        yield path, node


def validate_sensitive_workflow_expressions(
    document: MappingNode,
    source: Path,
    *,
    allowed_token_paths: set[str],
    allowed_identity_expressions: dict[str, str],
) -> None:
    allowed_seen: set[str] = set()
    for path, node in iter_yaml_scalars(document):
        for match in GITHUB_EXPRESSION.finditer(node.value):
            expression = match.group(1).strip()
            if not SENSITIVE_EXPRESSION_CONTEXT.search(expression):
                continue
            if path in allowed_token_paths and node.value == "${{ github.token }}":
                allowed_seen.add(path)
                continue
            expected_identity = allowed_identity_expressions.get(path)
            if expected_identity is not None and node.value == expected_identity:
                allowed_seen.add(path)
                continue
            raise ContractError(
                "workflow may not expose a repository token, github.token, or secrets context "
                f"outside the exact reviewed GH_TOKEN env nodes, got {path} in {source}"
            )
    expected_allowed = allowed_token_paths | set(allowed_identity_expressions)
    if allowed_seen != expected_allowed:
        raise ContractError(
            "workflow must expose only the exact reviewed github token and identity expressions"
        )


def contains_repository_node(step: MappingNode, source: Path, path: str) -> bool:
    values = yaml_mapping(step, source, path)
    uses = values.get("uses")
    if uses is not None and yaml_scalar(uses, source, f"{path}.uses").startswith("./"):
        return True
    run = values.get("run")
    if run is None:
        return False
    return bool(
        re.search(
            r"(?:^|[\s;&|])(?:g?make|git|go)(?=\s|$)|(?:^|[\s;&|])(?:\./)?scripts/",
            yaml_scalar(run, source, f"{path}.run"),
        )
    )


def is_safe_gate_node(step: MappingNode, source: Path, path: str) -> bool:
    try:
        values = require_yaml_keys(step, ("name", "run"), source, path)
    except ContractError:
        return False
    commands = tuple(
        line.strip()
        for line in yaml_scalar(values["run"], source, f"{path}.run").splitlines()
        if line.strip()
    )
    return commands == SAFE_GATE_COMMANDS


def validate_workflow_semantic_safety(document: MappingNode, source: Path) -> None:
    root = yaml_mapping(document, source, "workflow")
    if "defaults" in root:
        raise ContractError(f"workflow may not override the reviewed run shell: {source}")
    top_env = root.get("env")
    if top_env is not None:
        env_values = yaml_mapping(top_env, source, "env")
        actual = {
            key: yaml_scalar(value, source, f"env.{key}") for key, value in env_values.items()
        }
        if not set(actual).issubset(SAFE_WORKFLOW_ENV) or any(
            SAFE_WORKFLOW_ENV[key] != value for key, value in actual.items()
        ):
            raise ContractError(
                f"workflow top-level env differs from the reviewed version allowlist: {source}"
            )

    jobs_node = root.get("jobs")
    if jobs_node is None:
        raise ContractError(f"workflow must define jobs: {source}")
    jobs = yaml_mapping(jobs_node, source, "jobs")
    for job_name, job_node in jobs.items():
        job_path = f"jobs.{job_name}"
        job = yaml_mapping(job_node, source, job_path)
        runner = yaml_scalar(job.get("runs-on"), source, f"{job_path}.runs-on")
        if runner != "ubuntu-24.04":
            raise ContractError(
                f"workflow job {job_name} must run on the exact Linux amd64 runner label "
                f"ubuntu-24.04: {source}"
            )
        for forbidden in ("defaults", "container", "services", "env"):
            if forbidden in job:
                raise ContractError(
                    f"workflow job {job_name} may not define {forbidden}: {source}"
                )
        steps_node = job.get("steps")
        if steps_node is None:
            raise ContractError(f"workflow job {job_name} must define steps: {source}")
        steps = yaml_sequence(steps_node, source, f"{job_path}.steps")
        checkout_indexes: list[int] = []
        for index, step_node in enumerate(steps):
            step_path = f"{job_path}.steps[{index}]"
            step = yaml_mapping(step_node, source, step_path)
            if "shell" in step:
                raise ContractError(
                    f"workflow job {job_name} may not override the reviewed step shell: {source}"
                )
            env_node = step.get("env")
            if env_node is not None:
                env_path = f"{step_path}.env"
                env_values = yaml_mapping(env_node, source, env_path)
                for env_name, env_value in env_values.items():
                    if DANGEROUS_WORKFLOW_ENV.fullmatch(env_name):
                        env_scalar = yaml_scalar(
                            env_value, source, f"{env_path}.{env_name}"
                        )
                        explicitly_cleared = (
                            env_value.tag == "tag:yaml.org,2002:str"
                            and env_scalar == ""
                        )
                        allowed_clean_value = (
                            env_path in CLEAN_EXECUTION_ENV_PATHS
                            and env_name in CLEAN_EXECUTION_ENV_MAP
                            and env_scalar == CLEAN_EXECUTION_ENV_MAP[env_name]
                        )
                        if explicitly_cleared or allowed_clean_value:
                            continue
                        raise ContractError(
                            "workflow defines dangerous execution-context environment "
                            f"{env_name}: {source}"
                        )
            uses_node = step.get("uses")
            if uses_node is None:
                continue
            uses = yaml_scalar(uses_node, source, f"{step_path}.uses")
            if re.fullmatch(r"actions/checkout@[0-9a-f]{40}", uses):
                checkout_indexes.append(index)
        if not checkout_indexes:
            if any(
                contains_repository_node(step, source, f"{job_path}.steps[{index}]")
                for index, step in enumerate(steps)
            ):
                raise ContractError(
                    f"workflow job {job_name} runs repository commands without a guarded checkout: {source}"
                )
            continue
        for checkout_index in checkout_indexes:
            checkout_path = f"{job_path}.steps[{checkout_index}]"
            checkout = yaml_mapping(steps[checkout_index], source, checkout_path)
            with_node = checkout.get("with")
            if with_node is None:
                raise ContractError(f"workflow job {job_name} checkout must define with")
            checkout_with = yaml_mapping(with_node, source, f"{checkout_path}.with")
            persist_credentials = checkout_with.get("persist-credentials")
            if not (
                isinstance(persist_credentials, ScalarNode)
                and persist_credentials.value == "false"
                and persist_credentials.tag == "tag:yaml.org,2002:bool"
            ):
                raise ContractError(
                    f"workflow job {job_name} checkout must disable persisted credentials"
                )
            require_yaml_scalar(
                checkout_with.get("filter"),
                "blob:none",
                source,
                f"{checkout_path}.with.filter",
            )
            require_yaml_scalar(
                checkout_with.get("sparse-checkout-cone-mode"),
                "false",
                source,
                f"{checkout_path}.with.sparse-checkout-cone-mode",
                tag="tag:yaml.org,2002:bool",
            )
            sparse = yaml_scalar(
                checkout_with.get("sparse-checkout"),
                source,
                f"{checkout_path}.with.sparse-checkout",
            )
            patterns = tuple(line.strip() for line in sparse.splitlines() if line.strip())
            if patterns != ROUND6_SPARSE_PATTERNS:
                raise ContractError(
                    f"workflow job {job_name} sparse checkout differs from the Round6 contract"
                )
            if checkout_index + 1 >= len(steps) or not is_safe_gate_node(
                steps[checkout_index + 1],
                source,
                f"{job_path}.steps[{checkout_index + 1}]",
            ):
                raise ContractError(
                    f"workflow job {job_name} must run the exact Round6 safe-gate immediately after checkout"
                )
        first_checkout = min(checkout_indexes)
        if any(
            contains_repository_node(step, source, f"{job_path}.steps[{index}]")
            for index, step in enumerate(steps[:first_checkout])
        ):
            raise ContractError(
                f"workflow job {job_name} runs repository commands before its guarded checkout"
            )


def assert_safe_repo_path(path: Path, root: Path) -> Path:
    root = root.resolve()
    candidate = path if path.is_absolute() else root / path
    try:
        relative = candidate.absolute().relative_to(root)
    except ValueError as exc:
        raise ContractError(f"gate input escapes repository root: {path}") from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ContractError(f"invalid repository-relative gate input: {path}")
    for part in relative.parts:
        lowered = part.lower()
        if any(marker in lowered for marker in RESTRICTED_PATH_MARKERS):
            raise ContractError(f"gate refuses restricted path before reading it: {relative}")
    return root / relative


def read_regular_text(path: Path, root: Path) -> str:
    safe_path = assert_safe_repo_path(path, root)
    try:
        resolved = safe_path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ContractError(f"required gate input is missing: {safe_path}") from exc
    resolved_root = root.resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise ContractError(f"gate input escapes repository root: {safe_path}")
    if safe_path.is_symlink() or not safe_path.is_file():
        raise ContractError(f"gate input must be a regular non-symlink file: {safe_path}")
    return safe_path.read_text(encoding="utf-8")


def logical_make_lines(text: str) -> list[str]:
    logical: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        pending = pending + line.lstrip() if pending else line
        if pending.endswith("\\"):
            pending = pending[:-1] + " "
            continue
        logical.append(pending)
        pending = ""
    if pending:
        logical.append(pending)
    return logical


def logical_shell_commands(text: str) -> tuple[str, ...]:
    commands: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        pending = f"{pending} {line}".strip() if pending else line
        trailing = len(pending) - len(pending.rstrip("\\"))
        if trailing % 2 == 1:
            pending = pending[:-1].rstrip()
            continue
        commands.append(pending)
        pending = ""
    if pending:
        raise ContractError("unterminated shell continuation in final release identity step")
    return tuple(commands)


def shell_tokens(line: str) -> list[str]:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return []
    try:
        lexer = shlex.shlex(stripped, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        lexer.commenters = ""
        return list(lexer)
    except ValueError as exc:
        raise ContractError(f"cannot parse gate command line: {stripped!r}: {exc}") from exc


def extract_make_targets(text: str) -> set[str]:
    targets: set[str] = set()
    for line in text.splitlines():
        if not re.search(r"(?:^|[\s;&|])(?:[^\s]*/)?g?make(?=\s|$)", line):
            continue
        tokens = shell_tokens(line)
        for index, token in enumerate(tokens):
            if Path(token).name not in {"make", "gmake"}:
                continue
            for candidate in tokens[index + 1 :]:
                if candidate in SHELL_OPERATORS:
                    break
                if candidate.startswith(("-C", "--directory", "-f", "--file", "--eval", "-E")):
                    raise ContractError(
                        f"Make directory/file/eval dispatch cannot be audited safely: {candidate!r}"
                    )
                if candidate in {"-s", "--silent", "--no-print-directory"}:
                    continue
                if candidate.startswith("-"):
                    raise ContractError(f"unsupported Make option cannot be audited safely: {candidate!r}")
                if ASSIGNMENT.match(candidate):
                    if candidate.startswith(("MAKEFILES=", "MAKEFLAGS=")):
                        raise ContractError("dynamic Make environment cannot be audited safely")
                    continue
                if "$" in candidate or "`" in candidate:
                    raise ContractError(
                        f"dynamic Make target cannot be audited safely: {candidate!r}"
                    )
                if TARGET_NAME.match(candidate):
                    targets.add(candidate)
                else:
                    raise ContractError(f"invalid Make target cannot be audited safely: {candidate!r}")
    return targets


def extract_script_references(text: str) -> set[str]:
    return {match.group(1) for match in SCRIPT_REFERENCE.finditer(text)}


def extract_static_script_variables(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    assignment = re.compile(
        r"(?m)^\s*(?:local\s+|readonly\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.+)$"
    )
    for match in assignment.finditer(text):
        references = extract_script_references(match.group(2))
        if len(references) == 1:
            result[match.group(1)] = next(iter(references))
    return result


def interpreter_script(tokens: list[str], index: int, kind: str) -> str | None:
    cursor = index + 1
    while cursor < len(tokens):
        token = tokens[cursor]
        if token in SHELL_OPERATORS:
            return None
        if token == "--":
            cursor += 1
            break
        if kind == "python" and token in {"-c", "-m"}:
            raise ContractError(f"dynamic Python dispatch is forbidden: {token}")
        if kind == "python" and token in {"-W", "-X"}:
            cursor += 2
            continue
        if token.startswith("-") and token != "-":
            cursor += 1
            continue
        break
    if cursor >= len(tokens) or tokens[cursor] in SHELL_OPERATORS:
        return None
    candidate = tokens[cursor]
    if candidate == "-" and kind == "python":
        return None
    references = extract_script_references(candidate)
    if "$" in candidate or "`" in candidate:
        if len(references) != 1:
            raise ContractError(
                f"dynamic {kind} script path cannot be audited safely: {candidate!r}"
            )
        return next(iter(references))
    expected_suffix = ".py" if kind == "python" else ".sh"
    if not candidate.endswith(expected_suffix):
        raise ContractError(
            f"{kind} invocation must use a static repository {expected_suffix} script: {candidate!r}"
        )
    return candidate.removeprefix("./")


def command_indexes(tokens: list[str]) -> set[int]:
    indexes: set[int] = set()
    start = 0
    while start < len(tokens):
        end = start
        while end < len(tokens) and tokens[end] not in SHELL_OPERATORS:
            end += 1
        cursor = start
        while cursor < end and (
            ASSIGNMENT.match(tokens[cursor])
            or tokens[cursor] in {"if", "then", "while", "until", "do", "!", "time"}
        ):
            cursor += 1
        if cursor < end and tokens[cursor] in {"env", "sudo"}:
            cursor += 1
            while cursor < end and (
                ASSIGNMENT.match(tokens[cursor]) or tokens[cursor].startswith("-")
            ):
                cursor += 1
        if cursor < end:
            indexes.add(cursor)
        start = end + 1
    return indexes


SHELL_NEUTRAL_STATE = (("normal", 0),)


def shell_state_neutral(state: tuple[tuple[str, int], ...]) -> bool:
    return state == SHELL_NEUTRAL_STATE


def scan_shell_command_fragment(
    text: str, state: tuple[tuple[str, int], ...]
) -> tuple[str, tuple[tuple[str, int], ...]]:
    contexts = [[mode, depth] for mode, depth in state]
    index = 0
    code_end = len(text)
    while index < len(text):
        mode, depth = contexts[-1]
        character = text[index]
        if mode == "single":
            if character == "'":
                contexts[-1][0] = "normal"
            index += 1
            continue
        if mode == "backtick":
            if character == "\\":
                index += 2 if index + 1 < len(text) else 1
                continue
            if character == "`":
                contexts.pop()
                index += 1
                continue
            if character == "$" and text[index + 1 : index + 2] == "(":
                contexts.append(["normal", 1])
                index += 2
                continue
            index += 1
            continue
        if character == "\\":
            index += 2 if index + 1 < len(text) else 1
            continue
        if character == "$" and text[index + 1 : index + 2] == "(":
            contexts.append(["normal", 1])
            index += 2
            continue
        if mode == "double":
            if character == '"':
                contexts[-1][0] = "normal"
            elif character == "`":
                contexts.append(["backtick", -1])
            index += 1
            continue
        if character == "'":
            contexts[-1][0] = "single"
            index += 1
            continue
        if character == '"':
            contexts[-1][0] = "double"
            index += 1
            continue
        if character == "`":
            contexts.append(["backtick", -1])
            index += 1
            continue
        if (
            character == "#"
            and (index == 0 or text[index - 1].isspace() or text[index - 1] in ";|&(")
        ):
            code_end = index
            break
        if character in "<>" and text[index + 1 : index + 2] == "(":
            contexts.append(["normal", 1])
            index += 2
            continue
        if depth > 0 and character == "(":
            contexts[-1][1] += 1
        elif depth > 0 and character == ")":
            contexts[-1][1] -= 1
            if contexts[-1][1] == 0:
                contexts.pop()
        index += 1
    return text[:code_end].rstrip(), tuple((mode, depth) for mode, depth in contexts)


def shell_line_continuation(
    text: str, state: tuple[tuple[str, int], ...]
) -> tuple[str, tuple[tuple[str, int], ...], bool]:
    code, next_state = scan_shell_command_fragment(text, state)
    trailing = len(code) - len(code.rstrip("\\"))
    in_single = next_state[-1][0] == "single"
    return code, next_state, trailing % 2 == 1 and not in_single


def scan_shell_array_fragment(
    text: str, source: Path, state: tuple[bool, bool]
) -> tuple[bool, bool]:
    in_single, in_double = state
    index = 0
    while index < len(text):
        character = text[index]
        if in_single:
            if character == "'":
                in_single = False
            index += 1
            continue
        if character == "\\":
            index += 2 if index + 1 < len(text) else 1
            continue
        if character == "'" and not in_double:
            in_single = True
            index += 1
            continue
        if character == '"':
            in_double = not in_double
            index += 1
            continue
        if (
            character == "#"
            and not in_double
            and (index == 0 or text[index - 1].isspace() or text[index - 1] in ";|&(")
        ):
            break
        if character == "`" or (
            character == "$"
            and text[index + 1 : index + 2] == "("
            and text[index + 1 : index + 3] != "(("
        ) or (
            not in_double
            and character in "<>"
            and text[index + 1 : index + 2] == "("
        ):
            raise ContractError(
                f"shell array contains executable substitution that cannot be audited safely: {source}"
            )
        index += 1
    return in_single, in_double


def auditable_shell_commands(text: str, source: Path) -> tuple[str, ...]:
    commands: list[str] = []
    pending = ""
    heredocs: list[tuple[str, bool]] = []
    in_array = False
    array_state = (False, False)
    command_state = SHELL_NEUTRAL_STATE
    array_start = re.compile(
        r"^(?:(?:local|readonly|declare)(?:\s+-[aA])?\s+)?"
        r"[A-Za-z_][A-Za-z0-9_]*\+?=\("
    )
    for raw in text.splitlines():
        if heredocs:
            delimiter, strip_tabs = heredocs[0]
            candidate = raw.lstrip("\t") if strip_tabs else raw
            if candidate == delimiter:
                heredocs.pop(0)
                if not heredocs and shell_state_neutral(command_state) and pending:
                    commands.append(pending)
                    pending = ""
            continue

        line = raw.strip()
        if not line or (line.startswith("#") and shell_state_neutral(command_state)):
            continue
        if in_array:
            array_state = scan_shell_array_fragment(line, source, array_state)
            if array_state == (False, False) and re.fullmatch(
                r"\)\s*;?(?:\s+#.*)?", line
            ):
                in_array = False
            continue
        if shell_state_neutral(command_state) and not pending and array_start.match(line):
            array_state = scan_shell_array_fragment(line, source, (False, False))
            if array_state != (False, False) or not re.search(
                r"\)\s*;?(?:\s+#.*)?$", line
            ):
                in_array = True
            continue

        line, command_state, continued = shell_line_continuation(line, command_state)
        if not line:
            continue
        if continued:
            line = line[:-1].rstrip()
        pending = f"{pending} {line}".strip() if pending else line
        for match in HEREDOC.finditer(line):
            delimiter = match.group("delimiter")
            if delimiter[:1] in {"'", '"'}:
                delimiter = delimiter[1:-1]
            heredocs.append((delimiter, match.group("strip_tabs") == "-"))
        if continued or heredocs or not shell_state_neutral(command_state):
            continue
        commands.append(pending)
        pending = ""

    if pending or heredocs or in_array or not shell_state_neutral(command_state):
        raise ContractError(f"unterminated shell construct cannot be audited safely: {source}")
    return tuple(commands)


def reject_dynamic_dispatch(text: str, source: Path) -> set[str]:
    if re.search(r"(?m)(?:^|[;&|])\s*(?:env\s+[^\n;&|]*\s+)?(?:bash|sh)\s+[^\n;&|]*-c(?:\s|$)", text):
        raise ContractError(f"dynamic shell dispatch cannot be audited safely: {source}")
    if re.search(r"(?m)(?:^|[;&|])\s*(?:env\s+[^\n;&|]*\s+)?python(?:3(?:\.\d+)?)?\s+[^\n;&|]*(?:-c|-m)(?:\s|$)", text):
        raise ContractError(f"dynamic Python dispatch cannot be audited safely: {source}")
    if re.search(r"(?m)(?:^|[;&|])\s*eval(?:\s|$)|\$\((?:MAKE|\{?MAKE\}?)\)", text):
        raise ContractError(f"dynamic shell/Make dispatch cannot be audited safely: {source}")
    if re.search(r"(?m)\bMAKEFILES\s*=|\bMAKEFLAGS\s*=|\bxargs\b|\bfind\b[^\n]*-exec\b", text):
        raise ContractError(f"dynamic command fan-out cannot be audited safely: {source}")

    scripts = set(extract_script_references(text))
    static_variables = extract_static_script_variables(text)
    variable_command = re.compile(
        r"^\s*(?:(?:if|while|until|then)\s+|!\s+)?[\"']?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?"
    )
    for line in auditable_shell_commands(text, source):
        match = variable_command.search(line)
        if match and not extract_script_references(line):
            variable = match.group(1)
            if variable in static_variables:
                scripts.add(static_variables[variable])
            elif variable not in SAFE_DYNAMIC_TOOL_VARIABLES:
                raise ContractError(
                    f"dynamic command variable cannot be audited safely in {source}: ${variable}"
                )

        if not re.search(
            r"(?:^|\s)(?:python(?:3(?:\.\d+)?)?|bash|sh|source|\.)(?:\s|$)",
            line,
        ) and not re.search(r"(?:^|[\s;&|])\.\.?/", line):
            continue
        tokens = shell_tokens(line)
        for index in command_indexes(tokens):
            token = tokens[index]
            name = Path(token).name
            if token.startswith(("./", "../")):
                references = extract_script_references(token)
                normalized = token.removeprefix("./")
                if len(references) != 1 or normalized not in references:
                    raise ContractError(
                        f"direct repository executable cannot be audited safely in {source}: {token!r}"
                    )
                scripts.update(references)
            if re.fullmatch(r"python(?:3(?:\.\d+)?)?", name):
                script = interpreter_script(tokens, index, "python")
                if script:
                    scripts.add(script)
            elif name in {"bash", "sh"}:
                script = interpreter_script(tokens, index, "shell")
                if script:
                    scripts.add(script)
            elif token in {"source", "."}:
                script = interpreter_script(tokens, index, "shell")
                if script:
                    scripts.add(script)
    return scripts


def reject_go_all_packages(text: str, source: Path) -> None:
    for line in text.splitlines():
        if "./..." not in line:
            continue
        tokens = shell_tokens(line)
        for index, token in enumerate(tokens):
            normalized = token.strip('"\'')
            is_go = (
                Path(normalized).name == "go"
                or normalized in {"$(GO)", "$GO", "${GO}", "$go_bin", "${go_bin}"}
            )
            if not is_go:
                continue
            for candidate in tokens[index + 1 :]:
                if candidate in SHELL_OPERATORS:
                    break
                if candidate == "./...":
                    raise ContractError(f"reachable go ... ./... is forbidden: {source}")


def audit_command_text(text: str, source: Path) -> tuple[set[str], set[str]]:
    scripts = reject_dynamic_dispatch(text, source)
    reject_go_all_packages(text, source)
    return extract_make_targets(text), scripts | extract_script_references(text)


def mapping_block(text: str, key: str, indent: int) -> str:
    lines = text.splitlines()
    prefix = " " * indent
    start = None
    for index, line in enumerate(lines):
        if line == f"{prefix}{key}:" or line.startswith(f"{prefix}{key}: "):
            start = index
            break
    if start is None:
        raise ContractError(f"required YAML key is missing: {key}")
    collected = [lines[start]]
    for line in lines[start + 1 :]:
        if not line.strip():
            collected.append(line)
            continue
        current_indent = len(line) - len(line.lstrip(" "))
        if current_indent <= indent:
            break
        collected.append(line)
    return "\n".join(collected)


def yaml_run_blocks(text: str) -> list[str]:
    lines = text.splitlines()
    blocks: list[str] = []
    index = 0
    while index < len(lines):
        match = re.match(r"^(\s*)(-\s+)?run:\s*(.*)$", lines[index])
        if not match:
            index += 1
            continue
        indent = len(match.group(1)) + (len(match.group(2)) if match.group(2) else 0)
        value = match.group(3).strip()
        if value and not value.startswith(("|", ">")):
            blocks.append(value)
            index += 1
            continue
        collected: list[str] = []
        index += 1
        while index < len(lines):
            line = lines[index]
            if line.strip():
                current_indent = len(line) - len(line.lstrip(" "))
                if current_indent <= indent:
                    break
                collected.append(line[indent + 2 :])
            else:
                collected.append("")
            index += 1
        blocks.append("\n".join(collected))
    return blocks


def job_blocks(text: str) -> dict[str, str]:
    jobs = mapping_block(text, "jobs", 0)
    lines = jobs.splitlines()
    starts: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        match = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if match:
            starts.append((index, match.group(1)))
    result: dict[str, str] = {}
    for position, (start, name) in enumerate(starts):
        end = starts[position + 1][0] if position + 1 < len(starts) else len(lines)
        result[name] = "\n".join(lines[start:end])
    if not result:
        raise ContractError("workflow must define at least one job")
    return result


def step_blocks(job: str) -> list[str]:
    lines = job.splitlines()
    starts = [index for index, line in enumerate(lines) if re.match(r"^      -\s+", line)]
    result: list[str] = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        result.append("\n".join(lines[start:end]))
    return result


def sparse_patterns_from_checkout(step: str) -> tuple[str, ...]:
    match = re.search(r"(?m)^(\s*)sparse-checkout:\s*\|\s*$", step)
    if not match:
        raise ContractError("Round6 checkout must define sparse-checkout as a literal block")
    lines = step.splitlines()
    start = step[: match.start()].count("\n")
    indent = len(match.group(1))
    patterns: list[str] = []
    for line in lines[start + 1 :]:
        if not line.strip():
            continue
        current_indent = len(line) - len(line.lstrip(" "))
        if current_indent <= indent:
            break
        patterns.append(line.strip())
    return tuple(patterns)


def is_safe_gate_step(step: str) -> bool:
    if re.search(r"(?m)^\s+continue-on-error:\s*true\s*$", step):
        return False
    if re.search(r"(?m)^\s+if:\s*", step):
        return False
    runs = yaml_run_blocks(step)
    if len(runs) != 1:
        return False
    commands = tuple(line.strip() for line in runs[0].splitlines() if line.strip())
    return commands == SAFE_GATE_COMMANDS


def contains_repository_command(step: str) -> bool:
    if re.search(r"(?m)^\s+(?:-\s+)?uses:\s*\./", step):
        return True
    for command in yaml_run_blocks(step):
        if re.search(
            r"(?:^|[\s;&|])(?:g?make|git|go)(?=\s|$)|(?:^|[\s;&|])(?:\./)?scripts/",
            command,
        ):
            return True
    return False


def reject_workflow_yaml_indirection(text: str, source: Path) -> None:
    block_scalar_indent: int | None = None
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if block_scalar_indent is not None:
            if indent > block_scalar_indent:
                continue
            block_scalar_indent = None
        stripped = raw_line.lstrip(" ")
        if stripped.startswith(("%", "---", "...", "? ")):
            raise ContractError(f"workflow uses unsupported YAML directives/keys: {source}")
        if stripped.startswith(("&", "*", "!")):
            raise ContractError(
                f"workflow may not use YAML anchors, aliases, merges, or tags: {source}"
            )
        if re.match(r'^(?:"[^"]*"|\'[^\']*\')\s*:', stripped):
            raise ContractError(f"workflow mapping keys may not be quoted: {source}")
        if re.match(r"^<<\s*:", stripped) or re.search(
            r"(?::\s*|-\s+)(?:[&*][A-Za-z_][A-Za-z0-9_-]*|!![^\s#]+)",
            stripped,
        ):
            raise ContractError(f"workflow may not use YAML anchors, aliases, merges, or tags: {source}")
        if re.search(r":\s*[\[{]", stripped):
            raise ContractError(f"workflow may not use flow-style YAML mappings/sequences: {source}")
        if re.match(r"^[A-Za-z0-9_-]+\s*:\s*[|>][+-]?\s*(?:#.*)?$", stripped):
            block_scalar_indent = indent


def validate_workflow_environment(text: str, source: Path) -> None:
    top_env_count = len(re.findall(r"(?m)^env:\s*(?:$|#)", text))
    if top_env_count > 1:
        raise ContractError(f"workflow may define top-level env at most once: {source}")
    if top_env_count == 1:
        env_block = mapping_block(text, "env", 0)
        env_lines = {
            line.strip() for line in env_block.splitlines()[1:] if line.strip()
        }
        if not env_lines.issubset(SAFE_WORKFLOW_ENV_LINES):
            raise ContractError(f"workflow top-level env differs from the reviewed version allowlist: {source}")
    if re.search(r"(?m)^    env:\s*(?:$|#)", text):
        raise ContractError(f"workflow jobs may not inherit custom job-level env: {source}")


def validate_workflow_safety(text: str, source: Path) -> tuple[tuple[str, ...], ...]:
    document = parse_workflow_yaml(text, source)
    validate_workflow_semantic_safety(document, source)
    reject_workflow_yaml_indirection(text, source)
    validate_workflow_environment(text, source)
    if re.search(r"(?m)^defaults:\s*(?:$|#)", text):
        raise ContractError(f"workflow may not override the reviewed run shell: {source}")
    sparse_sets: list[tuple[str, ...]] = []
    for job_name, job in job_blocks(text).items():
        runners = re.findall(r"(?m)^    runs-on:\s*([^\s#]+)\s*(?:#.*)?$", job)
        if runners != ["ubuntu-24.04"]:
            raise ContractError(
                f"workflow job {job_name} must run on the exact Linux amd64 runner label ubuntu-24.04: {source}"
            )
        for key in ("defaults", "container", "services"):
            if re.search(rf"(?m)^    {key}:\s*", job):
                raise ContractError(
                    f"workflow job {job_name} may not define {key}: {source}"
                )
        steps = step_blocks(job)
        if any(re.search(r"(?m)^        shell:\s*", step) for step in steps):
            raise ContractError(
                f"workflow job {job_name} may not override the reviewed step shell: {source}"
            )
        checkout_indexes = [
            index
            for index, step in enumerate(steps)
            if re.search(
                r"(?m)^\s+(?:-\s+)?uses:\s*actions/checkout@[0-9a-f]{40}(?:\s+#.*)?$",
                step,
            )
        ]
        if not checkout_indexes:
            if any(contains_repository_command(step) for step in steps):
                raise ContractError(
                    f"workflow job {job_name} runs repository commands without a guarded checkout: {source}"
                )
            continue
        for checkout_index in checkout_indexes:
            checkout = steps[checkout_index]
            if not re.search(r"(?m)^\s+persist-credentials:\s*false\s*$", checkout):
                raise ContractError(
                    f"workflow job {job_name} checkout must disable persisted credentials"
                )
            if not re.search(r"(?m)^\s+filter:\s*blob:none\s*$", checkout):
                raise ContractError(f"workflow job {job_name} checkout must use filter: blob:none")
            if not re.search(r"(?m)^\s+sparse-checkout-cone-mode:\s*false\s*$", checkout):
                raise ContractError(
                    f"workflow job {job_name} checkout must use sparse-checkout-cone-mode: false"
                )
            patterns = sparse_patterns_from_checkout(checkout)
            if patterns != ROUND6_SPARSE_PATTERNS:
                raise ContractError(
                    f"workflow job {job_name} sparse checkout differs from the Round6 contract"
                )
            sparse_sets.append(patterns)
            if checkout_index + 1 >= len(steps) or not is_safe_gate_step(steps[checkout_index + 1]):
                raise ContractError(
                    f"workflow job {job_name} must run the exact Round6 safe-gate immediately after checkout"
                )
        first_checkout = min(checkout_indexes)
        if any(contains_repository_command(step) for step in steps[:first_checkout]):
            raise ContractError(
                f"workflow job {job_name} runs repository commands before its guarded checkout"
            )
    return tuple(sparse_sets)


def exact_string_mapping(
    node: Node, source: Path, path: str
) -> tuple[tuple[str, str], ...]:
    if not isinstance(node, MappingNode):
        raise ContractError(f"workflow {path} must be a mapping")
    values: list[tuple[str, str]] = []
    for key_node, value_node in node.value:
        if value_node.tag != "tag:yaml.org,2002:str":
            raise ContractError(f"workflow {path}.{key_node.value} must be an exact string")
        values.append(
            (
                key_node.value,
                yaml_scalar(value_node, source, f"{path}.{key_node.value}"),
            )
        )
    return tuple(values)


def validate_candidate_workflow(text: str, source: Path) -> None:
    validate_workflow_safety(text, source)
    document = parse_workflow_yaml(text, source)
    validate_sensitive_workflow_expressions(
        document,
        source,
        allowed_token_paths=CANDIDATE_ALLOWED_GITHUB_TOKEN_PATHS,
        allowed_identity_expressions=CANDIDATE_ALLOWED_GITHUB_IDENTITY_EXPRESSIONS,
    )
    root = require_yaml_keys(document, CANDIDATE_TOP_LEVEL_KEYS, source, "workflow")
    require_yaml_scalar(root["name"], CANDIDATE_WORKFLOW_NAME, source, "name")

    if yaml_mapping_keys(root["on"], source, "on") != ("workflow_dispatch",):
        raise ContractError("Round6 candidate must remain manual-only workflow_dispatch")
    on = yaml_mapping(root["on"], source, "on")
    dispatch = require_yaml_keys(
        on["workflow_dispatch"], ("inputs",), source, "on.workflow_dispatch"
    )
    inputs = require_yaml_keys(
        dispatch["inputs"],
        CANDIDATE_INPUT_ORDER,
        source,
        "on.workflow_dispatch.inputs",
    )
    for input_name, input_node in inputs.items():
        path = f"on.workflow_dispatch.inputs.{input_name}"
        expected_keys = (
            ("description", "required", "type", "default")
            if input_name == "authorize_clean_candidate"
            else ("description", "required", "type")
        )
        values = require_yaml_keys(input_node, expected_keys, source, path)
        if not yaml_scalar(values["description"], source, f"{path}.description").strip():
            raise ContractError(f"workflow {path}.description may not be empty")
        require_yaml_scalar(
            values["required"],
            "true",
            source,
            f"{path}.required",
            tag="tag:yaml.org,2002:bool",
        )
        if input_name == "authorize_clean_candidate":
            require_yaml_scalar(values["type"], "boolean", source, f"{path}.type")
            require_yaml_scalar(
                values["default"],
                "false",
                source,
                f"{path}.default",
                tag="tag:yaml.org,2002:bool",
            )
        else:
            require_yaml_scalar(values["type"], "string", source, f"{path}.type")

    permissions = require_yaml_keys(
        root["permissions"], ("actions", "contents"), source, "permissions"
    )
    require_yaml_scalar(permissions["actions"], "read", source, "permissions.actions")
    require_yaml_scalar(permissions["contents"], "read", source, "permissions.contents")
    concurrency = require_yaml_keys(
        root["concurrency"], ("group", "cancel-in-progress"), source, "concurrency"
    )
    require_yaml_scalar(
        concurrency["group"],
        "round6-clean-candidate-${{ inputs.expected_commit }}",
        source,
        "concurrency.group",
    )
    require_yaml_scalar(
        concurrency["cancel-in-progress"],
        "false",
        source,
        "concurrency.cancel-in-progress",
        tag="tag:yaml.org,2002:bool",
    )
    env = require_yaml_keys(
        root["env"],
        ("GO_VERSION", "VERSION", "CYCLONEDX_GOMOD_VERSION", "GOVULNCHECK_VERSION"),
        source,
        "env",
    )
    for env_name in (
        "GO_VERSION",
        "VERSION",
        "CYCLONEDX_GOMOD_VERSION",
        "GOVULNCHECK_VERSION",
    ):
        require_yaml_scalar(
            env[env_name], SAFE_WORKFLOW_ENV[env_name], source, f"env.{env_name}"
        )

    jobs = require_yaml_keys(root["jobs"], ("admission", "build"), source, "jobs")
    steps_by_job: dict[str, list[Node]] = {}
    for job_name in ("admission", "build"):
        job_path = f"jobs.{job_name}"
        job = require_yaml_keys(
            jobs[job_name], CANDIDATE_JOB_KEYS[job_name], source, job_path
        )
        require_yaml_scalar(job["runs-on"], "ubuntu-24.04", source, f"{job_path}.runs-on")
        require_yaml_scalar(
            job["timeout-minutes"],
            "5" if job_name == "admission" else "45",
            source,
            f"{job_path}.timeout-minutes",
            tag="tag:yaml.org,2002:int",
        )
        if job_name == "build":
            require_yaml_scalar(job["needs"], "admission", source, f"{job_path}.needs")
            job_permissions = require_yaml_keys(
                job["permissions"], ("contents",), source, f"{job_path}.permissions"
            )
            require_yaml_scalar(
                job_permissions["contents"],
                "read",
                source,
                f"{job_path}.permissions.contents",
            )

        steps = yaml_sequence(job["steps"], source, f"{job_path}.steps")
        contracts = CANDIDATE_STEP_CONTRACTS[job_name]
        if len(steps) != len(contracts):
            raise ContractError(
                f"Round6 candidate {job_name} job must contain exactly "
                f"{len(contracts)} reviewed steps"
            )
        for index, (step_node, contract) in enumerate(zip(steps, contracts)):
            expected_name, expected_keys, expected_action = contract
            step_path = f"{job_path}.steps[{index}]"
            step = require_yaml_keys(step_node, expected_keys, source, step_path)
            require_yaml_scalar(step["name"], expected_name, source, f"{step_path}.name")
            if expected_action is not None:
                require_yaml_scalar(step["uses"], expected_action, source, f"{step_path}.uses")
            contract_key = (job_name, index)
            if "run" in step:
                run_node = step["run"]
                run_text = yaml_scalar(run_node, source, f"{step_path}.run")
                expected_hash = CANDIDATE_STEP_RUN_SHA256.get(contract_key)
                if (
                    expected_hash is None
                    or run_node.tag != "tag:yaml.org,2002:str"
                    or run_node.style != CANDIDATE_STEP_RUN_STYLE[contract_key]
                    or hashlib.sha256(run_text.encode("utf-8")).hexdigest()
                    != expected_hash
                ):
                    raise ContractError(
                        f"Round6 candidate {step_path} run must match the exact reviewed text"
                    )
                for command in mutation_shell_commands(run_text):
                    for segment in shell_command_segments(command):
                        reason = mutating_command_reason(segment)
                        if reason is not None:
                            raise ContractError(
                                f"Round6 candidate forbids {reason}: {step_path}"
                            )
            elif contract_key in CANDIDATE_STEP_RUN_SHA256:
                raise ContractError(f"Round6 candidate {step_path} is missing reviewed run")
            if "env" in step:
                actual_env = exact_string_mapping(step["env"], source, f"{step_path}.env")
                if actual_env != CANDIDATE_STEP_ENV.get(contract_key):
                    raise ContractError(
                        f"Round6 candidate {step_path}.env must match the exact reviewed mapping"
                    )
            elif contract_key in CANDIDATE_STEP_ENV:
                raise ContractError(f"Round6 candidate {step_path} is missing reviewed env")
            if "with" in step:
                yaml_mapping(step["with"], source, f"{step_path}.with")
        steps_by_job[job_name] = steps

    checkout = yaml_mapping(steps_by_job["build"][0], source, "jobs.build.steps[0]")
    checkout_with = require_yaml_keys(
        checkout["with"],
        (
            "ref",
            "fetch-depth",
            "persist-credentials",
            "filter",
            "sparse-checkout-cone-mode",
            "sparse-checkout",
        ),
        source,
        "jobs.build.steps[0].with",
    )
    require_yaml_scalar(
        checkout_with["ref"],
        "${{ inputs.expected_commit }}",
        source,
        "jobs.build.steps[0].with.ref",
    )
    require_yaml_scalar(
        checkout_with["fetch-depth"],
        "0",
        source,
        "jobs.build.steps[0].with.fetch-depth",
        tag="tag:yaml.org,2002:int",
    )
    require_yaml_scalar(
        checkout_with["persist-credentials"],
        "false",
        source,
        "jobs.build.steps[0].with.persist-credentials",
        tag="tag:yaml.org,2002:bool",
    )
    require_yaml_scalar(
        checkout_with["filter"], "blob:none", source, "jobs.build.steps[0].with.filter"
    )
    require_yaml_scalar(
        checkout_with["sparse-checkout-cone-mode"],
        "false",
        source,
        "jobs.build.steps[0].with.sparse-checkout-cone-mode",
        tag="tag:yaml.org,2002:bool",
    )
    sparse = yaml_scalar(
        checkout_with["sparse-checkout"], source, "jobs.build.steps[0].with.sparse-checkout"
    )
    if tuple(line.strip() for line in sparse.splitlines() if line.strip()) != ROUND6_SPARSE_PATTERNS:
        raise ContractError("Round6 candidate checkout sparse boundary changed")

    setup_go = yaml_mapping(steps_by_job["build"][3], source, "jobs.build.steps[3]")
    setup_go_with = require_yaml_keys(
        setup_go["with"], ("go-version", "cache"), source, "jobs.build.steps[3].with"
    )
    require_yaml_scalar(
        setup_go_with["go-version"],
        "${{ env.GO_VERSION }}",
        source,
        "jobs.build.steps[3].with.go-version",
    )
    require_yaml_scalar(
        setup_go_with["cache"],
        "true",
        source,
        "jobs.build.steps[3].with.cache",
        tag="tag:yaml.org,2002:bool",
    )

    upload = yaml_mapping(steps_by_job["build"][9], source, "jobs.build.steps[9]")
    upload_with = require_yaml_keys(
        upload["with"],
        ("name", "path", "if-no-files-found", "retention-days"),
        source,
        "jobs.build.steps[9].with",
    )
    require_yaml_scalar(
        upload_with["name"],
        "round6-v0.15-candidate-${{ inputs.expected_commit }}",
        source,
        "jobs.build.steps[9].with.name",
    )
    upload_paths = yaml_scalar(upload_with["path"], source, "jobs.build.steps[9].with.path")
    if tuple(line.strip() for line in upload_paths.splitlines() if line.strip()) != CANDIDATE_ARTIFACTS:
        raise ContractError("Round6 candidate private artifact allowlist changed")
    require_yaml_scalar(
        upload_with["if-no-files-found"],
        "error",
        source,
        "jobs.build.steps[9].with.if-no-files-found",
    )
    require_yaml_scalar(
        upload_with["retention-days"],
        "30",
        source,
        "jobs.build.steps[9].with.retention-days",
        tag="tag:yaml.org,2002:int",
    )

    if re.search(r"(?m)^\s*contents\s*:\s*write\s*$", text):
        raise ContractError("Round6 candidate workflow must remain contents: read only")
    if re.search(
        r"(?i)(?:softprops/action-gh-release|\bgh\s+release\b|\bgit\s+(?:tag|push|update-ref)\b)",
        text,
    ):
        raise ContractError("Round6 candidate workflow may not create tags or releases")


def validate_candidate_script(text: str, source: Path) -> None:
    expected_hash = CANDIDATE_SCRIPT_SHA256.get(source.name)
    if expected_hash is None:
        raise ContractError(f"unreviewed Round6 candidate script: {source}")
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != expected_hash:
        raise ContractError(
            f"Round6 candidate script must match the exact reviewed safety contract: {source}"
        )


def validate_reproducibility_wrapper_script(text: str, source: Path) -> None:
    if (
        hashlib.sha256(text.encode("utf-8")).hexdigest()
        != REPRODUCIBILITY_WRAPPER_SCRIPT_SHA256
    ):
        raise ContractError(
            f"legacy reproducibility wrapper must match the exact reviewed safety contract: {source}"
        )


def validate_frozen_evaluation_tree_script(text: str, source: Path) -> None:
    if text.count(FROZEN_EVALUATION_STATUS_COMMAND) != 1:
        raise ContractError(
            "frozen evaluation tree verifier must reject staged, unstaged, and untracked paths: "
            f"{source}"
        )
    if (
        hashlib.sha256(text.encode("utf-8")).hexdigest()
        != FROZEN_EVALUATION_TREE_SCRIPT_SHA256
    ):
        raise ContractError(
            f"frozen evaluation tree verifier must match the exact reviewed metadata-only contract: {source}"
        )


def validate_round6_doc_fixture_wrapper_script(
    text: str, source: Path, root: Path
) -> None:
    if (
        hashlib.sha256(text.encode("utf-8")).hexdigest()
        != ROUND6_DOC_FIXTURE_WRAPPER_SCRIPT_SHA256
    ):
        raise ContractError(
            f"Round6 document fixture wrapper must match the exact reviewed contract: {source}"
        )
    for relative, expected in ROUND6_DOC_FIXTURE_DEPENDENCY_SHA256.items():
        dependency = root / relative
        dependency_text = read_regular_text(dependency, root)
        if hashlib.sha256(dependency_text.encode("utf-8")).hexdigest() != expected:
            raise ContractError(
                f"Round6 document fixture dependency changed outside the reviewed contract: {dependency}"
            )


def validate_round6_privacy_fixture_script(text: str, source: Path) -> None:
    if (
        hashlib.sha256(text.encode("utf-8")).hexdigest()
        != ROUND6_PRIVACY_FIXTURE_SCRIPT_SHA256
    ):
        raise ContractError(
            f"Round6 privacy fixture must match the exact reviewed contract: {source}"
        )


def validate_cpa_compat_script(text: str, source: Path) -> None:
    if text.count(CPA_COMPAT_FINAL_OUTPUT_CONTRACT) != 1 or text.count(
        "CPA latest source/compile compatibility PASS"
    ) != 1:
        raise ContractError(
            f"CPA compatibility output must claim latest PASS only after remote verification: {source}"
        )
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != CPA_COMPAT_SCRIPT_SHA256:
        raise ContractError(
            f"CPA compatibility script must match the exact reviewed remote-verification contract: {source}"
        )


def shell_function_body(text: str, name: str, source: Path) -> str:
    match = re.search(rf"(?ms)^{re.escape(name)}\(\) \{{\n(.*?)^\}}(?:\n|\Z)", text)
    if not match:
        raise ContractError(f"release helper lacks reviewed function {name}: {source}")
    return match.group(1)


def validate_release_mode_contracts(root: Path) -> None:
    common_path = root / "scripts/release-common.sh"
    if not common_path.exists():
        return
    common = read_regular_text(common_path, root)
    for script_name, expected_hash in EXTERNAL_ATTESTATION_SCRIPT_SHA256.items():
        path = root / "scripts" / script_name
        text = read_regular_text(path, root)
        if hashlib.sha256(text.encode("utf-8")).hexdigest() != expected_hash:
            raise ContractError(
                f"external release attestation script differs from reviewed contract: {script_name}"
            )
    formal_body = shell_function_body(
        common, "release_assert_formal_build", common_path
    )
    if (
        '[[ "$RELEASE_BUILD_KIND" == formal ]]' not in formal_body
        or '[[ "$RELEASE_DIRTY" == false ]]' not in formal_body
    ):
        raise ContractError(
            "release_assert_formal_build must reject candidate and dirty build modes"
        )
    candidate_body = shell_function_body(
        common, "release_assert_candidate_build", common_path
    )
    for required in (
        '[[ "$RELEASE_BUILD_KIND" == candidate ]]',
        '[[ "$RELEASE_DIRTY" == false ]]',
        'if git -C "$RELEASE_ROOT" show-ref --verify --quiet "refs/tags/$formal_tag"; then',
        'release_die "candidate builds are forbidden after any formal tag ref $formal_tag exists"',
    ):
        if required not in candidate_body:
            raise ContractError(
                "release_assert_candidate_build must stay clean, exact-mode, and pre-formal-tag only"
            )

    rc_body = shell_function_body(common, "release_assert_rc_build", common_path)
    for required in (
        '[[ "$RELEASE_BUILD_KIND" == rc ]]',
        '[[ "$RELEASE_DIRTY" == false ]]',
        '[[ "$RELEASE_RC_TAG" == "v$RELEASE_ARTIFACT_VERSION" ]]',
        'if git -C "$RELEASE_ROOT" show-ref --verify --quiet "refs/tags/$formal_tag"; then',
        'release_die "RC builds are forbidden after the formal tag $formal_tag exists"',
    ):
        if required not in rc_body:
            raise ContractError(
                "release_assert_rc_build must stay clean, exact-tagged, and pre-formal-tag only"
            )

    rc_script_path = root / "scripts/round6-rc-artifacts.sh"
    if rc_script_path.exists():
        rc_script = read_regular_text(rc_script_path, root)
        if hashlib.sha256(rc_script.encode("utf-8")).hexdigest() != RC_RELEASE_SCRIPT_SHA256:
            raise ContractError("RC release artifact script differs from reviewed contract")

    for script_name in FORMAL_OPERATION_SCRIPTS:
        path = root / "scripts" / script_name
        text = read_regular_text(path, root)
        commands = tuple(
            command.strip()
            for command in logical_shell_commands(text)
            if command.strip() and not command.lstrip().startswith("#")
        )
        required = ("release_init", "release_assert_tag", "release_assert_formal_build")
        positions: list[int] = []
        for command in required:
            matches = [index for index, actual in enumerate(commands) if actual == command]
            if len(matches) != 1:
                raise ContractError(
                    f"formal operation {script_name} must invoke {command} exactly once"
                )
            positions.append(matches[0])
        if positions != sorted(positions):
            raise ContractError(
                f"formal operation {script_name} must assert tag then formal build before work"
            )
        if any(
            "RELEASE_CANDIDATE_BUILD" in command or "RELEASE_RC_" in command
            for command in commands
        ):
            raise ContractError(
                f"formal operation {script_name} may not enable candidate or RC build mode"
            )

    evidence_path = root / "scripts/generate-release-evidence.sh"
    evidence_text = read_regular_text(evidence_path, root)
    if hashlib.sha256(evidence_text.encode("utf-8")).hexdigest() != GENERATE_RELEASE_EVIDENCE_SCRIPT_SHA256:
        raise ContractError(
            "release evidence generator must match the immutable attestation snapshot contract"
        )


def validate_run_hash(
    step: dict[str, Node],
    expected_hash: str,
    source: Path,
    path: str,
) -> None:
    run = yaml_scalar(step.get("run"), source, f"{path}.run")
    if hashlib.sha256(run.encode("utf-8")).hexdigest() != expected_hash:
        raise ContractError(f"workflow {path}.run must match the exact reviewed text")


def validate_formal_release_workflow(text: str, source: Path) -> None:
    document = parse_workflow_yaml(text, source)
    root = require_yaml_keys(
        document,
        ("name", "on", "permissions", "concurrency", "env", "jobs"),
        source,
        "workflow",
    )
    require_yaml_scalar(root["name"], "Release", source, "name")
    on = require_yaml_keys(root["on"], ("push",), source, "on")
    push = require_yaml_keys(on["push"], ("tags",), source, "on.push")
    tags = yaml_sequence(push["tags"], source, "on.push.tags")
    if len(tags) != 1:
        raise ContractError("formal release workflow must trigger only for exact tag v0.15")
    require_yaml_scalar(tags[0], "v0.15", source, "on.push.tags[0]")
    permissions = require_yaml_keys(
        root["permissions"], ("contents",), source, "permissions"
    )
    require_yaml_scalar(permissions["contents"], "read", source, "permissions.contents")
    concurrency = require_yaml_keys(
        root["concurrency"], ("group", "cancel-in-progress"), source, "concurrency"
    )
    require_yaml_scalar(
        concurrency["group"],
        "${{ github.workflow }}-${{ github.ref }}",
        source,
        "concurrency.group",
    )
    require_yaml_scalar(
        concurrency["cancel-in-progress"],
        "false",
        source,
        "concurrency.cancel-in-progress",
        tag="tag:yaml.org,2002:bool",
    )
    env = require_yaml_keys(
        root["env"],
        ("GO_VERSION", "VERSION", "CYCLONEDX_GOMOD_VERSION", "GOVULNCHECK_VERSION"),
        source,
        "env",
    )
    for env_name in ("GO_VERSION", "VERSION", "CYCLONEDX_GOMOD_VERSION", "GOVULNCHECK_VERSION"):
        require_yaml_scalar(env[env_name], SAFE_WORKFLOW_ENV[env_name], source, f"env.{env_name}")

    jobs = require_yaml_keys(
        root["jobs"], ("admission", "build-and-verify", "publish"), source, "jobs"
    )
    admission_path = "jobs.admission"
    admission = require_yaml_keys(
        jobs["admission"],
        ("permissions", "runs-on", "timeout-minutes", "steps"),
        source,
        admission_path,
    )
    admission_permissions = require_yaml_keys(
        admission["permissions"], ("contents",), source, f"{admission_path}.permissions"
    )
    require_yaml_scalar(
        admission_permissions["contents"],
        "read",
        source,
        f"{admission_path}.permissions.contents",
    )
    require_yaml_scalar(
        admission["runs-on"], "ubuntu-24.04", source, f"{admission_path}.runs-on"
    )
    require_yaml_scalar(
        admission["timeout-minutes"],
        "10",
        source,
        f"{admission_path}.timeout-minutes",
        tag="tag:yaml.org,2002:int",
    )
    admission_steps = yaml_sequence(admission["steps"], source, f"{admission_path}.steps")
    if len(admission_steps) != 1:
        raise ContractError("formal release admission must contain exactly one no-checkout step")
    admission_step = require_yaml_keys(
        admission_steps[0],
        ("name", "env", "run"),
        source,
        f"{admission_path}.steps[0]",
    )
    require_yaml_scalar(
        admission_step["name"],
        "Admit exact main-tip tag and attested Round6 candidate before checkout",
        source,
        f"{admission_path}.steps[0].name",
    )
    expected_admission_env = (
        ("GH_TOKEN", "${{ github.token }}"),
        ("DISPATCH_REF", "${{ github.ref }}"),
        ("DISPATCH_SHA", "${{ github.sha }}"),
        ("WORKFLOW_REF", "${{ github.workflow_ref }}"),
        ("WORKFLOW_SHA", "${{ github.workflow_sha }}"),
    )
    if exact_string_mapping(
        admission_step["env"], source, f"{admission_path}.steps[0].env"
    ) != expected_admission_env:
        raise ContractError("formal release no-checkout admission environment changed")
    admission_run = yaml_scalar(
        admission_step["run"], source, f"{admission_path}.steps[0].run"
    )
    validate_run_hash(
        admission_step,
        FORMAL_RELEASE_STEP_RUN_SHA256[("admission", 0)],
        source,
        f"{admission_path}.steps[0]",
    )
    if re.search(r"(?i)actions/checkout@|(?:^|[\s;&|])(?:\./)?scripts/|(?:^|[\s;&|])(?:g?make)(?=\s|$)", admission_run):
        raise ContractError("formal release admission must remain no-checkout and repository-code-free")

    build_path = "jobs.build-and-verify"
    build = require_yaml_keys(
        jobs["build-and-verify"],
        ("needs", "permissions", "env", "runs-on", "timeout-minutes", "steps"),
        source,
        build_path,
    )
    require_yaml_scalar(build["needs"], "admission", source, f"{build_path}.needs")
    build_permissions = require_yaml_keys(
        build["permissions"], ("actions", "contents"), source, f"{build_path}.permissions"
    )
    require_yaml_scalar(
        build_permissions["actions"], "read", source, f"{build_path}.permissions.actions"
    )
    require_yaml_scalar(
        build_permissions["contents"], "read", source, f"{build_path}.permissions.contents"
    )
    if exact_string_mapping(build["env"], source, f"{build_path}.env") != (
        ("ROUND6_SAFE_SPARSE_BUILD", "1"),
    ):
        raise ContractError("formal release sparse-build environment changed")
    require_yaml_scalar(build["runs-on"], "ubuntu-24.04", source, f"{build_path}.runs-on")
    require_yaml_scalar(
        build["timeout-minutes"],
        "60",
        source,
        f"{build_path}.timeout-minutes",
        tag="tag:yaml.org,2002:int",
    )
    build_steps = yaml_sequence(build["steps"], source, f"{build_path}.steps")
    build_contracts = (
        (
            "Checkout tagged source and full history",
            ("name", "uses", "with"),
            "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        ),
        (
            "Set up pinned Go",
            ("name", "uses", "with"),
            "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16",
        ),
        ("Install native release dependencies", ("name", "run"), None),
        ("Install pinned security and SBOM tools", ("name", "run"), None),
        ("Tag, source version, and clean-tree preflight", ("name", "run"), None),
        (
            "Verify Host, audit, and independent evaluation attestation before formal gates",
            ("name", "id", "env", "run"),
            None,
        ),
        (
            "Download the immutable blocked workflow artifact",
            ("name", "uses", "with"),
            "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131",
        ),
        (
            "Prove the blocked draft matches its immutable workflow artifact",
            ("name", "run"),
            None,
        ),
        ("Run all release gates and build artifacts", ("name", "env", "run"), None),
        ("Recheck hashes and source cleanliness", ("name", "run"), None),
        (
            "Byte-compare formal assets and bind the verified prerelease attestation",
            ("name", "env", "run"),
            None,
        ),
        (
            "Upload exact verified release artifacts",
            ("name", "uses", "with"),
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        ),
    )
    if len(build_steps) != len(build_contracts):
        raise ContractError("formal release build job must contain exactly twelve reviewed steps")
    for index, (step_node, contract) in enumerate(zip(build_steps, build_contracts)):
        name, keys, action = contract
        path = f"{build_path}.steps[{index}]"
        step = require_yaml_keys(step_node, keys, source, path)
        require_yaml_scalar(step["name"], name, source, f"{path}.name")
        if action is not None:
            require_yaml_scalar(step["uses"], action, source, f"{path}.uses")
        expected_hash = FORMAL_RELEASE_STEP_RUN_SHA256.get(("build-and-verify", index))
        if expected_hash is not None:
            validate_run_hash(step, expected_hash, source, path)

    checkout = yaml_mapping(build_steps[0], source, f"{build_path}.steps[0]")
    checkout_with = require_yaml_keys(
        checkout["with"],
        (
            "fetch-depth",
            "persist-credentials",
            "filter",
            "sparse-checkout-cone-mode",
            "sparse-checkout",
        ),
        source,
        f"{build_path}.steps[0].with",
    )
    require_yaml_scalar(
        checkout_with["fetch-depth"],
        "0",
        source,
        f"{build_path}.steps[0].with.fetch-depth",
        tag="tag:yaml.org,2002:int",
    )
    require_yaml_scalar(
        checkout_with["persist-credentials"],
        "false",
        source,
        f"{build_path}.steps[0].with.persist-credentials",
        tag="tag:yaml.org,2002:bool",
    )
    require_yaml_scalar(
        checkout_with["filter"],
        "blob:none",
        source,
        f"{build_path}.steps[0].with.filter",
    )
    require_yaml_scalar(
        checkout_with["sparse-checkout-cone-mode"],
        "false",
        source,
        f"{build_path}.steps[0].with.sparse-checkout-cone-mode",
        tag="tag:yaml.org,2002:bool",
    )
    sparse = yaml_scalar(
        checkout_with["sparse-checkout"],
        source,
        f"{build_path}.steps[0].with.sparse-checkout",
    )
    if tuple(line.strip() for line in sparse.splitlines() if line.strip()) != ROUND6_SPARSE_PATTERNS:
        raise ContractError("formal release sparse checkout differs from Round6 restrictions")
    setup_go = yaml_mapping(build_steps[1], source, f"{build_path}.steps[1]")
    setup_with = require_yaml_keys(
        setup_go["with"], ("go-version", "cache"), source, f"{build_path}.steps[1].with"
    )
    require_yaml_scalar(
        setup_with["go-version"], "${{ env.GO_VERSION }}", source, f"{build_path}.steps[1].with.go-version"
    )
    require_yaml_scalar(
        setup_with["cache"],
        "true",
        source,
        f"{build_path}.steps[1].with.cache",
        tag="tag:yaml.org,2002:bool",
    )
    attestation_step = yaml_mapping(build_steps[5], source, f"{build_path}.steps[5]")
    require_yaml_scalar(
        attestation_step["id"], "candidate_gate", source, f"{build_path}.steps[5].id"
    )
    if exact_string_mapping(
        attestation_step["env"], source, f"{build_path}.steps[5].env"
    ) != (("GH_TOKEN", "${{ github.token }}"),):
        raise ContractError("formal release attestation verification env changed")
    attestation_run = yaml_scalar(
        attestation_step["run"], source, f"{build_path}.steps[5].run"
    )
    for required in (
        './scripts/verify-external-release-attestation.sh "$attestation"',
        "'CI' '.github/workflows/ci.yml' 'push'",
        "'Round6 clean candidate - NOT A RELEASE'",
        "'.github/workflows/round6-candidate.yml' 'workflow_dispatch'",
        "'Round6 prerelease - BLOCKED / PENDING HOST AND INDEPENDENT AUDIT'",
        "'.github/workflows/round6-blocked-prerelease.yml' 'workflow_dispatch'",
    ):
        if required not in attestation_run:
            raise ContractError(
                "formal release must verify external attestation and every attested workflow run"
            )
    blocked_download = yaml_mapping(build_steps[6], source, f"{build_path}.steps[6]")
    blocked_download_with = require_yaml_keys(
        blocked_download["with"],
        ("name", "path", "github-token", "repository", "run-id"),
        source,
        f"{build_path}.steps[6].with",
    )
    for key, expected in (
        ("name", "round6-blocked-attested-${{ steps.candidate_gate.outputs.expected_commit }}"),
        ("path", "${{ runner.temp }}/blocked-run-assets"),
        ("github-token", "${{ github.token }}"),
        ("repository", "${{ github.repository }}"),
        ("run-id", "${{ steps.candidate_gate.outputs.blocked_run_id }}"),
    ):
        require_yaml_scalar(
            blocked_download_with[key], expected, source, f"{build_path}.steps[6].with.{key}"
        )
    step8 = yaml_mapping(build_steps[8], source, f"{build_path}.steps[8]")
    if exact_string_mapping(step8["env"], source, f"{build_path}.steps[8].env") != (
        ("CPA_LATEST_VERIFY_REMOTE", "1"),
    ):
        raise ContractError("formal release gates must keep remote CPA verification enabled")
    step10 = yaml_mapping(build_steps[10], source, f"{build_path}.steps[10]")
    if exact_string_mapping(step10["env"], source, f"{build_path}.steps[10].env") != (
        ("FORMAL_WORKFLOW_SHA", "${{ github.workflow_sha }}"),
    ):
        raise ContractError("formal release provenance binding env changed")
    upload = yaml_mapping(build_steps[11], source, f"{build_path}.steps[11]")
    upload_with = require_yaml_keys(
        upload["with"],
        ("name", "path", "if-no-files-found"),
        source,
        f"{build_path}.steps[11].with",
    )
    require_yaml_scalar(
        upload_with["name"],
        "cyber-abuse-guard-v0.15-release",
        source,
        f"{build_path}.steps[11].with.name",
    )
    upload_paths = yaml_scalar(upload_with["path"], source, f"{build_path}.steps[11].with.path")
    if tuple(line.strip() for line in upload_paths.splitlines() if line.strip()) != FORMAL_RELEASE_ARTIFACTS:
        raise ContractError("formal release artifact transfer allowlist changed")
    require_yaml_scalar(
        upload_with["if-no-files-found"],
        "error",
        source,
        f"{build_path}.steps[11].with.if-no-files-found",
    )

    publish_path = "jobs.publish"
    publish = require_yaml_keys(
        jobs["publish"],
        ("needs", "environment", "permissions", "runs-on", "timeout-minutes", "steps"),
        source,
        publish_path,
    )
    require_yaml_scalar(publish["needs"], "build-and-verify", source, f"{publish_path}.needs")
    require_yaml_scalar(publish["environment"], "formal-release", source, f"{publish_path}.environment")
    publish_permissions = require_yaml_keys(
        publish["permissions"], ("actions", "contents"), source, f"{publish_path}.permissions"
    )
    require_yaml_scalar(
        publish_permissions["actions"], "read", source, f"{publish_path}.permissions.actions"
    )
    require_yaml_scalar(
        publish_permissions["contents"], "write", source, f"{publish_path}.permissions.contents"
    )
    require_yaml_scalar(publish["runs-on"], "ubuntu-24.04", source, f"{publish_path}.runs-on")
    require_yaml_scalar(
        publish["timeout-minutes"],
        "15",
        source,
        f"{publish_path}.timeout-minutes",
        tag="tag:yaml.org,2002:int",
    )
    publish_steps = yaml_sequence(publish["steps"], source, f"{publish_path}.steps")
    publish_contracts = (
        (
            "Download exact verified release artifact",
            ("name", "uses", "with"),
            "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131",
        ),
        ("Reverify transferred filenames and checksums", ("name", "env", "run"), None),
        (
            "Recheck the release commit is still the exact main tip",
            ("name", "env", "run"),
            None,
        ),
        (
            "Create draft v0.15 GitHub release",
            ("name", "uses", "with"),
            "softprops/action-gh-release@718ea10b132b3b2eba29c1007bb80653f286566b",
        ),
    )
    if len(publish_steps) != len(publish_contracts):
        raise ContractError("formal release publish job must contain exactly four reviewed steps")
    for index, (step_node, contract) in enumerate(zip(publish_steps, publish_contracts)):
        name, keys, action = contract
        path = f"{publish_path}.steps[{index}]"
        step = require_yaml_keys(step_node, keys, source, path)
        require_yaml_scalar(step["name"], name, source, f"{path}.name")
        if action is not None:
            require_yaml_scalar(step["uses"], action, source, f"{path}.uses")
        expected_hash = FORMAL_RELEASE_STEP_RUN_SHA256.get(("publish", index))
        if expected_hash is not None:
            validate_run_hash(step, expected_hash, source, path)
    download = yaml_mapping(publish_steps[0], source, f"{publish_path}.steps[0]")
    download_with = require_yaml_keys(
        download["with"], ("name", "path"), source, f"{publish_path}.steps[0].with"
    )
    require_yaml_scalar(
        download_with["name"], "cyber-abuse-guard-v0.15-release", source, f"{publish_path}.steps[0].with.name"
    )
    require_yaml_scalar(download_with["path"], "dist", source, f"{publish_path}.steps[0].with.path")
    verifier = yaml_mapping(publish_steps[1], source, f"{publish_path}.steps[1]")
    expected_verifier_env = (
        ("BASH_ENV", ""),
        ("ENV", ""),
        ("PATH", "/usr/bin:/bin"),
        ("LC_ALL", "C"),
        ("LANG", "C"),
        ("CDPATH", ""),
        ("GLOBIGNORE", ""),
        ("PROMPT_COMMAND", ""),
        ("LD_PRELOAD", ""),
        ("LD_LIBRARY_PATH", ""),
        ("LD_AUDIT", ""),
        ("PYTHONPATH", ""),
        ("PYTHONHOME", ""),
        ("PERL5OPT", ""),
        ("RUBYOPT", ""),
        ("NODE_OPTIONS", ""),
        ("NODE_PATH", ""),
    )
    if exact_string_mapping(
        verifier["env"], source, f"{publish_path}.steps[1].env"
    ) != expected_verifier_env:
        raise ContractError("formal release publish verifier environment changed")
    main_tip = yaml_mapping(publish_steps[2], source, f"{publish_path}.steps[2]")
    if exact_string_mapping(
        main_tip["env"], source, f"{publish_path}.steps[2].env"
    ) != (("GH_TOKEN", "${{ github.token }}"),):
        raise ContractError("formal release main-tip recheck environment changed")
    release = yaml_mapping(publish_steps[3], source, f"{publish_path}.steps[3]")
    release_with = require_yaml_keys(
        release["with"],
        (
            "tag_name",
            "name",
            "draft",
            "prerelease",
            "make_latest",
            "fail_on_unmatched_files",
            "body_path",
            "files",
        ),
        source,
        f"{publish_path}.steps[3].with",
    )
    for key, expected in (("tag_name", "v0.15"), ("name", "v0.15"), ("body_path", "dist/release-evidence-final.md")):
        require_yaml_scalar(release_with[key], expected, source, f"{publish_path}.steps[3].with.{key}")
    for key, expected in (("draft", "true"), ("prerelease", "false"), ("make_latest", "false"), ("fail_on_unmatched_files", "true")):
        require_yaml_scalar(
            release_with[key],
            expected,
            source,
            f"{publish_path}.steps[3].with.{key}",
            tag="tag:yaml.org,2002:bool",
        )
    release_files = yaml_scalar(release_with["files"], source, f"{publish_path}.steps[3].with.files")
    if tuple(line.strip() for line in release_files.splitlines() if line.strip()) != FORMAL_RELEASE_ARTIFACTS:
        raise ContractError("draft release file allowlist differs from verified transfer")
    if any(
        yaml_scalar(yaml_mapping(step, source, f"{publish_path}.steps[{index}]").get("uses"), source, f"{publish_path}.steps[{index}].uses").startswith("actions/checkout@")
        for index, step in enumerate(publish_steps)
        if "uses" in yaml_mapping(step, source, f"{publish_path}.steps[{index}]")
    ):
        raise ContractError("contents:write publish job must never checkout repository source")
    if len(re.findall(r"(?m)^\s+contents:\s*write\s*$", text)) != 1:
        raise ContractError("formal release contents:write must be isolated to publish")


def validate_release_promote_workflow(text: str, source: Path) -> None:
    document = parse_workflow_yaml(text, source)
    root = require_yaml_keys(
        document,
        ("name", "on", "permissions", "concurrency", "jobs"),
        source,
        "workflow",
    )
    require_yaml_scalar(root["name"], "Promote verified v0.15 release", source, "name")
    on = require_yaml_keys(root["on"], ("workflow_dispatch",), source, "on")
    dispatch = require_yaml_keys(on["workflow_dispatch"], ("inputs",), source, "on.workflow_dispatch")
    inputs = require_yaml_keys(
        dispatch["inputs"],
        ("expected_commit", "expected_tree", "authorize_promotion"),
        source,
        "on.workflow_dispatch.inputs",
    )
    for name, node in inputs.items():
        path = f"on.workflow_dispatch.inputs.{name}"
        keys = (
            ("description", "required", "type", "default")
            if name == "authorize_promotion"
            else ("description", "required", "type")
        )
        values = require_yaml_keys(node, keys, source, path)
        yaml_scalar(values["description"], source, f"{path}.description")
        require_yaml_scalar(
            values["required"], "true", source, f"{path}.required", tag="tag:yaml.org,2002:bool"
        )
        if name == "authorize_promotion":
            require_yaml_scalar(values["type"], "boolean", source, f"{path}.type")
            require_yaml_scalar(
                values["default"], "false", source, f"{path}.default", tag="tag:yaml.org,2002:bool"
            )
        else:
            require_yaml_scalar(values["type"], "string", source, f"{path}.type")
    permissions = require_yaml_keys(root["permissions"], ("contents",), source, "permissions")
    require_yaml_scalar(permissions["contents"], "read", source, "permissions.contents")
    concurrency = require_yaml_keys(
        root["concurrency"], ("group", "cancel-in-progress"), source, "concurrency"
    )
    require_yaml_scalar(concurrency["group"], "promote-v0.15", source, "concurrency.group")
    require_yaml_scalar(
        concurrency["cancel-in-progress"],
        "false",
        source,
        "concurrency.cancel-in-progress",
        tag="tag:yaml.org,2002:bool",
    )
    jobs = require_yaml_keys(root["jobs"], ("verify", "promote"), source, "jobs")
    verify = require_yaml_keys(
        jobs["verify"],
        ("permissions", "runs-on", "timeout-minutes", "outputs", "steps"),
        source,
        "jobs.verify",
    )
    verify_permissions = require_yaml_keys(
        verify["permissions"], ("actions", "contents"), source, "jobs.verify.permissions"
    )
    require_yaml_scalar(verify_permissions["actions"], "read", source, "jobs.verify.permissions.actions")
    require_yaml_scalar(verify_permissions["contents"], "read", source, "jobs.verify.permissions.contents")
    require_yaml_scalar(verify["runs-on"], "ubuntu-24.04", source, "jobs.verify.runs-on")
    require_yaml_scalar(
        verify["timeout-minutes"], "10", source, "jobs.verify.timeout-minutes", tag="tag:yaml.org,2002:int"
    )
    outputs = require_yaml_keys(
        verify["outputs"],
        ("release_id", "asset_fingerprint", "metadata_fingerprint", "formal_run_id"),
        source,
        "jobs.verify.outputs",
    )
    require_yaml_scalar(
        outputs["release_id"], "${{ steps.verify.outputs.release_id }}", source, "jobs.verify.outputs.release_id"
    )
    require_yaml_scalar(
        outputs["asset_fingerprint"],
        "${{ steps.verify.outputs.asset_fingerprint }}",
        source,
        "jobs.verify.outputs.asset_fingerprint",
    )
    require_yaml_scalar(
        outputs["metadata_fingerprint"],
        "${{ steps.verify.outputs.metadata_fingerprint }}",
        source,
        "jobs.verify.outputs.metadata_fingerprint",
    )
    require_yaml_scalar(
        outputs["formal_run_id"],
        "${{ steps.verify.outputs.formal_run_id }}",
        source,
        "jobs.verify.outputs.formal_run_id",
    )
    verify_steps = yaml_sequence(verify["steps"], source, "jobs.verify.steps")
    if len(verify_steps) != 3:
        raise ContractError("release promotion verify job must contain exactly three reviewed steps")
    verify_step = require_yaml_keys(
        verify_steps[0], ("name", "id", "env", "run"), source, "jobs.verify.steps[0]"
    )
    require_yaml_scalar(
        verify_step["name"],
        "Verify immutable draft, provenance, and release assets",
        source,
        "jobs.verify.steps[0].name",
    )
    require_yaml_scalar(verify_step["id"], "verify", source, "jobs.verify.steps[0].id")
    expected_verify_env = (
        ("GH_TOKEN", "${{ github.token }}"),
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("AUTHORIZED", "${{ inputs.authorize_promotion }}"),
        ("DISPATCH_REF", "${{ github.ref }}"),
        ("DISPATCH_SHA", "${{ github.sha }}"),
        ("WORKFLOW_REF", "${{ github.workflow_ref }}"),
        ("WORKFLOW_SHA", "${{ github.workflow_sha }}"),
    )
    if exact_string_mapping(verify_step["env"], source, "jobs.verify.steps[0].env") != expected_verify_env:
        raise ContractError("release promotion verify environment changed")
    validate_run_hash(
        verify_step,
        PROMOTE_STEP_RUN_SHA256[("verify", 0)],
        source,
        "jobs.verify.steps[0]",
    )
    formal_download = require_yaml_keys(
        verify_steps[1],
        ("name", "uses", "with"),
        source,
        "jobs.verify.steps[1]",
    )
    require_yaml_scalar(
        formal_download["name"],
        "Download the exact formal workflow artifact",
        source,
        "jobs.verify.steps[1].name",
    )
    require_yaml_scalar(
        formal_download["uses"],
        "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131",
        source,
        "jobs.verify.steps[1].uses",
    )
    formal_download_with = require_yaml_keys(
        formal_download["with"],
        ("name", "path", "github-token", "repository", "run-id"),
        source,
        "jobs.verify.steps[1].with",
    )
    for key, expected in (
        ("name", "cyber-abuse-guard-v0.15-release"),
        ("path", "${{ runner.temp }}/formal-run-assets"),
        ("github-token", "${{ github.token }}"),
        ("repository", "${{ github.repository }}"),
        ("run-id", "${{ steps.verify.outputs.formal_run_id }}"),
    ):
        require_yaml_scalar(
            formal_download_with[key], expected, source, f"jobs.verify.steps[1].with.{key}"
        )
    formal_compare = require_yaml_keys(
        verify_steps[2], ("name", "run"), source, "jobs.verify.steps[2]"
    )
    require_yaml_scalar(
        formal_compare["name"],
        "Prove every draft asset is byte-identical to the formal workflow artifact",
        source,
        "jobs.verify.steps[2].name",
    )
    validate_run_hash(
        formal_compare,
        PROMOTE_STEP_RUN_SHA256[("verify", 2)],
        source,
        "jobs.verify.steps[2]",
    )

    promote = require_yaml_keys(
        jobs["promote"],
        ("needs", "environment", "permissions", "runs-on", "timeout-minutes", "steps"),
        source,
        "jobs.promote",
    )
    require_yaml_scalar(promote["needs"], "verify", source, "jobs.promote.needs")
    require_yaml_scalar(
        promote["environment"], "formal-release-promotion", source, "jobs.promote.environment"
    )
    promote_permissions = require_yaml_keys(
        promote["permissions"], ("contents",), source, "jobs.promote.permissions"
    )
    require_yaml_scalar(
        promote_permissions["contents"], "write", source, "jobs.promote.permissions.contents"
    )
    require_yaml_scalar(promote["runs-on"], "ubuntu-24.04", source, "jobs.promote.runs-on")
    require_yaml_scalar(
        promote["timeout-minutes"], "5", source, "jobs.promote.timeout-minutes", tag="tag:yaml.org,2002:int"
    )
    promote_steps = yaml_sequence(promote["steps"], source, "jobs.promote.steps")
    if len(promote_steps) != 1:
        raise ContractError("release promotion write job must contain exactly one reviewed step")
    promote_step = require_yaml_keys(
        promote_steps[0], ("name", "env", "run"), source, "jobs.promote.steps[0]"
    )
    require_yaml_scalar(
        promote_step["name"],
        "Reverify immutable asset set and publish the same draft",
        source,
        "jobs.promote.steps[0].name",
    )
    expected_promote_env = (
        ("GH_TOKEN", "${{ github.token }}"),
        ("RELEASE_ID", "${{ needs.verify.outputs.release_id }}"),
        ("EXPECTED_ASSET_FINGERPRINT", "${{ needs.verify.outputs.asset_fingerprint }}"),
        ("EXPECTED_METADATA_FINGERPRINT", "${{ needs.verify.outputs.metadata_fingerprint }}"),
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
    )
    if exact_string_mapping(promote_step["env"], source, "jobs.promote.steps[0].env") != expected_promote_env:
        raise ContractError("release promotion write environment changed")
    validate_run_hash(
        promote_step,
        PROMOTE_STEP_RUN_SHA256[("promote", 0)],
        source,
        "jobs.promote.steps[0]",
    )
    if re.search(r"(?i)actions/checkout@|(?:^|[\s;&|])(?:\./)?scripts/", text):
        raise ContractError("release promotion must remain no-checkout and script-free")
    if len(re.findall(r"(?m)^\s+contents:\s*write\s*$", text)) != 1:
        raise ContractError("release promotion contents:write must be isolated to promote")


def validate_blocked_prerelease_structure(
    document: MappingNode, source: Path
) -> dict[str, list[Node]]:
    root = require_yaml_keys(document, BLOCKED_TOP_LEVEL_KEYS, source, "workflow")
    if BLOCKED_PRERELEASE_MARKER not in yaml_scalar(root["name"], source, "name"):
        raise ContractError(
            f"blocked prerelease workflow name must contain {BLOCKED_PRERELEASE_MARKER!r}: {source}"
        )

    if yaml_mapping_keys(root["on"], source, "on") != ("workflow_dispatch",):
        raise ContractError("blocked prerelease must remain manual-only workflow_dispatch")
    on = yaml_mapping(root["on"], source, "on")
    dispatch = require_yaml_keys(
        on["workflow_dispatch"], ("inputs",), source, "on.workflow_dispatch"
    )
    inputs = require_yaml_keys(
        dispatch["inputs"],
        BLOCKED_PRERELEASE_INPUT_ORDER,
        source,
        "on.workflow_dispatch.inputs",
    )
    choice_inputs = {
        "host_v7286_validation",
        "independent_audit_validation",
        "independent_evaluation_validation",
    }
    for input_name, input_node in inputs.items():
        path = f"on.workflow_dispatch.inputs.{input_name}"
        if input_name in choice_inputs:
            expected_keys = ("description", "required", "type", "default", "options")
        elif input_name == "authorize_blocked_prerelease":
            expected_keys = ("description", "required", "type", "default")
        else:
            expected_keys = ("description", "required", "type")
        values = require_yaml_keys(input_node, expected_keys, source, path)
        yaml_scalar(values["description"], source, f"{path}.description")
        require_yaml_scalar(
            values["required"],
            "true",
            source,
            f"{path}.required",
            tag="tag:yaml.org,2002:bool",
        )
        if input_name in choice_inputs:
            require_yaml_scalar(values["type"], "choice", source, f"{path}.type")
            require_yaml_scalar(values["default"], "BLOCKED", source, f"{path}.default")
            options = yaml_sequence(values["options"], source, f"{path}.options")
            if [yaml_scalar(value, source, f"{path}.options") for value in options] != [
                "BLOCKED",
                "PASS",
            ]:
                raise ContractError(f"workflow {path}.options must remain BLOCKED then PASS")
        elif input_name == "authorize_blocked_prerelease":
            require_yaml_scalar(values["type"], "boolean", source, f"{path}.type")
            require_yaml_scalar(
                values["default"],
                "false",
                source,
                f"{path}.default",
                tag="tag:yaml.org,2002:bool",
            )
        else:
            require_yaml_scalar(values["type"], "string", source, f"{path}.type")

    permission_keys = yaml_mapping_keys(root["permissions"], source, "permissions")
    if "actions" not in permission_keys:
        raise ContractError("blocked prerelease must grant top-level actions: read")
    permissions = require_yaml_keys(
        root["permissions"], ("actions", "contents"), source, "permissions"
    )
    require_yaml_scalar(permissions["actions"], "read", source, "permissions.actions")
    require_yaml_scalar(permissions["contents"], "read", source, "permissions.contents")
    concurrency = require_yaml_keys(
        root["concurrency"], ("group", "cancel-in-progress"), source, "concurrency"
    )
    require_yaml_scalar(
        concurrency["group"],
        "round6-blocked-prerelease-${{ inputs.tag }}",
        source,
        "concurrency.group",
    )
    require_yaml_scalar(
        concurrency["cancel-in-progress"],
        "false",
        source,
        "concurrency.cancel-in-progress",
        tag="tag:yaml.org,2002:bool",
    )
    env = require_yaml_keys(
        root["env"],
        ("GO_VERSION", "VERSION", "CYCLONEDX_GOMOD_VERSION"),
        source,
        "env",
    )
    for env_name in ("GO_VERSION", "VERSION", "CYCLONEDX_GOMOD_VERSION"):
        require_yaml_scalar(
            env[env_name], SAFE_WORKFLOW_ENV[env_name], source, f"env.{env_name}"
        )

    jobs = require_yaml_keys(
        root["jobs"], ("admission", "verify", "publish"), source, "jobs"
    )
    steps_by_job: dict[str, list[Node]] = {}
    expected_timeouts = {"admission": "5", "verify": "60", "publish": "10"}
    for job_name in ("admission", "verify", "publish"):
        job_path = f"jobs.{job_name}"
        if job_name == "publish" and "environment" not in yaml_mapping(
            jobs[job_name], source, job_path
        ):
            raise ContractError(
                "publish job must use the round6-independent-audit protected environment"
            )
        job = require_yaml_keys(
            jobs[job_name], BLOCKED_JOB_KEYS[job_name], source, job_path
        )
        require_yaml_scalar(
            job["runs-on"], "ubuntu-24.04", source, f"{job_path}.runs-on"
        )
        require_yaml_scalar(
            job["timeout-minutes"],
            expected_timeouts[job_name],
            source,
            f"{job_path}.timeout-minutes",
            tag="tag:yaml.org,2002:int",
        )
        if job_name == "verify":
            require_yaml_scalar(job["needs"], "admission", source, f"{job_path}.needs")
            verify_permissions = require_yaml_keys(
                job["permissions"],
                ("actions", "contents"),
                source,
                f"{job_path}.permissions",
            )
            require_yaml_scalar(
                verify_permissions["actions"],
                "read",
                source,
                f"{job_path}.permissions.actions",
            )
            require_yaml_scalar(
                verify_permissions["contents"],
                "read",
                source,
                f"{job_path}.permissions.contents",
            )
        elif job_name == "publish":
            require_yaml_scalar(job["needs"], "verify", source, f"{job_path}.needs")
            require_yaml_scalar(
                job["environment"],
                "round6-independent-audit",
                source,
                f"{job_path}.environment",
            )
            expected_publish_if = (
                "inputs.host_v7286_validation == 'PASS' && "
                "inputs.independent_audit_validation == 'PASS' && "
                "inputs.independent_evaluation_validation == 'PASS' && "
                "inputs.authorize_blocked_prerelease == true"
            )
            if yaml_scalar(job["if"], source, f"{job_path}.if") != expected_publish_if:
                raise ContractError(
                    "publish job is missing explicit gate: exact reviewed if expression"
                )
            publish_permissions = require_yaml_keys(
                job["permissions"],
                ("actions", "contents"),
                source,
                f"{job_path}.permissions",
            )
            require_yaml_scalar(
                publish_permissions["actions"],
                "read",
                source,
                f"{job_path}.permissions.actions",
            )
            require_yaml_scalar(
                publish_permissions["contents"],
                "write",
                source,
                f"{job_path}.permissions.contents",
            )

        steps = yaml_sequence(job["steps"], source, f"{job_path}.steps")
        contracts = BLOCKED_STEP_CONTRACTS[job_name]
        if len(steps) != len(contracts):
            count_words = {2: "two", 3: "three", 4: "four", 14: "fourteen"}
            raise ContractError(
                f"blocked prerelease {job_name} job must contain exactly "
                f"{count_words.get(len(contracts), str(len(contracts)))} reviewed steps"
            )
        for index, (step_node, (expected_name, expected_keys, expected_action)) in enumerate(
            zip(steps, contracts)
        ):
            step_path = f"{job_path}.steps[{index}]"
            step = require_yaml_keys(step_node, expected_keys, source, step_path)
            require_yaml_scalar(step["name"], expected_name, source, f"{step_path}.name")
            if expected_action is not None:
                require_yaml_scalar(
                    step["uses"], expected_action, source, f"{step_path}.uses"
                )
            contract_key = (job_name, index)
            if "run" in step:
                run_node = step["run"]
                run_text = yaml_scalar(run_node, source, f"{step_path}.run")
                expected_hash = BLOCKED_STEP_RUN_SHA256.get(contract_key)
                if (
                    expected_hash is None
                    or run_node.tag != "tag:yaml.org,2002:str"
                    or run_node.style != BLOCKED_STEP_RUN_STYLE[contract_key]
                    or hashlib.sha256(run_text.encode("utf-8")).hexdigest()
                    != expected_hash
                ):
                    raise ContractError(
                        f"blocked prerelease {step_path} run must match the exact reviewed text"
                    )
            elif contract_key in BLOCKED_STEP_RUN_SHA256:
                raise ContractError(f"blocked prerelease {step_path} is missing reviewed run")
            if "env" in step:
                env_path = f"{step_path}.env"
                env_node = step["env"]
                if not isinstance(env_node, MappingNode):
                    raise ContractError(f"blocked prerelease {env_path} must be a mapping")
                actual_env = tuple(
                    (
                        key_node.value,
                        yaml_scalar(value_node, source, f"{env_path}.{key_node.value}"),
                    )
                    for key_node, value_node in env_node.value
                )
                if any(
                    value_node.tag != "tag:yaml.org,2002:str"
                    for _, value_node in env_node.value
                ) or actual_env != BLOCKED_STEP_ENV.get(contract_key):
                    raise ContractError(
                        f"blocked prerelease {env_path} must match the exact reviewed mapping"
                    )
            elif contract_key in BLOCKED_STEP_ENV:
                raise ContractError(f"blocked prerelease {step_path} is missing reviewed env")
            if "with" in step:
                yaml_mapping(step["with"], source, f"{step_path}.with")
        steps_by_job[job_name] = steps

    checkout = yaml_mapping(steps_by_job["verify"][0], source, "jobs.verify.steps[0]")
    checkout_with = require_yaml_keys(
        checkout["with"],
        (
            "ref",
            "fetch-depth",
            "persist-credentials",
            "filter",
            "sparse-checkout-cone-mode",
            "sparse-checkout",
        ),
        source,
        "jobs.verify.steps[0].with",
    )
    require_yaml_scalar(
        checkout_with["ref"],
        "${{ inputs.tag }}",
        source,
        "jobs.verify.steps[0].with.ref",
    )
    require_yaml_scalar(
        checkout_with["fetch-depth"],
        "0",
        source,
        "jobs.verify.steps[0].with.fetch-depth",
        tag="tag:yaml.org,2002:int",
    )
    persist_credentials = checkout_with["persist-credentials"]
    if not (
        isinstance(persist_credentials, ScalarNode)
        and persist_credentials.value == "false"
        and persist_credentials.tag == "tag:yaml.org,2002:bool"
    ):
        raise ContractError("blocked prerelease checkout must disable persisted credentials")
    require_yaml_scalar(
        checkout_with["filter"],
        "blob:none",
        source,
        "jobs.verify.steps[0].with.filter",
    )
    require_yaml_scalar(
        checkout_with["sparse-checkout-cone-mode"],
        "false",
        source,
        "jobs.verify.steps[0].with.sparse-checkout-cone-mode",
        tag="tag:yaml.org,2002:bool",
    )
    sparse = yaml_scalar(
        checkout_with["sparse-checkout"],
        source,
        "jobs.verify.steps[0].with.sparse-checkout",
    )
    if tuple(line.strip() for line in sparse.splitlines() if line.strip()) != ROUND6_SPARSE_PATTERNS:
        raise ContractError("blocked prerelease checkout sparse boundary changed")

    setup_go = yaml_mapping(steps_by_job["verify"][3], source, "jobs.verify.steps[3]")
    setup_go_with = require_yaml_keys(
        setup_go["with"],
        ("go-version", "cache"),
        source,
        "jobs.verify.steps[3].with",
    )
    require_yaml_scalar(
        setup_go_with["go-version"],
        "${{ env.GO_VERSION }}",
        source,
        "jobs.verify.steps[3].with.go-version",
    )
    require_yaml_scalar(
        setup_go_with["cache"],
        "true",
        source,
        "jobs.verify.steps[3].with.cache",
        tag="tag:yaml.org,2002:bool",
    )

    candidate_download = yaml_mapping(
        steps_by_job["verify"][5], source, "jobs.verify.steps[5]"
    )
    candidate_download_with = require_yaml_keys(
        candidate_download["with"],
        ("name", "path", "github-token", "repository", "run-id"),
        source,
        "jobs.verify.steps[5].with",
    )
    for key, expected in (
        ("name", "round6-v0.15-candidate-${{ inputs.expected_commit }}"),
        ("path", "${{ runner.temp }}/host-tested-candidate"),
        ("github-token", "${{ github.token }}"),
        ("repository", "${{ github.repository }}"),
        ("run-id", "${{ inputs.candidate_run_id }}"),
    ):
        require_yaml_scalar(
            candidate_download_with[key],
            expected,
            source,
            f"jobs.verify.steps[5].with.{key}",
        )

    upload = yaml_mapping(steps_by_job["verify"][13], source, "jobs.verify.steps[13]")
    upload_with = require_yaml_keys(
        upload["with"],
        ("name", "path", "if-no-files-found", "retention-days"),
        source,
        "jobs.verify.steps[13].with",
    )
    require_yaml_scalar(
        upload_with["name"],
        "round6-blocked-${{ inputs.expected_commit }}",
        source,
        "jobs.verify.steps[13].with.name",
    )
    expected_artifacts = (
        "dist/cyber-abuse-guard-v0.15.so",
        "dist/cyber-abuse-guard-v0.15.so.sha256",
        "dist/cyber-abuse-guard_0.15_linux_amd64.zip",
        "dist/build-metadata.json",
        "dist/checksums.txt",
        "dist/ruleset-manifest.json",
        "dist/ruleset.sha256",
        "dist/sbom.cdx.json",
    )
    upload_paths = yaml_scalar(
        upload_with["path"], source, "jobs.verify.steps[13].with.path"
    )
    if tuple(line.strip() for line in upload_paths.splitlines() if line.strip()) != expected_artifacts:
        raise ContractError("blocked prerelease artifact transfer allowlist changed")
    require_yaml_scalar(
        upload_with["if-no-files-found"],
        "error",
        source,
        "jobs.verify.steps[13].with.if-no-files-found",
    )
    require_yaml_scalar(
        upload_with["retention-days"],
        "1",
        source,
        "jobs.verify.steps[13].with.retention-days",
        tag="tag:yaml.org,2002:int",
    )

    download = yaml_mapping(steps_by_job["publish"][0], source, "jobs.publish.steps[0]")
    download_with = require_yaml_keys(
        download["with"],
        ("name", "path"),
        source,
        "jobs.publish.steps[0].with",
    )
    require_yaml_scalar(
        download_with["name"],
        "round6-blocked-${{ inputs.expected_commit }}",
        source,
        "jobs.publish.steps[0].with.name",
    )
    require_yaml_scalar(
        download_with["path"], "dist", source, "jobs.publish.steps[0].with.path"
    )
    attested_upload = yaml_mapping(
        steps_by_job["publish"][2], source, "jobs.publish.steps[2]"
    )
    attested_upload_with = require_yaml_keys(
        attested_upload["with"],
        ("name", "path", "if-no-files-found", "retention-days"),
        source,
        "jobs.publish.steps[2].with",
    )
    require_yaml_scalar(
        attested_upload_with["name"],
        "round6-blocked-attested-${{ inputs.expected_commit }}",
        source,
        "jobs.publish.steps[2].with.name",
    )
    expected_attested_artifacts = expected_artifacts + (
        "dist/round6-prerelease-attestation.json",
        "dist/round6-prerelease-attestation.json.sha256",
    )
    attested_paths = yaml_scalar(
        attested_upload_with["path"], source, "jobs.publish.steps[2].with.path"
    )
    if tuple(
        line.strip() for line in attested_paths.splitlines() if line.strip()
    ) != expected_attested_artifacts:
        raise ContractError("blocked prerelease attested artifact allowlist changed")
    require_yaml_scalar(
        attested_upload_with["if-no-files-found"],
        "error",
        source,
        "jobs.publish.steps[2].with.if-no-files-found",
    )
    require_yaml_scalar(
        attested_upload_with["retention-days"],
        "30",
        source,
        "jobs.publish.steps[2].with.retention-days",
        tag="tag:yaml.org,2002:int",
    )
    return steps_by_job


def shell_command_segments(command: str) -> tuple[list[str], ...]:
    tokens = shell_tokens(command)
    segments: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token in SHELL_OPERATORS:
            if current:
                segments.append(current)
                current = []
            continue
        current.append(token)
    if current:
        segments.append(current)
    return tuple(segments)


HEREDOC = re.compile(
    r"(?<!<)<<(?P<strip_tabs>-?)(?!<)\s*"
    r"(?P<delimiter>'[^'\r\n]+'|\"[^\"\r\n]+\"|[A-Za-z0-9_.-]+)"
)


def mutation_shell_commands(
    text: str, source: Path = Path("<workflow>")
) -> tuple[str, ...]:
    commands: list[str] = []
    pending = ""
    heredocs: list[tuple[str, bool]] = []
    in_array = False
    array_state = (False, False)
    command_state = SHELL_NEUTRAL_STATE
    array_start = re.compile(
        r"^(?:(?:local|readonly|declare)(?:\s+-[aA])?\s+)?"
        r"[A-Za-z_][A-Za-z0-9_]*\+?=\("
    )
    for raw in text.splitlines():
        if heredocs:
            delimiter, strip_tabs = heredocs[0]
            candidate = raw.lstrip("\t") if strip_tabs else raw
            if candidate == delimiter:
                heredocs.pop(0)
                if not heredocs and shell_state_neutral(command_state) and pending:
                    shell_tokens(pending)
                    commands.append(pending)
                    pending = ""
            continue

        line = raw.strip()
        if not line or (line.startswith("#") and shell_state_neutral(command_state)):
            continue
        if in_array:
            array_state = scan_shell_array_fragment(line, source, array_state)
            if array_state == (False, False) and re.fullmatch(
                r"\)\s*;?(?:\s+#.*)?", line
            ):
                in_array = False
            continue
        if shell_state_neutral(command_state) and not pending and array_start.match(line):
            array_state = scan_shell_array_fragment(line, source, (False, False))
            if array_state != (False, False) or not re.search(
                r"\)\s*;?(?:\s+#.*)?$", line
            ):
                in_array = True
            continue

        line, command_state, continued = shell_line_continuation(line, command_state)
        if not line:
            continue
        if continued:
            line = line[:-1].rstrip()
        pending = f"{pending} {line}".strip() if pending else line
        for match in HEREDOC.finditer(line):
            delimiter = match.group("delimiter")
            if delimiter[:1] in {"'", '"'}:
                delimiter = delimiter[1:-1]
            heredocs.append((delimiter, match.group("strip_tabs") == "-"))
        if continued or heredocs or not shell_state_neutral(command_state):
            continue

        shell_tokens(pending)
        commands.append(pending)
        pending = ""

    if pending or heredocs or in_array or not shell_state_neutral(command_state):
        raise ContractError("unterminated shell construct in blocked prerelease workflow")
    return tuple(commands)


def unwrap_shell_command(segment: list[str]) -> tuple[str, list[str]] | None:
    cursor = 0
    while cursor < len(segment) and (
        ASSIGNMENT.match(segment[cursor])
        or segment[cursor] in {"if", "then", "while", "until", "do", "!"}
    ):
        cursor += 1
    while cursor < len(segment):
        wrapper = Path(segment[cursor]).name
        if wrapper == "command":
            cursor += 1
            while cursor < len(segment) and segment[cursor].startswith("-"):
                cursor += 1
            continue
        if wrapper == "env":
            cursor += 1
            while cursor < len(segment):
                token = segment[cursor]
                if token == "--":
                    cursor += 1
                    break
                if token in {"-S", "--split-string"}:
                    if cursor + 1 >= len(segment):
                        raise ContractError("env split-string option lacks its command string")
                    try:
                        expanded = shlex.split(segment[cursor + 1], posix=True)
                    except ValueError as exc:
                        raise ContractError(
                            "cannot parse env split-string command safely"
                        ) from exc
                    return unwrap_shell_command(expanded + segment[cursor + 2 :])
                if token.startswith("--split-string=") or (
                    token.startswith("-S") and token != "-S"
                ):
                    value = token.split("=", 1)[1] if "=" in token else token[2:]
                    try:
                        expanded = shlex.split(value, posix=True)
                    except ValueError as exc:
                        raise ContractError(
                            "cannot parse env split-string command safely"
                        ) from exc
                    return unwrap_shell_command(expanded + segment[cursor + 1 :])
                if token in {"-u", "--unset", "-C", "--chdir"}:
                    cursor += 2
                    continue
                if token.startswith(("--unset=", "--chdir=")):
                    cursor += 1
                    continue
                if token in {"-i", "--ignore-environment"} or ASSIGNMENT.match(token):
                    cursor += 1
                    continue
                if token.startswith("-"):
                    cursor += 1
                    continue
                break
            continue
        if wrapper == "time":
            cursor += 1
            value_options = {"-f", "--format", "-o", "--output"}
            while cursor < len(segment):
                token = segment[cursor]
                if token == "--":
                    cursor += 1
                    break
                option_name = token.split("=", 1)[0]
                if option_name in value_options:
                    cursor += 1 if "=" in token else 2
                    continue
                if token.startswith(("-f", "-o")) and len(token) > 2:
                    cursor += 1
                    continue
                if token.startswith("-"):
                    cursor += 1
                    continue
                break
            continue
        if wrapper == "timeout":
            cursor += 1
            value_options = {"-k", "--kill-after", "-s", "--signal"}
            while cursor < len(segment):
                token = segment[cursor]
                if token == "--":
                    cursor += 1
                    break
                option_name = token.split("=", 1)[0]
                if option_name in value_options:
                    cursor += 1 if "=" in token else 2
                    continue
                if token.startswith(("-k", "-s")) and len(token) > 2:
                    cursor += 1
                    continue
                if token.startswith("-"):
                    cursor += 1
                    continue
                break
            if cursor >= len(segment):
                return None
            cursor += 1
            continue
        if wrapper == "nice":
            cursor += 1
            while cursor < len(segment):
                token = segment[cursor]
                if token == "--":
                    cursor += 1
                    break
                option_name = token.split("=", 1)[0]
                if option_name in {"-n", "--adjustment"}:
                    cursor += 1 if "=" in token else 2
                    continue
                if token.startswith("-n") and len(token) > 2:
                    cursor += 1
                    continue
                if re.fullmatch(r"-\d+", token) or token.startswith("--"):
                    cursor += 1
                    continue
                break
            continue
        if wrapper == "nohup":
            cursor += 1
            while cursor < len(segment) and segment[cursor].startswith("-"):
                if segment[cursor] == "--":
                    cursor += 1
                    break
                cursor += 1
            continue
        if wrapper == "stdbuf":
            cursor += 1
            value_options = {"-i", "--input", "-o", "--output", "-e", "--error"}
            while cursor < len(segment):
                token = segment[cursor]
                if token == "--":
                    cursor += 1
                    break
                option_name = token.split("=", 1)[0]
                if option_name in value_options:
                    cursor += 1 if "=" in token else 2
                    continue
                if token.startswith(("-i", "-o", "-e")) and len(token) > 2:
                    cursor += 1
                    continue
                if token.startswith("-"):
                    cursor += 1
                    continue
                break
            continue
        if wrapper == "sudo":
            cursor += 1
            value_options = {
                "-u", "--user", "-g", "--group", "-h", "--host",
                "-p", "--prompt", "-C", "--close-from", "-T",
                "--command-timeout", "-R", "--chroot", "-D", "--chdir",
            }
            while cursor < len(segment):
                token = segment[cursor]
                if token == "--":
                    cursor += 1
                    break
                option_name = token.split("=", 1)[0]
                if option_name in value_options:
                    cursor += 1 if "=" in token else 2
                    continue
                if token.startswith("-"):
                    cursor += 1
                    continue
                break
            continue
        break
    if cursor >= len(segment):
        return None
    return segment[cursor], segment[cursor + 1 :]


def option_subcommand(args: list[str], value_options: set[str]) -> str | None:
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            index += 1
            break
        option_name = token.split("=", 1)[0]
        if option_name in value_options:
            index += 1 if "=" in token else 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        return Path(token).name
    if index < len(args):
        return Path(args[index]).name
    return None


def mutating_command_reason(segment: list[str]) -> str | None:
    unwrapped = unwrap_shell_command(segment)
    if unwrapped is None:
        return None
    executable_path, args = unwrapped
    executable = Path(executable_path).name
    if executable in {"sh", "bash", "dash", "zsh"} and any(
        token == "-c"
        or (token.startswith("-") and not token.startswith("--") and "c" in token[1:])
        for token in args
    ):
        return f"{executable} dynamic command execution"
    if executable == "eval":
        return "eval dynamic command execution"
    if executable == "xargs":
        return "xargs dynamic command execution"
    if executable == "find" and any(
        token in {"-exec", "-execdir", "-ok", "-okdir"} for token in args
    ):
        return "find dynamic command execution"
    if re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", executable) and any(
        token == "-c" or token.startswith("-c") for token in args
    ):
        return f"{executable} dynamic command execution"
    if executable == "node" and any(
        token in {"-e", "--eval", "-p", "--print"}
        or token.startswith(("-e", "--eval=", "-p", "--print="))
        for token in args
    ):
        return "node dynamic command execution"
    if executable == "git":
        subcommand = option_subcommand(
            args,
            {"-C", "-c", "--config-env", "--exec-path", "--git-dir", "--work-tree", "--namespace"},
        )
        if subcommand in {"push", "tag", "update-ref"}:
            return f"git {subcommand}"
    elif executable == "gh":
        subcommand = option_subcommand(
            args, {"-R", "--repo", "--hostname", "--config", "--cwd"}
        )
        if subcommand in {"api", "release"}:
            return f"gh {subcommand}"
    elif executable == "curl":
        for token in args:
            lower = token.lower()
            if lower.startswith(("--request", "--data", "--form", "--upload-file", "--json", "--config")):
                return f"curl {token}"
            if token.startswith("-") and not token.startswith("--") and any(
                option in token[1:] for option in "XdFTK"
            ):
                return f"curl {token}"
        if re.search(
            r"(?i)x-http-method-override\s*:\s*(?:post|put|patch|delete)", " ".join(args)
        ):
            return "curl method override"
    elif executable == "wget":
        for token in args:
            if token.lower().startswith(
                ("--method", "--post-data", "--post-file", "--body-data", "--body-file", "--upload-file")
            ):
                return f"wget {token}"
    return None


def validate_pre_final_mutations(
    steps_by_job: dict[str, list[Node]], source: Path
) -> None:
    for job_name in ("admission", "verify", "publish"):
        steps = steps_by_job[job_name]
        limit = len(steps) - 1 if job_name == "publish" else len(steps)
        for index, step_node in enumerate(steps[:limit]):
            path = f"jobs.{job_name}.steps[{index}]"
            step = yaml_mapping(step_node, source, path)
            run_node = step.get("run")
            if run_node is None:
                continue
            for command in mutation_shell_commands(
                yaml_scalar(run_node, source, f"{path}.run")
            ):
                for segment in shell_command_segments(command):
                    reason = mutating_command_reason(segment)
                    if reason is not None:
                        raise ContractError(
                            f"blocked prerelease forbids {reason} before final publish: {path}"
                        )


def validate_blocked_prerelease_workflow(text: str, source: Path) -> None:
    validate_workflow_safety(text, source)
    document = parse_workflow_yaml(text, source)
    validate_sensitive_workflow_expressions(
        document,
        source,
        allowed_token_paths=BLOCKED_ALLOWED_GITHUB_TOKEN_PATHS,
        allowed_identity_expressions=BLOCKED_ALLOWED_GITHUB_IDENTITY_EXPRESSIONS,
    )


    steps_by_job = validate_blocked_prerelease_structure(document, source)
    validate_pre_final_mutations(steps_by_job, source)
    if not re.search(
        rf"(?m)^name:\s*.*{re.escape(BLOCKED_PRERELEASE_MARKER)}.*$", text
    ):
        raise ContractError(
            f"blocked prerelease workflow name must contain {BLOCKED_PRERELEASE_MARKER!r}: {source}"
        )

    on_block = mapping_block(text, "on", 0)
    events = set(re.findall(r"(?m)^  ([A-Za-z0-9_-]+):", on_block))
    if events != {"workflow_dispatch"}:
        raise ContractError(
            f"blocked prerelease must be manual-only workflow_dispatch, got {sorted(events)}"
        )
    dispatch_block = mapping_block(on_block, "workflow_dispatch", 2)
    inputs_block = mapping_block(dispatch_block, "inputs", 4)
    for input_name in BLOCKED_PRERELEASE_INPUTS:
        input_block = mapping_block(inputs_block, input_name, 6)
        if not re.search(r"(?m)^        required:\s*true\s*$", input_block):
            raise ContractError(
                f"blocked prerelease input {input_name} must be explicitly required"
            )
    authorization_block = mapping_block(
        inputs_block, "authorize_blocked_prerelease", 6
    )
    if not re.search(r"(?m)^        type:\s*boolean\s*$", authorization_block) or not re.search(
        r"(?m)^        default:\s*false\s*$", authorization_block
    ):
        raise ContractError(
            "blocked prerelease authorization must be a required boolean defaulting false"
        )

    permissions = mapping_block(text, "permissions", 0)
    if not re.search(r"(?m)^  actions:\s*read\s*$", permissions):
        raise ContractError("blocked prerelease must grant top-level actions: read")
    if not re.search(r"(?m)^  contents:\s*read\s*$", permissions):
        raise ContractError("blocked prerelease top-level contents permission must remain read-only")

    if "${{ secrets." in text:
        raise ContractError("blocked prerelease may not expose repository secrets")
    if text.count("${{ github.token }}") != 4:
        raise ContractError(
            "blocked prerelease may expose github.token only to reviewed CI, candidate admission, candidate download, and final publish steps"
        )

    jobs = job_blocks(text)
    if set(jobs) != {"admission", "verify", "publish"}:
        raise ContractError(
            "blocked prerelease must define exactly admission, verify, and publish jobs"
        )
    admission = jobs["admission"]
    verify_job = jobs["verify"]
    publish_job = jobs["publish"]
    admission_steps = step_blocks(admission)
    if len(admission_steps) != 3:
        raise ContractError("blocked prerelease admission must contain exactly three reviewed steps")
    reviewed_admission = (
        (
            "Fail closed unless every external gate and authorization is explicit",
            ADMISSION_INPUT_ENV,
            ADMISSION_INPUT_COMMANDS,
        ),
        (
            "Bind admission to a successful CI run for the exact commit",
            ADMISSION_CI_ENV,
            ADMISSION_CI_COMMANDS,
        ),
        (
            "Bind admission to the successful clean-candidate run",
            CANDIDATE_ADMISSION_ENV,
            CANDIDATE_ADMISSION_COMMANDS,
        ),
    )
    for step, (name, expected_env, expected_commands) in zip(
        admission_steps, reviewed_admission
    ):
        if not re.search(rf"(?m)^\s+-\s+name:\s*{re.escape(name)}\s*$", step):
            raise ContractError("blocked prerelease admission step name/order changed")
        if re.search(r"(?m)^\s+(?:if|continue-on-error|shell):", step):
            raise ContractError("blocked prerelease admission steps must be unconditional")
        try:
            env_block = mapping_block(step, "env", 8)
        except ContractError as exc:
            raise ContractError("blocked prerelease admission step lacks exact environment") from exc
        actual_env = tuple(
            line.strip() for line in env_block.splitlines()[1:] if line.strip()
        )
        runs = yaml_run_blocks(step)
        actual_commands = (
            tuple(line.rstrip() for line in runs[0].splitlines() if line.strip())
            if len(runs) == 1
            else ()
        )
        if actual_env != expected_env or actual_commands != expected_commands:
            raise ContractError(
                "blocked prerelease admission must use the exact reviewed environment and executable command sequence"
            )

    if not re.search(r"(?m)^    needs:\s*admission\s*$", verify_job):
        raise ContractError("blocked prerelease verify job must depend on admission")
    if re.search(r"(?m)^    (?:if|environment):\s*", verify_job):
        raise ContractError("blocked prerelease verify job may not be conditional or environment-gated")
    verify_permissions = tuple(
        line.strip()
        for line in mapping_block(verify_job, "permissions", 4).splitlines()
        if line.strip()
    )
    if verify_permissions != ("permissions:", "actions: read", "contents: read"):
        raise ContractError(
            "blocked prerelease verify job must remain actions/contents read only"
        )
    if re.search(r"(?m)^\s+(?:GH_TOKEN|GITHUB_TOKEN):", verify_job):
        raise ContractError(
            "blocked prerelease verify job may pass github.token only to the exact candidate artifact download input"
        )

    verify_steps = step_blocks(verify_job)
    if len(verify_steps) < 4:
        raise ContractError("blocked prerelease verify job is missing reviewed verification steps")
    final_verify_step = verify_steps[-2]
    if not re.search(
        r"(?m)^\s+-\s+name:\s*Reverify source and artifact identity before transfer\s*$",
        final_verify_step,
    ):
        raise ContractError("blocked prerelease verify job must freeze identity before transfer")
    if re.search(r"(?m)^\s+(?:if|continue-on-error|shell):", final_verify_step):
        raise ContractError("blocked prerelease final verify identity step must be unconditional")
    upload_step = verify_steps[-1]
    if not re.search(
        r"(?m)^\s+-\s+name:\s*Upload exact verified blocked-development artifacts\s*$",
        upload_step,
    ) or not re.search(
        r"(?m)^\s+uses:\s*actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a(?:\s+#.*)?$",
        upload_step,
    ):
        raise ContractError("blocked prerelease verify job must end with the pinned artifact upload")
    expected_upload_with = """        with:
          name: round6-blocked-${{ inputs.expected_commit }}
          path: |
            dist/cyber-abuse-guard-v0.15.so
            dist/cyber-abuse-guard-v0.15.so.sha256
            dist/cyber-abuse-guard_0.15_linux_amd64.zip
            dist/build-metadata.json
            dist/checksums.txt
            dist/ruleset-manifest.json
            dist/ruleset.sha256
            dist/sbom.cdx.json
          if-no-files-found: error
          retention-days: 1"""
    if mapping_block(upload_step, "with", 8) != expected_upload_with:
        raise ContractError("blocked prerelease artifact transfer allowlist changed")

    publish_if = tuple(
        line.strip()
        for line in mapping_block(publish_job, "if", 4).splitlines()
        if line.strip()
    )
    if publish_if != BLOCKED_PRERELEASE_IF_LINES:
        raise ContractError("publish job is missing explicit gate: exact reviewed if expression")
    if not re.search(r"(?m)^    needs:\s*verify\s*$", publish_job):
        raise ContractError("publish job must depend on successful exact-source verification")
    if not re.search(
        r"(?m)^    environment:\s*round6-independent-audit\s*$", publish_job
    ):
        raise ContractError(
            "publish job must use the round6-independent-audit protected environment"
        )
    publish_permissions = tuple(
        line.strip()
        for line in mapping_block(publish_job, "permissions", 4).splitlines()
        if line.strip()
    )
    if publish_permissions != ("permissions:", "actions: read", "contents: write"):
        raise ContractError("only the fully gated publish job may receive contents: write")
    if len(re.findall(r"(?m)^\s+contents:\s*write\s*$", text)) != 1:
        raise ContractError("contents: write must appear only once in the publish job")

    publish_steps = step_blocks(publish_job)
    if len(publish_steps) != 4:
        raise ContractError("blocked prerelease publish job must contain exactly four reviewed steps")
    download_step, transfer_step, _, final_publish_step = publish_steps
    if not re.search(
        r"(?m)^\s+-\s+name:\s*Download exact verified blocked-development artifacts\s*$",
        download_step,
    ) or not re.search(
        r"(?m)^\s+uses:\s*actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131(?:\s+#.*)?$",
        download_step,
    ):
        raise ContractError("blocked prerelease publish job must use the pinned artifact download")
    expected_download_with = """        with:
          name: round6-blocked-${{ inputs.expected_commit }}
          path: dist"""
    if mapping_block(download_step, "with", 8) != expected_download_with:
        raise ContractError("blocked prerelease artifact download identity changed")

    if not re.search(
        r"(?m)^\s+-\s+name:\s*Reverify transferred artifact identity without a repository token\s*$",
        transfer_step,
    ):
        raise ContractError("blocked prerelease publish job lacks token-free transfer verification")
    if re.search(
        r"(?m)^\s+(?:if|continue-on-error|shell):", transfer_step
    ):
        raise ContractError("blocked prerelease transfer verification must be unconditional")
    if not re.search(
        r"(?m)^\s+-\s+name:\s*Recheck immutable tag and create draft blocked prerelease\s*$",
        final_publish_step,
    ) or re.search(r"(?m)^\s+(?:if|continue-on-error|shell):", final_publish_step):
        raise ContractError("blocked prerelease must end with one unconditional publish step")
def validate_rc_release_workflow(text: str, source: Path) -> None:
    parse_workflow_yaml(text, source)
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != RC_RELEASE_WORKFLOW_SHA256:
        raise ContractError("RC release workflow differs from the exact reviewed contract")
    required = (
        "RC release v0.15-rc.2 - Linux sandbox validation",
        "Bind RC authorization to annotated exact-main tag before checkout",
        "Bind RC admission to successful exact-main push CI",
        "Checkout exact RC tag with restricted data excluded",
        "Recheck restricted-data and workflow contracts",
        "Recheck regressions and latest CPA v7.2.86 contracts",
        "Run RC-versioned CPA Host integration",
        "Build and reproduce exact RC release assets",
        "Reverify transferred RC assets without repository source",
        "Recheck immutable tag and main before publication",
        "Create, byte-check, and publish v0.15-rc.2 prerelease",
        "SANDBOX_ONLY / SERVER_VALIDATION_REQUIRED / NOT_FORMAL / NOT_ROUND6_CANDIDATE",
        "cyber-abuse-guard_0.15-rc.2_linux_amd64.zip",
        "rc-release-manifest.json.sha256",
        "--draft",
        "--prerelease",
        "--latest=false",
    )
    for marker in required:
        if marker not in text:
            raise ContractError(f"RC release workflow is missing reviewed marker: {marker}")
    if text.count("contents: write") != 1:
        raise ContractError("RC release workflow must expose contents: write only in publish")
    if re.search(r"(?im)runs-on:\s*(?:windows|macos)", text):
        raise ContractError("RC release workflow must remain Linux only")
    if "round6-prerelease-attestation.json" in text or "formal-release-attestation.json" in text:
        raise ContractError("RC release workflow may not emit formal evidence assets")


def validate_round6_reproducibility_script(text: str, source: Path) -> None:
    match = re.search(
        r"sparse-checkout\s+set\s+--no-cone(?P<body>.*?)\n\s*git\s+-C\s+[^\n]+\s+checkout",
        text,
        re.DOTALL,
    )
    if not match:
        raise ContractError(f"Round6 reproducibility script lacks a static sparse checkout: {source}")
    patterns = tuple(
        re.findall(r"['\"]((?:/\*|!/[^'\"]+))['\"]", match.group("body"))
    )
    if patterns != ROUND6_SPARSE_PATTERNS:
        raise ContractError(
            f"Round6 reproducibility sparse checkout differs from the workflow contract: {source}"
        )
    if text.count(ROUND6_REPRODUCIBILITY_ENTRY_MODE_CONTRACT) != 1:
        raise ContractError(
            "Round6 reproducibility entry mode must keep development separate from release: "
            f"{source}"
        )
    if text.count(ROUND6_REPRODUCIBILITY_MODE_CONTRACT) != 1:
        raise ContractError(
            "Round6 reproducibility modes must keep the exact candidate and formal assertions: "
            f"{source}"
        )
    if text.count(ROUND6_REPRODUCIBILITY_PACKAGE_BRANCH_CONTRACT) != 1:
        raise ContractError(
            "Round6 reproducibility package-release must remain in the exact formal-only branch: "
            f"{source}"
        )
    for contract in ROUND6_REPRODUCIBILITY_CHECKSUMS_CONTRACT:
        if text.count(contract) != 1:
            raise ContractError(
                "Round6 reproducibility must generate and compare the exact checksums manifest: "
                f"{source}"
            )
    if (
        hashlib.sha256(text.encode("utf-8")).hexdigest()
        != ROUND6_REPRODUCIBILITY_SCRIPT_SHA256
    ):
        raise ContractError(
            f"Round6 reproducibility script must match the exact reviewed safety contract: {source}"
        )


def validate_round6_linux_build_script(text: str, source: Path) -> None:
    commands = tuple(
        command
        for command in logical_shell_commands(text)
        if not command.lstrip().startswith("#")
    )
    required_prefix = (
        "set -euo pipefail",
        'root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"',
        'source "$root/scripts/release-common.sh"',
        'go_bin="${GO:-go}"',
        'release_require_commands "$go_bin" file sha256sum git sed awk sort tail readelf mkdir rm basename',
        "release_init",
        "release_assert_tag",
        'dist="${DIST_DIR:-$root/dist}"',
        'artifact="$dist/cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}.so"',
        'if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then',
        'echo "build-linux-amd64.sh requires an amd64 Linux environment (native, WSL2, or Docker)." >&2',
        "exit 1",
        "fi",
        'go_version="$($go_bin env GOVERSION)"',
        'if [[ "$go_version" != go1.26.4 ]]; then',
        "printf 'build-linux-amd64.sh requires Go go1.26.4, got %s\\n' \"$go_version\" >&2",
        "exit 1",
        "fi",
        'mkdir -p "$dist"',
        'cd "$root"',
        'ldflags="-s -w -buildid="',
        'ldflags+=" -X github.com/yujianwudi/cyber-abuse-guard/internal/buildinfo.Version=$RELEASE_ARTIFACT_VERSION"',
        'ldflags+=" -X github.com/yujianwudi/cyber-abuse-guard/internal/buildinfo.Commit=$RELEASE_GIT_COMMIT"',
        'ldflags+=" -X github.com/yujianwudi/cyber-abuse-guard/internal/buildinfo.RulesetVersion=$RELEASE_RULESET_VERSION"',
        'ldflags+=" -X github.com/yujianwudi/cyber-abuse-guard/internal/buildinfo.RulesetSHA256=$RELEASE_RULESET_SHA256"',
        'ldflags+=" -X github.com/yujianwudi/cyber-abuse-guard/internal/buildinfo.Dirty=$RELEASE_DIRTY"',
        'export SOURCE_DATE_EPOCH="$RELEASE_SOURCE_DATE_EPOCH"',
        'CGO_ENABLED=1 GOOS=linux GOARCH=amd64 "$go_bin" build -mod=readonly -trimpath -buildvcs=false -buildmode=c-shared -tags=sqlite_omit_load_extension -ldflags="$ldflags" -o "$artifact" ./cmd/cyber-abuse-guard',
        'rm -f "${artifact%.so}.h"',
        '(cd "$dist" && sha256sum "$(basename "$artifact")" > "$(basename "$artifact").sha256")',
        'OUTPUT_DIR="$dist" GO="$go_bin" "$root/scripts/release-ruleset-manifest.sh"',
    )
    required_sequence = (
        'OUTPUT_DIR="$dist" GO="$go_bin" "$root/scripts/release-build-metadata.sh"',
        'file "$artifact"',
        'glibc_tags="$(readelf --version-info --wide "$artifact" | awk \'{ line = $0; while (match(line, /GLIBC_[A-Za-z0-9_.]+/)) { print substr(line, RSTART, RLENGTH); line = substr(line, RSTART + RLENGTH) } }\' | LC_ALL=C sort -u)"',
        'if [[ -z "$glibc_tags" ]]; then',
        "echo 'build artifact has no auditable GLIBC version-needed tags' >&2",
        "exit 1",
        "fi",
        'while IFS= read -r glibc_tag; do',
        'if [[ ! "$glibc_tag" =~ ^GLIBC_[0-9]+([.][0-9]+)*$ ]]; then',
        "printf 'build requires unsupported non-numeric glibc version tag %s\\n' \"$glibc_tag\" >&2",
        "exit 1",
        "fi",
        'done <<<"$glibc_tags"',
        'max_glibc="$(printf \'%s\\n\' "$glibc_tags" | sed \'s/^GLIBC_//\' | LC_ALL=C sort -Vu | tail -1)"',
        'if [[ -z "$max_glibc" || "$(printf \'%s\\n\' "$max_glibc" \'2.34\' | sort -V | tail -1)" != 2.34 ]]; then',
        "printf 'build requires unsupported glibc %s; maximum allowed is 2.34\\n' \"$max_glibc\" >&2",
        "exit 1",
        "fi",
        '(cd "$dist" && sha256sum -c "$(basename "$artifact").sha256")',
        "release_assert_source_unchanged",
    )
    required_suffix = (
        "printf 'build identity: version=%s commit=%s tree=%s ruleset=%s ruleset_sha256=%s classifier=%s classifier_sha256=%s scanner=%s dirty=%s\\n' \"$RELEASE_ARTIFACT_VERSION\" \"$RELEASE_GIT_COMMIT\" \"$RELEASE_GIT_TREE\" \"$RELEASE_RULESET_VERSION\" \"$RELEASE_RULESET_SHA256\" \"$RELEASE_CLASSIFIER_POLICY_VERSION\" \"$RELEASE_CLASSIFIER_POLICY_SHA256\" \"$RELEASE_STREAMING_SCANNER\" \"$RELEASE_DIRTY\"",
    )
    if commands != required_prefix + required_sequence + required_suffix:
        raise ContractError(
            f"Round6 Linux build must execute the exact glibc 2.34 reviewed fail-closed command sequence: {source}"
        )


def parse_makefile(
    text: str,
) -> tuple[dict[str, set[str]], dict[str, str], dict[str, set[str]]]:
    dependencies: dict[str, set[str]] = defaultdict(set)
    dynamic_dependencies: dict[str, set[str]] = defaultdict(set)
    recipes: dict[str, list[str]] = defaultdict(list)
    current_targets: list[str] = []
    for line in logical_make_lines(text):
        if line.startswith("\t"):
            for target in current_targets:
                recipes[target].append(line[1:])
            continue
        current_targets = []
        match = re.match(
            r"^([A-Za-z0-9_.%/-]+(?:\s+[A-Za-z0-9_.%/-]+)*):\s*(.*)$", line
        )
        if not match:
            continue
        targets = match.group(1).split()
        raw_dependencies = match.group(2).split("#", 1)[0].strip()
        for target in targets:
            dependencies.setdefault(target, set())
        for candidate in raw_dependencies.split():
            if candidate == "|":
                continue
            if "$" in candidate or "`" in candidate:
                for target in targets:
                    dynamic_dependencies[target].add(candidate)
                continue
            if TARGET_NAME.match(candidate):
                for target in targets:
                    dependencies[target].add(candidate)
        current_targets = targets
    return (
        dict(dependencies),
        {target: "\n".join(lines) for target, lines in recipes.items()},
        dict(dynamic_dependencies),
    )


def validate_round6_makefile_contract(text: str, source: Path) -> None:
    dependencies, recipes, _ = parse_makefile(text)
    module_commands = tuple(
        " ".join(line.split())
        for line in recipes.get("round6-module-verify", "").splitlines()
        if line.strip()
    )
    expected_module_commands = (
        "$(GO) mod verify",
        "$(GO) list -tags=$(TEST_TAGS) -deps $(ROUND6_SAFE_PACKAGES) >/dev/null",
        "$(GO) -C integration/pluginstorecontract mod verify",
        "$(GO) -C integration/pluginstorecontract mod tidy -diff",
        "$(GO) -C integration/cpalatestcontract mod verify",
        "$(GO) -C integration/cpalatestcontract mod tidy -diff",
    )
    if module_commands != expected_module_commands:
        raise ContractError(
            "round6-module-verify must tidy-diff only the two included integration modules: "
            f"{source}"
        )
    if dependencies.get("round6-benchmark") != {"benchmark"}:
        raise ContractError(
            f"round6-benchmark must retain the reviewed benchmark dependency: {source}"
        )
    commands = tuple(
        " ".join(line.split())
        for line in recipes.get("round6-benchmark", "").splitlines()
        if line.strip()
    )
    expected = (
        "@$(GO) test ./internal/extract -list='^BenchmarkRound6ScanLongJSON$$' | grep -Fxq 'BenchmarkRound6ScanLongJSON' || { echo 'required Round6 long-JSON benchmark is missing' >&2; exit 1; }",
        "$(GO) test ./internal/extract -run='^$$' -bench='^BenchmarkRound6ScanLongJSON$$' -benchmem -benchtime=1x -count=1",
    )
    if commands != expected:
        raise ContractError(
            f"round6-benchmark must fail closed and execute the extract benchmark: {source}"
        )
    required_script_commands = (
        "bash -n ./scripts/round6-candidate-artifacts.sh",
        "./scripts/release-candidate-contract-test.sh",
        "bash -n ./scripts/verify-external-release-attestation.sh",
        "./scripts/verify-external-release-attestation-test.sh",
    )
    for target in ("script-test", "round6-script-test"):
        target_commands = tuple(
            " ".join(line.split())
            for line in recipes.get(target, "").splitlines()
            if line.strip()
        )
        positions: list[int] = []
        for command in required_script_commands:
            matches = [
                index for index, actual in enumerate(target_commands) if actual == command
            ]
            if len(matches) != 1:
                raise ContractError(
                    f"{target} must reach the exact reviewed Round6 script gate: {command}"
                )
            positions.append(matches[0])
        if positions != sorted(positions):
            raise ContractError(
                f"{target} must preserve the reviewed Round6 script-gate order"
            )
    round6_commands = tuple(
        " ".join(line.split())
        for line in recipes.get("round6-script-test", "").splitlines()
        if line.strip()
    )
    required_mutation_fixtures = (
        "bash ./scripts/release-evidence-privacy-test.sh",
        "bash ./scripts/round6-doc-consistency-fixture-test.sh",
    )
    positions = []
    for command in required_mutation_fixtures:
        matches = [
            index for index, actual in enumerate(round6_commands) if actual == command
        ]
        if len(matches) != 1:
            raise ContractError(
                f"round6-script-test must execute the exact reviewed privacy-safe mutation fixture: {command}"
            )
        positions.append(matches[0])
    if positions != sorted(positions) or any(
        "release-doc-consistency-test.sh" in command for command in round6_commands
    ):
        raise ContractError(
            "round6-script-test must preserve the privacy-safe mutation fixture boundary"
        )


def dotted_name(node: ast.AST, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = dotted_name(node.value, aliases)
        return f"{parent}.{node.attr}" if parent else None
    return None


def literal_command(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, (ast.List, ast.Tuple)):
        values: list[str] = []
        for element in node.elts:
            if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
                return None
            values.append(element.value)
        return shlex.join(values)
    return None


def local_python_imports(tree: ast.AST, source: Path, root: Path) -> set[str]:
    result: set[str] = set()
    for node in ast.walk(tree):
        modules: list[tuple[str, int]] = []
        if isinstance(node, ast.Import):
            modules.extend((alias.name, 0) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.append((node.module, node.level))
        for module, level in modules:
            relative = Path(*module.split("."))
            bases = [source.parent] if level else [source.parent, root]
            for base in bases:
                for candidate in (base / f"{relative}.py", base / relative / "__init__.py"):
                    try:
                        safe = assert_safe_repo_path(candidate, root)
                    except ContractError:
                        raise
                    if safe.exists():
                        result.add(safe.relative_to(root).as_posix())
                        break
    return result


def audit_python_source(
    text: str, source: Path, root: Path
) -> tuple[set[str], set[str]]:
    try:
        tree = ast.parse(text, filename=str(source))
    except SyntaxError as exc:
        raise ContractError(f"cannot parse reachable Python script {source}: {exc}") from exc
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    targets: set[str] = set()
    scripts = local_python_imports(tree, source, root)
    subprocess_calls = {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
    }
    forbidden_calls = {
        "eval",
        "exec",
        "compile",
        "runpy.run_module",
        "importlib.import_module",
    }
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = dotted_name(node.func, aliases)
        if not name:
            continue
        if name in forbidden_calls or name.startswith(("os.exec", "os.spawn")):
            raise ContractError(f"dynamic Python dispatch is forbidden in {source}: {name}")
        if name == "runpy.run_path":
            command = literal_command(node.args[0] if node.args else None)
            if not command or not command.endswith(".py"):
                raise ContractError(f"dynamic Python run_path is forbidden in {source}")
            scripts.add(command.removeprefix("./"))
            continue
        if name in {"os.system", "os.popen"}:
            raise ContractError(f"Python shell dispatch is forbidden in {source}: {name}")
        if name not in subprocess_calls:
            continue
        argument = node.args[0] if node.args else next(
            (keyword.value for keyword in node.keywords if keyword.arg in {"args", "cmd"}),
            None,
        )
        command = literal_command(argument)
        if command is None:
            raise ContractError(f"dynamic Python command is forbidden in {source}: {name}")
        for keyword in node.keywords:
            if keyword.arg in {"cwd", "env"}:
                raise ContractError(
                    f"Python command with dynamic execution context is forbidden in {source}: {name}"
                )
            if keyword.arg == "shell" and not (
                isinstance(keyword.value, ast.Constant) and keyword.value.value is False
            ):
                raise ContractError(f"Python shell dispatch is forbidden in {source}: {name}")
        command_targets, command_scripts = audit_command_text(command, source)
        targets.update(command_targets)
        scripts.update(command_scripts)
    return targets, scripts


def default_entrypoints(root: Path) -> list[Path]:
    entries = [root / ".github/workflows/ci.yml"]
    for relative in (
        ".github/workflows/blocked-prerelease.yml",
        ".github/workflows/round6-candidate.yml",
        ".github/workflows/release.yml",
        ".github/workflows/release-rc.yml",
        ".github/workflows/release-promote.yml",
    ):
        optional = root / relative
        if optional.exists():
            entries.append(optional)
    for pattern in (
        ".github/workflows/*round6*prerelease*.yml",
        ".github/workflows/*round6*prerelease*.yaml",
        "scripts/*round6*prerelease*.sh",
    ):
        entries.extend(root.glob(pattern))
    return sorted(set(entries))


def audit(root: Path, entrypoints: list[Path]) -> tuple[set[str], set[str]]:
    root = root.resolve()
    if (root / ".github/workflows/round6-candidate.yml").exists():
        validate_consumed_boundary_files(root)
    makefile_text = read_regular_text(root / "Makefile", root)
    dependencies, recipes, dynamic_dependencies = parse_makefile(makefile_text)
    validate_release_mode_contracts(root)

    direct_targets: set[str] = set()
    inspected_scripts: set[str] = set()
    script_queue: list[str] = []
    for entrypoint in entrypoints:
        text = read_regular_text(entrypoint, root)
        if entrypoint.suffix.lower() in {".yml", ".yaml"}:
            name = entrypoint.name.lower()
            if name == "round6-candidate.yml":
                validate_candidate_workflow(text, entrypoint)
            elif name == "release-rc.yml":
                validate_rc_release_workflow(text, entrypoint)
            elif "prerelease" in name:
                validate_blocked_prerelease_workflow(text, entrypoint)
            elif name == "release.yml":
                validate_formal_release_workflow(text, entrypoint)
                continue
            elif name == "release-promote.yml":
                validate_release_promote_workflow(text, entrypoint)
                continue
            else:
                validate_workflow_safety(text, entrypoint)
            command_text = "\n".join(yaml_run_blocks(text))
        else:
            command_text = text
        targets, scripts = audit_command_text(command_text, entrypoint)
        direct_targets.update(targets)
        script_queue.extend(scripts)

    reviewed_control_scripts = (
        REPRODUCIBILITY_WRAPPER_SCRIPT,
        FROZEN_EVALUATION_TREE_SCRIPT,
    )
    if (
        (root / ".github/workflows/ci.yml").resolve()
        in {path.resolve() for path in entrypoints}
        and all((root / relative).exists() for relative in reviewed_control_scripts)
    ):
        script_queue.extend(reviewed_control_scripts)

    visited: set[str] = set()
    target_queue = list(direct_targets)
    while script_queue or target_queue:
        if script_queue:
            relative = script_queue.pop().removeprefix("./")
            if relative in inspected_scripts:
                continue
            if relative == FROZEN_EVALUATION_TREE_SCRIPT:
                script_path = root / relative
                try:
                    resolved = script_path.resolve(strict=True)
                except FileNotFoundError as exc:
                    raise ContractError(
                        f"required gate input is missing: {script_path}"
                    ) from exc
                if (
                    script_path.is_symlink()
                    or not script_path.is_file()
                    or (resolved != root and root not in resolved.parents)
                ):
                    raise ContractError(
                        f"reviewed frozen evaluation verifier must be a regular repository file: {script_path}"
                    )
                script_text = script_path.read_text(encoding="utf-8")
                validate_frozen_evaluation_tree_script(script_text, script_path)
                inspected_scripts.add(relative)
                continue
            if relative == ROUND6_DOC_FIXTURE_WRAPPER_SCRIPT:
                script_path = root / relative
                script_text = read_regular_text(script_path, root)
                validate_round6_doc_fixture_wrapper_script(script_text, script_path, root)
                inspected_scripts.add(relative)
                inspected_scripts.update(ROUND6_DOC_FIXTURE_DEPENDENCY_SHA256)
                continue
            assert_safe_repo_path(Path(relative), root)
            if (
                FORBIDDEN_SCRIPT_NAME.search(Path(relative).name)
                and relative != REPRODUCIBILITY_WRAPPER_SCRIPT
            ):
                raise ContractError(f"Round6 entrypoint reaches forbidden script: {relative}")
            inspected_scripts.add(relative)
            script_path = root / relative
            script_text = read_regular_text(script_path, root)
            suffix = script_path.suffix.lower()
            if suffix == ".sh":
                if script_path.name in CANDIDATE_SCRIPT_SHA256:
                    validate_candidate_script(script_text, script_path)
                if relative == REPRODUCIBILITY_WRAPPER_SCRIPT:
                    validate_reproducibility_wrapper_script(script_text, script_path)
                if relative == ROUND6_PRIVACY_FIXTURE_SCRIPT:
                    validate_round6_privacy_fixture_script(script_text, script_path)
                if relative == CPA_COMPAT_SCRIPT:
                    validate_cpa_compat_script(script_text, script_path)
                if script_path.name == "round6-reproducibility-test.sh":
                    validate_round6_reproducibility_script(script_text, script_path)
                if script_path.name == "build-linux-amd64.sh":
                    validate_round6_linux_build_script(script_text, script_path)
                command_text = script_text
                if script_path.name in {
                    "round6-candidate-artifacts.sh",
                    "round6-rc-artifacts.sh",
                }:
                    command_text = command_text.replace(
                        "release_require_commands make ", "release_require_commands "
                    ).replace('make -C "$root" -j1', "make")
                    if script_path.name == "round6-rc-artifacts.sh":
                        command_text = command_text.replace(
                            'make -C "$clone" -j1', "make"
                        ).replace("\\\n", " ")
                elif script_path.name == "verify-external-release-attestation-test.sh":
                    command_text = command_text.replace('make -C "$root"', "make")
                elif script_path.name == "round6-reproducibility-test.sh":
                    command_text = command_text.replace(
                        ROUND6_REPRODUCIBILITY_FORMAL_PACKAGE_COMMAND, "", 1
                    )
                targets, scripts = audit_command_text(command_text, script_path)
            elif suffix == ".py":
                targets, scripts = audit_python_source(script_text, script_path, root)
            else:
                raise ContractError(f"unsupported reachable script type: {relative}")
            target_queue.extend(targets)
            script_queue.extend(scripts)
            continue

        target = target_queue.pop()
        if target in visited:
            continue
        visited.add(target)
        if target in FORBIDDEN_TARGETS or FORBIDDEN_TARGET_NAME.search(target):
            raise ContractError(f"Round6 entrypoint reaches forbidden Make target: {target}")
        if target not in dependencies:
            raise ContractError(f"Round6 entrypoint reaches unknown Make target: {target}")
        if target == "round6-benchmark":
            validate_round6_makefile_contract(makefile_text, root / "Makefile")
        if dynamic_dependencies.get(target):
            raise ContractError(
                f"Round6 entrypoint reaches Make target with dynamic dependencies: {target}"
            )
        target_queue.extend(dependencies[target])
        recipe = recipes.get(target, "")
        recipe_targets, recipe_scripts = audit_command_text(
            recipe, root / f"Makefile:{target}"
        )
        target_queue.extend(recipe_targets)
        script_queue.extend(recipe_scripts)

    ci_entrypoint = root / ".github/workflows/ci.yml"
    required_script_paths = {
        "scripts/round6-candidate-artifacts.sh",
        "scripts/release-candidate-contract-test.sh",
        REPRODUCIBILITY_WRAPPER_SCRIPT,
        FROZEN_EVALUATION_TREE_SCRIPT,
        "scripts/verify-external-release-attestation.sh",
        "scripts/verify-external-release-attestation-test.sh",
        ROUND6_PRIVACY_FIXTURE_SCRIPT,
        ROUND6_DOC_FIXTURE_WRAPPER_SCRIPT,
        *ROUND6_DOC_FIXTURE_DEPENDENCY_SHA256,
    }
    if ci_entrypoint in {path.resolve() for path in entrypoints} and all(
        (root / relative).exists() for relative in required_script_paths
    ):
        missing = required_script_paths - inspected_scripts
        if missing:
            raise ContractError(
                "Round6 CI script gates do not reach reviewed release-safety scripts: "
                + ", ".join(sorted(missing))
            )

    return visited, inspected_scripts


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument(
        "--entrypoint",
        action="append",
        default=[],
        help="repository-relative workflow or script to audit; repeatable",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    root = args.root.resolve()
    entrypoints = (
        [root / item for item in args.entrypoint]
        if args.entrypoint
        else default_entrypoints(root)
    )
    try:
        targets, scripts = audit(root, entrypoints)
    except (ContractError, UnicodeError, OSError) as exc:
        print(f"Round6 safe gate contract: FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        "Round6 safe gate contract: PASS: "
        f"entrypoints={len(entrypoints)} make_targets={len(targets)} scripts={len(scripts)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
