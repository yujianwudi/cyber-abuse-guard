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
    "expected_so_sha256",
    "host_v7283_validation",
    "host_v7283_evidence_sha256",
    "host_v7282_validation",
    "host_v7282_evidence_sha256",
    "host_v7281_validation",
    "host_v7281_evidence_sha256",
    "independent_audit_validation",
    "independent_audit_sha256",
    "authorize_blocked_prerelease",
)
BLOCKED_PRERELEASE_INPUTS = set(BLOCKED_PRERELEASE_INPUT_ORDER)
BLOCKED_PRERELEASE_IF_LINES = (
    "if: >-",
    "inputs.host_v7283_validation == 'PASS' &&",
    "inputs.host_v7282_validation == 'PASS' &&",
    "inputs.host_v7281_validation == 'PASS' &&",
    "inputs.independent_audit_validation == 'PASS' &&",
    "inputs.authorize_blocked_prerelease == true",
)
ADMISSION_INPUT_ENV = (
    "TAG: ${{ inputs.tag }}",
    "EXPECTED_COMMIT: ${{ inputs.expected_commit }}",
    "EXPECTED_TREE: ${{ inputs.expected_tree }}",
    "CI_RUN_ID: ${{ inputs.ci_run_id }}",
    "EXPECTED_SO_SHA256: ${{ inputs.expected_so_sha256 }}",
    "DISPATCH_REF: ${{ github.ref }}",
    "DISPATCH_SHA: ${{ github.sha }}",
    "WORKFLOW_REF: ${{ github.workflow_ref }}",
    "WORKFLOW_SHA: ${{ github.workflow_sha }}",
    "HOST_V7283: ${{ inputs.host_v7283_validation }}",
    "HOST_V7283_SHA256: ${{ inputs.host_v7283_evidence_sha256 }}",
    "HOST_V7282: ${{ inputs.host_v7282_validation }}",
    "HOST_V7282_SHA256: ${{ inputs.host_v7282_evidence_sha256 }}",
    "HOST_V7281: ${{ inputs.host_v7281_validation }}",
    "HOST_V7281_SHA256: ${{ inputs.host_v7281_evidence_sha256 }}",
    "INDEPENDENT_AUDIT: ${{ inputs.independent_audit_validation }}",
    "INDEPENDENT_AUDIT_SHA256: ${{ inputs.independent_audit_sha256 }}",
    "AUTHORIZED: ${{ inputs.authorize_blocked_prerelease }}",
)
ADMISSION_INPUT_COMMANDS = (
    '[[ "$TAG" =~ ^v0\\.1\\.2-dev\\.round6([.][0-9]+)?$ ]]',
    '[[ "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]]',
    '[[ "$EXPECTED_TREE" =~ ^[0-9a-f]{40}$ ]]',
    '[[ "$CI_RUN_ID" =~ ^[1-9][0-9]*$ ]]',
    '[[ "$EXPECTED_SO_SHA256" =~ ^[0-9a-f]{64}$ ]]',
    '[[ "$DISPATCH_REF" == "refs/tags/$TAG" ]]',
    '[[ "$DISPATCH_SHA" == "$EXPECTED_COMMIT" ]]',
    '[[ "$WORKFLOW_SHA" == "$EXPECTED_COMMIT" ]]',
    '[[ "$WORKFLOW_REF" == "${GITHUB_REPOSITORY}/.github/workflows/round6-blocked-prerelease.yml@refs/tags/$TAG" ]]',
    '[[ "$HOST_V7283" == PASS ]]',
    '[[ "$HOST_V7282" == PASS ]]',
    '[[ "$HOST_V7281" == PASS ]]',
    '[[ "$INDEPENDENT_AUDIT" == PASS ]]',
    '[[ "$AUTHORIZED" == true ]]',
    '[[ "$HOST_V7283_SHA256" =~ ^[0-9a-f]{64}$ ]]',
    '[[ "$HOST_V7282_SHA256" =~ ^[0-9a-f]{64}$ ]]',
    '[[ "$HOST_V7281_SHA256" =~ ^[0-9a-f]{64}$ ]]',
    '[[ "$INDEPENDENT_AUDIT_SHA256" =~ ^[0-9a-f]{64}$ ]]',
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
SAFE_GATE_COMMANDS = (
    "python3 -B scripts/round6_safe_gate_contract_test.py",
    "python3 -B scripts/round6_safe_gate_contract.py --root .",
)
SAFE_WORKFLOW_ENV_LINES = {
    "GO_VERSION: '1.26.4'",
    "VERSION: '0.1.2'",
    "CYCLONEDX_GOMOD_VERSION: 'v1.9.0'",
    "GOVULNCHECK_VERSION: 'v1.6.0'",
}
SAFE_WORKFLOW_ENV = {
    "GO_VERSION": "1.26.4",
    "VERSION": "0.1.2",
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
    "jobs.verify.steps[9].env",
    "jobs.verify.steps[10].env",
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
        ("Run source and Round6 regression gates", ("name", "run"), None),
        (
            "Verify CPA v7.2.83 primary, v7.2.82 previous, and v7.2.81 backward source compatibility",
            ("name", "env", "run"),
            None,
        ),
        (
            "Build only privacy-safe blocked-development artifacts",
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
            "Recheck immutable tag and create draft blocked prerelease",
            ("name", "env", "run"),
            None,
        ),
    ),
}
ALLOWED_GITHUB_TOKEN_PATHS = {
    "jobs.admission.steps[1].env.GH_TOKEN",
    "jobs.publish.steps[2].env.GH_TOKEN",
}
ALLOWED_GITHUB_IDENTITY_EXPRESSIONS = {
    "jobs.admission.steps[0].env.DISPATCH_REF": "${{ github.ref }}",
    "jobs.admission.steps[0].env.DISPATCH_SHA": "${{ github.sha }}",
    "jobs.admission.steps[0].env.WORKFLOW_REF": "${{ github.workflow_ref }}",
    "jobs.admission.steps[0].env.WORKFLOW_SHA": "${{ github.workflow_sha }}",
}
GITHUB_EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
SENSITIVE_EXPRESSION_CONTEXT = re.compile(r"(?i)(?<![A-Za-z0-9_])(?:github|secrets)(?![A-Za-z0-9_])")
ROUND6_SPARSE_PATTERNS = (
    "/*",
    "!/cmd/evaluation-*",
    "!/cmd/holdout-*",
    "!/cmd/*private*",
    "!/cmd/*blind*",
    "!/cmd/*retired*",
    "!/docs/reports/EVALUATION_*",
    "!/docs/reports/HOLDOUT_*",
    "!/docs/reports/HOLDOUT_REPORT.md",
    "!/docs/**/*private*",
    "!/docs/**/*blind*",
    "!/docs/**/*retired*",
    "!/internal/classifier/evaluation_*",
    "!/internal/classifier/holdout_*",
    "!/internal/classifier/*private*",
    "!/internal/classifier/*blind*",
    "!/internal/classifier/*retired*",
    "!/testdata/evaluation-*",
    "!/testdata/holdout*",
    "!/testdata/*private*",
    "!/testdata/*blind*",
    "!/testdata/*retired*",
)
BLOCKED_STEP_RUN_SHA256 = {
    ("admission", 0): "0f5d145f08d0da37a2e4a6a5b9d8326ba0480d810c7aa10f30973944803ddd6a",
    ("admission", 1): "7f1817ec7b567df4be63fafd9ee2b2347ac37e01982e41ee3338f64c79cae81a",
    ("verify", 1): "b38e1f3a74567d8390bde6390c75c7e96a3bd0d5bc13de0e6a7dbbcfeec0a2fe",
    ("verify", 2): "3427df1bdbbcd38976514b679706f45fe6331981e750168beffd9bfdd1efdea1",
    ("verify", 4): "d53885f6485208a538692ab2737ef0824bc71bcf2f42c0d8c65a60ee906a0503",
    ("verify", 5): "feb84636bac16fb6245913190b0803f0644ee094423c531ad4e59c752e6bc9fd",
    ("verify", 6): "fa50af5a75fcdd76f7a5c0900c3f983b2ee285220229e1746c35671713cba7b7",
    ("verify", 7): "eabde1048cd0f10bfc3540f427c3674b3cf8d5fc0206bebc58e695a328dbb0cb",
    ("verify", 8): "72ba08821693dcb100be3d4dcfaac32d485191186d46fa22119ae7a7b60990b9",
    ("verify", 9): "17e57156996beab078ddb62b4b9c0d5dd1fee6f247fc69e859725a21590bc389",
    ("publish", 1): "d67141ec5e029c4e2176853cb764778a5bfe8afd5ce15cee10417ddc89991182",
    ("publish", 2): "d9a28c9084a735f88d87ecdc7c1dccf3bc9d8518370f6c6e9f3917e43bd769e9",
}
BLOCKED_STEP_RUN_STYLE = {
    ("admission", 0): "|",
    ("admission", 1): "|",
    ("verify", 1): "|",
    ("verify", 2): "|",
    ("verify", 4): "|",
    ("verify", 5): "|",
    ("verify", 6): None,
    ("verify", 7): None,
    ("verify", 8): None,
    ("verify", 9): "|",
    ("publish", 1): "|",
    ("publish", 2): "|",
}
BLOCKED_STEP_ENV = {
    ("admission", 0): (
        ("TAG", "${{ inputs.tag }}"),
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("CI_RUN_ID", "${{ inputs.ci_run_id }}"),
        ("EXPECTED_SO_SHA256", "${{ inputs.expected_so_sha256 }}"),
        ("DISPATCH_REF", "${{ github.ref }}"),
        ("DISPATCH_SHA", "${{ github.sha }}"),
        ("WORKFLOW_REF", "${{ github.workflow_ref }}"),
        ("WORKFLOW_SHA", "${{ github.workflow_sha }}"),
        ("HOST_V7283", "${{ inputs.host_v7283_validation }}"),
        ("HOST_V7283_SHA256", "${{ inputs.host_v7283_evidence_sha256 }}"),
        ("HOST_V7282", "${{ inputs.host_v7282_validation }}"),
        ("HOST_V7282_SHA256", "${{ inputs.host_v7282_evidence_sha256 }}"),
        ("HOST_V7281", "${{ inputs.host_v7281_validation }}"),
        ("HOST_V7281_SHA256", "${{ inputs.host_v7281_evidence_sha256 }}"),
        ("INDEPENDENT_AUDIT", "${{ inputs.independent_audit_validation }}"),
        ("INDEPENDENT_AUDIT_SHA256", "${{ inputs.independent_audit_sha256 }}"),
        ("AUTHORIZED", "${{ inputs.authorize_blocked_prerelease }}"),
    ),
    ("admission", 1): (
        ("CI_RUN_ID", "${{ inputs.ci_run_id }}"),
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("GH_TOKEN", "${{ github.token }}"),
    ),
    ("verify", 2): (
        ("TAG", "${{ inputs.tag }}"),
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
    ),
    ("verify", 6): (("CPA_COMPAT_VERIFY_REMOTE", "1"),),
    ("verify", 7): (
        ("ALLOW_DIRTY_BUILD", "1"),
        ("REQUIRE_DIST_ARTIFACTS", "1"),
    ),
    ("verify", 9): (
        ("TAG", "${{ inputs.tag }}"),
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("EXPECTED_SO_SHA256", "${{ inputs.expected_so_sha256 }}"),
    )
    + CLEAN_EXECUTION_ENV,
    ("verify", 10): CLEAN_EXECUTION_ENV,
    ("publish", 1): (
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("EXPECTED_SO_SHA256", "${{ inputs.expected_so_sha256 }}"),
    ),
    ("publish", 2): (
        ("GH_TOKEN", "${{ github.token }}"),
        ("TAG", "${{ inputs.tag }}"),
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("EXPECTED_SO_SHA256", "${{ inputs.expected_so_sha256 }}"),
        ("CI_RUN_ID", "${{ inputs.ci_run_id }}"),
        ("HOST_V7283_SHA256", "${{ inputs.host_v7283_evidence_sha256 }}"),
        ("HOST_V7282_SHA256", "${{ inputs.host_v7282_evidence_sha256 }}"),
        ("HOST_V7281_SHA256", "${{ inputs.host_v7281_evidence_sha256 }}"),
        ("INDEPENDENT_AUDIT_SHA256", "${{ inputs.independent_audit_sha256 }}"),
    ),
}


class ContractError(RuntimeError):
    pass


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


def validate_sensitive_workflow_expressions(document: MappingNode, source: Path) -> None:
    allowed_seen: set[str] = set()
    for path, node in iter_yaml_scalars(document):
        for match in GITHUB_EXPRESSION.finditer(node.value):
            expression = match.group(1).strip()
            if not SENSITIVE_EXPRESSION_CONTEXT.search(expression):
                continue
            if path in ALLOWED_GITHUB_TOKEN_PATHS and node.value == "${{ github.token }}":
                allowed_seen.add(path)
                continue
            expected_identity = ALLOWED_GITHUB_IDENTITY_EXPRESSIONS.get(path)
            if expected_identity is not None and node.value == expected_identity:
                allowed_seen.add(path)
                continue
            raise ContractError(
                "workflow may not expose a repository token, github.token, or secrets context "
                f"outside the exact reviewed GH_TOKEN env nodes, got {path} in {source}"
            )
    expected_allowed = ALLOWED_GITHUB_TOKEN_PATHS | set(
        ALLOWED_GITHUB_IDENTITY_EXPRESSIONS
    )
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
        if pending.endswith("\\"):
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
    previous_continues = False
    for line in text.splitlines():
        current_continues = line.rstrip().endswith("\\")
        match = variable_command.search(line)
        if match and not previous_continues and not extract_script_references(line):
            variable = match.group(1)
            if variable in static_variables:
                scripts.add(static_variables[variable])
            elif variable not in SAFE_DYNAMIC_TOOL_VARIABLES:
                raise ContractError(
                    f"dynamic command variable cannot be audited safely in {source}: ${variable}"
                )

        if not re.search(r"(?:^|\s)(?:python(?:3(?:\.\d+)?)?|bash|sh|source|\.)(?:\s|$)", line):
            previous_continues = current_continues
            continue
        tokens = shell_tokens(line)
        for index in command_indexes(tokens):
            token = tokens[index]
            name = Path(token).name
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
        previous_continues = current_continues
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
        "host_v7283_validation",
        "host_v7282_validation",
        "host_v7281_validation",
        "independent_audit_validation",
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
                job["permissions"], ("contents",), source, f"{job_path}.permissions"
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
                "inputs.host_v7283_validation == 'PASS' && "
                "inputs.host_v7282_validation == 'PASS' && "
                "inputs.host_v7281_validation == 'PASS' && "
                "inputs.independent_audit_validation == 'PASS' && "
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
            count_words = {2: "two", 3: "three", 11: "eleven"}
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

    upload = yaml_mapping(steps_by_job["verify"][10], source, "jobs.verify.steps[10]")
    upload_with = require_yaml_keys(
        upload["with"],
        ("name", "path", "if-no-files-found", "retention-days"),
        source,
        "jobs.verify.steps[10].with",
    )
    require_yaml_scalar(
        upload_with["name"],
        "round6-blocked-${{ inputs.expected_commit }}",
        source,
        "jobs.verify.steps[10].with.name",
    )
    expected_artifacts = (
        "dist/cyber-abuse-guard-v0.1.2-dirty.so",
        "dist/cyber-abuse-guard-v0.1.2-dirty.so.sha256",
        "dist/cyber-abuse-guard_0.1.2-dirty_linux_amd64.zip",
        "dist/build-metadata.json",
        "dist/checksums.txt",
        "dist/ruleset-manifest.json",
        "dist/ruleset.sha256",
        "dist/sbom.cdx.json",
    )
    upload_paths = yaml_scalar(
        upload_with["path"], source, "jobs.verify.steps[10].with.path"
    )
    if tuple(line.strip() for line in upload_paths.splitlines() if line.strip()) != expected_artifacts:
        raise ContractError("blocked prerelease artifact transfer allowlist changed")
    require_yaml_scalar(
        upload_with["if-no-files-found"],
        "error",
        source,
        "jobs.verify.steps[10].with.if-no-files-found",
    )
    require_yaml_scalar(
        upload_with["retention-days"],
        "1",
        source,
        "jobs.verify.steps[10].with.retention-days",
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


def mutation_shell_commands(text: str) -> tuple[str, ...]:
    commands: list[str] = []
    pending = ""
    heredocs: list[tuple[str, bool]] = []
    for raw in text.splitlines():
        if heredocs:
            delimiter, strip_tabs = heredocs[0]
            candidate = raw.lstrip("\t") if strip_tabs else raw
            if candidate == delimiter:
                heredocs.pop(0)
            continue

        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        continued = line.endswith("\\")
        if continued:
            line = line[:-1].rstrip()
        pending = f"{pending} {line}".strip() if pending else line
        if continued:
            continue

        try:
            shell_tokens(pending)
        except ContractError as exc:
            cause = exc.__cause__
            if isinstance(cause, ValueError) and str(cause) in {
                "No closing quotation",
                "No escaped character",
            }:
                continue
            raise

        commands.append(pending)
        for match in HEREDOC.finditer(pending):
            delimiter = match.group("delimiter")
            if delimiter[:1] in {"'", '"'}:
                delimiter = delimiter[1:-1]
            heredocs.append((delimiter, match.group("strip_tabs") == "-"))
        pending = ""

    if pending:
        raise ContractError("unterminated shell command in blocked prerelease workflow")
    if heredocs:
        raise ContractError("unterminated heredoc in blocked prerelease workflow")
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
    return Path(segment[cursor]).name, segment[cursor + 1 :]


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
    executable, args = unwrapped
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
    validate_sensitive_workflow_expressions(document, source)
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
    if text.count("${{ github.token }}") != 2:
        raise ContractError(
            "blocked prerelease may expose github.token only to reviewed admission and final publish steps"
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
    if len(admission_steps) != 2:
        raise ContractError("blocked prerelease admission must contain exactly two reviewed steps")
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
    if verify_permissions != ("permissions:", "contents: read"):
        raise ContractError("blocked prerelease verify job must remain contents: read only")
    if re.search(r"\$\{\{\s*(?:github\.token|secrets\.)", verify_job) or re.search(
        r"(?m)^\s+(?:GH_TOKEN|GITHUB_TOKEN):", verify_job
    ):
        raise ContractError("blocked prerelease verify job may not receive a repository token")

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
            dist/cyber-abuse-guard-v0.1.2-dirty.so
            dist/cyber-abuse-guard-v0.1.2-dirty.so.sha256
            dist/cyber-abuse-guard_0.1.2-dirty_linux_amd64.zip
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
    if len(publish_steps) != 3:
        raise ContractError("blocked prerelease publish job must contain exactly three reviewed steps")
    download_step, transfer_step, final_publish_step = publish_steps
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
    optional = root / ".github/workflows/blocked-prerelease.yml"
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
    makefile_text = read_regular_text(root / "Makefile", root)
    dependencies, recipes, dynamic_dependencies = parse_makefile(makefile_text)

    direct_targets: set[str] = set()
    inspected_scripts: set[str] = set()
    script_queue: list[str] = []
    for entrypoint in entrypoints:
        text = read_regular_text(entrypoint, root)
        if entrypoint.suffix.lower() in {".yml", ".yaml"}:
            validate_workflow_safety(text, entrypoint)
            if "prerelease" in entrypoint.name.lower():
                validate_blocked_prerelease_workflow(text, entrypoint)
            command_text = "\n".join(yaml_run_blocks(text))
        else:
            command_text = text
        targets, scripts = audit_command_text(command_text, entrypoint)
        direct_targets.update(targets)
        script_queue.extend(scripts)

    visited: set[str] = set()
    target_queue = list(direct_targets)
    while script_queue or target_queue:
        if script_queue:
            relative = script_queue.pop().removeprefix("./")
            if relative in inspected_scripts:
                continue
            assert_safe_repo_path(Path(relative), root)
            if FORBIDDEN_SCRIPT_NAME.search(Path(relative).name):
                raise ContractError(f"Round6 entrypoint reaches forbidden script: {relative}")
            inspected_scripts.add(relative)
            script_path = root / relative
            script_text = read_regular_text(script_path, root)
            suffix = script_path.suffix.lower()
            if suffix == ".sh":
                if script_path.name == "round6-reproducibility-test.sh":
                    validate_round6_reproducibility_script(script_text, script_path)
                if script_path.name == "build-linux-amd64.sh":
                    validate_round6_linux_build_script(script_text, script_path)
                targets, scripts = audit_command_text(script_text, script_path)
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
