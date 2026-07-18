#!/usr/bin/env python3

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

from round6_safe_gate_contract import (
    BLOCKED_PRERELEASE_MARKER,
    CONSUMED_BOUNDARY_LINES,
    EXTERNAL_ATTESTATION_SCRIPT_SHA256,
    FORMAL_OPERATION_SCRIPTS,
    FORBIDDEN_TARGETS,
    ROUND6_SPARSE_PATTERNS,
    ContractError,
    audit,
    default_entrypoints,
    mutation_shell_commands,
    mutating_command_reason,
    shell_command_segments,
    validate_blocked_prerelease_workflow,
    validate_candidate_script,
    validate_candidate_workflow,
    validate_cpa_compat_script,
    validate_consumed_boundary_files,
    validate_formal_release_workflow,
    validate_frozen_evaluation_tree_script,
    validate_release_mode_contracts,
    validate_rc_release_workflow,
    validate_release_promote_workflow,
    validate_reproducibility_wrapper_script,
    validate_round6_doc_fixture_wrapper_script,
    validate_round6_linux_build_script,
    validate_round6_makefile_contract,
    validate_round6_privacy_fixture_script,
    validate_round6_reproducibility_script,
)


CHECKOUT_SHA = "a" * 40


class Round6SafeGateContractTest(unittest.TestCase):
    def checkout_step(self, patterns: tuple[str, ...] = ROUND6_SPARSE_PATTERNS) -> str:
        sparse = "\n".join(f"            {pattern}" for pattern in patterns)
        return f"""      - uses: actions/checkout@{CHECKOUT_SHA}
        with:
          persist-credentials: false
          filter: blob:none
          sparse-checkout-cone-mode: false
          sparse-checkout: |
{sparse}
"""

    def gate_step(self, continue_on_error: bool = False) -> str:
        ignored = "        continue-on-error: true\n" if continue_on_error else ""
        return f"""      - name: Round6 safe gate
{ignored}        run: |
          python3 -B scripts/round6_safe_gate_contract_test.py
          python3 -B scripts/round6_safe_gate_contract.py --root .
"""

    def run_step(self, command: str) -> str:
        if "\n" not in command:
            return f"      - run: {command}\n"
        body = "\n".join(f"          {line}" for line in command.splitlines())
        return f"      - run: |\n{body}\n"

    def workflow(
        self,
        command: str,
        *,
        patterns: tuple[str, ...] = ROUND6_SPARSE_PATTERNS,
        gate: str = "immediate",
        continue_on_error: bool = False,
    ) -> str:
        checkout = self.checkout_step(patterns)
        safe_gate = self.gate_step(continue_on_error)
        command_step = self.run_step(command)
        if gate == "immediate":
            steps = checkout + safe_gate + command_step
        elif gate == "late":
            steps = checkout + command_step + safe_gate
        elif gate == "missing":
            steps = checkout + command_step
        else:
            raise AssertionError(gate)
        return f"""name: CI

on:
  push:

jobs:
  quality:
    runs-on: ubuntu-24.04
    steps:
{steps}"""

    def fixture(
        self,
        makefile: str,
        command: str = "make safe",
        scripts: dict[str, str] | None = None,
        workflow: str | None = None,
    ) -> tuple[Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / ".github/workflows").mkdir(parents=True)
        (root / "scripts").mkdir()
        (root / "Makefile").write_text(makefile, encoding="utf-8")
        entrypoint = root / ".github/workflows/ci.yml"
        entrypoint.write_text(workflow or self.workflow(command), encoding="utf-8")
        payloads = {
            "scripts/round6_safe_gate_contract.py": "# synthetic gate\n",
            "scripts/round6_safe_gate_contract_test.py": "# synthetic gate tests\n",
        }
        payloads.update(scripts or {})
        for relative, content in payloads.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return root, entrypoint

    def test_safe_transitive_graph_passes(self):
        root, entrypoint = self.fixture(
            "unit-test: test\n\ntest:\n\t@true\n",
            "make unit-test",
        )
        targets, _ = audit(root, [entrypoint])
        self.assertEqual(targets, {"unit-test", "test"})

    def test_all_legacy_targets_fail(self):
        for target in sorted(FORBIDDEN_TARGETS):
            with self.subTest(target=target):
                root, entrypoint = self.fixture(f"{target}:\n\t@true\n", f"make {target}")
                with self.assertRaisesRegex(ContractError, "forbidden Make target"):
                    audit(root, [entrypoint])

    def test_second_make_on_same_line_is_audited(self):
        root, entrypoint = self.fixture(
            "safe:\n\t@true\nholdout-test:\n\t@true\n",
            "make safe && make holdout-test",
        )
        with self.assertRaisesRegex(ContractError, "forbidden Make target"):
            audit(root, [entrypoint])

    def test_unknown_target_fails_closed(self):
        root, entrypoint = self.fixture("safe:\n\t@true\n", "make unreviewed-target")
        with self.assertRaisesRegex(ContractError, "unknown Make target"):
            audit(root, [entrypoint])

    def test_dynamic_make_target_fails_closed(self):
        root, entrypoint = self.fixture("safe:\n\t@true\n", "make ${ROUND6_TARGET}")
        with self.assertRaisesRegex(ContractError, "dynamic Make target"):
            audit(root, [entrypoint])

    def test_make_directory_dispatch_fails_closed(self):
        root, entrypoint = self.fixture("safe:\n\t@true\n", "make -C alternate safe")
        with self.assertRaisesRegex(ContractError, "Make directory/file/eval dispatch"):
            audit(root, [entrypoint])

    def test_shell_c_dispatch_fails_closed(self):
        root, entrypoint = self.fixture("safe:\n\t@true\n", "bash -c 'make safe'")
        with self.assertRaisesRegex(ContractError, "dynamic shell dispatch"):
            audit(root, [entrypoint])

    def test_python_c_dispatch_fails_closed(self):
        root, entrypoint = self.fixture("safe:\n\t@true\n", "python3 -c 'print(1)'")
        with self.assertRaisesRegex(ContractError, "dynamic Python dispatch"):
            audit(root, [entrypoint])

    def test_go_all_packages_in_workflow_fails(self):
        root, entrypoint = self.fixture("safe:\n\t@true\n", "go test ./...")
        with self.assertRaisesRegex(ContractError, "reachable go"):
            audit(root, [entrypoint])

    def test_go_all_packages_in_make_recipe_fails(self):
        root, entrypoint = self.fixture("safe:\n\tgo test ./...\n")
        with self.assertRaisesRegex(ContractError, "reachable go"):
            audit(root, [entrypoint])

    def test_go_all_packages_in_shell_script_fails(self):
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            "bash scripts/driver.sh",
            {"scripts/driver.sh": "#!/usr/bin/env bash\ngo test ./...\n"},
        )
        with self.assertRaisesRegex(ContractError, "reachable go"):
            audit(root, [entrypoint])

    def test_python_static_subprocess_is_recursively_audited(self):
        root, entrypoint = self.fixture(
            "holdout-test:\n\t@true\n",
            "python3 scripts/driver.py",
            {
                "scripts/driver.py": (
                    "import subprocess\n"
                    "subprocess.run(['make', 'holdout-test'], check=True)\n"
                )
            },
        )
        with self.assertRaisesRegex(ContractError, "forbidden Make target"):
            audit(root, [entrypoint])

    def test_direct_repository_executable_in_workflow_fails_closed(self):
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            "./tools/run-gate",
            {"tools/run-gate": "#!/usr/bin/env bash\nexit 0\n"},
        )
        with self.assertRaisesRegex(ContractError, "direct repository executable"):
            audit(root, [entrypoint])

    def test_direct_repository_executable_in_make_recipe_fails_closed(self):
        root, entrypoint = self.fixture(
            "safe:\n\t./tools/run-gate\n",
            scripts={"tools/run-gate": "#!/usr/bin/env bash\nexit 0\n"},
        )
        with self.assertRaisesRegex(ContractError, "direct repository executable"):
            audit(root, [entrypoint])

    def test_direct_repository_executable_in_python_subprocess_fails_closed(self):
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            "python3 scripts/driver.py",
            {
                "scripts/driver.py": (
                    "import subprocess\n"
                    "subprocess.run(['./tools/run-gate'], check=True)\n"
                ),
                "tools/run-gate": "#!/usr/bin/env bash\nexit 0\n",
            },
        )
        with self.assertRaisesRegex(ContractError, "direct repository executable"):
            audit(root, [entrypoint])

    def test_shell_array_execution_substitutions_fail_closed(self):
        commands = (
            'values=("$(./tools/run-gate)")\nmake safe',
            'values=(\n  "$(./tools/run-gate)"\n)\nmake safe',
            'values=(`./tools/run-gate`)\nmake safe',
            'values=( <(./tools/run-gate) )\nmake safe',
        )
        for command in commands:
            with self.subTest(command=command):
                root, entrypoint = self.fixture("safe:\n\t@true\n", command)
                with self.assertRaisesRegex(
                    ContractError, "shell array contains executable substitution"
                ):
                    audit(root, [entrypoint])

    def test_shell_array_single_quoted_substitution_is_literal(self):
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            "values=('$(literal)' '<(literal)' '>(literal)' '`literal`')\nmake safe",
        )
        targets, _ = audit(root, [entrypoint])
        self.assertEqual(targets, {"safe"})

    def test_even_trailing_backslashes_do_not_hide_next_command(self):
        command = "printf '%s' safe " + "\\\\" + "\n$runner\nmake safe"
        root, entrypoint = self.fixture("safe:\n\t@true\n", command)
        with self.assertRaisesRegex(ContractError, "dynamic command variable"):
            audit(root, [entrypoint])

    def test_python_dynamic_subprocess_fails_closed(self):
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            "python3 scripts/driver.py",
            {
                "scripts/driver.py": (
                    "import subprocess\n"
                    "command = ['make', 'safe']\n"
                    "subprocess.run(command, check=True)\n"
                )
            },
        )
        with self.assertRaisesRegex(ContractError, "dynamic Python command"):
            audit(root, [entrypoint])

    def test_python_shell_true_fails_closed(self):
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            "python3 scripts/driver.py",
            {
                "scripts/driver.py": (
                    "import subprocess\n"
                    "subprocess.run(['make', 'safe'], shell=True, check=True)\n"
                )
            },
        )
        with self.assertRaisesRegex(ContractError, "Python shell dispatch"):
            audit(root, [entrypoint])

    def test_python_os_system_fails_closed(self):
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            "python3 scripts/driver.py",
            {"scripts/driver.py": "import os\nos.system('make safe')\n"},
        )
        with self.assertRaisesRegex(ContractError, "Python shell dispatch"):
            audit(root, [entrypoint])

    def test_python_local_import_is_recursively_audited(self):
        root, entrypoint = self.fixture(
            "holdout-test:\n\t@true\n",
            "python3 scripts/driver.py",
            {
                "scripts/driver.py": "import helper\n",
                "scripts/helper.py": (
                    "import subprocess\n"
                    "subprocess.run(['make', 'holdout-test'], check=True)\n"
                ),
            },
        )
        with self.assertRaisesRegex(ContractError, "forbidden Make target"):
            audit(root, [entrypoint])

    def test_restricted_script_name_is_refused_before_read(self):
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            "python3 scripts/private_helper.py",
            {"scripts/private_helper.py": "raise AssertionError('must not be parsed')\n"},
        )
        with self.assertRaisesRegex(ContractError, "refuses restricted path before reading"):
            audit(root, [entrypoint])

    def test_checkout_without_gate_fails(self):
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            workflow=self.workflow("make safe", gate="missing"),
        )
        with self.assertRaisesRegex(ContractError, "immediately after checkout"):
            audit(root, [entrypoint])

    def test_gate_after_repository_command_fails(self):
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            workflow=self.workflow("make safe", gate="late"),
        )
        with self.assertRaisesRegex(ContractError, "immediately after checkout"):
            audit(root, [entrypoint])

    def test_gate_continue_on_error_fails(self):
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            workflow=self.workflow("make safe", continue_on_error=True),
        )
        with self.assertRaisesRegex(ContractError, "immediately after checkout"):
            audit(root, [entrypoint])

    def test_sparse_checkout_missing_private_pattern_fails(self):
        patterns = tuple(
            pattern
            for pattern in ROUND6_SPARSE_PATTERNS
            if pattern != "!/cmd/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*"
        )
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            workflow=self.workflow("make safe", patterns=patterns),
        )
        with self.assertRaisesRegex(ContractError, "sparse checkout differs"):
            audit(root, [entrypoint])

    def test_sparse_checkout_missing_consumed_pattern_fails(self):
        self.assertIn("!/internal/classifier/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*", ROUND6_SPARSE_PATTERNS)
        patterns = tuple(
            pattern
            for pattern in ROUND6_SPARSE_PATTERNS
            if pattern != "!/internal/classifier/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*"
        )
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            workflow=self.workflow("make safe", patterns=patterns),
        )
        with self.assertRaisesRegex(ContractError, "sparse checkout differs"):
            audit(root, [entrypoint])

    def test_windows_or_macos_runner_fails(self):
        for runner in ("windows-2025", "macos-15"):
            with self.subTest(runner=runner):
                root, entrypoint = self.fixture(
                    "safe:\n\t@true\n",
                    workflow=self.workflow("make safe").replace(
                        "runs-on: ubuntu-24.04", f"runs-on: {runner}"
                    ),
                )
                with self.assertRaisesRegex(ContractError, "Linux amd64 runner"):
                    audit(root, [entrypoint])

    def test_workflow_defaults_shell_override_fails(self):
        workflow = self.workflow("make safe").replace(
            "jobs:\n",
            "defaults:\n  run:\n    shell: bash {0}\n\njobs:\n",
        )
        root, entrypoint = self.fixture("safe:\n\t@true\n", workflow=workflow)
        with self.assertRaisesRegex(ContractError, "override the reviewed run shell"):
            audit(root, [entrypoint])

    def test_workflow_container_override_fails(self):
        workflow = self.workflow("make safe").replace(
            "    runs-on: ubuntu-24.04\n",
            "    runs-on: ubuntu-24.04\n    container: attacker-controlled:latest\n",
            1,
        )
        root, entrypoint = self.fixture("safe:\n\t@true\n", workflow=workflow)
        with self.assertRaisesRegex(ContractError, "may not define container"):
            audit(root, [entrypoint])

    def test_workflow_quoted_or_anchored_execution_keys_fail(self):
        mutations = (
            self.workflow("make safe").replace(
                "jobs:\n", '"defaults":\n  run:\n    shell: bash {0}\n\njobs:\n'
            ),
            self.workflow("make safe").replace(
                "jobs:\n", "defaults: &unsafe_defaults\n  run:\n    shell: bash {0}\n\njobs:\n"
            ),
            self.workflow("make safe").replace(
                "    runs-on: ubuntu-24.04\n",
                '    runs-on: ubuntu-24.04\n    "container": attacker-controlled:latest\n',
                1,
            ),
            self.workflow("make safe").replace(
                "        run: |\n",
                '        "shell": bash {0}\n        run: |\n',
                1,
            ),
            self.workflow("make safe").replace(
                "jobs:\n", "&unsafe_key defaults:\n  run:\n    shell: bash {0}\n\njobs:\n"
            ),
            self.workflow("make safe").replace(
                "jobs:\n", "!!str defaults:\n  run:\n    shell: bash {0}\n\njobs:\n"
            ),
            self.workflow("make safe").replace(
                "    runs-on: ubuntu-24.04\n",
                "    runs-on: ubuntu-24.04\n    &unsafe_key container: attacker-controlled:latest\n",
                1,
            ),
            self.workflow("make safe").replace(
                "        run: |\n",
                "        &unsafe_key shell: bash {0}\n        run: |\n",
                1,
            ),
            self.workflow("make safe").replace(
                "jobs:\n",
                "&env_key env:\n  &unsafe_key BASH_ENV: ./scripts/evil-bash-env.sh\n\njobs:\n",
            ),
            self.workflow("make safe").replace(
                "jobs:\n", "defaults: *unsafe_defaults\n\njobs:\n"
            ),
            "%YAML 1.2\n---\n" + self.workflow("make safe"),
            self.workflow("make safe").replace(
                "jobs:\n", "env: {BASH_ENV: ./scripts/evil-bash-env.sh}\n\njobs:\n"
            ),
        )
        for index, workflow in enumerate(mutations):
            with self.subTest(index=index):
                root, entrypoint = self.fixture("safe:\n\t@true\n", workflow=workflow)
                with self.assertRaisesRegex(
                    ContractError, "quoted|anchors|override the reviewed run shell"
                ):
                    audit(root, [entrypoint])

    def test_workflow_dangerous_execution_environment_fails(self):
        workflow = self.workflow("make safe").replace(
            "jobs:\n", "env:\n  BASH_ENV: ./scripts/evil-bash-env.sh\n\njobs:\n"
        )
        root, entrypoint = self.fixture("safe:\n\t@true\n", workflow=workflow)
        with self.assertRaisesRegex(ContractError, "top-level env|dangerous execution-context"):
            audit(root, [entrypoint])

    def test_workflow_spaced_semantic_execution_keys_fail(self):
        mutations = (
            self.workflow("make safe").replace(
                "jobs:\n", "defaults :\n  run:\n    shell: bash {0}\n\njobs:\n"
            ),
            self.workflow("make safe").replace(
                "    runs-on: ubuntu-24.04\n",
                "    runs-on: ubuntu-24.04\n    container : attacker-controlled:latest\n",
                1,
            ),
            self.workflow("make safe").replace(
                "        run: |\n", "        shell : bash {0}\n        run: |\n", 1
            ),
            self.workflow("make safe").replace(
                "jobs:\n", "env :\n  BASH_ENV : ./scripts/evil-bash-env.sh\n\njobs:\n"
            ),
            self.workflow("make safe").replace(
                "      - name: Round6 safe gate\n",
                "      - name: Round6 safe gate\n        continue-on-error : true\n",
                1,
            ),
        )
        for index, workflow in enumerate(mutations):
            with self.subTest(index=index):
                root, entrypoint = self.fixture("safe:\n\t@true\n", workflow=workflow)
                with self.assertRaisesRegex(
                    ContractError,
                    "override the reviewed run shell|container|step shell|top-level env|immediately after checkout",
                ):
                    audit(root, [entrypoint])

    def test_workflow_explicit_mapping_key_fails(self):
        workflow = self.workflow("make safe").replace(
            "jobs:\n", "? defaults\n:\n  run:\n    shell: bash {0}\n\njobs:\n"
        )
        root, entrypoint = self.fixture("safe:\n\t@true\n", workflow=workflow)
        with self.assertRaisesRegex(ContractError, "explicit YAML mapping keys"):
            audit(root, [entrypoint])

    def test_workflow_duplicate_semantic_key_fails(self):
        workflow = self.workflow("make safe").replace(
            "    runs-on: ubuntu-24.04\n",
            "    runs-on: ubuntu-24.04\n    runs-on : ubuntu-24.04\n",
            1,
        )
        root, entrypoint = self.fixture("safe:\n\t@true\n", workflow=workflow)
        with self.assertRaisesRegex(ContractError, "duplicate semantic key"):
            audit(root, [entrypoint])

    def reproducibility_script(self) -> tuple[str, Path]:
        source = Path(__file__).with_name("round6-reproducibility-test.sh")
        return source.read_text(encoding="utf-8"), source

    def test_reproducibility_sparse_contract_passes(self):
        text, source = self.reproducibility_script()
        validate_round6_reproducibility_script(text, source)

    def test_reproducibility_sparse_contract_mismatch_fails(self):
        original, source = self.reproducibility_script()
        text = original.replace(" '!/testdata/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*'", "", 1)
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "differs from the workflow contract"):
            validate_round6_reproducibility_script(text, source)

    def test_reproducibility_consumed_sparse_contract_mismatch_fails(self):
        original, source = self.reproducibility_script()
        text = original.replace(" '!/internal/classifier/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*'", "", 1)
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "differs from the workflow contract"):
            validate_round6_reproducibility_script(text, source)

    def test_reproducibility_entry_mode_contract_is_locked(self):
        original, source = self.reproducibility_script()
        text = original.replace(
            'reproducibility_mode="${ROUND6_REPRODUCIBILITY_MODE:-release}"',
            'reproducibility_mode="${ROUND6_REPRODUCIBILITY_MODE:-development}"',
            1,
        )
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "entry mode"):
            validate_round6_reproducibility_script(text, source)

    def test_consumed_nonworkflow_boundaries_are_mutation_locked(self):
        root = Path(__file__).parent.parent
        validate_consumed_boundary_files(root)
        for relative, required_lines in CONSUMED_BOUNDARY_LINES.items():
            for required in required_lines:
                with self.subTest(relative=relative, required=required):
                    temporary = tempfile.TemporaryDirectory()
                    self.addCleanup(temporary.cleanup)
                    fixture = Path(temporary.name)
                    for boundary_relative in CONSUMED_BOUNDARY_LINES:
                        source = root / boundary_relative
                        destination = fixture / boundary_relative
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        text = source.read_text(encoding="utf-8")
                        if boundary_relative == relative:
                            text = text.replace(required + "\n", "", 1)
                        destination.write_text(text, encoding="utf-8")
                    with self.assertRaisesRegex(ContractError, "consumed exclusion boundary"):
                        validate_consumed_boundary_files(fixture)

    def test_reproducibility_package_release_cannot_escape_formal_branch(self):
        original, source = self.reproducibility_script()
        mutations = (
            original.replace(
                '  if [[ "$RELEASE_BUILD_KIND" == formal ]]; then\n'
                '    env "${common_env[@]}" "$clone/scripts/package-release.sh"\n',
                '  if [[ "$RELEASE_BUILD_KIND" == candidate ]]; then\n'
                '    env "${common_env[@]}" "$clone/scripts/package-release.sh"\n',
                1,
            ),
            original.replace(
                '    env "${common_env[@]}" "$clone/scripts/package-release.sh"\n',
                "    true\n",
                1,
            )
            + 'env "${common_env[@]}" "$clone/scripts/package-release.sh"\n',
        )
        for text in mutations:
            self.assertNotEqual(text, original)
            with self.assertRaisesRegex(ContractError, "formal-only branch"):
                validate_round6_reproducibility_script(text, source)

    def test_reproducibility_checksums_manifest_is_generated_and_compared(self):
        original, source = self.reproducibility_script()
        mutations = (
            original.replace("        sbom.cdx.json >checksums.txt\n", "", 1),
            original.replace(
                'compare_artifact "checksums manifest" checksums.txt\n', "", 1
            ),
            original.replace(" build-metadata.json checksums.txt \\\n", " build-metadata.json \\\n", 1),
        )
        for text in mutations:
            self.assertNotEqual(text, original)
            with self.assertRaisesRegex(ContractError, "checksums manifest"):
                validate_round6_reproducibility_script(text, source)

    def test_reproducibility_wrapper_is_exact_and_only_delegates(self):
        source = Path(__file__).with_name("reproducibility-test.sh")
        text = source.read_text(encoding="utf-8")
        validate_reproducibility_wrapper_script(text, source)
        with self.assertRaisesRegex(ContractError, "exact reviewed"):
            validate_reproducibility_wrapper_script(text + "\ntrue\n", source)

    def test_frozen_evaluation_tree_verifier_is_exact_metadata_only_contract(self):
        source = Path(__file__).with_name("verify-frozen-evaluation-v10-tree.sh")
        text = source.read_text(encoding="utf-8")
        validate_frozen_evaluation_tree_script(text, source)
        with self.assertRaisesRegex(ContractError, "metadata-only contract"):
            validate_frozen_evaluation_tree_script(text + "\ntrue\n", source)
        without_untracked = text.replace("--untracked-files=all", "--untracked-files=no", 1)
        self.assertNotEqual(without_untracked, text)
        with self.assertRaisesRegex(ContractError, "staged, unstaged, and untracked"):
            validate_frozen_evaluation_tree_script(without_untracked, source)

    def test_round6_privacy_and_document_fixture_hashes_are_frozen(self):
        root = Path(__file__).parent.parent
        privacy = root / "scripts/release-evidence-privacy-test.sh"
        privacy_text = privacy.read_text(encoding="utf-8")
        validate_round6_privacy_fixture_script(privacy_text, privacy)
        with self.assertRaisesRegex(ContractError, "privacy fixture"):
            validate_round6_privacy_fixture_script(privacy_text + "\ntrue\n", privacy)

        wrapper = root / "scripts/round6-doc-consistency-fixture-test.sh"
        wrapper_text = wrapper.read_text(encoding="utf-8")
        validate_round6_doc_fixture_wrapper_script(wrapper_text, wrapper, root)
        with self.assertRaisesRegex(ContractError, "document fixture wrapper"):
            validate_round6_doc_fixture_wrapper_script(
                wrapper_text + "\ntrue\n", wrapper, root
            )

    def test_cpa_local_compatibility_output_cannot_claim_latest_pass(self):
        source = Path(__file__).with_name("cpa-latest-compat.sh")
        text = source.read_text(encoding="utf-8")
        validate_cpa_compat_script(text, source)
        mutation = text + "\nprintf 'CPA latest source/compile compatibility PASS'\n"
        with self.assertRaisesRegex(ContractError, "only after remote verification"):
            validate_cpa_compat_script(mutation, source)

    def test_cpa_compatibility_remote_control_flow_is_frozen(self):
        source = Path(__file__).with_name("cpa-latest-compat.sh")
        text = source.read_text(encoding="utf-8")
        mutations = (
            text + "\n: <<'ROUND6_INERT'\nremote check bypass fixture\nROUND6_INERT\n",
            text.replace(
                'if [[ "$verify_remote" == 1 ]]; then\n  for required_command in curl jq; do',
                'if false; then\n  for required_command in curl jq; do',
                1,
            ),
        )
        for mutation in mutations:
            self.assertNotEqual(mutation, text)
            with self.assertRaisesRegex(ContractError, "exact reviewed remote-verification contract"):
                validate_cpa_compat_script(mutation, source)

    def test_linux_build_glibc_contract_passes(self):
        source = Path(__file__).with_name("build-linux-amd64.sh")
        validate_round6_linux_build_script(source.read_text(encoding="utf-8"), source)

    def test_linux_build_glibc_contract_bypass_fails(self):
        source = Path(__file__).with_name("build-linux-amd64.sh")
        text = source.read_text(encoding="utf-8").replace(
            '"$(printf \'%s\\n\' "$max_glibc" \'2.34\' | sort -V | tail -1)" != 2.34',
            '"$(printf \'%s\\n\' "$max_glibc" \'2.35\' | sort -V | tail -1)" != 2.35',
        )
        with self.assertRaisesRegex(ContractError, "glibc 2.34"):
            validate_round6_linux_build_script(text, source)

    def test_linux_build_glibc_missing_exit_fails(self):
        source = Path(__file__).with_name("build-linux-amd64.sh")
        original = source.read_text(encoding="utf-8")
        text = original.replace(
            "  printf 'build requires unsupported glibc %s; maximum allowed is 2.34\\n' \"$max_glibc\" >&2\n"
            "  exit 1\n",
            "  printf 'build requires unsupported glibc %s; maximum allowed is 2.34\\n' \"$max_glibc\" >&2\n",
        )
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "exact glibc 2.34"):
            validate_round6_linux_build_script(text, source)

    def test_linux_build_glibc_if_false_fails(self):
        source = Path(__file__).with_name("build-linux-amd64.sh")
        original = source.read_text(encoding="utf-8")
        text = original.replace('file "$artifact"\n', 'if false; then\nfile "$artifact"\n').replace(
            '(cd "$dist" && sha256sum -c "$(basename "$artifact").sha256")\n',
            '(cd "$dist" && sha256sum -c "$(basename "$artifact").sha256")\nfi\n',
        )
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "exact glibc 2.34|control wrapper"):
            validate_round6_linux_build_script(text, source)

    def test_linux_build_glibc_or_true_fails(self):
        source = Path(__file__).with_name("build-linux-amd64.sh")
        original = source.read_text(encoding="utf-8")
        text = original.replace('  LC_ALL=C sort -u)"\n', '  LC_ALL=C sort -u)" || true\n', 1)
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "exact glibc 2.34|success bypass"):
            validate_round6_linux_build_script(text, source)

    def test_linux_build_set_plus_e_fails(self):
        source = Path(__file__).with_name("build-linux-amd64.sh")
        original = source.read_text(encoding="utf-8")
        text = original.replace("set -euo pipefail\n", "set -euo pipefail\nset +e\n", 1)
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "exact glibc 2.34"):
            validate_round6_linux_build_script(text, source)

    def test_linux_build_bare_exit_before_checks_fails(self):
        source = Path(__file__).with_name("build-linux-amd64.sh")
        original = source.read_text(encoding="utf-8")
        text = original.replace(
            'OUTPUT_DIR="$dist" GO="$go_bin" "$root/scripts/release-build-metadata.sh"\n',
            'exit\nOUTPUT_DIR="$dist" GO="$go_bin" "$root/scripts/release-build-metadata.sh"\n',
            1,
        )
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "exact glibc 2.34"):
            validate_round6_linux_build_script(text, source)

    def test_linux_build_allowed_if_wrapper_still_fails(self):
        source = Path(__file__).with_name("build-linux-amd64.sh")
        original = source.read_text(encoding="utf-8")
        text = original.replace(
            'OUTPUT_DIR="$dist" GO="$go_bin" "$root/scripts/release-build-metadata.sh"\n',
            'if [[ "$go_version" != go1.26.4 ]]; then\n'
            'OUTPUT_DIR="$dist" GO="$go_bin" "$root/scripts/release-build-metadata.sh"\n',
            1,
        ).replace(
            'release_assert_source_unchanged\n',
            'release_assert_source_unchanged\nfi\n',
            1,
        )
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "exact glibc 2.34"):
            validate_round6_linux_build_script(text, source)

    def test_round6_benchmark_contract_passes(self):
        source = Path(__file__).parent.parent / "Makefile"
        validate_round6_makefile_contract(source.read_text(encoding="utf-8"), source)

    def test_round6_benchmark_wrong_package_fails(self):
        source = Path(__file__).parent.parent / "Makefile"
        original = source.read_text(encoding="utf-8")
        text = original.replace(
            "$(GO) test ./internal/extract -run='^$$'",
            "$(GO) test ./internal/classifier -run='^$$'",
        )
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "execute the extract benchmark"):
            validate_round6_makefile_contract(text, source)

    def test_round6_module_verify_tidy_diff_is_integration_only(self):
        source = Path(__file__).parent.parent / "Makefile"
        original = source.read_text(encoding="utf-8")
        before, marker, round6 = original.partition("round6-module-verify:")
        self.assertTrue(marker)
        mutations = tuple(
            before + marker + mutation
            for mutation in (
                round6.replace(
                    "\t$(GO) -C integration/pluginstorecontract mod tidy -diff\n",
                    "",
                    1,
                ),
                round6.replace(
                    "\t$(GO) -C integration/cpalatestcontract mod tidy -diff\n",
                    "",
                    1,
                ),
                round6.replace(
                    "\t$(GO) mod verify\n",
                    "\t$(GO) mod verify\n\t$(GO) mod tidy -diff\n",
                    1,
                ),
            )
        )
        for text in mutations:
            self.assertNotEqual(text, original)
            with self.assertRaisesRegex(ContractError, "included integration modules"):
                validate_round6_makefile_contract(text, source)

    def test_round6_makefile_candidate_script_gates_are_reachable(self):
        source = Path(__file__).parent.parent / "Makefile"
        original = source.read_text(encoding="utf-8")
        required_lines = (
            "\tbash -n ./scripts/round6-candidate-artifacts.sh\n",
            "\t./scripts/release-candidate-contract-test.sh\n",
            "\tbash -n ./scripts/verify-external-release-attestation.sh\n",
            "\t./scripts/verify-external-release-attestation-test.sh\n",
        )
        for required_line in required_lines:
            with self.subTest(required_line=required_line.strip()):
                text = original.replace(required_line, "", 1)
                self.assertNotEqual(text, original)
                with self.assertRaisesRegex(ContractError, "reviewed Round6 script gate"):
                    validate_round6_makefile_contract(text, source)

    def test_round6_makefile_runs_privacy_safe_mutation_fixtures(self):
        source = Path(__file__).parent.parent / "Makefile"
        original = source.read_text(encoding="utf-8")
        before, marker, round6 = original.rpartition("round6-script-test:")
        self.assertTrue(marker)
        for required_line in (
            "\tbash ./scripts/release-evidence-privacy-test.sh\n",
            "\tbash ./scripts/round6-doc-consistency-fixture-test.sh\n",
        ):
            with self.subTest(required_line=required_line.strip()):
                mutated_round6 = round6.replace(required_line, "", 1)
                self.assertNotEqual(mutated_round6, round6)
                text = before + marker + mutated_round6
                with self.assertRaisesRegex(ContractError, "privacy-safe mutation fixture"):
                    validate_round6_makefile_contract(text, source)

    def candidate_workflow(self) -> str:
        source = Path(__file__).parent.parent / ".github/workflows/round6-candidate.yml"
        return source.read_text(encoding="utf-8")

    def formal_release_workflow(self) -> str:
        source = Path(__file__).parent.parent / ".github/workflows/release.yml"
        return source.read_text(encoding="utf-8")

    def release_promote_workflow(self) -> str:
        source = Path(__file__).parent.parent / ".github/workflows/release-promote.yml"
        return source.read_text(encoding="utf-8")

    def test_candidate_workflow_full_contract_passes(self):
        validate_candidate_workflow(
            self.candidate_workflow(), Path("round6-candidate.yml")
        )

    def test_candidate_workflow_must_remain_manual_and_read_only(self):
        original = self.candidate_workflow()
        mutations = (
            original.replace("  workflow_dispatch:\n", "  push:\n", 1),
            original.replace("  contents: read\n", "  contents: write\n", 1),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(ContractError, "manual-only|read|exact scalar"):
                validate_candidate_workflow(workflow, Path("round6-candidate.yml"))

    def test_candidate_workflow_exact_commit_and_push_ci_binding_are_locked(self):
        original = self.candidate_workflow()
        protected_lines = (
            '          [[ "$DISPATCH_REF" == "refs/heads/main" ]]\n',
            '          [[ "$DISPATCH_SHA" == "$EXPECTED_COMMIT" ]]\n',
            '             .event == "push" and\n',
            '             .head_sha == $expected_commit and\n',
            '             .conclusion == "success" and\n',
        )
        for protected_line in protected_lines:
            with self.subTest(protected_line=protected_line.strip()):
                workflow = original.replace(protected_line, "", 1)
                self.assertNotEqual(workflow, original)
                with self.assertRaisesRegex(ContractError, "exact reviewed text"):
                    validate_candidate_workflow(workflow, Path("round6-candidate.yml"))

    def test_candidate_workflow_sparse_boundary_and_gate_are_locked(self):
        original = self.candidate_workflow()
        mutations = (
            original.replace("            !/testdata/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*\n", "", 1),
            original.replace(
                "          python3 -B scripts/round6_safe_gate_contract.py --root .\n",
                "          true\n",
                1,
            ),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(ContractError, "sparse|safe-gate"):
                validate_candidate_workflow(workflow, Path("round6-candidate.yml"))

    def test_candidate_workflow_consumed_boundary_is_locked(self):
        original = self.candidate_workflow()
        workflow = original.replace(
            "            !/internal/classifier/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*\n", "", 1
        )
        self.assertNotEqual(workflow, original)
        with self.assertRaisesRegex(ContractError, "sparse"):
            validate_candidate_workflow(workflow, Path("round6-candidate.yml"))

    def test_candidate_builder_reproducibility_and_clean_names_are_locked(self):
        original = self.candidate_workflow()
        mutations = (
            original.replace(
                "        run: ./scripts/round6-candidate-artifacts.sh\n",
                "        run: true\n",
                1,
            ),
            original.replace(
                "        run: make round6-reproducibility-test\n",
                "        run: make clean-tree-check\n",
                1,
            ),
            original.replace(
                "            dist/cyber-abuse-guard_0.15_linux_amd64.zip\n",
                "            dist/nested/cyber-abuse-guard_0.15-dirty_linux_amd64.zip\n",
                1,
            ),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(ContractError, "exact reviewed text|artifact allowlist"):
                validate_candidate_workflow(workflow, Path("round6-candidate.yml"))

    def test_candidate_workflow_rejects_release_or_token_expansion(self):
        original = self.candidate_workflow()
        release_action = original.replace(
            "      - name: Upload private exact-commit candidate\n",
            "      - name: Publish candidate\n"
            "        uses: softprops/action-gh-release@0123456789abcdef0123456789abcdef01234567\n"
            "      - name: Upload private exact-commit candidate\n",
            1,
        )
        token_expansion = original.replace(
            "          CPA_COMPAT_VERIFY_REMOTE: '1'\n",
            "          CPA_COMPAT_VERIFY_REMOTE: '1'\n"
            "          UNREVIEWED_TOKEN: ${{ github.token }}\n",
            1,
        )
        git_tag = original.replace(
            "        run: ./scripts/round6-candidate-artifacts.sh\n",
            "        run: git tag -f v0.15 HEAD\n",
            1,
        )
        for workflow in (release_action, token_expansion, git_tag):
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(
                ContractError,
                "reviewed steps|github.token|repository token|exact reviewed text|tags or releases",
            ):
                validate_candidate_workflow(workflow, Path("round6-candidate.yml"))

    def test_candidate_scripts_match_reviewed_contract_and_are_ci_reachable(self):
        root = Path(__file__).parent.parent
        for name in (
            "round6-candidate-artifacts.sh",
            "release-candidate-contract-test.sh",
        ):
            with self.subTest(name=name):
                source = root / "scripts" / name
                text = source.read_text(encoding="utf-8")
                validate_candidate_script(text, source)
                with self.assertRaisesRegex(ContractError, "exact reviewed"):
                    validate_candidate_script(text + "\n# bypass\n", source)
        _, inspected = audit(root, default_entrypoints(root))
        self.assertTrue(
            {
                "scripts/round6-candidate-artifacts.sh",
                "scripts/release-candidate-contract-test.sh",
                "scripts/reproducibility-test.sh",
                "scripts/verify-frozen-evaluation-v10-tree.sh",
                "scripts/verify-external-release-attestation.sh",
                "scripts/verify-external-release-attestation-test.sh",
            }.issubset(inspected)
        )

    def test_formal_release_workflow_full_contract_passes(self):
        validate_formal_release_workflow(
            self.formal_release_workflow(), Path("release.yml")
        )

    def test_formal_release_read_build_and_write_publish_are_separated(self):
        original = self.formal_release_workflow()
        mutations = (
            original.replace("      actions: read\n", "", 1),
            original.replace("      contents: read\n", "      contents: write\n", 1),
            original.replace(
                "      ROUND6_SAFE_SPARSE_BUILD: '1'\n",
                "      ROUND6_SAFE_SPARSE_BUILD: '0'\n",
                1,
            ),
            original.replace("          BASH_ENV: ''\n", "          BASH_ENV: /tmp/attacker\n", 1),
            original.replace(
                "      - name: Download exact verified release artifact\n",
                "      - name: Checkout in write job\n"
                "        uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n"
                "      - name: Download exact verified release artifact\n",
                1,
            ),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(
                ContractError,
                "actions|exact scalar|four reviewed steps|contents|verifier environment|sparse-build",
            ):
                validate_formal_release_workflow(workflow, Path("release.yml"))

    def test_formal_release_draft_flags_and_attested_assets_are_locked(self):
        original = self.formal_release_workflow()
        mutations = (
            original.replace("          draft: true\n", "          draft: false\n", 1),
            original.replace("          make_latest: false\n", "          make_latest: true\n", 1),
            original.replace(
                "            dist/formal-release-attestation.json.sha256\n",
                "",
                1,
            ),
            original.replace(
                '          cmp -s "$ROUND6_CANDIDATE_SO" dist/cyber-abuse-guard-v0.15.so\n',
                "",
                1,
            ),
            original.replace(
                '            ./scripts/verify-external-release-attestation.sh "$attestation"\n',
                "",
                1,
            ),
            original.replace("            !/testdata/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*\n", "", 1),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(
                ContractError,
                "exact scalar|artifact transfer|exact reviewed text|sparse checkout",
            ):
                validate_formal_release_workflow(workflow, Path("release.yml"))

    def test_formal_release_no_checkout_admission_is_required_before_build(self):
        original = self.formal_release_workflow()
        mutations = (
            original.replace("    needs: admission\n", "", 1),
            original.replace(
                '          [[ "$(jq -r \'.object.sha\' <<<"$main_ref")" == "$DISPATCH_SHA" ]]\n',
                "",
                1,
            ),
            original.replace(
                '              .commit == $commit and .tree == $tree and\n',
                '              .tree == $tree and\n',
                1,
            ),
            original.replace(
                "      - name: Admit exact main-tip tag and attested Round6 candidate before checkout\n",
                "      - name: Checkout unadmitted repository code\n"
                "        uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n"
                "      - name: Admit exact main-tip tag and attested Round6 candidate before checkout\n",
                1,
            ),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(
                ContractError, "admission|exact reviewed text|exact scalar|no-checkout|keys/order"
            ):
                validate_formal_release_workflow(workflow, Path("release.yml"))

    def test_formal_release_consumed_sparse_boundary_is_locked(self):
        original = self.formal_release_workflow()
        workflow = original.replace(
            "            !/internal/classifier/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*\n", "", 1
        )
        self.assertNotEqual(workflow, original)
        with self.assertRaisesRegex(ContractError, "sparse checkout"):
            validate_formal_release_workflow(workflow, Path("release.yml"))

    def test_formal_operations_cannot_use_candidate_tag_bypass(self):
        root = Path(__file__).parent.parent
        validate_release_mode_contracts(root)
        for script_name in FORMAL_OPERATION_SCRIPTS:
            with self.subTest(script_name=script_name):
                temporary = tempfile.TemporaryDirectory()
                self.addCleanup(temporary.cleanup)
                fixture = Path(temporary.name)
                (fixture / "scripts").mkdir()
                names = (
                    "release-common.sh",
                ) + FORMAL_OPERATION_SCRIPTS + tuple(EXTERNAL_ATTESTATION_SCRIPT_SHA256)
                for name in names:
                    text = (root / "scripts" / name).read_text(encoding="utf-8")
                    if name == script_name:
                        text = text.replace("release_assert_formal_build\n", "true\n", 1)
                    (fixture / "scripts" / name).write_text(text, encoding="utf-8")
                with self.assertRaisesRegex(ContractError, "release_assert_formal_build"):
                    validate_release_mode_contracts(fixture)

    def test_release_common_formal_assertion_rejects_candidate_mode(self):
        root = Path(__file__).parent.parent
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        fixture = Path(temporary.name)
        (fixture / "scripts").mkdir()
        for name in (
            "release-common.sh",
        ) + FORMAL_OPERATION_SCRIPTS + tuple(EXTERNAL_ATTESTATION_SCRIPT_SHA256):
            text = (root / "scripts" / name).read_text(encoding="utf-8")
            if name == "release-common.sh":
                text = text.replace(
                    '[[ "$RELEASE_BUILD_KIND" == formal ]]',
                    '[[ "$RELEASE_BUILD_KIND" == candidate ]]',
                    1,
                )
            (fixture / "scripts" / name).write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(ContractError, "reject candidate"):
            validate_release_mode_contracts(fixture)

    def test_external_attestation_verifier_and_contract_are_locked(self):
        root = Path(__file__).parent.parent
        for changed_name in EXTERNAL_ATTESTATION_SCRIPT_SHA256:
            with self.subTest(changed_name=changed_name):
                temporary = tempfile.TemporaryDirectory()
                self.addCleanup(temporary.cleanup)
                fixture = Path(temporary.name)
                (fixture / "scripts").mkdir()
                names = (
                    "release-common.sh",
                ) + FORMAL_OPERATION_SCRIPTS + tuple(EXTERNAL_ATTESTATION_SCRIPT_SHA256)
                for name in names:
                    text = (root / "scripts" / name).read_text(encoding="utf-8")
                    if name == changed_name:
                        text += "\n# bypass\n"
                    (fixture / "scripts" / name).write_text(text, encoding="utf-8")
                with self.assertRaisesRegex(
                    ContractError, "external release attestation script differs"
                ):
                    validate_release_mode_contracts(fixture)

    def test_release_evidence_uses_exact_immutable_attestation_snapshot_contract(self):
        root = Path(__file__).parent.parent
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        fixture = Path(temporary.name)
        (fixture / "scripts").mkdir()
        names = (
            "release-common.sh",
        ) + FORMAL_OPERATION_SCRIPTS + tuple(EXTERNAL_ATTESTATION_SCRIPT_SHA256)
        for name in names:
            text = (root / "scripts" / name).read_text(encoding="utf-8")
            if name == "generate-release-evidence.sh":
                text = text.replace(
                    'cp --no-dereference -- "$external_attestation_input" \\\n',
                    'true # removed immutable attestation snapshot copy\n',
                    1,
                )
            (fixture / "scripts" / name).write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(ContractError, "immutable attestation snapshot"):
            validate_release_mode_contracts(fixture)

    def test_release_promotion_full_contract_passes(self):
        validate_release_promote_workflow(
            self.release_promote_workflow(), Path("release-promote.yml")
        )

    def test_release_promotion_remains_manual_no_checkout_and_write_isolated(self):
        original = self.release_promote_workflow()
        mutations = (
            original.replace("  workflow_dispatch:\n", "  push:\n", 1),
            original.replace("    environment: formal-release-promotion\n", "", 1),
            original.replace("      contents: read\n", "      contents: write\n", 1),
            original.replace(
                "      - name: Reverify immutable asset set and publish the same draft\n",
                "      - name: Checkout attacker source\n"
                "        uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n"
                "      - name: Reverify immutable asset set and publish the same draft\n",
                1,
            ),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(
                ContractError,
                "workflow_dispatch|environment|write|read|exact scalar|one reviewed step",
            ):
                validate_release_promote_workflow(workflow, Path("release-promote.yml"))

    def test_release_promotion_ref_fingerprint_and_patch_are_locked(self):
        original = self.release_promote_workflow()
        protected_lines = (
            '          [[ "$DISPATCH_REF" == refs/tags/v0.15 ]]\n',
            '          [[ "$actual_fingerprint" == "$EXPECTED_ASSET_FINGERPRINT" ]]\n',
            '          [[ "$actual_metadata_fingerprint" == "$EXPECTED_METADATA_FINGERPRINT" ]]\n',
            "          promoted=\"$(gh api --method PATCH \\\n",
        )
        for protected_line in protected_lines:
            with self.subTest(protected_line=protected_line.strip()):
                workflow = original.replace(protected_line, "", 1)
                self.assertNotEqual(workflow, original)
                with self.assertRaisesRegex(ContractError, "exact reviewed text"):
                    validate_release_promote_workflow(
                        workflow, Path("release-promote.yml")
                    )

    def blocked_workflow(self, trigger: str = "workflow_dispatch", latest: str = "false") -> str:
        source = Path(__file__).parent.parent / ".github/workflows/round6-blocked-prerelease.yml"
        text = source.read_text(encoding="utf-8")
        if trigger != "workflow_dispatch":
            text = text.replace("  workflow_dispatch:\n", f"  {trigger}:\n", 1)
        if latest != "false":
            text = text.replace("--latest=false", f"--latest={latest}", 1)
        return text

    def test_blocked_prerelease_full_contract_passes(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        source = Path(temporary.name) / "round6-blocked-prerelease.yml"
        validate_blocked_prerelease_workflow(self.blocked_workflow(), source)

    def test_blocked_prerelease_consumed_sparse_boundary_is_locked(self):
        original = self.blocked_workflow()
        workflow = original.replace(
            "            !/internal/classifier/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*\n", "", 1
        )
        self.assertNotEqual(workflow, original)
        with self.assertRaisesRegex(ContractError, "sparse"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_automatic_trigger_fails(self):
        with self.assertRaisesRegex(ContractError, "manual-only"):
            validate_blocked_prerelease_workflow(
                self.blocked_workflow(trigger="push"), Path("round6-prerelease.yml")
            )

    def test_blocked_prerelease_latest_true_fails(self):
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(
                self.blocked_workflow(latest="true"), Path("round6-prerelease.yml")
            )

    def test_blocked_prerelease_missing_expected_tree_fails(self):
        workflow = self.blocked_workflow().replace(
            "      expected_tree:\n", "      removed_expected_tree:\n", 1
        )
        with self.assertRaisesRegex(ContractError, "expected_tree"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_missing_ci_run_id_fails(self):
        workflow = self.blocked_workflow().replace(
            "      ci_run_id:\n", "      removed_ci_run_id:\n", 1
        )
        with self.assertRaisesRegex(ContractError, "ci_run_id"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_missing_candidate_run_id_fails(self):
        workflow = self.blocked_workflow().replace(
            "      candidate_run_id:\n", "      removed_candidate_run_id:\n", 1
        )
        with self.assertRaisesRegex(ContractError, "candidate_run_id"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_missing_expected_so_sha256_fails(self):
        workflow = self.blocked_workflow().replace(
            "      expected_so_sha256:\n", "      removed_expected_so_sha256:\n", 1
        )
        with self.assertRaisesRegex(ContractError, "expected_so_sha256"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_missing_expected_store_zip_sha256_fails(self):
        workflow = self.blocked_workflow().replace(
            "      expected_store_zip_sha256:\n",
            "      removed_expected_store_zip_sha256:\n",
            1,
        )
        with self.assertRaisesRegex(ContractError, "expected_store_zip_sha256"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_requires_consumed_independent_evaluation(self):
        original = self.blocked_workflow()
        for input_name in (
            "independent_evaluation_validation",
            "independent_evaluation_id",
            "independent_evaluation_sha256",
        ):
            with self.subTest(input_name=input_name):
                workflow = original.replace(
                    f"      {input_name}:\n", f"      removed_{input_name}:\n", 1
                )
                self.assertNotEqual(workflow, original)
                with self.assertRaisesRegex(ContractError, input_name):
                    validate_blocked_prerelease_workflow(
                        workflow, Path("round6-prerelease.yml")
                    )

    def test_blocked_prerelease_evaluation_pass_id_and_hash_gates_are_locked(self):
        original = self.blocked_workflow()
        protected_lines = (
            '          [[ "$INDEPENDENT_EVALUATION" == PASS ]]\n',
            '          [[ "$INDEPENDENT_EVALUATION_ID" =~ ^evaluation-v(1[1-9]|[2-9][0-9]|[1-9][0-9]{2,})$ ]]\n',
            '          [[ "$INDEPENDENT_EVALUATION_SHA256" =~ ^[0-9a-f]{64}$ ]]\n',
            "      inputs.independent_evaluation_validation == 'PASS' &&\n",
        )
        for protected_line in protected_lines:
            with self.subTest(protected_line=protected_line.strip()):
                workflow = original.replace(protected_line, "", 1)
                self.assertNotEqual(workflow, original)
                with self.assertRaisesRegex(
                    ContractError, "exact reviewed|missing explicit gate"
                ):
                    validate_blocked_prerelease_workflow(
                        workflow, Path("round6-prerelease.yml")
                    )

        leading_zero_bypass = original.replace(
            "^evaluation-v(1[1-9]|[2-9][0-9]|[1-9][0-9]{2,})$",
            "^evaluation-v([0-9]+)$",
            1,
        )
        self.assertNotEqual(leading_zero_bypass, original)
        with self.assertRaisesRegex(ContractError, "exact reviewed"):
            validate_blocked_prerelease_workflow(
                leading_zero_bypass, Path("round6-prerelease.yml")
            )

    def test_blocked_prerelease_candidate_run_identity_is_locked(self):
        original = self.blocked_workflow()
        protected_lines = (
            '             .name == "Round6 clean candidate - NOT A RELEASE" and\n',
            '             .path == ".github/workflows/round6-candidate.yml" and\n',
            '             .event == "workflow_dispatch" and\n'
            '             .head_sha == $expected_commit and\n',
        )
        for protected_line in protected_lines:
            with self.subTest(protected_line=protected_line.strip()):
                workflow = original.replace(protected_line, "", 1)
                self.assertNotEqual(workflow, original)
                with self.assertRaisesRegex(ContractError, "exact reviewed"):
                    validate_blocked_prerelease_workflow(
                        workflow, Path("round6-prerelease.yml")
                    )

    def test_blocked_prerelease_missing_v7286_host_inputs_fail(self):
        original = self.blocked_workflow()
        for input_name in (
            "host_v7286_validation",
            "host_v7286_evidence_sha256",
        ):
            with self.subTest(input_name=input_name):
                workflow = original.replace(
                    f"      {input_name}:\n", f"      removed_{input_name}:\n", 1
                )
                self.assertNotEqual(workflow, original)
                with self.assertRaisesRegex(ContractError, input_name):
                    validate_blocked_prerelease_workflow(
                        workflow, Path("round6-prerelease.yml")
                    )

    def test_blocked_prerelease_rejects_legacy_host_blockers(self):
        original = self.blocked_workflow()
        legacy_input = original.replace(
            "      independent_audit_validation:\n",
            "      host_v7282_validation:\n"
            "        description: Legacy Host blocker must not return\n"
            "        required: true\n"
            "        type: choice\n"
            "        default: BLOCKED\n"
            "        options:\n"
            "          - BLOCKED\n"
            "          - PASS\n"
            "      independent_audit_validation:\n",
            1,
        )
        legacy_gate = original.replace(
            "      inputs.host_v7286_validation == 'PASS' &&\n",
            "      inputs.host_v7286_validation == 'PASS' &&\n"
            "      inputs.host_v7282_validation == 'PASS' &&\n",
            1,
        )
        for workflow in (legacy_input, legacy_gate):
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(ContractError, "keys/order changed|explicit gate"):
                validate_blocked_prerelease_workflow(
                    workflow, Path("round6-prerelease.yml")
                )

    def test_blocked_prerelease_missing_actions_read_fails(self):
        workflow = self.blocked_workflow().replace("  actions: read\n", "")
        with self.assertRaisesRegex(ContractError, "actions: read"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_missing_protected_environment_fails(self):
        workflow = self.blocked_workflow().replace(
            "    environment: round6-independent-audit\n", ""
        )
        with self.assertRaisesRegex(ContractError, "protected environment"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_missing_ci_conclusion_fails(self):
        workflow = self.blocked_workflow().replace(
            '             .conclusion == "success" and\n',
            '             .conclusion != "success" and\n',
        )
        with self.assertRaisesRegex(ContractError, "exact reviewed"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_admission_comment_spoof_fails(self):
        workflow = self.blocked_workflow().replace(
            '          [[ "$HOST_V7286" == PASS ]]\n',
            '          # [[ "$HOST_V7286" == PASS ]]\n          true\n',
        )
        with self.assertRaisesRegex(ContractError, "exact reviewed"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_identity_env_spoof_fails(self):
        original = self.blocked_workflow()
        cases = (
            ("DISPATCH_REF", "${{ github.ref }}", "refs/heads/main"),
            ("DISPATCH_SHA", "${{ github.sha }}", "0000000000000000000000000000000000000000"),
            ("WORKFLOW_REF", "${{ github.workflow_ref }}", "owner/repo/.github/workflows/round6-blocked-prerelease.yml@refs/heads/main"),
            ("WORKFLOW_SHA", "${{ github.workflow_sha }}", "0000000000000000000000000000000000000000"),
        )
        for name, expected, spoofed in cases:
            with self.subTest(name=name):
                workflow = original.replace(
                    f"          {name}: {expected}\n",
                    f"          {name}: {spoofed}\n",
                    1,
                )
                self.assertNotEqual(workflow, original)
                with self.assertRaisesRegex(ContractError, "exact reviewed"):
                    validate_blocked_prerelease_workflow(
                        workflow, Path("round6-prerelease.yml")
                    )

    def test_blocked_prerelease_identity_command_spoof_fails(self):
        original = self.blocked_workflow()
        commands = (
            '[[ "$DISPATCH_REF" == "refs/tags/$TAG" ]]',
            '[[ "$DISPATCH_SHA" == "$EXPECTED_COMMIT" ]]',
            '[[ "$WORKFLOW_SHA" == "$EXPECTED_COMMIT" ]]',
            '[[ "$WORKFLOW_REF" == "${GITHUB_REPOSITORY}/.github/workflows/round6-blocked-prerelease.yml@refs/tags/$TAG" ]]',
        )
        for command in commands:
            with self.subTest(command=command):
                workflow = original.replace(
                    f"          {command}\n",
                    "          true\n",
                    1,
                )
                self.assertNotEqual(workflow, original)
                with self.assertRaisesRegex(ContractError, "exact reviewed"):
                    validate_blocked_prerelease_workflow(
                        workflow, Path("round6-prerelease.yml")
                    )

    def test_blocked_prerelease_if_expression_spoof_fails(self):
        workflow = self.blocked_workflow().replace(
            "    if: >-\n      inputs.host_v7286_validation == 'PASS' &&\n      inputs.independent_audit_validation == 'PASS' &&\n      inputs.independent_evaluation_validation == 'PASS' &&\n      inputs.authorize_blocked_prerelease == true\n",
            "    if: ${{ true }}\n"
            "    # inputs.host_v7286_validation == 'PASS' &&\n"
            "    # inputs.independent_audit_validation == 'PASS' && inputs.independent_evaluation_validation == 'PASS' &&\n"
            "    # inputs.authorize_blocked_prerelease == true\n",
        )
        with self.assertRaisesRegex(ContractError, "missing explicit gate"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_missing_host_gate_fails(self):
        original = self.blocked_workflow()
        for version in ("7286",):
            with self.subTest(version=version):
                workflow = original.replace(
                    f"      inputs.host_v{version}_validation == 'PASS' &&\n", "", 1
                )
                self.assertNotEqual(workflow, original)
                with self.assertRaisesRegex(ContractError, "missing explicit gate"):
                    validate_blocked_prerelease_workflow(
                        workflow, Path("round6-prerelease.yml")
                    )

    def test_blocked_prerelease_missing_remote_tag_recheck_fails(self):
        workflow = self.blocked_workflow().replace(
            "          tag_ref=\"$(/usr/bin/gh api --header 'Accept: application/vnd.github+json' --header 'X-GitHub-Api-Version: 2022-11-28' \"repos/$GITHUB_REPOSITORY/git/ref/tags/$TAG\")\"\n",
            "",
        )
        self.assertNotEqual(workflow, self.blocked_workflow())
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_missing_metadata_identity_fails(self):
        workflow = self.blocked_workflow().replace(
            ".commit == $commit and .tree == $tree",
            ".commit != $commit or .tree != $tree",
        )
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_final_identity_comment_spoof_fails(self):
        workflow = self.blocked_workflow().replace(
            "          tag_ref=\"$(/usr/bin/gh api --header 'Accept: application/vnd.github+json' --header 'X-GitHub-Api-Version: 2022-11-28' \"repos/$GITHUB_REPOSITORY/git/ref/tags/$TAG\")\"\n",
            "          # tag_ref=\"$(/usr/bin/gh api --header 'Accept: application/vnd.github+json' --header 'X-GitHub-Api-Version: 2022-11-28' \"repos/$GITHUB_REPOSITORY/git/ref/tags/$TAG\")\"\n",
        )
        self.assertNotEqual(workflow, self.blocked_workflow())
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_final_identity_or_true_fails(self):
        workflow = self.blocked_workflow().replace(
            '          [[ "$(/usr/bin/jq -r \'.ref\' <<<"$tag_ref")" == "refs/tags/$TAG" ]]\n',
            '          [[ "$(/usr/bin/jq -r \'.ref\' <<<"$tag_ref")" == "refs/tags/$TAG" ]] || true\n',
        )
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_final_identity_if_false_fails(self):
        workflow = self.blocked_workflow().replace(
            "          tag_ref=\"$(/usr/bin/gh api --header 'Accept: application/vnd.github+json' --header 'X-GitHub-Api-Version: 2022-11-28' \"repos/$GITHUB_REPOSITORY/git/ref/tags/$TAG\")\"\n",
            "          if false; then\n"
            "          tag_ref=\"$(/usr/bin/gh api --header 'Accept: application/vnd.github+json' --header 'X-GitHub-Api-Version: 2022-11-28' \"repos/$GITHUB_REPOSITORY/git/ref/tags/$TAG\")\"\n",
        ).replace(
            '          [[ "$(/usr/bin/jq -r \'.ref\' <<<"$tag_ref")" == "refs/tags/$TAG" ]]\n',
            '          [[ "$(/usr/bin/jq -r \'.ref\' <<<"$tag_ref")" == "refs/tags/$TAG" ]]\n          fi\n',
        )
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_final_identity_semicolon_true_fails(self):
        workflow = self.blocked_workflow().replace(
            "            dist/build-metadata.json >/dev/null\n",
            "            dist/build-metadata.json >/dev/null; true\n",
            1,
        )
        self.assertNotEqual(workflow, self.blocked_workflow())
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_final_artifact_hash_or_true_fails(self):
        workflow = self.blocked_workflow().replace(
            '          [[ "$actual_so_sha256" == "$EXPECTED_SO_SHA256" ]]\n',
            '          [[ "$actual_so_sha256" == "$EXPECTED_SO_SHA256" ]] || true\n',
        )
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_release_action_must_be_last(self):
        workflow = self.blocked_workflow() + """      - name: Mutate release afterward
        run: gh release edit "$TAG" --latest
"""
        with self.assertRaisesRegex(ContractError, "exactly four reviewed steps"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_existing_draft_extra_asset_guard_is_frozen(self):
        original = self.blocked_workflow()
        expected_builder = '          expected_assets_json="$(/usr/bin/jq -cn --args '
        guard = '            if ! /usr/bin/jq -e --argjson expected "$expected_assets_json" '
        final_exact_set = '          /usr/bin/jq -e --argjson expected "$expected_assets_json" '
        self.assertIn(expected_builder, original)
        self.assertIn(guard, original)
        self.assertIn(final_exact_set, original)
        self.assertIn('(($actual - $expected) | length == 0)', original)
        self.assertIn('(($actual | length) == ($actual | unique | length))', original)
        self.assertIn('(($actual | sort) == ($expected | sort))', original)
        self.assertNotIn('/usr/bin/comm -13', original)
        self.assertLess(
            original.index(expected_builder),
            original.index('            /usr/bin/gh release create "$TAG"'),
        )
        self.assertLess(
            original.index(guard),
            original.index('            /usr/bin/gh release edit "$TAG" \\\n'),
        )
        self.assertLess(
            original.index(guard),
            original.index('            /usr/bin/gh release upload "$TAG"'),
        )
        workflow = original.replace(guard, '            if /usr/bin/true; then # ', 1)
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_release_commands_pin_repository(self):
        original = self.blocked_workflow()
        repository_flag = '              --repo "$GITHUB_REPOSITORY" \\\n'
        self.assertEqual(original.count(repository_flag), 3)
        workflow = original.replace(repository_flag, "", 1)
        self.assertNotEqual(workflow, original)
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_duplicate_action_key_fails(self):
        workflow = self.blocked_workflow().replace(
            "            --draft \\\n", "            --draft \\\n            --draft \\\n", 1
        )
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_missing_body_artifact_hash_fails(self):
        workflow = self.blocked_workflow().replace(
            '            "Candidate Linux amd64 SO SHA-256: $EXPECTED_SO_SHA256" \\\n',
            "            'Candidate Linux amd64 SO SHA-256: unavailable' \\\n",
            1,
        )
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_attestation_identity_is_locked(self):
        original = self.blocked_workflow()
        protected_lines = (
            '              status: "HOST_AUDIT_AND_EVALUATION_PASS / FORMAL_RELEASE_BLOCKED",\n',
            "              candidate_run_id: ($candidate_run_id | tonumber),\n",
            "                store_zip_sha256: $store_zip_sha256\n",
            "                independent_audit_sha256: $independent_audit_sha256,\n",
            "                independent_evaluation_id: $independent_evaluation_id,\n",
            '                independent_evaluation_status: "CONSUMED / PASS",\n',
            "                independent_evaluation_sha256: $independent_evaluation_sha256\n",
            "                ref: $workflow_ref,\n",
            "            dist/round6-prerelease-attestation.json\n",
            "            dist/round6-prerelease-attestation.json.sha256\n",
        )
        for protected_line in protected_lines:
            with self.subTest(protected_line=protected_line.strip()):
                workflow = original.replace(protected_line, "", 1)
                self.assertNotEqual(workflow, original)
                with self.assertRaisesRegex(
                    ContractError,
                    "exact reviewed text|attested artifact allowlist changed",
                ):
                    validate_blocked_prerelease_workflow(
                        workflow, Path("round6-prerelease.yml")
                    )

    def test_blocked_prerelease_missing_v7286_host_evidence_note_fails(self):
        original = self.blocked_workflow()
        workflow = original.replace(
            '            "CPA v7.2.86 Host evidence SHA-256: $HOST_V7286_SHA256" \\\n',
            "",
            1,
        )
        self.assertNotEqual(workflow, original)
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_verify_token_exposure_fails(self):
        workflow = self.blocked_workflow().replace(
            "          CPA_COMPAT_VERIFY_REMOTE: '1'\n",
            "          CPA_COMPAT_VERIFY_REMOTE: '1'\n          GITHUB_TOKEN: ${{ github.token }}\n",
            1,
        )
        with self.assertRaisesRegex(ContractError, "github.token|repository token"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_bracket_token_and_secret_exposure_fail(self):
        expressions = (
            "${{ github['token'] }}",
            "${{ secrets['WRITE_PAT'] }}",
            "${{ toJSON(github) }}",
            "${{ toJSON(secrets) }}",
        )
        for expression in expressions:
            with self.subTest(expression=expression):
                workflow = self.blocked_workflow().replace(
                    "          CPA_COMPAT_VERIFY_REMOTE: '1'\n",
                    "          CPA_COMPAT_VERIFY_REMOTE: '1'\n"
                    f"          UNREVIEWED_CONTEXT: {expression}\n",
                    1,
                )
                with self.assertRaisesRegex(
                    ContractError, "github.token|repository token|secrets context"
                ):
                    validate_blocked_prerelease_workflow(
                        workflow, Path("round6-prerelease.yml")
                    )

    def test_blocked_prerelease_semantic_step_control_bypasses_fail(self):
        mutations = (
            self.blocked_workflow().replace(
                "      - name: Fail closed unless every external gate and authorization is explicit\n",
                "      - name: Fail closed unless every external gate and authorization is explicit\n"
                "        if : false\n",
                1,
            ),
            self.blocked_workflow().replace(
                "      - name: Reverify source and artifact identity before transfer\n",
                "      - name: Reverify source and artifact identity before transfer\n"
                "        continue-on-error : true\n",
                1,
            ),
            self.blocked_workflow().replace(
                "      - name: Recheck immutable tag and create draft blocked prerelease\n",
                "      - name: Recheck immutable tag and create draft blocked prerelease\n"
                "        shell : bash {0}\n",
                1,
            ),
        )
        for index, workflow in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaisesRegex(
                    ContractError, "keys/order changed|override the reviewed step shell"
                ):
                    validate_blocked_prerelease_workflow(
                        workflow, Path("round6-prerelease.yml")
                    )

    def test_blocked_prerelease_spaced_env_and_trigger_bypasses_fail(self):
        mutations = (
            self.blocked_workflow().replace(
                "env:\n  GO_VERSION:",
                "env :\n  BASH_ENV : /tmp/attacker\n  GO_VERSION:",
                1,
            ),
            self.blocked_workflow().replace(
                "\npermissions:\n", "  push :\n\npermissions:\n", 1
            ),
        )
        for index, workflow in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaisesRegex(
                    ContractError, "top-level env|manual-only|dangerous execution-context"
                ):
                    validate_blocked_prerelease_workflow(
                        workflow, Path("round6-prerelease.yml")
                    )

    def test_blocked_prerelease_extra_action_and_changed_action_sha_fail(self):
        marker = "      - name: Reverify source and artifact identity before transfer\n"
        extra_action = self.blocked_workflow().replace(
            marker,
            "      - name: Unreviewed external action\n"
            "        uses: attacker/example@0123456789abcdef0123456789abcdef01234567\n"
            + marker,
            1,
        )
        changed_sha = self.blocked_workflow().replace(
            "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16",
            "actions/setup-go@0123456789abcdef0123456789abcdef01234567",
            1,
        )
        for workflow in (extra_action, changed_sha):
            with self.assertRaisesRegex(
                ContractError, "exactly eleven|exact scalar|dangerous execution-context"
            ):
                validate_blocked_prerelease_workflow(
                    workflow, Path("round6-prerelease.yml")
                )

    def test_blocked_prerelease_pull_request_ci_run_fails(self):
        workflow = self.blocked_workflow().replace(
            '             .event == "push" and\n',
            '             .event == "pull_request" and\n',
            1,
        )
        with self.assertRaisesRegex(ContractError, "exact reviewed"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_persisted_checkout_credentials_fail(self):
        workflow = self.blocked_workflow().replace(
            "          persist-credentials: false\n",
            "          persist-credentials: true\n",
            1,
        )
        with self.assertRaisesRegex(ContractError, "disable persisted credentials"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_early_release_mutation_fails(self):
        commands = (
            "gh release create v0.1.2-dev.round6 --latest",
            "gh api -X PATCH repos/example/example/git/refs/tags/v0.1.2-dev.round6",
            "git push origin refs/tags/v0.1.2-dev.round6",
            "git tag -f v0.1.2-dev.round6 HEAD",
            "git update-ref refs/tags/v0.1.2-dev.round6 HEAD",
            "curl -X POST https://api.github.test/repos/example/example/releases",
            "curl --data '{}' https://api.github.test/repos/example/example/releases",
            "curl -F file=@candidate.so https://api.github.test/upload",
            "curl --upload-file candidate.so https://api.github.test/upload",
            "wget --post-data=tag=v0.1.2-dev.round6 https://api.github.test/releases",
            "/usr/bin/curl --data '{}' https://api.github.test/releases",
            "command curl --data '{}' https://api.github.test/releases",
            "env curl --data '{}' https://api.github.test/releases",
            "env -S 'curl --data {} https://api.github.test/releases'",
            "sudo env --split-string='git --no-pager tag v0.1.2-dev.round6'",
            "/usr/bin/time -f %E git --no-pager tag v0.1.2-dev.round6",
            "timeout --signal KILL 5s gh --hostname github.com api repos/example/example",
            "nice -n 10 nohup stdbuf -oL wget --post-data=x https://api.github.test/releases",
            "bash -lc 'curl --data x https://api.github.test/releases'",
            "eval 'git tag v0.1.2-dev.round6'",
            "xargs curl",
            "find . -exec curl --data x https://api.github.test/releases {} \\;",
            "python3.14 -I -c 'import requests'",
            "node --eval=\"fetch('https://api.github.test/releases')\"",
        )
        for command in commands:
            with self.subTest(command=command):
                reasons = [
                    mutating_command_reason(segment)
                    for logical_command in mutation_shell_commands(command)
                    for segment in shell_command_segments(logical_command)
                ]
                self.assertTrue(any(reasons), command)

    def test_mutation_parser_handles_multiline_quotes_heredocs_and_fail_closed(self):
        script = """jq -e '(.commit == $commit and
 .tree == $tree)' build-metadata.json
cat <<'BODY'
curl --data attacker-controlled-body https://api.github.test/releases
BODY
command /usr/bin/git --no-pager tag v0.1.2-dev.round6
"""
        reasons = [
            mutating_command_reason(segment)
            for logical_command in mutation_shell_commands(script)
            for segment in shell_command_segments(logical_command)
            if mutating_command_reason(segment)
        ]
        self.assertEqual(reasons, ["git tag"])
        self.assertEqual(
            mutation_shell_commands("jq -r .value <<<'{}'\necho safe"),
            ("jq -r .value <<<'{}'", "echo safe"),
        )
        for malformed in ("echo 'unterminated", "cat <<BODY\nmissing terminator"):
            with self.subTest(malformed=malformed):
                with self.assertRaisesRegex(ContractError, "unterminated"):
                    mutation_shell_commands(malformed)

    def test_mutation_parser_rejects_array_execution_substitutions(self):
        commands = (
            'values=("$(gh release create v0.15)")',
            'values=(\n  "$(gh release create v0.15)"\n)',
            'values=(`gh release create v0.15`)',
            'values=( <(gh release create v0.15) )',
        )
        for command in commands:
            with self.subTest(command=command):
                with self.assertRaisesRegex(
                    ContractError, "shell array contains executable substitution"
                ):
                    mutation_shell_commands(command)

    def test_mutation_parser_even_trailing_backslashes_do_not_hide_command(self):
        script = "printf '%s' safe " + "\\\\" + "\ngh release create v0.15"
        reasons = [
            mutating_command_reason(segment)
            for command in mutation_shell_commands(script)
            for segment in shell_command_segments(command)
            if mutating_command_reason(segment)
        ]
        self.assertEqual(reasons, ["gh release"])

    def test_blocked_prerelease_github_env_bash_env_injection_fails(self):
        original = self.blocked_workflow()
        workflow = original.replace(
            "        run: make clean-tree-check\n",
            "        run: |\n"
            "          printf '%s\\n' 'BASH_ENV=/tmp/attacker' >> \"$GITHUB_ENV\"\n"
            "          make clean-tree-check\n",
            1,
        )
        self.assertNotEqual(workflow, original)
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_required_verification_env_cannot_be_disabled(self):
        original = self.blocked_workflow()
        mutations = (
            original.replace("          CPA_COMPAT_VERIFY_REMOTE: '1'\n", "          CPA_COMPAT_VERIFY_REMOTE: '0'\n", 1),
            original.replace("          REQUIRE_DIST_ARTIFACTS: '1'\n", "          REQUIRE_DIST_ARTIFACTS: '0'\n", 1),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(ContractError, "exact reviewed mapping"):
                validate_blocked_prerelease_workflow(
                    workflow, Path("round6-prerelease.yml")
                )

    def test_blocked_prerelease_regression_step_cannot_be_noop(self):
        original = self.blocked_workflow()
        workflow = original.replace(
            "        run: |\n"
            "          make round6-format-check round6-git-diff-check round6-module-verify round6-regression round6-vet\n"
            "          go test ./internal/classifier -run '^TestClassifierPolicyIdentity$' -count=1\n",
            "        run: true\n",
            1,
        )
        self.assertNotEqual(workflow, original)
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_clean_execution_env_is_exact(self):
        original = self.blocked_workflow()
        mutations = (
            original.replace("          BASH_ENV: ''\n", "", 1),
            original.replace("          BASH_ENV: ''\n", "          BASH_ENV: /tmp/attacker\n", 1),
            original.replace("          PATH: /usr/bin:/bin\n", "          PATH: /tmp/bin\n", 1),
            original.replace("          GIT_CONFIG_COUNT: '0'\n", "          GIT_CONFIG_COUNT: '1'\n", 1),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(
                ContractError, "exact reviewed mapping|dangerous execution-context"
            ):
                validate_blocked_prerelease_workflow(
                    workflow, Path("round6-prerelease.yml")
                )

    def test_blocked_prerelease_canonical_checksums_and_zip_identity_are_locked(self):
        original = self.blocked_workflow()
        protected_lines = (
            '          [[ "$actual_checksum_files" == "$expected_checksum_files" ]]\n',
            '          [[ "$(/usr/bin/sha256sum "$zip_so_file" | /usr/bin/awk \'{print $1}\')" == "$EXPECTED_SO_SHA256" ]]\n',
            '          [[ "$(/usr/bin/sha256sum "$zip_path" | /usr/bin/awk \'{print $1}\')" == "$EXPECTED_STORE_ZIP_SHA256" ]]\n',
            '          [[ "$zip_listing" == "$zip_so" ]]\n',
        )
        for protected_line in protected_lines:
            with self.subTest(protected_line=protected_line.strip()):
                workflow = original.replace(protected_line, "", 1)
                self.assertNotEqual(workflow, original)
                with self.assertRaisesRegex(ContractError, "exact reviewed text"):
                    validate_blocked_prerelease_workflow(
                        workflow, Path("round6-prerelease.yml")
                    )

    def test_blocked_prerelease_final_tag_peel_bypass_fails(self):
        workflow = self.blocked_workflow().replace(
            '          [[ "$(/usr/bin/jq -r \'.object.sha\' <<<"$tag_object")" == "$EXPECTED_COMMIT" ]]\n',
            '          [[ "$(/usr/bin/jq -r \'.object.sha\' <<<"$tag_object")" == "$EXPECTED_COMMIT" ]] || true\n',
            1,
        )
        self.assertNotEqual(workflow, self.blocked_workflow())
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_rc_release_workflow_matches_reviewed_contract(self):
        workflow_path = Path(__file__).resolve().parent.parent / ".github/workflows/release-rc.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        validate_rc_release_workflow(workflow, workflow_path)

    def test_rc_release_workflow_mutation_fails_closed(self):
        workflow_path = Path(__file__).resolve().parent.parent / ".github/workflows/release-rc.yml"
        original = workflow_path.read_text(encoding="utf-8")
        mutations = (
            original.replace("[[ \"$TAG\" == v0.15-rc.2 ]]", "[[ \"$TAG\" == v0.15-rc.* ]]", 1),
            original.replace("--latest=false", "--latest", 1),
            original.replace("contents: write", "contents: read", 1),
            original.replace("make cpa-host-fixture-contract cpa-latest-compat", "true", 1),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(ContractError, "exact reviewed contract"):
                validate_rc_release_workflow(workflow, workflow_path)


if __name__ == "__main__":
    unittest.main()
