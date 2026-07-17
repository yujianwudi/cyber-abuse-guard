#!/usr/bin/env python3

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

from round6_safe_gate_contract import (
    BLOCKED_PRERELEASE_MARKER,
    FORBIDDEN_TARGETS,
    ROUND6_SPARSE_PATTERNS,
    ContractError,
    audit,
    mutation_shell_commands,
    mutating_command_reason,
    shell_command_segments,
    validate_blocked_prerelease_workflow,
    validate_round6_linux_build_script,
    validate_round6_makefile_contract,
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
            pattern for pattern in ROUND6_SPARSE_PATTERNS if pattern != "!/cmd/*private*"
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

    def reproducibility_script(self, patterns: tuple[str, ...]) -> str:
        quoted = " \\\n+    ".join(repr(pattern) for pattern in patterns)
        return f"""#!/usr/bin/env bash
git -C "$destination" sparse-checkout set --no-cone \\
    {quoted}
git -C "$destination" checkout "$commit"
"""

    def test_reproducibility_sparse_contract_passes(self):
        validate_round6_reproducibility_script(
            self.reproducibility_script(ROUND6_SPARSE_PATTERNS), Path("round6-repro.sh")
        )

    def test_reproducibility_sparse_contract_mismatch_fails(self):
        patterns = ROUND6_SPARSE_PATTERNS[:-1]
        with self.assertRaisesRegex(ContractError, "differs from the workflow contract"):
            validate_round6_reproducibility_script(
                self.reproducibility_script(patterns), Path("round6-repro.sh")
            )

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

    def test_blocked_prerelease_missing_expected_so_sha256_fails(self):
        workflow = self.blocked_workflow().replace(
            "      expected_so_sha256:\n", "      removed_expected_so_sha256:\n", 1
        )
        with self.assertRaisesRegex(ContractError, "expected_so_sha256"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_missing_v7283_host_inputs_fail(self):
        original = self.blocked_workflow()
        for input_name in (
            "host_v7283_validation",
            "host_v7283_evidence_sha256",
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
            '          [[ "$HOST_V7283" == PASS ]]\n',
            '          # [[ "$HOST_V7283" == PASS ]]\n          true\n',
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
            "    if: >-\n      inputs.host_v7283_validation == 'PASS' &&\n      inputs.host_v7282_validation == 'PASS' &&\n      inputs.host_v7281_validation == 'PASS' &&\n      inputs.independent_audit_validation == 'PASS' &&\n      inputs.authorize_blocked_prerelease == true\n",
            "    if: ${{{{ true }}}}\n"
            "    # inputs.host_v7283_validation == 'PASS' && inputs.host_v7282_validation == 'PASS' &&\n"
            "    # inputs.host_v7281_validation == 'PASS' &&\n"
            "    # inputs.independent_audit_validation == 'PASS' && inputs.authorize_blocked_prerelease == true\n",
        )
        with self.assertRaisesRegex(ContractError, "missing explicit gate"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_missing_host_gate_fails(self):
        original = self.blocked_workflow()
        for version in ("7283", "7282", "7281"):
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
            "          remote_tag_commit=\"$(/usr/bin/git ls-remote --tags origin \"refs/tags/$TAG^{}\" | /usr/bin/awk '{print $1}')\"\n",
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
            "          remote_tag_commit=\"$(/usr/bin/git ls-remote --tags origin \"refs/tags/$TAG^{}\" | /usr/bin/awk '{print $1}')\"\n",
            "          # remote_tag_commit=\"$(/usr/bin/git ls-remote --tags origin \"refs/tags/$TAG^{}\" | /usr/bin/awk '{print $1}')\"\n",
        )
        self.assertNotEqual(workflow, self.blocked_workflow())
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_final_identity_or_true_fails(self):
        workflow = self.blocked_workflow().replace(
            '          [[ "$remote_tag_commit" == "$EXPECTED_COMMIT" ]]\n',
            '          [[ "$remote_tag_commit" == "$EXPECTED_COMMIT" ]] || true\n',
        )
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_final_identity_if_false_fails(self):
        workflow = self.blocked_workflow().replace(
            "          remote_tag_commit=\"$(/usr/bin/git ls-remote --tags origin \"refs/tags/$TAG^{}\" | /usr/bin/awk '{print $1}')\"\n",
            "          if false; then\n"
            "          remote_tag_commit=\"$(/usr/bin/git ls-remote --tags origin \"refs/tags/$TAG^{}\" | /usr/bin/awk '{print $1}')\"\n",
        ).replace(
            '          [[ "$remote_tag_commit" == "$EXPECTED_COMMIT" ]]\n',
            '          [[ "$remote_tag_commit" == "$EXPECTED_COMMIT" ]]\n          fi\n',
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
        with self.assertRaisesRegex(ContractError, "exactly three reviewed steps"):
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

    def test_blocked_prerelease_missing_v7283_host_evidence_note_fails(self):
        original = self.blocked_workflow()
        workflow = original.replace(
            '            "CPA v7.2.83 Host evidence SHA-256: $HOST_V7283_SHA256" \\\n',
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
            '          /usr/bin/cmp -s <(/usr/bin/unzip -p "$zip_path" "$zip_so_checksum") dist/cyber-abuse-guard-v0.1.2-dirty.so.sha256\n',
            '            /usr/bin/cmp -s <(/usr/bin/unzip -p "$zip_path" "$entry") "dist/$entry"\n',
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


if __name__ == "__main__":
    unittest.main()
