from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from audit_consumers import audit  # noqa: E402
from validate_policy import load_policy, validate_policy  # noqa: E402


class PolicyContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.docs, cls.parse_errors = load_policy(ROOT)

    def make_consumer_fixture(self, root: Path) -> tuple[Path, Path, Path, Path]:
        dotnix_root = root / "dotnix"
        templates_root = root / "Templates"
        dotnix_agents = dotnix_root / "config.d/opencode/agents"
        templates_agents = templates_root / "components/agent-core/.opencode/agents"
        dotnix_agents.mkdir(parents=True)
        templates_agents.mkdir(parents=True)

        models = self.docs["models"]["models"]
        roles = self.docs["roles"]["roles"]
        for profile, directory in (("global", dotnix_agents), ("agent-core", templates_agents)):
            for role, assignment in self.docs[profile]["assignments"].items():
                mode = roles[role]["kind"]
                model = models[assignment["primary_model"]]["id"]
                (directory / f"{role}.md").write_text(
                    f"---\nmode: {mode}\nmodel: {model}\n---\n", encoding="utf-8"
                )
        return dotnix_root, templates_root, dotnix_agents, templates_agents

    def test_policy_is_valid(self) -> None:
        self.assertEqual([], validate_policy(ROOT))

    def test_optional_workers_are_global_noncanonical_and_procedural(self) -> None:
        optional = self.docs["optional-workers"]
        contract = optional["contract"]
        self.assertEqual("global", contract["profile"])
        self.assertEqual("optional", contract["presence"])
        self.assertFalse(contract["enabled_by_default"])
        self.assertEqual("procedural-parent-control", contract["runtime_enforcement"])
        self.assertEqual(1, contract["retry_limit"])
        self.assertEqual(2, contract["max_attempts"])
        self.assertEqual(
            ["local-investigator", "local-tracer", "local-background"],
            optional["workers"]["allowed"],
        )

    def test_parent_evidence_validation_is_fail_closed(self) -> None:
        evidence = self.docs["optional-workers"]["evidence"]
        self.assertEqual("parent", evidence["validation_owner"])
        self.assertEqual("parent-observed-session-events", evidence["tool_call_count_source"])
        self.assertEqual("untrusted", evidence["worker_output_trust"])
        self.assertEqual("BLOCKED", evidence["wrong_or_unsupported_result"])
        self.assertFalse(evidence["wrong_or_unsupported_retry"])

    def test_optional_worker_contract_rejects_unknown_and_retry_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "policy", root / "policy")
            shutil.copytree(ROOT / "profiles", root / "profiles")
            path = root / "policy/optional-workers.toml"
            path.write_text(path.read_text() + "\n[contract.extra]\nenabled = true\n", encoding="utf-8")
            self.assertTrue(any("optional-workers.contract: unknown fields" in error for error in validate_policy(root)))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "policy", root / "policy")
            shutil.copytree(ROOT / "profiles", root / "profiles")
            path = root / "policy/optional-workers.toml"
            path.write_text(path.read_text().replace("retry_limit = 1", "retry_limit = 2"), encoding="utf-8")
            self.assertIn("optional-workers.contract.retry_limit: must be 1", validate_policy(root))

    def test_malformed_table_is_reported_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "policy", root / "policy")
            shutil.copytree(ROOT / "profiles", root / "profiles")
            (root / "policy/roles.toml").write_text('schema_version = 1\nroles = "invalid"\n', encoding="utf-8")
            errors = validate_policy(root)
            self.assertIn("policy/roles.toml: roles must be a table", errors)

    def test_validator_rejects_duplicated_intentional_difference_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "policy", root / "policy")
            shutil.copytree(ROOT / "profiles", root / "profiles")
            invariants_path = root / "policy/invariants.toml"
            contents = invariants_path.read_text(encoding="utf-8").replace(
                'role = "general"\nfield = "authority"',
                'role = "general"\nfield = "authority"\nglobal = "foo"\nagent-core = "bar"',
                1,
            )
            invariants_path.write_text(contents, encoding="utf-8")
            errors = validate_policy(root)
            self.assertTrue(any("canonical values must not be duplicated" in error for error in errors))

    def test_exact_model_aliases_and_no_provider_literals(self) -> None:
        self.assertEqual([], self.parse_errors)
        models = self.docs["models"]["models"]
        self.assertEqual({"sol", "terra", "luna"}, set(models.keys()))
        self.assertEqual(
            {
                "sol": "openai/gpt-5.6-sol",
                "terra": "openai/gpt-5.6-terra",
                "luna": "openai/gpt-5.6-luna",
            },
            {alias: model["id"] for alias, model in models.items()},
        )
        model_ids = {model["id"] for model in models.values()}
        self.assertNotIn("spark", {alias for alias in models})
        self.assertNotIn("openai/gpt-5.3-codex-spark", model_ids)
        self.assertNotIn("openai/gpt-5.3-codex-terra", model_ids)
        self.assertNotIn("openai/gpt-5.3-codex-sol", model_ids)
        self.assertFalse(any("spark" in model_id for model_id in model_ids))
        self.assertEqual({"gpt56"}, set(self.docs["models"]["quota_families"]))
        self.assertTrue(all(model["quota_family"] == "gpt56" for model in models.values()))
        self.assertFalse((ROOT / "policy/fallback.toml").exists())

    def test_fixed_model_invariants_replace_routing_invariants(self) -> None:
        identifiers = {item["id"] for item in self.docs["invariants"]["invariants"]}
        self.assertTrue(
            {
                "model-alias-only",
                "single-configured-model",
                "model-substitution-forbidden",
                "alternate-model-retry-forbidden",
                "availability-fail-closed",
                "exact-model-failure-reporting",
                "fallback-agents-forbidden",
                "consumer-audit-read-only",
            }.issubset(identifiers)
        )
        self.assertFalse(any(identifier.startswith("fallback-preserves-") for identifier in identifiers))

    def test_all_model_assignments_are_known(self) -> None:
        self.assertEqual([], self.parse_errors)
        models = self.docs["models"]["models"]
        for profile in ("global", "agent-core"):
            for assignment in self.docs[profile]["assignments"].values():
                self.assertIn(assignment["primary_model"], models)

    def test_profile_scoping_does_not_force_roles(self) -> None:
        for role_id, role in self.docs["roles"]["roles"].items():
            if role["classification"] == "GLOBAL_ONLY":
                self.assertNotIn(role_id, self.docs["agent-core"]["assignments"])
            if role["classification"] == "AGENT_CORE_ONLY":
                self.assertNotIn(role_id, self.docs["global"]["assignments"])

    def test_profile_only_roles_are_not_common(self) -> None:
        task_orchestrator = self.docs["roles"]["roles"]["task-orchestrator"]
        self.assertEqual("AGENT_CORE_ONLY", task_orchestrator["classification"])
        self.assertEqual(["agent-core"], task_orchestrator["profiles"])
        self.assertNotIn("task-orchestrator", self.docs["global"]["assignments"])

    def test_quota_family_is_defined_once_per_model(self) -> None:
        families = self.docs["models"]["quota_families"]
        for model in self.docs["models"]["models"].values():
            self.assertIsInstance(model["quota_family"], str)
            self.assertIn(model["quota_family"], families)

    def test_current_common_primary_assignments(self) -> None:
        expected = {
            "build": ("sol", "sol"),
            "plan": ("sol", "sol"),
            "architect": ("sol", "sol"),
            "general": ("luna", "luna"),
            "explore": ("luna", "luna"),
            "verifier": ("luna", "luna"),
            "reviewer": ("terra", "terra"),
            "investigator": ("terra", "terra"),
            "security-reviewer": ("terra", "terra"),
            "scout": ("luna", "luna"),
            "task-orchestrator": ("sol", "sol"),
        }
        for role, (global_model, agent_core_model) in expected.items():
            if role in self.docs["global"]["assignments"]:
                self.assertEqual(global_model, self.docs["global"]["assignments"][role]["primary_model"])
            self.assertEqual(agent_core_model, self.docs["agent-core"]["assignments"][role]["primary_model"])

    def test_intentional_differences_are_only_build_and_general_authority(self) -> None:
        identifiers = {item["id"] for item in self.docs["invariants"]["intentional_differences"]}
        self.assertEqual({"build-authority", "general-authority"}, identifiers)

    def test_intentional_differences_derive_canonical_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dotnix, templates, _, _ = self.make_consumer_fixture(Path(temporary))
            lines, counts = audit(dotnix, templates, ROOT)
            self.assertEqual(0, counts["DIFF"])
            self.assertEqual(0, counts["MISSING"])
            self.assertTrue(any(line.startswith("INTENTIONAL_DIFFERENCE id=build-authority ") for line in lines))
            self.assertTrue(any(line.startswith("INTENTIONAL_DIFFERENCE id=general-authority ") for line in lines))
            self.assertNotIn("INTENTIONAL_DIFFERENCE id=general-primary-model", "\n".join(lines))

    def test_task_orchestrator_global_absence_is_intentional(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dotnix, templates, _, _ = self.make_consumer_fixture(Path(temporary))
            lines, _ = audit(dotnix, templates, ROOT)
            differences = [
                line
                for line in lines
                if line.startswith("INTENTIONAL_DIFFERENCE") and "role=task-orchestrator" in line
            ]
            self.assertIn("INTENTIONAL_DIFFERENCE profile=global role=task-orchestrator expected=absent", differences)

    def test_matching_primary_models_and_modes_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dotnix, templates, dotnix_agents, templates_agents = self.make_consumer_fixture(Path(temporary))
            lines, counts = audit(dotnix, templates, ROOT)
            self.assertEqual(0, counts["DIFF"])
            self.assertEqual(0, counts["MISSING"])
            self.assertIn(
                "PASS profile=global role=build primary_model=openai/gpt-5.6-sol",
                lines,
            )
            self.assertIn(
                "PASS profile=agent-core role=plan mode=primary",
                lines,
            )
            self.assertIn("PASS profile=global fallback_agents=absent", lines)
            self.assertIn("PASS profile=agent-core fallback_agents=absent", lines)
            self.assertIn("PASS profile=agent-core model_fallback_policy=absent", lines)
            self.assertEqual(0, len(list(dotnix_agents.glob("*-fallback.md"))))
            self.assertEqual(0, len(list(templates_agents.glob("*-fallback.md"))))

    def test_wrong_primary_model_is_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dotnix, templates, _, _ = self.make_consumer_fixture(Path(temporary))
            plan_path = dotnix / "config.d/opencode/agents/plan.md"
            plan_path.write_text(
                plan_path.read_text(encoding="utf-8").replace("openai/gpt-5.6-sol", "openai/wrong"),
                encoding="utf-8",
            )
            lines, counts = audit(dotnix, templates, ROOT)
            self.assertEqual(1, counts["DIFF"])
            self.assertTrue(any("DIFF UNEXPECTED_DRIFT profile=global role=plan primary_model" in line for line in lines))

    def test_wrong_primary_mode_is_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dotnix, templates, dotnix_agents, _ = self.make_consumer_fixture(Path(temporary))
            build_path = dotnix_agents / "build.md"
            build_path.write_text(
                build_path.read_text(encoding="utf-8").replace("mode: primary", "mode: subagent"),
                encoding="utf-8",
            )
            lines, counts = audit(dotnix, templates, ROOT)
            self.assertEqual(1, counts["DIFF"])
            self.assertTrue(any("DIFF UNEXPECTED_DRIFT profile=global role=build mode='subagent' expected='primary'" in line for line in lines))

    def test_primary_fallback_residue_any_profile_is_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dotnix, templates, dotnix_agents, templates_agents = self.make_consumer_fixture(Path(temporary))
            (dotnix_agents / "foo-fallback.md").write_text(
                "---\nmode: subagent\nmodel: openai/gpt-5.6-sol\n---\n",
                encoding="utf-8",
            )
            (templates_agents / "foo-fallback.md").write_text(
                "---\nmode: subagent\nmodel: openai/gpt-5.6-luna\n---\n",
                encoding="utf-8",
            )
            _, counts = audit(dotnix, templates, ROOT)
            self.assertEqual(2, counts["DIFF"])

    def test_agent_core_model_fallback_policy_is_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dotnix, templates, _, _ = self.make_consumer_fixture(Path(temporary))
            binding_path = templates / "components/agent-core/.automation/model-fallback.toml"
            binding_path.parent.mkdir(parents=True)
            binding_path.write_text("version = 1\n", encoding="utf-8")
            lines, counts = audit(dotnix, templates, ROOT)
            self.assertEqual(1, counts["DIFF"])
            self.assertIn("DIFF UNEXPECTED_DRIFT profile=agent-core model_fallback_policy=model-fallback.toml expected=absent", lines)

    def test_missing_primary_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dotnix, templates, dotnix_agents, templates_agents = self.make_consumer_fixture(Path(temporary))
            (dotnix_agents / "build.md").unlink()
            (templates_agents / "build.md").unlink()
            _, counts = audit(dotnix, templates, ROOT)
            self.assertEqual(2, counts["MISSING"])

    def test_model_availability_contract_is_accepted(self) -> None:
        availability = self.docs["model-availability"]["policy"]
        expected = {
            "model_substitution": "forbidden",
            "alternate_model_retry": "forbidden",
            "unavailable_result": "BLOCKED",
            "report_exact_provider_model_failure": True,
            "fallback_agents": "forbidden",
        }
        self.assertEqual(expected, availability)

    def test_model_availability_contract_rejects_invalid_fields(self) -> None:
        variants = [
            ("model_substitution", "allowed"),
            ("alternate_model_retry", "allowed"),
            ("unavailable_result", "allowed"),
            ("report_exact_provider_model_failure", False),
            ("report_exact_provider_model_failure", 1),
            ("fallback_agents", True),
        ]
        for field, value in variants:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                shutil.copytree(ROOT / "policy", root / "policy")
                shutil.copytree(ROOT / "profiles", root / "profiles")
                availability_path = root / "policy/model-availability.toml"
                contents = availability_path.read_text(encoding="utf-8")
                marker = f"{field} = "
                lines = []
                for line in contents.splitlines():
                    if line.startswith(marker):
                        if isinstance(value, bool):
                            rendered = "true" if value else "false"
                        elif isinstance(value, str):
                            rendered = f"\"{value}\""
                        else:
                            rendered = str(value)
                        lines.append(f"{marker}{rendered}")
                    else:
                        lines.append(line)
                availability_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                errors = validate_policy(root)
                self.assertTrue(any(field in error for error in errors))

    def test_model_availability_contract_rejects_unknown_policy_field(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "policy", root / "policy")
            shutil.copytree(ROOT / "profiles", root / "profiles")
            availability_path = root / "policy/model-availability.toml"
            contents = availability_path.read_text(encoding="utf-8").replace(
                'fallback_agents = "forbidden"',
                'fallback_agents = "forbidden"\nemergency_model_substitution = "allowed"',
            )
            availability_path.write_text(contents, encoding="utf-8")
            errors = validate_policy(root)
            self.assertIn(
                "model-availability.policy: unknown fields ['emergency_model_substitution']",
                errors,
            )

    def test_model_availability_contract_rejects_unknown_top_level_table(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "policy", root / "policy")
            shutil.copytree(ROOT / "profiles", root / "profiles")
            availability_path = root / "policy/model-availability.toml"
            contents = availability_path.read_text(encoding="utf-8")
            availability_path.write_text(
                contents + "\n[legacy_fallback]\nenabled = true\n",
                encoding="utf-8",
            )
            errors = validate_policy(root)
            self.assertIn(
                "policy/model-availability.toml: unknown top-level keys ['legacy_fallback']",
                errors,
            )

    def test_model_availability_contract_rejects_missing_required_field(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "policy", root / "policy")
            shutil.copytree(ROOT / "profiles", root / "profiles")
            availability_path = root / "policy/model-availability.toml"
            contents = availability_path.read_text(encoding="utf-8").replace(
                'fallback_agents = "forbidden"\n',
                "",
            )
            availability_path.write_text(contents, encoding="utf-8")
            errors = validate_policy(root)
            self.assertIn(
                "model-availability.policy.fallback_agents: required field is missing",
                errors,
            )

    def test_model_availability_contract_rejects_non_integer_schema_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "policy", root / "policy")
            shutil.copytree(ROOT / "profiles", root / "profiles")
            availability_path = root / "policy/model-availability.toml"
            contents = availability_path.read_text(encoding="utf-8").replace(
                "schema_version = 1",
                "schema_version = true",
                1,
            )
            availability_path.write_text(contents, encoding="utf-8")
            errors = validate_policy(root)
            self.assertIn(
                "policy/model-availability.toml: schema_version must be 1",
                errors,
            )

    def test_role_assignment_rejects_substitution_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "policy", root / "policy")
            shutil.copytree(ROOT / "profiles", root / "profiles")
            profile_path = root / "profiles/global.toml"
            contents = profile_path.read_text(encoding="utf-8").replace(
                'primary_model = "sol"\nauthority = "implementation-orchestrator"',
                'primary_model = "sol"\nauthority = "implementation-orchestrator"\nfallback_model = "luna"',
                1,
            )
            profile_path.write_text(contents, encoding="utf-8")
            errors = validate_policy(root)
            self.assertTrue(any("unsupported fields ['fallback_model']" in error for error in errors))

    def test_no_provider_model_literals_outside_models(self) -> None:
        self.assertEqual([], self.parse_errors)

        def has_model_literal(node) -> bool:
            if isinstance(node, dict):
                return any(has_model_literal(value) for value in node.values())
            if isinstance(node, list):
                return any(has_model_literal(value) for value in node)
            return isinstance(node, str) and node.startswith("openai/")

        for name, document in self.docs.items():
            if name == "models":
                continue
            self.assertFalse(has_model_literal(document), f"{name} contains provider model literals")


if __name__ == "__main__":
    unittest.main()
