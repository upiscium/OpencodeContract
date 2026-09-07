from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

from audit_consumers import audit  # noqa: E402
from policy_audit import audit_profile, result_exit_code  # noqa: E402
from validate_policy import load_policy  # noqa: E402


class ConsumerAuditCliTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.documents, errors = load_policy(ROOT)
        if errors:
            raise AssertionError(errors)

    def make_consumer(self, root: Path, profile: str, *, with_model_fallback: bool = False) -> Path:
        consumer = root / profile
        agent_dir = {
            "global": consumer / "config.d/opencode/agents",
            "agent-core": consumer / "components/agent-core/.opencode/agents",
        }[profile]
        agent_dir.mkdir(parents=True)
        models = self.documents["models"]["models"]
        roles = self.documents["roles"]["roles"]
        assignments = self.documents[profile]["assignments"]
        for role, assignment in assignments.items():
            mode = roles[role]["kind"]
            model = models[assignment["primary_model"]]["id"]
            (agent_dir / f"{role}.md").write_text(
                f"---\nmode: {mode}\nmodel: {model}\n---\n", encoding="utf-8"
            )

        if profile == "agent-core" and with_model_fallback:
            binding = consumer / "components/agent-core/.automation/model-fallback.toml"
            binding.parent.mkdir(parents=True)
            binding.write_text("version = 1\n", encoding="utf-8")

        return consumer

    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(TOOLS / "opencode_policy.py"), *arguments],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def add_local_workers(self, consumer: Path) -> None:
        bundle = consumer / "config.d/opencode"
        agents = bundle / "agents"
        bindings = {
            "local-investigator": ("local-quality", "quality-model"),
            "local-tracer": ("local-fast", "fast-model"),
            "local-background": ("local-background", "background-model"),
        }
        permissions = """permission:
  "*": deny
  read: allow
  grep: allow
  glob: deny
  list: deny
  lsp: deny
  bash: deny
  edit: deny
  task: deny
  question: deny
  webfetch: deny
  websearch: deny
  skill: deny
  todowrite: deny
  external_directory: deny
  doom_loop: deny"""
        for worker, (provider, model) in bindings.items():
            (agents / f"{worker}.md").write_text(
                f"---\nmode: subagent\nhidden: true\nmodel: {provider}/{model}\n{permissions}\n---\n",
                encoding="utf-8",
            )
        providers = {
            provider: {"models": {model: {"name": model}}}
            for provider, model in bindings.values()
        }
        (bundle / "opencode.json").write_text(json.dumps({"provider": providers}), encoding="utf-8")
        (bundle / "local-workers.toml").write_text(
            """schema_version = 1
profile = "global"
enabled_by_default = false
opt_in = "explicit-manual"
dispatch = "manual-or-shadow"
max_in_flight = 1
required_tools = ["read", "grep"]
retry_limit = 1
retry_eligibility = "normal_successful_response_with_required_tool_call_count_0"
retry_exclusions = ["api_failure", "runtime_failure", "model_failure", "permission_failure", "schema_failure", "wrong_evidence", "blocked_response", "approval_or_decision", "non_normal_response", "required_tool_call_count_gt_0"]
retry_model_policy = "same_agent_same_model_only"
fallback = "none"

[[workers]]
class = "local-investigator"
provider = "local-quality"
model = "quality-model"
role = "read-only advisory"

[[workers]]
class = "local-tracer"
provider = "local-fast"
model = "fast-model"
role = "read-only advisory"

[[workers]]
class = "local-background"
provider = "local-background"
model = "background-model"
role = "read-only advisory"

[metrics]
counters = ["local_task_total", "local_task_completed", "local_task_rejected", "local_task_retried", "local_tool_required_miss", "local_wrong_answer_detected", "local_runtime_failure"]
optional_observations = ["local_task_latency_ms", "local_input_tokens", "local_output_tokens"]
metadata = ["attempts", "retry_reason", "worker", "configured_model", "required_tool", "required_tool_call_count", "failure_class"]
""",
            encoding="utf-8",
        )

    def assert_local_invalid(self, consumer: Path, reason: str) -> None:
        lines, counts = audit_profile("global", consumer, self.documents)
        self.assertGreater(counts["DIFF"], 0, lines)
        self.assertTrue(any(reason in line for line in lines), lines)
        self.assertEqual(1, result_exit_code(lines, counts, strict=True))

    def run_legacy_dual_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(TOOLS / "audit_consumers.py"), *arguments],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_conforming_global_consumer_passes_without_second_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            consumer = self.make_consumer(root, "global")
            self.assertFalse((root / "agent-core").exists())
            lines, counts = audit_profile("global", consumer, self.documents)
            self.assertEqual(0, counts["DIFF"])
            self.assertEqual(0, counts["MISSING"])
            self.assertIn("PASS profile=global role=plan mode=primary", lines)
            self.assertIn("PASS profile=global fallback_agents=absent", lines)
            self.assertIn("PASS local_workers=absent", lines)

    def test_conforming_agent_core_consumer_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "agent-core")
            lines, counts = audit_profile("agent-core", consumer, self.documents)
            self.assertEqual(0, counts["DIFF"])
            self.assertEqual(0, counts["MISSING"])
            self.assertIn("PASS profile=agent-core role=plan mode=primary", lines)
            self.assertIn("PASS profile=agent-core model_fallback_policy=absent", lines)
            self.assertFalse(any("local_workers=" in line for line in lines))

    def test_conforming_optional_local_workers_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "global")
            self.add_local_workers(consumer)
            lines, counts = audit_profile("global", consumer, self.documents)
            self.assertEqual(0, counts["DIFF"], lines)
            self.assertIn("PASS local_workers=valid static_guarantee=configuration_only", lines)

    def test_missing_or_extra_worker_fails(self) -> None:
        mutations = (
            ('\n[[workers]]\nclass = "local-background"\nprovider = "local-background"\nmodel = "background-model"\nrole = "read-only advisory"\n', "\n"),
            ('\n[metrics]\n', '\n[[workers]]\nclass = "local-extra"\nprovider = "local-extra"\nmodel = "extra-model"\nrole = "read-only advisory"\n\n[metrics]\n'),
        )
        for original, replacement in mutations:
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as temporary:
                consumer = self.make_consumer(Path(temporary), "global")
                self.add_local_workers(consumer)
                manifest = consumer / "config.d/opencode/local-workers.toml"
                manifest.write_text(manifest.read_text().replace(original, replacement), encoding="utf-8")
                self.assert_local_invalid(consumer, "worker_classes")

    def test_visible_or_primary_worker_fails(self) -> None:
        for original, replacement in (("hidden: true", "hidden: false"), ("mode: subagent", "mode: primary")):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as temporary:
                consumer = self.make_consumer(Path(temporary), "global")
                self.add_local_workers(consumer)
                agent = consumer / "config.d/opencode/agents/local-tracer.md"
                agent.write_text(agent.read_text().replace(original, replacement), encoding="utf-8")
                self.assert_local_invalid(consumer, "visibility_or_mode")

    def test_permission_drift_fails(self) -> None:
        mutations = (
            ('  "*": deny\n', ""),
            ("  read: allow\n", ""),
            ("  grep: allow\n", ""),
            ("  edit: deny", "  edit: allow"),
            ("  doom_loop: deny", "  doom_loop: deny\n  write: allow"),
        )
        for original, replacement in mutations:
            with self.subTest(original=original), tempfile.TemporaryDirectory() as temporary:
                consumer = self.make_consumer(Path(temporary), "global")
                self.add_local_workers(consumer)
                agent = consumer / "config.d/opencode/agents/local-investigator.md"
                agent.write_text(agent.read_text().replace(original, replacement), encoding="utf-8")
                self.assert_local_invalid(consumer, "permissions")

    def test_dispatch_retry_and_failure_handling_drift_fails(self) -> None:
        mutations = (
            ('dispatch = "manual-or-shadow"', 'dispatch = "implicit"'),
            ("retry_limit = 1", "retry_limit = 2"),
            ('retry_model_policy = "same_agent_same_model_only"', 'retry_model_policy = "cross_model"'),
            ('fallback = "none"', 'fallback = "canonical-role"'),
            ('"wrong_evidence", ', ""),
            ('"required_tool_call_count_gt_0"', '"required_tool_call_count_any"'),
        )
        for original, replacement in mutations:
            with self.subTest(original=original), tempfile.TemporaryDirectory() as temporary:
                consumer = self.make_consumer(Path(temporary), "global")
                self.add_local_workers(consumer)
                manifest = consumer / "config.d/opencode/local-workers.toml"
                manifest.write_text(manifest.read_text().replace(original, replacement), encoding="utf-8")
                self.assert_local_invalid(consumer, "manifest_")

    def test_provider_model_resolution_and_canonical_model_drift_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "global")
            self.add_local_workers(consumer)
            config = consumer / "config.d/opencode/opencode.json"
            config.write_text(config.read_text().replace('"quality-model"', '"other-model"'), encoding="utf-8")
            self.assert_local_invalid(consumer, "unresolved_model")
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "global")
            self.add_local_workers(consumer)
            manifest = consumer / "config.d/opencode/local-workers.toml"
            manifest.write_text(
                manifest.read_text().replace('provider = "local-quality"', 'provider = "openai"').replace(
                    'model = "quality-model"', 'model = "gpt-5.6-sol"'
                ), encoding="utf-8"
            )
            self.assert_local_invalid(consumer, "canonical_model")

    def test_unregistered_agent_and_partial_deployment_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "global")
            agent_dir = consumer / "config.d/opencode/agents"
            (agent_dir / "emergency.md").write_text("---\nmode: subagent\n---\n", encoding="utf-8")
            self.assert_local_invalid(consumer, "unregistered_agent=forbidden")
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "global")
            self.add_local_workers(consumer)
            (consumer / "config.d/opencode/local-workers.toml").unlink()
            self.assert_local_invalid(consumer, "unregistered_agent=forbidden")

    def test_repository_local_manifest_is_outside_global_audit_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "global")
            nested = consumer / "repository/.opencode"
            nested.mkdir(parents=True)
            (nested / "local-workers.toml").write_text("invalid = true\n", encoding="utf-8")
            lines, counts = audit_profile("global", consumer, self.documents)
            self.assertEqual(0, counts["DIFF"], lines)
            self.assertIn("PASS local_workers=absent", lines)

    def test_invalid_utf8_is_controlled_drift(self) -> None:
        for relative in ("local-workers.toml", "opencode.json", "agents/local-tracer.md"):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                consumer = self.make_consumer(Path(temporary), "global")
                self.add_local_workers(consumer)
                (consumer / "config.d/opencode" / relative).write_bytes(b"\xff\xfe")
                lines, counts = audit_profile("global", consumer, self.documents)
                self.assertGreater(counts["DIFF"], 0, lines)
                self.assertEqual(1, result_exit_code(lines, counts, strict=True))

    def test_symlinked_profile_directory_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            consumer = self.make_consumer(root, "global")
            external = root / "external-agents"
            external.mkdir()
            preferred = consumer / "packages/opencode/config"
            preferred.mkdir(parents=True)
            (preferred / "agents").symlink_to(external, target_is_directory=True)
            lines, counts = audit_profile("global", consumer, self.documents)
            self.assertTrue(any("unsafe_path=forbidden" in line for line in lines), lines)
            self.assertEqual(1, counts["DIFF"])

    def test_symlinked_canonical_agent_escape_is_rejected_for_both_profiles(self) -> None:
        for profile, relative in (
            ("global", "config.d/opencode/agents/plan.md"),
            ("agent-core", "components/agent-core/.opencode/agents/plan.md"),
        ):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                consumer = self.make_consumer(root, profile)
                external = root / f"external-{profile}.md"
                external.write_text((consumer / relative).read_text(), encoding="utf-8")
                agent = consumer / relative
                agent.unlink()
                agent.symlink_to(external)
                lines, counts = audit_profile(profile, consumer, self.documents)
                self.assertTrue(any("role=plan" in line and "unsafe_path=forbidden" in line for line in lines), lines)
                self.assertEqual(1, counts["DIFF"])

    def test_agent_core_has_no_optional_worker_requirement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "agent-core")
            agent_dir = consumer / "components/agent-core/.opencode/agents"
            (agent_dir / "local-background.md").write_text("---\nmode: subagent\n---\n", encoding="utf-8")
            lines, counts = audit_profile("agent-core", consumer, self.documents)
            self.assertEqual(0, counts["DIFF"], lines)
            self.assertFalse(any("local_workers=" in line for line in lines))

    def test_global_model_drift_is_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "global")
            plan = consumer / "config.d/opencode/agents/plan.md"
            plan.write_text(plan.read_text().replace("openai/gpt-5.6-sol", "openai/wrong"), encoding="utf-8")
            lines, counts = audit_profile("global", consumer, self.documents)
            self.assertEqual(1, counts["DIFF"])
            self.assertTrue(any("role=plan primary_model" in line for line in lines))

    def test_global_mode_drift_is_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "global")
            general = consumer / "config.d/opencode/agents/general.md"
            general.write_text(general.read_text().replace("mode: subagent", "mode: primary"), encoding="utf-8")
            lines, counts = audit_profile("global", consumer, self.documents)
            self.assertEqual(1, counts["DIFF"])
            self.assertTrue(any("role=general mode='primary' expected='subagent'" in line for line in lines))

    def test_global_fallback_agent_residue_is_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "global")
            (consumer / "config.d/opencode/agents/plan-fallback.md").write_text(
                "---\nmode: subagent\nmodel: openai/gpt-5.6-sol\n---\n", encoding="utf-8"
            )
            lines, counts = audit_profile("global", consumer, self.documents)
            self.assertEqual(1, counts["DIFF"])
            self.assertTrue(any("fallback_residue=forbidden" in line for line in lines))

    def test_agent_core_fallback_residue_is_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "agent-core")
            (consumer / "components/agent-core/.opencode/agents/verifier-fallback.md").write_text(
                "---\nmode: subagent\nmodel: openai/gpt-5.6-sol\n---\n", encoding="utf-8"
            )
            lines, counts = audit_profile("agent-core", consumer, self.documents)
            self.assertEqual(1, counts["DIFF"])
            self.assertTrue(any("fallback_residue=forbidden" in line for line in lines))

    def test_arbitrary_fallback_agent_residue_is_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "global")
            (consumer / "config.d/opencode/agents/foo-fallback.md").write_text(
                "---\nmode: subagent\nmodel: openai/gpt-5.6-sol\n---\n", encoding="utf-8"
            )
            lines, counts = audit_profile("global", consumer, self.documents)
            self.assertEqual(1, counts["DIFF"])
            self.assertTrue(any("agent=foo-fallback" in line for line in lines))

    def test_agent_core_model_fallback_policy_residue_is_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "agent-core", with_model_fallback=True)
            lines, counts = audit_profile("agent-core", consumer, self.documents)
            self.assertEqual(1, counts["DIFF"])
            self.assertTrue(any("model_fallback_policy=model-fallback.toml" in line for line in lines))

    def test_missing_primary_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "global")
            (consumer / "config.d/opencode/agents/plan.md").unlink()
            _, counts = audit_profile("global", consumer, self.documents)
            self.assertEqual(1, counts["MISSING"])

    def test_unknown_profile_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "unknown profile"):
                audit_profile("unknown", Path(temporary), self.documents)
            result = self.run_cli("audit-consumer", "--profile", "unknown", "--consumer", temporary)
            self.assertNotEqual(0, result.returncode)

    def test_validate_command(self) -> None:
        result = self.run_cli("validate")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("VALID policy contract", result.stdout)

    def test_audit_consumer_global_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "global")
            result = self.run_cli("audit-consumer", "--profile", "global", "--consumer", str(consumer), "--strict")
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn("DIFF=0 MISSING=0", result.stdout)

    def test_audit_consumer_agent_core_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "agent-core")
            result = self.run_cli(
                "audit-consumer", "--profile", "agent-core", "--consumer", str(consumer), "--strict"
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn("DIFF=0 MISSING=0", result.stdout)

    def test_strict_failure_is_nonzero_for_fallback_residue(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "global")
            (consumer / "config.d/opencode/agents/foo-fallback.md").write_text(
                "---\nmode: subagent\nmodel: openai/gpt-5.6-sol\n---\n", encoding="utf-8"
            )
            result = self.run_cli("audit-consumer", "--profile", "global", "--consumer", str(consumer), "--strict")
            self.assertEqual(1, result.returncode)
            self.assertIn("DIFF=1", result.stdout)

    def test_malformed_arguments_fail(self) -> None:
        result = self.run_cli("audit-consumer", "--profile", "global")
        self.assertNotEqual(0, result.returncode)
        result = self.run_cli("audit-consumer", "--profile", "global", "--consumer", "/definitely/missing")
        self.assertNotEqual(0, result.returncode)

    def test_legacy_dual_cli_rejects_invalid_consumer_path(self) -> None:
        result = self.run_legacy_dual_cli("--dotnix", "/definitely/missing-dotnix", "--templates", "/definitely/missing-templates")
        self.assertEqual(2, result.returncode)

    def test_policy_invalid_result_is_unconditionally_nonzero(self) -> None:
        self.assertEqual(
            1,
            result_exit_code(["DIFF POLICY_INVALID malformed"], {"DIFF": 1, "MISSING": 0}, False),
        )

    def test_dual_audit_regression(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            global_consumer = self.make_consumer(root, "global")
            agent_core_consumer = self.make_consumer(root, "agent-core")
            _, counts = audit(global_consumer, agent_core_consumer, ROOT)
            self.assertEqual(0, counts["DIFF"])
            self.assertEqual(0, counts["MISSING"])

    def test_intentional_differences_are_unchanged(self) -> None:
        identifiers = {item["id"] for item in self.documents["invariants"]["intentional_differences"]}
        self.assertEqual({"build-authority", "general-authority"}, identifiers)

    def test_read_only_consumer_tree_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "global")
            paths = sorted(consumer.rglob("*"), key=lambda p: len(p.parts), reverse=True)
            try:
                for path in paths:
                    path.chmod(0o555 if path.is_dir() else 0o444)
                consumer.chmod(0o555)
                _, counts = audit_profile("global", consumer, self.documents)
                self.assertEqual(0, counts["DIFF"])
                self.assertEqual(0, counts["MISSING"])
            finally:
                consumer.chmod(0o755)
                for path in reversed(paths):
                    if path.exists():
                        path.chmod(0o755 if path.is_dir() else 0o644)


if __name__ == "__main__":
    unittest.main()
