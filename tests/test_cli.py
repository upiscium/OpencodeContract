from __future__ import annotations

import json
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

from audit_consumers import audit  # noqa: E402
from policy_audit import (  # noqa: E402
    _permission_wildcard_match,
    audit_profile,
    result_exit_code,
)
from validate_policy import load_policy  # noqa: E402


PERMISSION_CLASSES = (
    "safe-read-only",
    "local-filesystem-delete",
    "repository-history-destruction",
    "remote-destructive-operation",
    "privilege-escalation",
    "system-store-destruction",
)
PERMISSION_PROBES = (
    ("git status", "safe-read-only"),
    ("rm -rf cache", "local-filesystem-delete"),
    ("git reset --hard HEAD", "repository-history-destruction"),
    ("git push --force origin main", "remote-destructive-operation"),
    ("sudo command", "privilege-escalation"),
    ("nix store delete /nix/store/example", "system-store-destruction"),
)
PARENT_BASH_PERMISSIONS = {
    "*": "ask",
    "git status*": "allow",
    "rm*": "ask",
    "git reset --hard*": "deny",
    "git clean*": "deny",
    "git push --force*": "deny",
    "git push --delete*": "deny",
    "sudo*": "deny",
    "nix store delete*": "deny",
}
LEAF_BASH_PERMISSIONS = {
    "*": "ask",
    "git status*": "allow",
    "rm*": "deny",
    "git reset --hard*": "deny",
    "git clean*": "deny",
    "git push --force*": "deny",
    "git push --delete*": "deny",
    "sudo*": "deny",
    "nix store delete*": "deny",
}


class ConsumerAuditCliTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.documents, errors = load_policy(ROOT)
        if errors:
            raise AssertionError(errors)

    def make_consumer(self, root: Path, profile: str, *, with_model_fallback: bool = False) -> Path:
        consumer = root / profile
        bundle = {
            "global": consumer / "config.d/opencode",
            "agent-core": consumer / "components/agent-core",
        }[profile]
        agent_dir = {
            "global": bundle / "agents",
            "agent-core": bundle / ".opencode/agents",
        }[profile]
        agent_dir.mkdir(parents=True)
        models = self.documents["models"]["models"]
        roles = self.documents["roles"]["roles"]
        assignments = self.documents[profile]["assignments"]
        for role, assignment in assignments.items():
            mode = roles[role]["kind"]
            role_permissions = (
                PARENT_BASH_PERMISSIONS
                if profile == "agent-core" and role == "task-orchestrator"
                else LEAF_BASH_PERMISSIONS
            )
            model = models[assignment["primary_model"]]["id"]
            permission_lines = "\n".join(
                f"    {json.dumps(pattern)}: {action}"
                for pattern, action in role_permissions.items()
            )
            (agent_dir / f"{role}.md").write_text(
                f"---\nmode: {mode}\nmodel: {model}\n"
                f"permission:\n  bash:\n{permission_lines}\n---\n",
                encoding="utf-8",
            )

        (bundle / "opencode.json").write_text(
            json.dumps({"permission": {"bash": PARENT_BASH_PERMISSIONS}}),
            encoding="utf-8",
        )
        source_prefix = "agents" if profile == "global" else ".opencode/agents"
        surface_sources = [("parent", "parent", "json", ["opencode.json"])]
        surface_sources.extend(
            (
                role,
                "parent" if profile == "agent-core" and role == "task-orchestrator" else "leaf",
                "agent-frontmatter",
                [f"{source_prefix}/{role}.md"],
            )
            for role in assignments
        )
        manifest_lines = [
            "schema_version = 1",
            'contract = "permission-semantics"',
            f'profile = "{profile}"',
        ]
        for surface_id, boundary, source_kind, sources in surface_sources:
            manifest_lines.extend(
                [
                    "",
                    "[[surfaces]]",
                    f'id = "{surface_id}"',
                    f'boundary = "{boundary}"',
                    f'source_kind = "{source_kind}"',
                    f"sources = [{', '.join(json.dumps(source) for source in sources)}]",
                ]
            )
        for surface_id, _, _, _ in surface_sources:
            for input_value, class_id in PERMISSION_PROBES:
                manifest_lines.extend(
                    [
                        "",
                        "[[probes]]",
                        f'surface = "{surface_id}"',
                        'tool = "bash"',
                        f"input = {json.dumps(input_value)}",
                        f'classes = ["{class_id}"]',
                    ]
                )
        (bundle / "opencode-contract-permissions.toml").write_text(
            "\n".join(manifest_lines) + "\n",
            encoding="utf-8",
        )

        if profile == "agent-core" and with_model_fallback:
            binding = consumer / "components/agent-core/.automation/model-fallback.toml"
            binding.parent.mkdir(parents=True)
            binding.write_text("version = 1\n", encoding="utf-8")

        return consumer

    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(TOOLS / "opencode_contract.py"), *arguments],
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
        config_path = bundle / "opencode.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config["provider"] = providers
        config_path.write_text(json.dumps(config), encoding="utf-8")
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

    def test_permission_surfaces_cover_all_classes_and_parse_nested_frontmatter(self) -> None:
        for profile in ("global", "agent-core"):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as temporary:
                consumer = self.make_consumer(Path(temporary), profile)
                lines, counts = audit_profile(profile, consumer, self.documents)
                self.assertEqual(0, counts["DIFF"], lines)
                self.assertEqual(0, counts["MISSING"], lines)
                surfaces = ["parent", *self.documents[profile]["assignments"]]
                for surface in surfaces:
                    observed = {
                        class_id
                        for _, class_id in PERMISSION_PROBES
                        if any(
                            line.startswith(f"PASS profile={profile} surface={surface} ")
                            and f"classes={class_id}" in line
                            for line in lines
                        )
                    }
                    self.assertEqual(set(PERMISSION_CLASSES), observed, surface)
                source = (
                    "agents/plan.md"
                    if profile == "global"
                    else ".opencode/agents/plan.md"
                )
                self.assertTrue(
                    any(
                        line.startswith(
                            f"PASS profile={profile} surface=plan source={source}"
                        )
                        and "classes=local-filesystem-delete" in line
                        and "actual=deny" in line
                        for line in lines
                    ),
                    lines,
                )

    def test_missing_permission_manifest_is_missing_and_strict_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "global")
            manifest = consumer / "config.d/opencode/opencode-contract-permissions.toml"
            manifest.unlink()
            lines, counts = audit_profile("global", consumer, self.documents)
            self.assertEqual(1, counts["MISSING"], lines)
            self.assertEqual(1, result_exit_code(lines, counts, strict=True))
            self.assertTrue(any("reason=manifest_missing" in line for line in lines), lines)
            result = self.run_cli(
                "audit-consumer",
                "--profile",
                "global",
                "--consumer",
                str(consumer),
                "--strict",
            )
            self.assertEqual(1, result.returncode, result.stdout + result.stderr)

    def test_permission_manifest_schema_errors_are_controlled_diffs(self) -> None:
        variants = (
            ("malformed", "schema_version = 1\nnot = [\n", "manifest_parse_error"),
            (
                "unknown top-level field",
                'profile = "global"\nunknown = true\n',
                "unknown fields",
            ),
            (
                "unknown surface field",
                'boundary = "parent"\nextra = true\n',
                "surfaces[0] unknown fields",
            ),
            (
                "unknown probe field",
                'tool = "bash"\nextra = true\n',
                "probes[0] unknown fields",
            ),
            ("unknown profile", 'profile = "unknown"', "manifest invalid profile"),
            (
                "profile mismatch",
                'profile = "agent-core"',
                "does not match selected profile",
            ),
            ("wrong contract", 'contract = "other-contract"', "manifest contract"),
            ("wrong schema", "schema_version = 2", "manifest schema_version"),
        )
        for label, replacement, reason in variants:
            with self.subTest(variant=label), tempfile.TemporaryDirectory() as temporary:
                consumer = self.make_consumer(Path(temporary), "global")
                manifest = consumer / "config.d/opencode/opencode-contract-permissions.toml"
                contents = manifest.read_text(encoding="utf-8")
                if label == "malformed":
                    contents = replacement
                elif label == "unknown top-level field":
                    contents = contents.replace('profile = "global"\n', replacement, 1)
                elif label == "unknown surface field":
                    contents = contents.replace(replacement.splitlines()[0], replacement, 1)
                elif label == "unknown probe field":
                    contents = contents.replace(replacement.splitlines()[0], replacement, 1)
                else:
                    old = {
                        "unknown profile": 'profile = "global"',
                        "profile mismatch": 'profile = "global"',
                        "wrong contract": 'contract = "permission-semantics"',
                        "wrong schema": "schema_version = 1",
                    }[label]
                    contents = contents.replace(old, replacement, 1)
                manifest.write_text(contents, encoding="utf-8")
                lines, counts = audit_profile("global", consumer, self.documents)
                self.assertEqual(1, counts["DIFF"], lines)
                self.assertEqual(0, counts["MISSING"], lines)
                self.assertTrue(any(reason in line for line in lines), lines)

    def test_permission_manifest_rejects_dangling_surface_and_missing_coverage(self) -> None:
        variants = (
            (
                "dangling surface",
                lambda contents: contents.replace(
                    'surface = "parent"', 'surface = "orphan"', 1
                ),
                "dangling='orphan'",
            ),
            (
                "missing class coverage",
                lambda contents: contents.replace(
                    '[[probes]]\nsurface = "parent"\ntool = "bash"\n'
                    'input = "git status"\nclasses = ["safe-read-only"]\n\n',
                    "",
                    1,
                ),
                "surface='parent' missing_coverage",
            ),
        )
        for label, mutate, reason in variants:
            with self.subTest(variant=label), tempfile.TemporaryDirectory() as temporary:
                consumer = self.make_consumer(Path(temporary), "global")
                manifest = consumer / "config.d/opencode/opencode-contract-permissions.toml"
                manifest.write_text(mutate(manifest.read_text(encoding="utf-8")), encoding="utf-8")
                lines, counts = audit_profile("global", consumer, self.documents)
                self.assertEqual(1, counts["DIFF"], lines)
                self.assertEqual(0, counts["MISSING"], lines)
                self.assertTrue(any(reason in line for line in lines), lines)

    def test_permission_manifest_cannot_swap_authority_or_benign_source(self) -> None:
        variants = (
            (
                "boundary swap",
                lambda contents: contents.replace(
                    'id = "build"\nboundary = "leaf"',
                    'id = "build"\nboundary = "parent"',
                    1,
                ),
                "source_boundary_mismatch=agents/build.md",
            ),
            (
                "benign source",
                lambda contents: contents.replace(
                    'sources = ["opencode.json"]',
                    'sources = ["agents/benign.md"]',
                    1,
                ),
                "missing_declared_source=opencode.json",
            ),
        )
        for label, mutate, reason in variants:
            with self.subTest(variant=label), tempfile.TemporaryDirectory() as temporary:
                consumer = self.make_consumer(Path(temporary), "global")
                manifest = consumer / "config.d/opencode/opencode-contract-permissions.toml"
                manifest.write_text(mutate(manifest.read_text(encoding="utf-8")), encoding="utf-8")
                lines, counts = audit_profile("global", consumer, self.documents)
                self.assertEqual(1, counts["DIFF"], lines)
                self.assertTrue(any(reason in line for line in lines), lines)

    def test_duplicate_probe_diagnostic_redacts_input(self) -> None:
        secret = "private-probe-input"
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "global")
            manifest = consumer / "config.d/opencode/opencode-contract-permissions.toml"
            contents = manifest.read_text(encoding="utf-8").replace(
                'input = "git status"',
                f'input = "{secret}"',
                1,
            )
            contents += (
                "\n[[probes]]\n"
                'surface = "parent"\n'
                'tool = "bash"\n'
                f'input = "{secret}"\n'
                'classes = ["safe-read-only"]\n'
            )
            manifest.write_text(contents, encoding="utf-8")
            lines, counts = audit_profile("global", consumer, self.documents)
            self.assertEqual(1, counts["DIFF"], lines)
            self.assertTrue(
                any(
                    f"input_sha256={hashlib.sha256(secret.encode()).hexdigest()}" in line
                    for line in lines
                ),
                lines,
            )
            self.assertFalse(any(secret in line for line in lines), lines)

    def test_wildcard_matching_handles_long_probe_inputs_without_recursion(self) -> None:
        long_input = "x" * 100_000
        self.assertTrue(_permission_wildcard_match("*", long_input))
        self.assertTrue(_permission_wildcard_match("x*", long_input))
        self.assertFalse(_permission_wildcard_match("?", long_input))

    def test_non_regular_permission_manifest_fails_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "global")
            manifest = consumer / "config.d/opencode/opencode-contract-permissions.toml"
            manifest.unlink()
            os.mkfifo(manifest)
            lines, counts = audit_profile("global", consumer, self.documents)
            self.assertEqual(1, counts["DIFF"], lines)
            self.assertTrue(any("reason=manifest_not_regular" in line for line in lines), lines)

    def test_permission_sources_missing_invalid_symlink_and_utf8_fail_closed(self) -> None:
        source = "agents/plan.md"
        missing_variants = (
            ("missing", source, "source_missing"),
            ("invalid", source, "source_parse_error"),
            ("symlink", source, "source_path_not_confined"),
            ("invalid utf8", "opencode.json", "source_parse_error"),
        )
        for label, replacement, reason in missing_variants:
            with self.subTest(source=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                consumer = self.make_consumer(root, "global")
                bundle = consumer / "config.d/opencode"
                manifest = bundle / "opencode-contract-permissions.toml"
                contents = manifest.read_text(encoding="utf-8")
                if label == "missing":
                    (bundle / replacement).unlink()
                elif label == "invalid":
                    (bundle / source).write_text("not frontmatter\n", encoding="utf-8")
                elif label == "symlink":
                    external = root / "external-permission.md"
                    external.write_text("---\npermission:\n  bash:\n    \"*\": deny\n---\n", encoding="utf-8")
                    (bundle / source).unlink()
                    (bundle / source).symlink_to(external)
                else:
                    (bundle / replacement).write_bytes(b"\xff\xfe")
                manifest.write_text(contents, encoding="utf-8")
                lines, counts = audit_profile("global", consumer, self.documents)
                if label == "missing":
                    self.assertGreaterEqual(counts["MISSING"], 6, lines)
                else:
                    self.assertGreater(counts["DIFF"], 0, lines)
                self.assertEqual(1, result_exit_code(lines, counts, strict=True))
                self.assertTrue(any(reason in line for line in lines), lines)

    def test_parent_local_delete_deny_or_allow_is_not_conforming(self) -> None:
        for action in ("deny", "allow"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as temporary:
                consumer = self.make_consumer(Path(temporary), "global")
                config_path = consumer / "config.d/opencode/opencode.json"
                config = json.loads(config_path.read_text(encoding="utf-8"))
                config["permission"]["bash"]["rm*"] = action
                config_path.write_text(json.dumps(config), encoding="utf-8")
                lines, counts = audit_profile("global", consumer, self.documents)
                self.assertEqual(1, counts["DIFF"], lines)
                self.assertTrue(
                    any(
                        "surface=parent" in line
                        and "expected=ask" in line
                        and f"actual={action}" in line
                        for line in lines
                    ),
                    lines,
                )

    def test_leaf_local_delete_allow_or_ask_is_not_conforming(self) -> None:
        for action in ("allow", "ask"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as temporary:
                consumer = self.make_consumer(Path(temporary), "global")
                agent = consumer / "config.d/opencode/agents/plan.md"
                contents = agent.read_text(encoding="utf-8").replace(
                    '    "rm*": deny', f'    "rm*": {action}', 1
                )
                agent.write_text(contents, encoding="utf-8")
                lines, counts = audit_profile("global", consumer, self.documents)
                self.assertEqual(1, counts["DIFF"], lines)
                self.assertTrue(
                    any(
                        "surface=plan" in line
                        and "expected=deny" in line
                        and f"actual={action}" in line
                        for line in lines
                    ),
                    lines,
                )

    def test_structural_permission_classes_reject_ask_and_allow(self) -> None:
        patterns = {
            "repository-history-destruction": "git reset --hard*",
            "remote-destructive-operation": "git push --force*",
            "privilege-escalation": "sudo*",
            "system-store-destruction": "nix store delete*",
        }
        for boundary in ("parent", "leaf"):
            for class_id, pattern in patterns.items():
                for action in ("ask", "allow"):
                    with self.subTest(boundary=boundary, class_id=class_id, action=action), tempfile.TemporaryDirectory() as temporary:
                        consumer = self.make_consumer(Path(temporary), "global")
                        surface = "parent" if boundary == "parent" else "plan"
                        if boundary == "parent":
                            config_path = consumer / "config.d/opencode/opencode.json"
                            config = json.loads(config_path.read_text(encoding="utf-8"))
                            config["permission"]["bash"][pattern] = action
                            config_path.write_text(json.dumps(config), encoding="utf-8")
                        else:
                            agent = consumer / "config.d/opencode/agents/plan.md"
                            contents = agent.read_text(encoding="utf-8").replace(
                                f'    "{pattern}": deny', f'    "{pattern}": {action}', 1
                            )
                            agent.write_text(contents, encoding="utf-8")
                        lines, counts = audit_profile("global", consumer, self.documents)
                        self.assertEqual(1, counts["DIFF"], lines)
                        self.assertTrue(
                            any(
                                f"surface={surface}" in line
                                and f"classes={class_id}" in line
                                and f"actual={action}" in line
                                for line in lines
                            ),
                            lines,
                        )

    def test_late_stronger_deny_overlap_makes_parent_local_delete_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "global")
            config_path = consumer / "config.d/opencode/opencode.json"
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config["permission"]["bash"]["rm -rf*"] = "deny"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            lines, counts = audit_profile("global", consumer, self.documents)
            self.assertEqual(1, counts["DIFF"], lines)
            self.assertTrue(
                any(
                    "surface=parent" in line
                    and "classes=local-filesystem-delete" in line
                    and "expected=ask actual=deny" in line
                    for line in lines
                ),
                lines,
            )

    def test_unrelated_unprobed_permission_entry_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "global")
            config_path = consumer / "config.d/opencode/opencode.json"
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config["permission"]["bash"]["echo*"] = "deny"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            lines, counts = audit_profile("global", consumer, self.documents)
            self.assertEqual(0, counts["DIFF"], lines)
            self.assertEqual(0, counts["MISSING"], lines)

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

    def test_nested_unregistered_agent_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "global")
            nested = consumer / "config.d/opencode/agents/extra"
            nested.mkdir()
            (nested / "evil.md").write_text("---\nmode: subagent\n---\n", encoding="utf-8")
            lines, counts = audit_profile("global", consumer, self.documents)
            self.assertEqual(1, result_exit_code(lines, counts, strict=True))
            self.assertTrue(
                any("agent=extra/evil" in line and "unregistered_agent=forbidden" in line for line in lines),
                lines,
            )

    def test_nested_fallback_agent_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer = self.make_consumer(Path(temporary), "global")
            nested = consumer / "config.d/opencode/agents/extra"
            nested.mkdir()
            (nested / "general-fallback.md").write_text("---\nmode: subagent\n---\n", encoding="utf-8")
            lines, counts = audit_profile("global", consumer, self.documents)
            self.assertEqual(1, result_exit_code(lines, counts, strict=True))
            self.assertTrue(
                any("agent=extra/general-fallback" in line and "fallback_residue=forbidden" in line for line in lines),
                lines,
            )

    def test_nested_agent_symlink_escape_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            consumer = self.make_consumer(root, "global")
            external = root / "external-agent.md"
            external.write_text("---\nmode: subagent\n---\n", encoding="utf-8")
            nested = consumer / "config.d/opencode/agents/extra"
            nested.mkdir()
            (nested / "evil.md").symlink_to(external)
            lines, counts = audit_profile("global", consumer, self.documents)
            self.assertEqual(1, result_exit_code(lines, counts, strict=True))
            self.assertTrue(
                any("agent=extra/evil" in line and "unsafe_path=forbidden" in line for line in lines),
                lines,
            )

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
                self.assertEqual(7, counts["DIFF"])

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
            plan.write_text(plan.read_text().replace("openai/gpt-5.6-luna", "openai/wrong"), encoding="utf-8")
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

    def test_agent_core_symlinked_fallback_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            consumer = self.make_consumer(root, "agent-core")
            external = root / "external-fallback.md"
            external.write_text("---\nmode: subagent\n---\n", encoding="utf-8")
            fallback = consumer / "components/agent-core/.opencode/agents/plan-fallback.md"
            fallback.symlink_to(external)
            lines, counts = audit_profile("agent-core", consumer, self.documents)
            self.assertEqual(1, counts["DIFF"], lines)
            self.assertTrue(any("agent=plan-fallback" in line and "unsafe_path=forbidden" in line for line in lines))

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
            self.assertEqual(7, counts["MISSING"])

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
