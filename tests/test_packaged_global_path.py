from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from policy_audit import _permission_contract_context, audit_profile  # noqa: E402
from validate_policy import load_policy  # noqa: E402


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
    "*": "deny",
    "rm*": "deny",
    "git reset --hard*": "deny",
    "git clean*": "deny",
    "git push --force*": "deny",
    "git push --delete*": "deny",
    "sudo*": "deny",
    "nix store delete*": "deny",
}


class PackagedGlobalPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.documents, errors = load_policy(ROOT)
        if errors:
            raise AssertionError(errors)

    def make_packaged_consumer(self, root: Path) -> tuple[Path, Path]:
        consumer = root / "dotnix"
        bundle = consumer / "packages/opencode/config"
        agent_dir = consumer / "packages/opencode/config/agents"
        agent_dir.mkdir(parents=True)

        models = self.documents["models"]["models"]
        roles = self.documents["roles"]["roles"]
        permission_context, context_errors = _permission_contract_context(
            "global", self.documents
        )
        if context_errors or permission_context is None:
            raise AssertionError(context_errors)
        surface_policy = self.documents["global"]["permission_surfaces"]
        parent_roles = set(surface_policy["parent_roles"])
        for role, assignment in self.documents["global"]["assignments"].items():
            mode = roles[role]["kind"]
            model = models[assignment["primary_model"]]["id"]
            role_permissions = (
                PARENT_BASH_PERMISSIONS
                if role in parent_roles
                else LEAF_BASH_PERMISSIONS
            )
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

        surface_roles = [
            (role, "parent") for role in surface_policy["parent_roles"]
        ] + [
            (role, "leaf") for role in surface_policy["leaf_roles"]
        ]
        manifest_lines = [
            "schema_version = 1",
            'contract = "permission-semantics"',
            'profile = "global"',
        ]
        for surface, boundary in surface_roles:
            manifest_lines.extend(
                [
                    "",
                    "[[surfaces]]",
                    f'id = "{surface}"',
                    f'boundary = "{boundary}"',
                    'base_source = "opencode.json"',
                    f'agent_source = "agents/{surface}.md"',
                    'signals = ["NEEDS_APPROVAL", "NEEDS_DECISION"]',
                ]
            )
            probes = tuple(
                (input_value, class_id)
                for input_value, class_id in PERMISSION_PROBES
                if boundary == "parent"
                or class_id in permission_context["mandatory_classes"]
            )
            for input_value, class_id in probes:
                manifest_lines.extend(
                    [
                        "",
                        "[[probes]]",
                        f'surface = "{surface}"',
                        'tool = "bash"',
                        f"input = {json.dumps(input_value)}",
                        f'classes = ["{class_id}"]',
                    ]
                )
        (bundle / "opencode-contract-permissions.toml").write_text(
            "\n".join(manifest_lines) + "\n",
            encoding="utf-8",
        )
        return consumer, agent_dir

    def test_packaged_global_path_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer, _ = self.make_packaged_consumer(Path(temporary))
            lines, counts = audit_profile("global", consumer, self.documents)
            self.assertEqual(0, counts["DIFF"])
            self.assertEqual(0, counts["MISSING"])
            self.assertIn("PASS profile=global role=build primary_model=openai/gpt-5.6-sol", lines)

    def test_packaged_path_precedes_legacy_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer, _ = self.make_packaged_consumer(Path(temporary))
            legacy = consumer / "config.d/opencode/agents"
            legacy.mkdir(parents=True)
            (legacy / "build.md").write_text(
                "---\nmode: primary\nmodel: openai/wrong\n---\n",
                encoding="utf-8",
            )
            _, counts = audit_profile("global", consumer, self.documents)
            self.assertEqual(0, counts["DIFF"])
            self.assertEqual(0, counts["MISSING"])


if __name__ == "__main__":
    unittest.main()
