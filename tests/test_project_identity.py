from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

from opencode_contract import build_parser  # noqa: E402


class ProjectIdentityTests(unittest.TestCase):
    def test_cli_uses_canonical_program_name(self) -> None:
        self.assertEqual("opencode-contract", build_parser().prog)

    def test_nix_package_and_binary_are_canonical(self) -> None:
        flake = (ROOT / "flake.nix").read_text(encoding="utf-8")
        self.assertIn('"opencode-contract" = package;', flake)
        self.assertIn('"$out/bin/opencode-contract"', flake)
        self.assertIn("tools/opencode_contract.py", flake)

    def test_cli_help_uses_canonical_program_name(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOLS / "opencode_contract.py"), "--help"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(result.stdout.startswith("usage: opencode-contract "), result.stdout)

    def test_source_has_no_legacy_project_identity(self) -> None:
        forbidden = (
            "OpenCode" + "Policy",
            "opencode" + "Policy",
            "opencode-" + "policy",
            "opencode_" + "policy",
            "github:upiscium/" + "OpenCode" + "Policy",
        )
        text_suffixes = {".md", ".nix", ".py", ".toml", ".json", ".jsonc", ".yaml", ".yml"}
        matches: list[str] = []
        for path in ROOT.rglob("*"):
            if not path.is_file() or path.suffix not in text_suffixes:
                continue
            if any(part in {".git", "__pycache__"} for part in path.parts):
                continue
            contents = path.read_text(encoding="utf-8")
            for legacy in forbidden:
                if legacy in contents:
                    matches.append(f"{path.relative_to(ROOT)}: {legacy}")
        self.assertEqual([], matches)


if __name__ == "__main__":
    unittest.main()
