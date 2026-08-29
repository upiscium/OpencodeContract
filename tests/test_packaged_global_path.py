from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from policy_audit import audit_profile  # noqa: E402
from validate_policy import load_policy  # noqa: E402


class PackagedGlobalPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.documents, errors = load_policy(ROOT)
        if errors:
            raise AssertionError(errors)

    def make_packaged_consumer(self, root: Path) -> tuple[Path, Path]:
        consumer = root / "dotnix"
        agent_dir = consumer / "packages/opencode/config/agents"
        agent_dir.mkdir(parents=True)

        models = self.documents["models"]["models"]
        roles = self.documents["roles"]["roles"]
        for role, assignment in self.documents["global"]["assignments"].items():
            mode = roles[role]["kind"]
            model = models[assignment["primary_model"]]["id"]
            (agent_dir / f"{role}.md").write_text(
                f"---\nmode: {mode}\nmodel: {model}\n---\n",
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
