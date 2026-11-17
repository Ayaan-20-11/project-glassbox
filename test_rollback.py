import json
from pathlib import Path
import tempfile
import unittest

from lab_rollback import (
    begin_change,
    commit_change,
    emergency_reset,
    init_baseline,
    revert_change,
    verify_against_baseline,
)


class RollbackManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "app.py").write_text("VALUE = 'baseline'\n", encoding="utf-8")
        (self.root / "config.json").write_text('{"mode": "safe"}\n', encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_baseline_is_immutable(self) -> None:
        self.assertEqual(init_baseline(self.root), 0)
        # Second attempt must refuse overwrite
        self.assertEqual(init_baseline(self.root), 1)

    def test_change_tracking_and_individual_revert(self) -> None:
        self.assertEqual(init_baseline(self.root), 0)
        self.assertEqual(begin_change(self.root, "exp-001", "Test tweak", ["app.py"]), 0)
        (self.root / "app.py").write_text("VALUE = 'modified'\n", encoding="utf-8")
        self.assertEqual(commit_change(self.root, "exp-001"), 0)

        self.assertNotEqual(verify_against_baseline(self.root, run_tests=False), 0)
        self.assertEqual(revert_change(self.root, "exp-001"), 0)
        self.assertEqual((self.root / "app.py").read_text(encoding="utf-8"), "VALUE = 'baseline'\n")
        self.assertEqual(verify_against_baseline(self.root, run_tests=False), 0)

        changelog = (self.root / ".lab_backups" / "changelog.jsonl").read_text(encoding="utf-8").splitlines()
        actions = [json.loads(line).get("action", "CHANGE") for line in changelog]
        self.assertEqual(actions, ["CHANGE", "REVERT"])

    def test_emergency_reset_restores_modified_and_removes_extra_files(self) -> None:
        self.assertEqual(init_baseline(self.root), 0)
        (self.root / "app.py").write_text("VALUE = 'corrupted'\n", encoding="utf-8")
        (self.root / "extra_experiment.txt").write_text("temp\n", encoding="utf-8")

        self.assertEqual(verify_against_baseline(self.root, run_tests=False), 2)
        self.assertEqual(emergency_reset(self.root, run_tests=False), 0)
        self.assertFalse((self.root / "extra_experiment.txt").exists())
        self.assertEqual((self.root / "app.py").read_text(encoding="utf-8"), "VALUE = 'baseline'\n")


if __name__ == "__main__":
    unittest.main()
