import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "lobster_analyze.py"


class ScanRootTests(unittest.TestCase):
    def test_invalid_root_exits_with_path_in_error(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            existing_file = base / "file.txt"
            existing_file.touch()
            output = base / "out.sarif"
            for root in (base / "missing", existing_file):
                with self.subTest(root=root):
                    result = subprocess.run(
                        [sys.executable, str(SCRIPT), "--root", str(root), "--output", str(output)],
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn(str(root), result.stderr)
                    self.assertFalse(output.exists())

    def test_empty_root_warns_and_writes_sarif(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "out.sarif"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(root), "--output", str(output)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("warning", result.stderr.lower())
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["runs"][0]["results"], [])
