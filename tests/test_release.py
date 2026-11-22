import io
import sys
from contextlib import redirect_stdout
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.create_release import Result, create_release  # noqa: E402


class FakeGh:
    """A gh CLI whose answers are driven by a scenario name."""

    def __init__(self, scenario: str):
        self.scenario = scenario
        self.calls = []
        self.views = 0

    def __call__(self, *args):
        self.calls.append(args)
        action = args[1]
        if action == "view":
            self.views += 1
            if self.scenario == "exists" or (self.scenario == "race" and self.views > 1):
                return Result(0, '{"tagName":"v0.2.1"}')
            return Result(1, "", "release not found")
        if action == "create":
            if self.scenario == "race":
                return Result(1, "", "HTTP 422: Validation Failed")
            if self.scenario == "api_error":
                return Result(1, "", "HTTP 500: Internal Server Error")
            return Result(0, "Created release")
        raise AssertionError(f"unexpected gh call: {args}")


class ReleaseStepTests(unittest.TestCase):
    def run_step(self, scenario):
        fake = FakeGh(scenario)
        output = io.StringIO()
        with redirect_stdout(output):
            code = create_release("v0.2.1", fake)
        return code, output.getvalue(), fake.calls

    def test_existing_release_is_skipped_without_a_create_call(self):
        code, output, calls = self.run_step("exists")
        self.assertEqual(code, 0)
        self.assertIn("already exists", output)
        self.assertEqual([c[1] for c in calls], ["view"])

    def test_missing_release_is_created(self):
        code, _, calls = self.run_step("missing")
        self.assertEqual(code, 0)
        self.assertEqual([c[1] for c in calls], ["view", "create"])
        self.assertIn("--verify-tag", calls[1])

    def test_release_created_concurrently_is_success(self):
        code, output, calls = self.run_step("race")
        self.assertEqual(code, 0)
        self.assertIn("concurrently", output)
        self.assertEqual([c[1] for c in calls], ["view", "create", "view"])

    def test_genuine_api_failure_still_fails(self):
        code, output, calls = self.run_step("api_error")
        self.assertEqual(code, 1)
        self.assertIn("HTTP 500", output)
        self.assertEqual([c[1] for c in calls], ["view", "create", "view"])

    def test_missing_tag_is_a_usage_error(self):
        fake = FakeGh("missing")
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = create_release("", fake)
        self.assertEqual(code, 2)
        self.assertIn("TAG is required", buffer.getvalue())
        self.assertEqual(fake.calls, [])


if __name__ == "__main__":
    unittest.main()
