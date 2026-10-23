import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import lobster_analyze as an  # noqa: E402

FIXTURES = os.path.join(ROOT, "tests", "fixtures")


def rules_for(source):
    findings, _problems = an.analyze_source(source, "t.lobster")
    return sorted(f["rule"] for f in findings)


def read(*parts):
    with open(os.path.join(FIXTURES, *parts), encoding="utf-8") as handle:
        return handle.read()


class RuleTests(unittest.TestCase):
    def test_shell_invocation_flagged(self):
        self.assertEqual(rules_for('launch_subprocess(["sh", "-c", "make"])'), ["shell-invocation"])
        self.assertEqual(rules_for('launch_subprocess(["cmd", "/c", "dir"])'), ["shell-invocation"])

    def test_plain_argument_list_passes(self):
        self.assertEqual(rules_for('launch_subprocess(["git", "clone", url])'), [])

    def test_string_built_command_flagged(self):
        self.assertEqual(rules_for('launch_subprocess(["git", "clone", url + "/x"])'), ["string-built-command"])

    def test_shell_with_concat_reports_both(self):
        self.assertEqual(rules_for('launch_subprocess(["sh", "-c", "rm " + x])'), ["shell-invocation", "string-built-command"])

    def test_path_outside_root(self):
        self.assertEqual(rules_for('read_file("/etc/passwd")'), ["read-outside-root"])
        self.assertEqual(rules_for('write_file("../x", "y")'), ["read-outside-root"])
        self.assertEqual(rules_for('read_file("data/x")'), [])

    def test_literal_secret(self):
        self.assertEqual(rules_for('api_token = "abc"'), ["literal-secret"])
        self.assertEqual(rules_for('api_token := "abc"'), ["literal-secret"])
        self.assertEqual(rules_for('api_token = ""'), [])

    def test_comments_and_strings_are_not_code(self):
        self.assertEqual(rules_for('// read_file("/etc/passwd")'), [])
        self.assertEqual(rules_for('x = "read_file(\\"/etc/passwd\\")"'), [])


class FixtureTests(unittest.TestCase):
    def test_bad_fixture_reports_every_rule(self):
        found = rules_for(read("bad", "sample.lobster"))
        for rule in an.active_rules():
            self.assertIn(rule, found)

    def test_good_fixture_is_clean(self):
        self.assertEqual(rules_for(read("good", "sample.lobster")), [])

    def test_unterminated_string_becomes_a_problem_not_a_crash(self):
        _findings, problems = an.analyze_source('x = "oops\ny = 1\n', "t.lobster")
        self.assertTrue(problems)

    def test_triple_quoted_string_is_one_token_and_not_code(self):
        findings, problems = an.analyze_source('x = """\nwrite_file("/etc/passwd", y);\n"""\nz = 1\n', "t.lobster")
        self.assertEqual((findings, problems), ([], []))

    def test_triple_quoted_string_keeps_line_numbers(self):
        findings, _problems = an.analyze_source('x = """\n\n"""\napi_token = "abc"\n', "t.lobster")
        self.assertEqual([f["line"] for f in findings], [4])

    def test_unterminated_triple_quoted_string_is_a_problem(self):
        _findings, problems = an.analyze_source('x = """never closed', "t.lobster")
        self.assertTrue(problems)

    def test_unterminated_block_comment_becomes_a_problem(self):
        _findings, problems = an.analyze_source("/* never closed", "t.lobster")
        self.assertTrue(problems)


class SarifTests(unittest.TestCase):
    def test_end_to_end_writes_valid_sarif_shape(self):
        out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, out)
        path = os.path.join(out, "r.sarif")
        self.assertEqual(an.main(["--root", FIXTURES, "--output", path]), 0)
        with open(path, encoding="utf-8") as handle:
            doc = json.load(handle)
        run = doc["runs"][0]
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(run["tool"]["driver"]["name"], "codeql-lobster")
        self.assertTrue(run["results"])
        for result in run["results"]:
            self.assertIn("findingHash/v1", result["partialFingerprints"])
            self.assertGreaterEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 1)

    def test_fail_on_findings_exits_nonzero(self):
        out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, out)
        code = an.main(["--root", os.path.join(FIXTURES, "bad"), "--output", os.path.join(out, "x.sarif"), "--fail-on-findings"])
        self.assertEqual(code, 1)

    def test_clean_tree_exits_zero_even_with_fail_flag(self):
        out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, out)
        code = an.main(["--root", os.path.join(FIXTURES, "good"), "--output", os.path.join(out, "x.sarif"), "--fail-on-findings"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
