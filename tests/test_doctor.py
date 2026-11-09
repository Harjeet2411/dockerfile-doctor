import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from dockerfile_doctor.cli import main
from dockerfile_doctor.parser import parse
from dockerfile_doctor.rules import lint, score

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def rules_for(text, **kw):
    return [f.rule for f in lint(parse(text), **kw)]


class ParserTests(unittest.TestCase):
    def test_continuations_comments_and_stages(self):
        df = parse("FROM node:20 AS deps\nRUN a \\\n  # note\n  && b\n\nFROM deps\nCMD x\n")
        self.assertEqual([i.keyword for i in df.instructions], ["FROM", "RUN", "FROM", "CMD"])
        self.assertEqual(df.instructions[1].args, "a && b")
        self.assertEqual([(s.image, s.name) for s in df.stages], [("node:20", "deps"), ("deps", None)])

    def test_escape_directive(self):
        df = parse("# escape=`\nFROM mcr.microsoft.com/windows:ltsc2022\nRUN a `\n  b\n")
        self.assertEqual(df.instructions[1].args, "a b")


class RuleTests(unittest.TestCase):
    def test_unpinned_base(self):
        self.assertIn("DD001", rules_for("FROM ubuntu\n"))
        self.assertIn("DD001", rules_for("FROM ubuntu:latest\n"))
        self.assertIn("DD001", rules_for("FROM localhost:5000/app\n"))  # port is not a tag
        self.assertNotIn("DD001", rules_for("FROM localhost:5000/app:1.4\n"))
        self.assertNotIn("DD001", rules_for("FROM ubuntu:24.04\nFROM scratch\n"))
        # A later stage built from an earlier stage name is not an image pull.
        self.assertEqual(rules_for("FROM go:1.23 AS b\nFROM b\nUSER 1000\n", ignore={"DD202"}), [])

    def test_root_user(self):
        self.assertIn("DD002", rules_for("FROM a:1\nCMD [\"x\"]\n"))
        self.assertIn("DD002", rules_for("FROM a:1\nUSER app\nUSER root\n"))
        self.assertNotIn("DD002", rules_for("FROM a:1\nUSER root\nRUN x\nUSER 10001:10001\n"))
        # Only the final stage matters.
        self.assertNotIn("DD002", rules_for("FROM a:1 AS b\nFROM c:1\nUSER app\n"))

    def test_secrets(self):
        self.assertIn("DD003", rules_for('FROM a:1\nENV DB_PASSWORD="hunter2" X=1\n'))
        self.assertIn("DD003", rules_for("FROM a:1\nENV GITHUB_TOKEN abc\n"))
        self.assertIn("DD003", rules_for("FROM a:1\nARG NPM_TOKEN=abc\n"))
        self.assertNotIn("DD003", rules_for("FROM a:1\nARG NPM_TOKEN\nENV TOKEN_URL=$URL\n"))

    def test_curl_pipe_and_add(self):
        self.assertIn("DD004", rules_for("FROM a:1\nRUN curl -sL https://x | bash\n"))
        self.assertNotIn("DD004", rules_for("FROM a:1\nRUN curl -sLo x.sh https://x && sha256sum -c x.sha && sh x.sh\n"))
        self.assertIn("DD005", rules_for("FROM a:1\nADD app.py /app/\n"))
        self.assertNotIn("DD005", rules_for("FROM a:1\nADD rootfs.tar.gz /\n"))

    def test_apt_rules(self):
        found = rules_for("FROM a:1\nRUN apt-get update\nRUN apt-get install -y curl\n")
        self.assertTrue({"DD101", "DD102", "DD103"} <= set(found))
        clean = "FROM a:1\nRUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*\n"
        self.assertFalse({"DD101", "DD102", "DD103"} & set(rules_for(clean)))

    def test_copy_before_install(self):
        self.assertIn("DD106", rules_for("FROM a:1\nCOPY . .\nRUN npm ci\n"))
        self.assertNotIn("DD106", rules_for("FROM a:1\nCOPY package*.json ./\nRUN npm ci\nCOPY . .\n"))

    def test_shell_form_and_workdir(self):
        self.assertIn("DD201", rules_for("FROM a:1\nCMD node server.js\n"))
        self.assertNotIn("DD201", rules_for('FROM a:1\nCMD ["node", "server.js"]\n'))
        self.assertIn("DD203", rules_for("FROM a:1\nWORKDIR app\n"))
        self.assertNotIn("DD203", rules_for("FROM a:1\nWORKDIR $HOME/app\n"))

    def test_ignore_and_score(self):
        self.assertNotIn("DD202", rules_for("FROM a:1\nUSER app\n", ignore={"DD202"}))
        self.assertEqual(score([]), 100)


class ExampleTests(unittest.TestCase):
    def test_good_example_is_clean(self):
        self.assertEqual(lint(parse((EXAMPLES / "Dockerfile.good").read_text())), [])

    def test_bad_example_hits_every_category(self):
        found = set(rules_for((EXAMPLES / "Dockerfile.bad").read_text()))
        for expected in ("DD001", "DD002", "DD003", "DD004", "DD005", "DD007", "DD101", "DD103", "DD105", "DD106", "DD201", "DD203"):
            self.assertIn(expected, found)


class CliTests(unittest.TestCase):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_exit_codes(self):
        self.assertEqual(self.run_cli(str(EXAMPLES / "Dockerfile.bad"))[0], 1)
        self.assertEqual(self.run_cli(str(EXAMPLES / "Dockerfile.good"))[0], 0)
        self.assertEqual(self.run_cli(str(EXAMPLES / "Dockerfile.bad"), "--fail-on", "never")[0], 0)
        self.assertEqual(self.run_cli("/nope/Dockerfile")[0], 2)

    def test_sarif_is_valid_shape(self):
        code, out, _ = self.run_cli(str(EXAMPLES / "Dockerfile.bad"), "-f", "sarif")
        sarif = json.loads(out)
        results = sarif["runs"][0]["results"]
        self.assertTrue(results)
        self.assertEqual({r["level"] for r in results} - {"error", "warning", "note"}, set())
        self.assertIn("startLine", results[0]["locations"][0]["physicalLocation"]["region"])

    def test_ignore_comma_list(self):
        _, out, _ = self.run_cli(str(EXAMPLES / "Dockerfile.bad"), "-f", "json", "--ignore", "dd001,DD002")
        rules = {f["rule"] for f in json.loads(out)[str(EXAMPLES / "Dockerfile.bad")]["findings"]}
        self.assertFalse({"DD001", "DD002"} & rules)


if __name__ == "__main__":
    unittest.main()
