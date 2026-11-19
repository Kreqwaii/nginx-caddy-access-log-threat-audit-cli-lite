import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from log_audit.cli import main

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_NGINX = os.path.join(REPO_ROOT, "sample_logs", "nginx_access.log")
SAMPLE_CADDY = os.path.join(REPO_ROOT, "sample_logs", "caddy_access.json")


class TestCLI(unittest.TestCase):
    def test_cli_nginx_json_output_and_exit_code(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([SAMPLE_NGINX, "--output", "json", "--fail-on", "high"])
        self.assertEqual(rc, 2)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["max_severity"], "critical")
        self.assertGreater(data["parsed_entries"], 0)

    def test_cli_caddy_markdown_output(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([SAMPLE_CADDY, "--output", "markdown", "--fail-on", "none"])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("# Access Log Threat & Performance Audit", out)
        self.assertIn("sqli_probe", out)

    def test_cli_text_output(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([SAMPLE_NGINX, "--output", "text", "--fail-on", "none"])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("=== Access Log Threat & Performance Audit ===", out)
        self.assertIn("Top IPs:", out)

    def test_cli_missing_file_returns_1(self):
        rc = main(["nonexistent_file_12345.log"])
        self.assertEqual(rc, 1)

    def test_cli_clean_log_returns_0(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8") as tf:
            tf.write('10.0.0.1 - - [19/Nov/2026:10:00:01 +0000] "GET /ok HTTP/1.1" 200 100 "-" "Mozilla/5.0"\n')
            tmp_path = tf.name
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main([tmp_path, "--fail-on", "low"])
            self.assertEqual(rc, 0)
        finally:
            os.remove(tmp_path)

    def test_cli_top_limit(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([SAMPLE_NGINX, "--output", "json", "--top", "2", "--fail-on", "none"])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertLessEqual(len(data["top_ips"]), 2)


if __name__ == "__main__":
    unittest.main()
