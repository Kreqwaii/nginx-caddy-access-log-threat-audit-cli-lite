from datetime import datetime, timezone
import unittest

from log_audit.analyzer import analyze_entries
from log_audit.parser import LogEntry


def _make_entry(
    ip="10.0.0.1",
    path="/",
    status=200,
    bytes_sent=100,
    ua="Mozilla/5.0",
    duration_ms=10.0,
):
    return LogEntry(
        ip=ip,
        timestamp=datetime(2026, 11, 19, 10, 0, 0, tzinfo=timezone.utc),
        method="GET",
        path=path,
        protocol="HTTP/1.1",
        status=status,
        bytes_sent=bytes_sent,
        referer="-",
        user_agent=ua,
        duration_ms=duration_ms,
        source_format="nginx",
    )


class TestAnalyzer(unittest.TestCase):
    def test_empty_entries(self):
        rep = analyze_entries([])
        self.assertEqual(rep.parsed_entries, 0)
        self.assertEqual(rep.max_severity, "none")
        self.assertEqual(rep.findings, [])

    def test_detect_sqli_union_select(self):
        rep = analyze_entries([_make_entry(path="/search?q=1%20UNION%20SELECT%201,2,3")])
        cats = [f.category for f in rep.findings]
        self.assertIn("sqli_probe", cats)
        self.assertEqual(rep.max_severity, "critical")

    def test_detect_sqli_sleep(self):
        rep = analyze_entries([_make_entry(path="/item?id=1%20AND%20SLEEP(5)")])
        self.assertEqual(rep.findings[0].category, "sqli_probe")

    def test_detect_xss_script(self):
        rep = analyze_entries([_make_entry(path="/comment?x=<script>alert(1)</script>")])
        cats = [f.category for f in rep.findings]
        self.assertIn("xss_probe", cats)
        self.assertEqual(rep.max_severity, "high")

    def test_detect_xss_onerror(self):
        rep = analyze_entries([_make_entry(path="/img?src=x%20onerror=alert(1)")])
        self.assertIn("xss_probe", [f.category for f in rep.findings])

    def test_detect_path_traversal(self):
        rep = analyze_entries([_make_entry(path="/static/../../etc/passwd")])
        self.assertIn("path_traversal", [f.category for f in rep.findings])

    def test_detect_sensitive_env_probe(self):
        rep = analyze_entries([_make_entry(path="/.env", status=404)])
        self.assertIn("path_traversal", [f.category for f in rep.findings])

    def test_detect_scanner_ua_deduplicated_per_ip(self):
        entries = [
            _make_entry(ip="1.2.3.4", path="/a", ua="sqlmap/1.7"),
            _make_entry(ip="1.2.3.4", path="/b", ua="sqlmap/1.7"),
        ]
        rep = analyze_entries(entries)
        scanner_findings = [f for f in rep.findings if f.category == "scanner_bot"]
        self.assertEqual(len(scanner_findings), 1)

    def test_detect_bruteforce_4xx(self):
        entries = [_make_entry(ip="5.5.5.5", path="/login", status=401) for _ in range(5)]
        rep = analyze_entries(entries, bruteforce_threshold=5)
        self.assertIn("bruteforce_4xx", [f.category for f in rep.findings])

    def test_bruteforce_below_threshold_not_flagged(self):
        entries = [_make_entry(ip="5.5.5.5", path="/login", status=401) for _ in range(4)]
        rep = analyze_entries(entries, bruteforce_threshold=5)
        self.assertNotIn("bruteforce_4xx", [f.category for f in rep.findings])

    def test_detect_5xx_spike(self):
        entries = [_make_entry(path="/checkout", status=502) for _ in range(5)]
        rep = analyze_entries(entries, spike_5xx_threshold=5)
        self.assertIn("5xx_spike", [f.category for f in rep.findings])

    def test_traffic_and_latency_stats(self):
        entries = [
            _make_entry(ip="1.1.1.1", path="/fast", bytes_sent=200, duration_ms=10.0),
            _make_entry(ip="2.2.2.2", path="/slow", bytes_sent=800, duration_ms=500.0),
        ]
        rep = analyze_entries(entries)
        self.assertEqual(rep.unique_ips, 2)
        self.assertEqual(rep.total_bytes, 1000)
        self.assertEqual(rep.top_slow_urls[0]["path"], "/slow")
        self.assertAlmostEqual(rep.latency_stats_ms["max"], 500.0, places=2)


if __name__ == "__main__":
    unittest.main()
