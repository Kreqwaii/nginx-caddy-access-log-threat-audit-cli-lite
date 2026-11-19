import unittest

from log_audit.parser import parse_caddy_line, parse_line, parse_nginx_line


class TestParser(unittest.TestCase):
    def test_parse_nginx_combined_basic(self):
        line = '10.0.0.1 - - [19/Nov/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        e = parse_nginx_line(line)
        self.assertIsNotNone(e)
        self.assertEqual(e.ip, "10.0.0.1")
        self.assertEqual(e.method, "GET")
        self.assertEqual(e.path, "/index.html")
        self.assertEqual(e.status, 200)
        self.assertEqual(e.bytes_sent, 1024)
        self.assertEqual(e.source_format, "nginx")
        self.assertIsNone(e.duration_ms)

    def test_parse_nginx_with_request_time(self):
        line = '10.0.0.2 - - [19/Nov/2026:10:00:02 +0000] "POST /api/pay HTTP/1.1" 502 512 "-" "curl/8.0" 1.250'
        e = parse_nginx_line(line)
        self.assertIsNotNone(e)
        self.assertEqual(e.status, 502)
        self.assertAlmostEqual(e.duration_ms, 1250.0, places=2)

    def test_parse_nginx_dash_bytes(self):
        line = '10.0.0.3 - - [19/Nov/2026:10:00:03 +0000] "HEAD /health HTTP/1.1" 204 - "-" "kube-probe/1.28"'
        e = parse_nginx_line(line)
        self.assertIsNotNone(e)
        self.assertEqual(e.bytes_sent, 0)

    def test_parse_nginx_invalid_returns_none(self):
        self.assertIsNone(parse_nginx_line("not a valid log line"))
        self.assertIsNone(parse_nginx_line("# comment"))
        self.assertIsNone(parse_nginx_line("   "))

    def test_parse_caddy_json_valid(self):
        line = '{"level":"info","ts":1763546400.5,"request":{"remote_ip":"192.168.1.5:5555","client_ip":"192.168.1.5","proto":"HTTP/2.0","method":"GET","uri":"/api/v1/items","headers":{"User-Agent":["Mozilla/5.0"],"Referer":["https://app.test"]}},"duration":0.042,"size":2048,"status":200}'
        e = parse_caddy_line(line)
        self.assertIsNotNone(e)
        self.assertEqual(e.ip, "192.168.1.5")
        self.assertEqual(e.method, "GET")
        self.assertEqual(e.path, "/api/v1/items")
        self.assertEqual(e.status, 200)
        self.assertEqual(e.bytes_sent, 2048)
        self.assertAlmostEqual(e.duration_ms, 42.0, places=2)
        self.assertEqual(e.source_format, "caddy")

    def test_parse_caddy_strips_port_and_ipv6(self):
        line = '{"ts":1763546400,"request":{"remote_addr":"[2001:db8::1]:443","method":"GET","uri":"/"},"status":200,"size":10}'
        e = parse_caddy_line(line)
        self.assertIsNotNone(e)
        self.assertEqual(e.ip, "2001:db8::1")

    def test_parse_caddy_invalid_json(self):
        self.assertIsNone(parse_caddy_line("{bad json"))
        self.assertIsNone(parse_caddy_line('{"msg":"no request key"}'))

    def test_parse_line_auto_detects_both(self):
        nginx_line = '1.1.1.1 - - [19/Nov/2026:10:00:01 +0000] "GET / HTTP/1.1" 200 100 "-" "UA"'
        caddy_line = '{"ts":1763546400,"request":{"remote_ip":"2.2.2.2","method":"GET","uri":"/"},"status":200,"size":100}'
        self.assertEqual(parse_line(nginx_line, fmt="auto").source_format, "nginx")
        self.assertEqual(parse_line(caddy_line, fmt="auto").source_format, "caddy")

    def test_parse_line_forced_format(self):
        nginx_line = '1.1.1.1 - - [19/Nov/2026:10:00:01 +0000] "GET / HTTP/1.1" 200 100 "-" "UA"'
        self.assertIsNone(parse_line(nginx_line, fmt="caddy"))
        self.assertIsNotNone(parse_line(nginx_line, fmt="nginx"))


if __name__ == "__main__":
    unittest.main()
