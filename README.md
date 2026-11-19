# Nginx & Caddy Access Log Threat & Performance Audit CLI (Lite)

Zero-dependency **Python 3.9+ stdlib** CLI tool for security threat detection and performance auditing of **Nginx (`combined`)** and **Caddy (JSON)** access logs.

## Features

- **Dual Format Auto-Detection**: Parses Nginx `combined` (with optional `request_time`) and Caddy JSON structured access logs.
- **Security Threat Detection**:
  - **SQLi Probes**: `UNION SELECT`, `INFORMATION_SCHEMA`, `SLEEP()`, boolean-based injections.
  - **XSS Probes**: `<script>`, `javascript:`, `onerror=`, `document.cookie`, `<iframe>`.
  - **Path Traversal & Sensitive Files**: `../`, `/etc/passwd`, `.env`, `.git/config`, `wp-login.php`, `actuator/env`.
  - **Scanner / Bot User-Agents**: `sqlmap`, `nikto`, `nuclei`, `gobuster`, `ffuf`, `nmap`, `python-requests`, etc.
  - **401/403/404 Brute-Force**: Configurable per-IP threshold.
  - **5xx Error Spikes**: Detects server error bursts with peak-minute attribution.
- **Performance & Traffic Analytics**:
  - Total requests, unique IPs, total bytes transferred, status code breakdown (`2xx`, `3xx`, `4xx`, `5xx`).
  - Top IPs by request volume & bandwidth.
  - Top error URLs and top slow URLs (`avg` / `p95` / `max` latency in ms).
- **CI/CD Ready**: `text`, `json`, and `markdown` output formats with `--fail-on` severity exit codes.

## Quick Start

```bash
# Audit an Nginx access log (auto-detected)
python -m log_audit sample_logs/nginx_access.log

# Audit a Caddy JSON access log and output Markdown
python -m log_audit sample_logs/caddy_access.json --output markdown

# Output JSON for CI/CD pipelines and fail on high+ severity
python -m log_audit sample_logs/nginx_access.log --output json --fail-on high

# Read from stdin
cat sample_logs/nginx_access.log | python -m log_audit - --format nginx
```

## CLI Options

- `--format {auto,nginx,caddy}`: Force log format or auto-detect (default: `auto`).
- `--output {text,json,markdown}`: Report output format (default: `text`).
- `--bruteforce-threshold N`: 401/403/404 requests per IP to flag brute-force (default: `5`).
- `--5xx-threshold N`: Total 5xx responses to flag a spike (default: `5`).
- `--top N`: Number of entries in Top IPs / Error URLs / Slow URLs (default: `10`).
- `--fail-on {none,low,medium,high,critical}`: Exit with code `2` if max severity reaches threshold (default: `high`).

## Running Tests

```bash
python -m unittest discover -s tests -v
```

## Pro Studio Version (Web Dashboard + Real-Time Tail + HTML Threat Reports)

Need **real-time `tail -f` streaming**, an **interactive Web Dashboard**, **GeoIP / ASN enrichment**, **multi-file correlation**, and **exportable HTML/PDF executive threat reports**?

Check out the **Pro Studio Version** here: https://funpay.com/users/20096179/

## License

MIT License — see [LICENSE](LICENSE).
