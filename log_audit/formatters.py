"""Output formatters (text, JSON, Markdown) for AuditReport."""

import json
from .analyzer import AuditReport


def format_json(report: AuditReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def format_text(report: AuditReport) -> str:
    lines = [
        "=== Access Log Threat & Performance Audit ===",
        f"Lines: {report.total_lines} | Parsed: {report.parsed_entries} | Unparsed: {report.unparsed_lines}",
        f"Unique IPs: {report.unique_ips} | Total Bytes: {report.total_bytes}",
        f"Status Breakdown: {report.status_counts}",
        f"Max Severity: {report.max_severity.upper()} | Findings: {len(report.findings)}",
    ]
    if report.latency_stats_ms.get("avg") is not None:
        lat = report.latency_stats_ms
        lines.append(f"Latency (ms): avg={lat['avg']} p95={lat['p95']} max={lat['max']}")

    if report.top_ips:
        lines.append("\nTop IPs:")
        for item in report.top_ips:
            lines.append(f"  - {item['ip']}: {item['requests']} reqs ({item['bytes']} bytes)")

    if report.top_error_urls:
        lines.append("\nTop Error URLs:")
        for item in report.top_error_urls:
            lines.append(f"  - {item['path']}: {item['errors']} errors")

    if report.top_slow_urls:
        lines.append("\nTop Slow URLs:")
        for item in report.top_slow_urls:
            lines.append(f"  - {item['path']}: avg={item['avg_ms']}ms max={item['max_ms']}ms (n={item['count']})")

    if report.findings:
        lines.append("\nSecurity & Reliability Findings:")
        for f in report.findings:
            lines.append(f"  [{f.severity.upper()}] {f.category} | ip={f.ip} | {f.path} -> {f.detail}")

    return "\n".join(lines)


def format_markdown(report: AuditReport) -> str:
    lines = [
        "# Access Log Threat & Performance Audit",
        "",
        "## Traffic Summary",
        f"- **Total Lines:** {report.total_lines} (Parsed: {report.parsed_entries}, Unparsed: {report.unparsed_lines})",
        f"- **Unique IPs:** {report.unique_ips}",
        f"- **Total Traffic:** {report.total_bytes} bytes",
        f"- **Status Breakdown:** `{report.status_counts}`",
        f"- **Max Severity:** `{report.max_severity.upper()}` ({len(report.findings)} findings)",
    ]
    if report.latency_stats_ms.get("avg") is not None:
        lat = report.latency_stats_ms
        lines.append(f"- **Latency (ms):** avg `{lat['avg']}`, p95 `{lat['p95']}`, max `{lat['max']}`")

    if report.findings:
        lines.extend([
            "",
            "## Findings",
            "| Severity | Category | IP | Path | Detail |",
            "|---|---|---|---|---|",
        ])
        for f in report.findings:
            lines.append(f"| {f.severity.upper()} | `{f.category}` | `{f.ip}` | `{f.path}` | {f.detail} |")

    if report.top_ips:
        lines.extend(["", "## Top IPs", "| IP | Requests | Bytes |", "|---|---|---|"])
        for item in report.top_ips:
            lines.append(f"| `{item['ip']}` | {item['requests']} | {item['bytes']} |")

    return "\n".join(lines)
