"""Security threat detection and performance analytics for parsed access logs."""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional
from urllib.parse import unquote

from .parser import LogEntry

SCANNER_UA_RE = re.compile(
    r"(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wfuzz|ffuf|"
    r"nuclei|acunetix|nessus|openvas|wpscan|havij|python-requests|curl/|wget/|"
    r"scrapy|mj12bot|ahrefsbot|semrushbot)",
    re.IGNORECASE,
)

SQLI_RE = re.compile(
    r"(\bunion\b.+\bselect\b|\bselect\b.+\bfrom\b|\binformation_schema\b|"
    r"\bsleep\s*\(|\bbenchmark\s*\(|\bwaitfor\s+delay\b|"
    r"(?:'|%27)\s*(?:or|and)\s*(?:'?\d|true)|--\s*$|/\*.*\*/)",
    re.IGNORECASE,
)

XSS_RE = re.compile(
    r"(<script\b|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie|<iframe\b)",
    re.IGNORECASE,
)

PATH_TRAVERSAL_RE = re.compile(
    r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self/environ|"
    r"wp-login\.php|wp-config\.php|\.env\b|\.git/config|phpinfo\.php|actuator/env)",
    re.IGNORECASE,
)


@dataclass
class ThreatFinding:
    category: str
    severity: str  # critical, high, medium, low
    ip: str
    path: str
    status: int
    detail: str


@dataclass
class AuditReport:
    total_lines: int = 0
    parsed_entries: int = 0
    unparsed_lines: int = 0
    unique_ips: int = 0
    total_bytes: int = 0
    status_counts: Dict[str, int] = field(default_factory=dict)
    top_ips: List[Dict[str, Any]] = field(default_factory=list)
    top_error_urls: List[Dict[str, Any]] = field(default_factory=list)
    top_slow_urls: List[Dict[str, Any]] = field(default_factory=list)
    latency_stats_ms: Dict[str, Optional[float]] = field(default_factory=dict)
    findings: List[ThreatFinding] = field(default_factory=list)
    summary_counts: Dict[str, int] = field(default_factory=dict)
    max_severity: str = "none"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_lines": self.total_lines,
            "parsed_entries": self.parsed_entries,
            "unparsed_lines": self.unparsed_lines,
            "unique_ips": self.unique_ips,
            "total_bytes": self.total_bytes,
            "status_counts": self.status_counts,
            "top_ips": self.top_ips,
            "top_error_urls": self.top_error_urls,
            "top_slow_urls": self.top_slow_urls,
            "latency_stats_ms": self.latency_stats_ms,
            "summary_counts": self.summary_counts,
            "max_severity": self.max_severity,
            "findings": [
                {
                    "category": f.category,
                    "severity": f.severity,
                    "ip": f.ip,
                    "path": f.path,
                    "status": f.status,
                    "detail": f.detail,
                }
                for f in self.findings
            ],
        }


SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _percentile(sorted_vals: List[float], pct: float) -> Optional[float]:
    if not sorted_vals:
        return None
    idx = int(round((pct / 100.0) * (len(sorted_vals) - 1)))
    return round(sorted_vals[idx], 3)


def analyze_entries(
    entries: List[LogEntry],
    total_lines: int = 0,
    unparsed_lines: int = 0,
    bruteforce_threshold: int = 5,
    spike_5xx_threshold: int = 5,
    top_n: int = 10,
) -> AuditReport:
    report = AuditReport(
        total_lines=total_lines or len(entries),
        parsed_entries=len(entries),
        unparsed_lines=unparsed_lines,
    )
    if not entries:
        return report

    ip_counter: Counter[str] = Counter()
    ip_bytes: Counter[str] = Counter()
    ip_auth_errors: Counter[str] = Counter()
    error_url_counter: Counter[str] = Counter()
    url_durations: Dict[str, List[float]] = defaultdict(list)
    all_durations: List[float] = []
    status_buckets: Counter[str] = Counter()
    count_5xx = 0
    minute_5xx: Counter[str] = Counter()

    findings: List[ThreatFinding] = []
    seen_scanner_ips = set()

    for e in entries:
        ip_counter[e.ip] += 1
        ip_bytes[e.ip] += e.bytes_sent
        report.total_bytes += e.bytes_sent

        bucket = f"{e.status // 100}xx" if e.status >= 100 else "other"
        status_buckets[bucket] += 1

        if e.status in (401, 403, 404):
            ip_auth_errors[e.ip] += 1

        if e.status >= 400:
            error_url_counter[e.path] += 1

        if e.status >= 500:
            count_5xx += 1
            if e.timestamp is not None:
                minute_5xx[e.timestamp.strftime("%Y-%m-%d %H:%M")] += 1

        if e.duration_ms is not None:
            all_durations.append(e.duration_ms)
            url_durations[e.path].append(e.duration_ms)

        decoded_path = unquote(e.path)

        if SQLI_RE.search(decoded_path):
            findings.append(
                ThreatFinding(
                    category="sqli_probe",
                    severity="critical",
                    ip=e.ip,
                    path=e.path,
                    status=e.status,
                    detail="SQL injection pattern detected in request URI",
                )
            )

        if XSS_RE.search(decoded_path):
            findings.append(
                ThreatFinding(
                    category="xss_probe",
                    severity="high",
                    ip=e.ip,
                    path=e.path,
                    status=e.status,
                    detail="XSS payload pattern detected in request URI",
                )
            )

        if PATH_TRAVERSAL_RE.search(decoded_path):
            findings.append(
                ThreatFinding(
                    category="path_traversal",
                    severity="high",
                    ip=e.ip,
                    path=e.path,
                    status=e.status,
                    detail="Path traversal or sensitive file probe detected",
                )
            )

        if SCANNER_UA_RE.search(e.user_agent) and e.ip not in seen_scanner_ips:
            seen_scanner_ips.add(e.ip)
            findings.append(
                ThreatFinding(
                    category="scanner_bot",
                    severity="medium",
                    ip=e.ip,
                    path=e.path,
                    status=e.status,
                    detail=f"Scanner/bot User-Agent detected: {e.user_agent[:80]}",
                )
            )

    for ip, cnt in ip_auth_errors.most_common():
        if cnt >= bruteforce_threshold:
            findings.append(
                ThreatFinding(
                    category="bruteforce_4xx",
                    severity="high",
                    ip=ip,
                    path="*",
                    status=401,
                    detail=f"High rate of 401/403/404 responses ({cnt} requests)",
                )
            )

    if count_5xx >= spike_5xx_threshold:
        peak_min, peak_cnt = ("unknown", count_5xx)
        if minute_5xx:
            peak_min, peak_cnt = minute_5xx.most_common(1)[0]
        findings.append(
            ThreatFinding(
                category="5xx_spike",
                severity="high",
                ip="*",
                path="*",
                status=500,
                detail=f"5xx server error spike: {count_5xx} total (peak {peak_cnt} at {peak_min})",
            )
        )

    report.unique_ips = len(ip_counter)
    report.status_counts = dict(sorted(status_buckets.items()))
    report.top_ips = [
        {"ip": ip, "requests": cnt, "bytes": ip_bytes[ip]}
        for ip, cnt in ip_counter.most_common(top_n)
    ]
    report.top_error_urls = [
        {"path": path, "errors": cnt}
        for path, cnt in error_url_counter.most_common(top_n)
    ]

    slow_list = []
    for path, durs in url_durations.items():
        slow_list.append(
            {
                "path": path,
                "count": len(durs),
                "avg_ms": round(sum(durs) / len(durs), 3),
                "max_ms": round(max(durs), 3),
            }
        )
    slow_list.sort(key=lambda x: x["avg_ms"], reverse=True)
    report.top_slow_urls = slow_list[:top_n]

    if all_durations:
        all_durations.sort()
        report.latency_stats_ms = {
            "avg": round(sum(all_durations) / len(all_durations), 3),
            "p95": _percentile(all_durations, 95.0),
            "max": round(all_durations[-1], 3),
        }
    else:
        report.latency_stats_ms = {"avg": None, "p95": None, "max": None}

    report.findings = findings
    cat_counts: Counter[str] = Counter(f.category for f in findings)
    report.summary_counts = dict(sorted(cat_counts.items()))

    max_sev = "none"
    for f in findings:
        if SEVERITY_RANK[f.severity] > SEVERITY_RANK[max_sev]:
            max_sev = f.severity
    report.max_severity = max_sev

    return report
