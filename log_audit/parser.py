"""Parsers for Nginx combined access logs and Caddy JSON access logs."""

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
from typing import Optional

# Nginx combined format:
# 192.168.1.10 - - [19/Nov/2026:10:15:32 +0000] "GET /api/v1/users HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0"
# Optional trailing request_time (e.g. 0.042 or rt=0.042)
NGINX_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
    r'(?:\s+(?:rt=)?(?P<rt>\d+(?:\.\d+)?))?'
    r'\s*$'
)


@dataclass
class LogEntry:
    ip: str
    timestamp: Optional[datetime]
    method: str
    path: str
    protocol: str
    status: int
    bytes_sent: int
    referer: str
    user_agent: str
    duration_ms: Optional[float]
    source_format: str
    raw: str = ""


def _parse_nginx_time(ts_str: str) -> Optional[datetime]:
    try:
        return datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        try:
            return datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None


def _parse_request_line(req: str) -> tuple[str, str, str]:
    parts = req.split(" ", 2)
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], parts[1], ""
    if len(parts) == 1 and parts[0]:
        return parts[0], "/", ""
    return "UNKNOWN", "/", ""


def parse_nginx_line(line: str) -> Optional[LogEntry]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = NGINX_COMBINED_RE.match(line)
    if not m:
        return None

    method, path, proto = _parse_request_line(m.group("request"))
    bytes_raw = m.group("bytes")
    bytes_sent = int(bytes_raw) if bytes_raw.isdigit() else 0
    rt_raw = m.group("rt")
    duration_ms = round(float(rt_raw) * 1000.0, 3) if rt_raw is not None else None

    return LogEntry(
        ip=m.group("ip"),
        timestamp=_parse_nginx_time(m.group("time")),
        method=method,
        path=path,
        protocol=proto,
        status=int(m.group("status")),
        bytes_sent=bytes_sent,
        referer=m.group("referer") or "-",
        user_agent=m.group("ua") or "-",
        duration_ms=duration_ms,
        source_format="nginx",
        raw=line,
    )


def _strip_port(addr: str) -> str:
    if not addr:
        return "0.0.0.0"
    if addr.startswith("[") and "]" in addr:
        return addr[1:addr.index("]")]
    if addr.count(":") == 1:
        return addr.split(":", 1)[0]
    return addr


def parse_caddy_line(line: str) -> Optional[LogEntry]:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict) or "request" not in obj:
        return None

    req = obj.get("request") or {}
    headers = req.get("headers") or {}
    ua_list = headers.get("User-Agent") or headers.get("user-agent") or ["-"]
    ref_list = headers.get("Referer") or headers.get("referer") or ["-"]
    ua = ua_list[0] if isinstance(ua_list, list) and ua_list else str(ua_list)
    ref = ref_list[0] if isinstance(ref_list, list) and ref_list else str(ref_list)

    ts_val = obj.get("ts")
    ts: Optional[datetime] = None
    if isinstance(ts_val, (int, float)):
        ts = datetime.fromtimestamp(float(ts_val), tz=timezone.utc)
    elif isinstance(ts_val, str):
        try:
            ts = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
        except ValueError:
            ts = None

    dur_val = obj.get("duration")
    duration_ms = round(float(dur_val) * 1000.0, 3) if isinstance(dur_val, (int, float)) else None

    ip_raw = req.get("client_ip") or req.get("remote_ip") or req.get("remote_addr") or "0.0.0.0"

    return LogEntry(
        ip=_strip_port(str(ip_raw)),
        timestamp=ts,
        method=str(req.get("method") or "GET"),
        path=str(req.get("uri") or "/"),
        protocol=str(req.get("proto") or "HTTP/1.1"),
        status=int(obj.get("status") or 0),
        bytes_sent=int(obj.get("size") or 0),
        referer=ref,
        user_agent=ua,
        duration_ms=duration_ms,
        source_format="caddy",
        raw=line,
    )


def parse_line(line: str, fmt: str = "auto") -> Optional[LogEntry]:
    stripped = line.strip()
    if not stripped:
        return None
    if fmt == "nginx":
        return parse_nginx_line(stripped)
    if fmt == "caddy":
        return parse_caddy_line(stripped)
    # auto
    if stripped.startswith("{"):
        entry = parse_caddy_line(stripped)
        if entry is not None:
            return entry
    return parse_nginx_line(stripped)
