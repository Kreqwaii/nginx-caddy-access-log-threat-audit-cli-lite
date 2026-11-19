"""CLI entrypoint for nginx-caddy-access-log-threat-audit-cli-lite."""

import argparse
import sys
from typing import List, Optional

from . import __version__
from .analyzer import SEVERITY_RANK, analyze_entries
from .formatters import format_json, format_markdown, format_text
from .parser import LogEntry, parse_line


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log-audit",
        description="Audit Nginx (combined) and Caddy (JSON) access logs for threats & performance issues.",
    )
    p.add_argument("logfile", help="Path to access log file (or '-' for stdin)")
    p.add_argument("--format", choices=["auto", "nginx", "caddy"], default="auto", help="Log format (default: auto)")
    p.add_argument("--output", choices=["text", "json", "markdown"], default="text", help="Output format")
    p.add_argument("--bruteforce-threshold", type=int, default=5, help="401/403/404 count per IP to flag brute-force")
    p.add_argument("--5xx-threshold", dest="spike_5xx_threshold", type=int, default=5, help="5xx count to flag spike")
    p.add_argument("--top", type=int, default=10, help="Top N items in summary tables")
    p.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high", "critical"],
        default="high",
        help="Exit with code 2 if max severity >= this level (default: high; use 'none' to disable)",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.logfile == "-":
        raw_lines = sys.stdin.read().splitlines()
    else:
        try:
            with open(args.logfile, "r", encoding="utf-8", errors="replace") as fh:
                raw_lines = fh.read().splitlines()
        except OSError as exc:
            print(f"Error reading log file: {exc}", file=sys.stderr)
            return 1

    entries: List[LogEntry] = []
    unparsed = 0
    non_empty = 0
    for line in raw_lines:
        if not line.strip():
            continue
        non_empty += 1
        entry = parse_line(line, fmt=args.format)
        if entry is None:
            unparsed += 1
        else:
            entries.append(entry)

    report = analyze_entries(
        entries,
        total_lines=non_empty,
        unparsed_lines=unparsed,
        bruteforce_threshold=args.bruteforce_threshold,
        spike_5xx_threshold=args.spike_5xx_threshold,
        top_n=args.top,
    )

    if args.output == "json":
        print(format_json(report))
    elif args.output == "markdown":
        print(format_markdown(report))
    else:
        print(format_text(report))

    if args.fail_on != "none":
        if SEVERITY_RANK[report.max_severity] >= SEVERITY_RANK[args.fail_on]:
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
