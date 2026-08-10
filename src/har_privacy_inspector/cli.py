from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core import inspect_and_sanitize


def _markdown(report: dict[str, object]) -> str:
    lines = [
        "# HAR Privacy Inspector report",
        "",
        f"- Entries: {report['entryCount']}",
        f"- Findings: {report['findingCount']}",
        f"- Source SHA-256: `{report['sourceSha256']}`",
        f"- Sanitized SHA-256: `{report['sanitizedSha256']}`",
        "",
        "| Finding | Count |",
        "|---|---:|",
    ]
    findings = report["findings"]
    assert isinstance(findings, list)
    if not findings:
        lines.append("| none | 0 |")
    for item in findings:
        assert isinstance(item, dict)
        lines.append(f"| {item['code']} | {item['count']} |")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect and sanitize a HAR file locally.")
    parser.add_argument("har", type=Path)
    parser.add_argument("--audit", type=Path)
    parser.add_argument("--sanitized", type=Path)
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    args = parser.parse_args(argv)
    if not args.har.is_file():
        parser.error("HAR file does not exist")
    report, sanitized = inspect_and_sanitize(args.har)
    rendered = json.dumps(report, indent=2) if args.format == "json" else _markdown(report)
    if args.audit:
        args.audit.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    if args.sanitized:
        if args.sanitized.resolve() == args.har.resolve():
            parser.error("sanitized output must not replace the source")
        args.sanitized.write_text(json.dumps(sanitized, indent=2) + "\n", encoding="utf-8")
    return 0
