from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core import inspect_and_sanitize


def _markdown(report: dict[str, object]) -> str:
    retained = report["retainedFields"]
    assert isinstance(retained, list)
    lines = [
        "# HAR Privacy Inspector report",
        "",
        f"- Entries: {report['entryCount']}",
        f"- Findings: {report['findingCount']}",
        f"- Source SHA-256: `{report['sourceSha256']}`",
        f"- Sanitized SHA-256: `{report['sanitizedSha256']}`",
        f"- Export mode: {report['exportMode']}",
        f"- Retained: {', '.join(str(item) for item in retained)}",
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
    parser.add_argument("--strict", action="store_true", help="Export only allowlisted structure")
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    args = parser.parse_args(argv)
    if not args.har.is_file():
        parser.error("HAR file does not exist")
    outputs = [path.resolve() for path in (args.audit, args.sanitized) if path]
    if args.har.resolve() in outputs or len(set(outputs)) != len(outputs):
        parser.error("output paths must differ from the source and each other")
    if any(path.exists() for path in outputs):
        parser.error("output already exists; choose a new output path")
    try:
        report, sanitized = inspect_and_sanitize(args.har, strict=args.strict)
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))
    rendered = json.dumps(report, indent=2) if args.format == "json" else _markdown(report)
    if args.audit:
        args.audit.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    if args.sanitized:
        args.sanitized.write_text(json.dumps(sanitized, indent=2) + "\n", encoding="utf-8")
    return 0
