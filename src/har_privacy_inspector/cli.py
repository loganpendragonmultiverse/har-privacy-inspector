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
    parser.add_argument(
        "--strict-url-mode",
        choices=("sanitized", "omit"),
        default="sanitized",
        help="With --strict, omit URLs entirely when set to omit",
    )
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    args = parser.parse_args(argv)
    try:
        if not args.har.is_file():
            parser.error("HAR file does not exist")
        requested = [path for path in (args.audit, args.sanitized) if path]
        # Check final links before resolve(): a self-link can make resolve raise.
        if any(path.is_symlink() for path in requested):
            parser.error("output already exists; choose a new output path")
        outputs = [path.resolve() for path in requested]
        if args.har.resolve() in outputs or len(set(outputs)) != len(outputs):
            parser.error("output paths must differ from the source and each other")
        if any(path.exists() for path in requested):
            parser.error("output already exists; choose a new output path")
    except (OSError, RuntimeError) as exc:
        parser.error(f"cannot resolve input/output paths: {exc}")
    try:
        report, sanitized = inspect_and_sanitize(
            args.har, strict=args.strict, strict_url_mode=args.strict_url_mode
        )
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))
    rendered = json.dumps(report, indent=2) if args.format == "json" else _markdown(report)
    try:
        if args.audit:
            with args.audit.open("x", encoding="utf-8") as handle:
                handle.write(rendered + "\n")
        else:
            print(rendered)
        if args.sanitized:
            with args.sanitized.open("x", encoding="utf-8") as handle:
                handle.write(json.dumps(sanitized, indent=2) + "\n")
    except OSError as exc:
        parser.error(str(exc))
    return 0
