from __future__ import annotations

import copy
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
}
REDACTED = "[REDACTED]"


def _mapping(value: object) -> dict[str, Any]:
    return cast(dict[str, Any], value) if isinstance(value, dict) else {}


def _sequence(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _site(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _redact_headers(container: dict[str, Any], counts: Counter[str]) -> None:
    for raw in _sequence(container.get("headers")):
        header = _mapping(raw)
        if str(header.get("name", "")).lower() in SENSITIVE_HEADERS:
            header["value"] = REDACTED
            counts["sensitive-header"] += 1
    for raw in _sequence(container.get("cookies")):
        cookie = _mapping(raw)
        if "value" in cookie:
            cookie["value"] = REDACTED
            counts["cookie"] += 1


def _redact_request(request: dict[str, Any], counts: Counter[str]) -> None:
    _redact_headers(request, counts)
    url = str(request.get("url", ""))
    split = urlsplit(url)
    query = parse_qsl(split.query, keep_blank_values=True)
    if query:
        request["url"] = urlunsplit(
            (
                split.scheme,
                split.netloc,
                split.path,
                urlencode([(name, REDACTED) for name, _ in query]),
                split.fragment,
            )
        )
        counts["query-value"] += len(query)
    for raw in _sequence(request.get("queryString")):
        item = _mapping(raw)
        if "value" in item:
            item["value"] = REDACTED
    post = _mapping(request.get("postData"))
    if "text" in post:
        post["text"] = REDACTED
        counts["request-body"] += 1
    for raw in _sequence(post.get("params")):
        item = _mapping(raw)
        if "value" in item:
            item["value"] = REDACTED


def _redact_response(response: dict[str, Any], counts: Counter[str]) -> None:
    _redact_headers(response, counts)
    content = _mapping(response.get("content"))
    if "text" in content:
        content["text"] = REDACTED
        content.pop("encoding", None)
        counts["response-body"] += 1


def inspect_and_sanitize(path: Path) -> tuple[dict[str, object], dict[str, Any]]:
    raw = path.read_bytes()
    loaded = json.loads(raw)
    if not isinstance(loaded, dict) or not isinstance(_mapping(loaded).get("log"), dict):
        raise TypeError("HAR root must contain a log object")
    sanitized = copy.deepcopy(cast(dict[str, Any], loaded))
    entries = _sequence(_mapping(sanitized["log"]).get("entries"))
    counts: Counter[str] = Counter()
    page_sites: set[str] = set()
    for raw_entry in entries:
        request = _mapping(_mapping(raw_entry).get("request"))
        host = urlsplit(str(request.get("url", ""))).hostname or ""
        if not page_sites and host:
            page_sites.add(_site(host))
        if host and page_sites and _site(host) not in page_sites:
            counts["third-party-request"] += 1
        _redact_request(request, counts)
        _redact_response(_mapping(_mapping(raw_entry).get("response")), counts)
    findings = [{"code": code, "count": count} for code, count in sorted(counts.items())]
    report: dict[str, object] = {
        "schemaVersion": 1,
        "source": path.name,
        "sourceSha256": hashlib.sha256(raw).hexdigest(),
        "entryCount": len(entries),
        "findingCount": sum(counts.values()),
        "findings": findings,
        "sanitizedSha256": hashlib.sha256(
            json.dumps(sanitized, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }
    return report, sanitized
