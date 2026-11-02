"""Bounded local JSON parsing and validation of the containers we sanitize."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 50_000_000
MAX_DEPTH = 100
MAX_NODES = 1_000_000
MAX_ENTRIES = 50_000


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _finite_constant(value: str) -> None:
    raise ValueError("non-finite JSON numbers are unsupported")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite JSON numbers are unsupported")
    return number


def _check_depth(text: str) -> None:
    depth = 0
    quoted = escaped = False
    for byte in text:
        if quoted:
            if escaped:
                escaped = False
            elif byte == "\\":
                escaped = True
            elif byte == '"':
                quoted = False
        elif byte == '"':
            quoted = True
        elif byte in ("[", "{"):
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError("HAR exceeds the JSON nesting limit")
        elif byte in ("]", "}"):
            depth -= 1


def read_har(path: Path) -> tuple[bytes, dict[str, Any]]:
    with path.open("rb") as handle:
        raw = handle.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("HAR exceeds the 50 MB input limit")
    text = raw.decode(json.detect_encoding(raw))
    _check_depth(text)
    loaded = json.loads(
        text,
        object_pairs_hook=_unique_object,
        parse_constant=_finite_constant,
        parse_float=_finite_float,
    )
    if not isinstance(loaded, dict) or not isinstance(loaded.get("log"), dict):
        raise TypeError("HAR root must contain a log object")
    pending = [loaded]
    nodes = 0
    while pending:
        value = pending.pop()
        nodes += 1
        if nodes > MAX_NODES:
            raise ValueError("HAR exceeds the JSON value-count limit")
        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    entries = loaded["log"].get("entries")
    if not isinstance(entries, list):
        raise TypeError("log.entries must be an array")
    if len(entries) > MAX_ENTRIES:
        raise ValueError("HAR exceeds the 50,000-entry limit")
    for entry in entries:
        if not isinstance(entry, dict):
            raise TypeError("each HAR entry must be an object")
        for key in ("request", "response"):
            if key in entry and not isinstance(entry[key], dict):
                raise TypeError("request and response containers must be objects")
            container = entry.get(key, {})
            for field in ("headers", "cookies", "queryString"):
                _object_array(container, field)
            for field in ("url", "redirectURL"):
                if field in container and not isinstance(container[field], str):
                    raise TypeError("URL fields must be strings")
            for field in ("postData", "content"):
                if field not in container:
                    continue
                body = container[field]
                if not isinstance(body, dict):
                    raise TypeError("body containers must be objects")
                if "text" in body and not isinstance(body["text"], str):
                    raise TypeError("body text must be a string")
                _object_array(body, "params")
    return raw, loaded


def _object_array(container: dict[str, Any], field: str) -> None:
    if field not in container:
        return
    values = container[field]
    if not isinstance(values, list) or any(not isinstance(item, dict) for item in values):
        raise TypeError("headers, cookies, queryString and params must be arrays of objects")
