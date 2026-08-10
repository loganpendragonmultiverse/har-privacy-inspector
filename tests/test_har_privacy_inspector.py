import json
from pathlib import Path

import pytest

from har_privacy_inspector.cli import main
from har_privacy_inspector.core import REDACTED, _site, inspect_and_sanitize


def _write(path: Path) -> None:
    data = {
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "request": {
                        "url": "https://app.example.test/path?token=secret",
                        "headers": [{"name": "Authorization", "value": "Bearer secret"}],
                        "cookies": [{"name": "sid", "value": "secret"}],
                        "queryString": [{"name": "token", "value": "secret"}],
                        "postData": {
                            "mimeType": "application/json",
                            "text": '{"secret":true}',
                            "params": [{"name": "p", "value": "secret"}],
                        },
                    },
                    "response": {
                        "headers": [{"name": "Set-Cookie", "value": "sid=secret"}],
                        "cookies": [],
                        "content": {"text": "private response", "encoding": "base64"},
                    },
                },
                {
                    "request": {"url": "https://tracker.other.test/pixel", "headers": []},
                    "response": {"headers": [], "content": {}},
                },
            ],
        }
    }
    path.write_text(json.dumps(data), encoding="utf-8")


def test_inspects_and_sanitizes_values(tmp_path: Path) -> None:
    path = tmp_path / "capture.har"
    _write(path)
    report, sanitized = inspect_and_sanitize(path)
    text = json.dumps(sanitized)
    assert "secret" not in text and "private response" not in text
    assert REDACTED in text
    codes = {item["code"] for item in report["findings"]}  # type: ignore[index]
    assert {
        "sensitive-header",
        "cookie",
        "query-value",
        "request-body",
        "response-body",
        "third-party-request",
    } <= codes


def test_report_is_value_free_and_fingerprinted(tmp_path: Path) -> None:
    path = tmp_path / "capture.har"
    _write(path)
    report, _ = inspect_and_sanitize(path)
    assert "secret" not in json.dumps(report)
    assert len(str(report["sourceSha256"])) == 64
    assert report["entryCount"] == 2


def test_cli_writes_audit_and_sanitized_copy(tmp_path: Path) -> None:
    source = tmp_path / "capture.har"
    audit = tmp_path / "audit.json"
    sanitized = tmp_path / "safe.har"
    _write(source)
    assert (
        main(
            [str(source), "--format", "json", "--audit", str(audit), "--sanitized", str(sanitized)]
        )
        == 0
    )
    assert '"schemaVersion": 1' in audit.read_text(encoding="utf-8")
    assert "secret" not in sanitized.read_text(encoding="utf-8")


def test_rejects_source_overwrite(tmp_path: Path) -> None:
    source = tmp_path / "capture.har"
    _write(source)
    with pytest.raises(SystemExit):
        main([str(source), "--sanitized", str(source)])


def test_invalid_har_rejected(tmp_path: Path) -> None:
    source = tmp_path / "bad.har"
    source.write_text("{}", encoding="utf-8")
    with pytest.raises(TypeError, match="log object"):
        inspect_and_sanitize(source)


def test_site_uses_last_two_labels() -> None:
    assert _site("api.example.com") == "example.com"
    assert _site("localhost") == "localhost"
