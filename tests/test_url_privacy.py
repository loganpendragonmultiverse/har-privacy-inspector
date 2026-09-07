import json
from pathlib import Path

import pytest

from har_privacy_inspector.cli import main
from har_privacy_inspector.core import inspect_and_sanitize


@pytest.mark.parametrize("strict", [False, True])
def test_secret_locations_and_source_preservation(tmp_path: Path, strict: bool) -> None:
    url = "https://QA_USER:QA_PASSWORD@example.test/path?token=QA_QUERY#QA_FRAGMENT"
    source = tmp_path / "capture.har"
    source.write_text(
        json.dumps(
            {
                "log": {
                    "entries": [
                        {
                            "request": {
                                "url": url,
                                "headers": [
                                    {"name": name, "value": url}
                                    for name in (
                                        "Location",
                                        "Content-Location",
                                        "Referer",
                                        "Origin",
                                        "Link",
                                        "Refresh",
                                    )
                                ],
                            },
                            "response": {"redirectURL": url, "status": 302, "bodySize": 4},
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    original = source.read_bytes()
    report, sanitized = inspect_and_sanitize(source, strict=strict)
    for secret in ("QA_USER", "QA_PASSWORD", "QA_QUERY", "QA_FRAGMENT"):
        assert secret not in json.dumps(sanitized)
        assert secret not in json.dumps(report)
    assert source.read_bytes() == original
    assert sanitized["log"]["entries"][0]["response"]["status"] == 302


def test_strict_drops_extensions_and_free_text(tmp_path: Path) -> None:
    source = tmp_path / "capture.har"
    source.write_text(
        json.dumps(
            {
                "_secret": "CANARY",
                "log": {
                    "pages": [{"title": "CANARY"}],
                    "entries": [
                        {
                            "_secret": "CANARY",
                            "request": {"url": "https://example.test/", "_secret": "CANARY"},
                            "response": {"status": "CANARY", "bodySize": True, "comment": "CANARY"},
                        }
                    ],
                },
            }
        )
    )
    report, safe = inspect_and_sanitize(source, strict=True)
    assert "CANARY" not in json.dumps(safe)
    assert "bodySize" not in json.dumps(safe)
    assert report["exportMode"] == "strict"
    assert main([str(source), "--strict"]) == 0


def test_malformed_url_fails_closed(tmp_path: Path) -> None:
    source = tmp_path / "capture.har"
    source.write_text(
        json.dumps({"log": {"entries": [{"request": {"url": "https://[bad:QA_PASSWORD"}}]}})
    )
    _, safe = inspect_and_sanitize(source)
    assert "QA_PASSWORD" not in json.dumps(safe)


@pytest.mark.parametrize("mode", ["source", "same", "existing", "invalid", "missing"])
def test_cli_rejects_unsafe_outputs_and_invalid_input(tmp_path: Path, mode: str) -> None:
    source = tmp_path / "capture.har"
    source.write_text('{"log":{"entries":[]}}')
    before = source.read_bytes()
    args = [str(source)]
    if mode == "source":
        args += ["--audit", str(source)]
    elif mode == "same":
        args += ["--audit", str(tmp_path / "out"), "--sanitized", str(tmp_path / "out")]
    elif mode == "existing":
        output = tmp_path / "out"
        output.write_text("keep")
        args += ["--audit", str(output)]
    elif mode == "invalid":
        source.write_text("null")
        before = source.read_bytes()
    else:
        args = [str(tmp_path / "absent")]
    with pytest.raises(SystemExit) as error:
        main(args)
    assert error.value.code == 2
    assert source.read_bytes() == before
