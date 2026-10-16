import hashlib
import json

import pytest

from har_privacy_inspector.cli import main
from har_privacy_inspector.core import inspect_and_sanitize


def fixture(tmp_path):
    source = tmp_path / "synthetic.har"
    canary = "URL_CANARY_762391"
    url = f"https://{canary}:{canary}@{canary}.test/{canary}?{canary}={canary}#{canary}"
    source.write_text(
        json.dumps(
            {
                "log": {
                    "entries": [
                        {
                            "_secret": url,
                            "request": {"url": url},
                            "response": {
                                "status": status,
                                "headersSize": 3,
                                "bodySize": 7,
                                "redirectURL": url,
                                "_extension": url,
                            },
                        }
                        for status in [201, 302]
                    ]
                }
            }
        )
    )
    return source, canary


def test_url_free_snapshot(tmp_path):
    source, canary = fixture(tmp_path)
    before = source.read_bytes()
    report, snapshot = inspect_and_sanitize(source, strict=True, strict_url_mode="omit")
    rendered = json.dumps(snapshot)
    assert canary not in rendered
    assert "url" not in rendered.lower()
    entries = snapshot["log"]["entries"]
    assert [e["_entryId"] for e in entries] == ["entry-000001", "entry-000002"]
    assert [e["response"]["status"] for e in entries] == [201, 302]
    assert all(e["response"]["bodySize"] == 7 for e in entries)
    assert report["exportMode"] == "strict-url-free"
    assert source.read_bytes() == before
    assert report["sourceSha256"] == hashlib.sha256(before).hexdigest()
    assert canary not in json.dumps(report)
    audit = tmp_path / "audit.json"
    output = tmp_path / "snapshot.json"
    assert (
        main(
            [
                str(source),
                "--strict",
                "--strict-url-mode",
                "omit",
                "--format",
                "json",
                "--audit",
                str(audit),
                "--sanitized",
                str(output),
            ]
        )
        == 0
    )
    assert canary not in output.read_text() + audit.read_text()


def test_defaults_and_invalid_modes(tmp_path):
    source, canary = fixture(tmp_path)
    assert inspect_and_sanitize(source) == inspect_and_sanitize(source, strict=False)
    assert canary in json.dumps(inspect_and_sanitize(source, strict=True)[1])
    for strict, mode in [(True, "bad"), (False, "omit"), (True, None)]:
        with pytest.raises(ValueError):
            inspect_and_sanitize(source, strict=strict, strict_url_mode=mode)
    with pytest.raises(SystemExit):
        main([str(source), "--strict-url-mode", "bad"])
    with pytest.raises(SystemExit):
        main([str(source), "--strict-url-mode", "omit"])
