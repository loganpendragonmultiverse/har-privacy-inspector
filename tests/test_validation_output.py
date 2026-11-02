import json
from pathlib import Path

import pytest

from har_privacy_inspector import validation
from har_privacy_inspector.cli import main
from har_privacy_inspector.core import inspect_and_sanitize


def write(source: Path, value: object) -> None:
    source.write_text(json.dumps(value), encoding="utf-8")


@pytest.mark.parametrize("entries", [None, {}, "bad", [None], [3]])
def test_malformed_entries_fail_without_output(tmp_path, entries):
    source = tmp_path / "capture.har"
    write(source, {"log": {"entries": entries}})
    output = tmp_path / "out.json"
    before = source.read_bytes()
    with pytest.raises(SystemExit) as error:
        main([str(source), "--strict", "--sanitized", str(output)])
    assert error.value.code == 2
    assert not output.exists()
    assert source.read_bytes() == before


@pytest.mark.parametrize(
    "entry",
    [
        {"request": None},
        {"response": []},
        {"request": {"headers": {}}},
        {"response": {"cookies": [None]}},
        {"request": {"queryString": "bad"}},
        {"request": {"url": 42}},
        {"response": {"redirectURL": []}},
        {"request": {"postData": []}},
        {"response": {"content": None}},
        {"response": {"content": {"text": 42}}},
        {"request": {"postData": {"params": [False]}}},
    ],
)
def test_malformed_sanitized_containers_rejected(tmp_path, entry):
    source = tmp_path / "capture.har"
    write(source, {"log": {"entries": [entry]}})
    with pytest.raises(TypeError):
        inspect_and_sanitize(source)


@pytest.mark.parametrize(
    "raw",
    [
        '{"log":{"entries":[],"entries":[]}}',
        '{"log":{"entries":[],"extension":NaN}}',
        '{"log":{"entries":[],"extension":Infinity}}',
        '{"log":{"entries":[],"extension":-Infinity}}',
    ],
)
def test_ambiguous_or_nonfinite_json_rejected(tmp_path, raw):
    source = tmp_path / "capture.har"
    source.write_text(raw)
    with pytest.raises(ValueError):
        inspect_and_sanitize(source)


def test_depth_strings_and_boundaries(tmp_path, monkeypatch):
    source = tmp_path / "capture.har"
    # Three containers: root, log, entries. Braces/quotes in strings are not nesting.
    write(source, {"log": {"entries": []}, "extra": '[{\\"}]]'})
    monkeypatch.setattr(validation, "MAX_DEPTH", 3)
    inspect_and_sanitize(source)
    monkeypatch.setattr(validation, "MAX_DEPTH", 2)
    with pytest.raises(ValueError, match="nesting"):
        inspect_and_sanitize(source)
    source.write_text('{"log":{"entries":[]},"extra":' + "[" * 1000 + "0" + "]" * 1000 + "}")
    with pytest.raises(ValueError, match="nesting"):
        inspect_and_sanitize(source)


def test_byte_entry_and_value_boundaries(tmp_path, monkeypatch):
    source = tmp_path / "capture.har"
    write(source, {"log": {"entries": [{}]}})
    size = source.stat().st_size
    monkeypatch.setattr(validation, "MAX_INPUT_BYTES", size)
    inspect_and_sanitize(source)
    monkeypatch.setattr(validation, "MAX_INPUT_BYTES", size - 1)
    with pytest.raises(ValueError, match="input limit"):
        inspect_and_sanitize(source)
    monkeypatch.setattr(validation, "MAX_INPUT_BYTES", size)
    monkeypatch.setattr(validation, "MAX_ENTRIES", 1)
    inspect_and_sanitize(source)
    monkeypatch.setattr(validation, "MAX_ENTRIES", 0)
    with pytest.raises(ValueError, match="entry limit"):
        inspect_and_sanitize(source)
    monkeypatch.setattr(validation, "MAX_ENTRIES", 1)
    monkeypatch.setattr(validation, "MAX_NODES", 4)
    inspect_and_sanitize(source)
    monkeypatch.setattr(validation, "MAX_NODES", 3)
    with pytest.raises(ValueError, match="value-count"):
        inspect_and_sanitize(source)


@pytest.mark.parametrize("output_flag", ["--audit", "--sanitized"])
def test_dangling_output_link_preserved(tmp_path, output_flag):
    source = tmp_path / "capture.har"
    write(source, {"log": {"entries": []}})
    target = tmp_path / "absent"
    link = tmp_path / "link"
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    with pytest.raises(SystemExit):
        main([str(source), output_flag, str(link)])
    assert link.is_symlink()
    assert not target.exists()


@pytest.mark.parametrize("output_flag", ["--audit", "--sanitized"])
def test_raced_regular_output_preserved(tmp_path, monkeypatch, output_flag):
    source = tmp_path / "capture.har"
    write(source, {"log": {"entries": []}})
    output = tmp_path / "out.json"
    original = Path.open

    def raced(self, mode="r", *args, **kwargs):
        if self == output and mode == "x":
            with original(self, "w") as handle:
                handle.write("other writer")
        return original(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", raced)
    with pytest.raises(SystemExit) as error:
        main([str(source), output_flag, str(output)])
    assert error.value.code == 2
    assert output.read_text() == "other writer"


def test_missing_parent_is_actionable_and_source_preserved(tmp_path):
    source = tmp_path / "capture.har"
    write(source, {"log": {"entries": []}})
    before = source.read_bytes()
    with pytest.raises(SystemExit) as error:
        main([str(source), "--audit", str(tmp_path / "absent" / "report.json")])
    assert error.value.code == 2
    assert source.read_bytes() == before


def test_separate_value_counts_and_standard_extension_preservation(tmp_path):
    source = tmp_path / "capture.har"
    write(
        source,
        {
            "log": {
                "entries": [
                    {
                        "request": {
                            "queryString": [{"value": "QUERY"}],
                            "postData": {"params": [{"value": "FORM"}]},
                        }
                    }
                ]
            },
            "extension": "REVIEW_ME",
        },
    )
    report, standard = inspect_and_sanitize(source)
    assert {"code": "query-field", "count": 1} in report["findings"]
    assert {"code": "form-value", "count": 1} in report["findings"]
    assert standard["extension"] == "REVIEW_ME"
    assert "QUERY" not in json.dumps(standard)
    assert "FORM" not in json.dumps(standard)
    _, strict = inspect_and_sanitize(source, strict=True)
    assert "extension" not in strict


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16", "utf-32"])
def test_depth_scanner_preserves_json_encodings_and_quoted_braces(tmp_path, encoding):
    source = tmp_path / "capture.har"
    data = {"log": {"entries": []}, "extra": 'quoted" and \\ and [[[', "finite": 1.25}
    source.write_bytes(json.dumps(data).encode(encoding))
    _, sanitized = inspect_and_sanitize(source)
    assert sanitized["extra"] == data["extra"]
    assert sanitized["finite"] == 1.25


def test_overflowing_json_float_is_rejected(tmp_path):
    source = tmp_path / "capture.har"
    source.write_text('{"log":{"entries":[]},"extra":1e9999}')
    with pytest.raises(ValueError, match="non-finite"):
        inspect_and_sanitize(source)


@pytest.mark.parametrize("ancestor", [False, True])
@pytest.mark.parametrize("output_flag", ["--audit", "--sanitized"])
def test_output_symlink_loops_are_actionable_and_preserved(tmp_path, ancestor, output_flag):
    source = tmp_path / "capture.har"
    write(source, {"log": {"entries": []}})
    before = source.read_bytes()
    link = tmp_path / "loop"
    try:
        link.symlink_to(link.name, target_is_directory=ancestor)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    output = link / "out.json" if ancestor else link
    with pytest.raises(SystemExit) as error:
        main([str(source), output_flag, str(output)])
    assert error.value.code == 2
    assert link.is_symlink()
    assert source.read_bytes() == before
