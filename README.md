# HAR Privacy Inspector

HAR Privacy Inspector audits browser network captures locally and creates a safer copy for sharing with support teams or reviewers.

It redacts sensitive header values, cookie values, query values, request bodies, response bodies, and form parameter values. The value-free audit counts redactions and likely third-party requests without publishing URLs, hosts, tokens, cookies, or payloads.

## Three-minute start

```bash
python -m pip install .
har-privacy-inspector capture.har --audit audit.md --sanitized capture.safe.har
har-privacy-inspector capture.har --format json --audit audit.json
```

## Scope and limitations

- Always review a sanitized HAR before sharing it; uncommon secrets can exist in names, paths, timings, sizes, or unsupported extension fields.
- Response bodies are removed rather than selectively interpreted.
- Third-party classification uses a conservative hostname approximation, not the Public Suffix List.
- The source HAR is never modified, and an identical output path is rejected.
- No network access, upload, telemetry, account, or browser integration is used.

Python 3.10+ on Windows, macOS, and Linux. Current release: **v1.2.0**. Pull requests are reviewed. MIT licensed.

## Version 1.1.0: reviewed improvements

Sanitize URL credentials, fragments, redirects and URL-bearing headers; add a strict structural export and protect all source/output paths.

```bash
har-privacy-inspector capture.har --strict --audit audit.json --format json --sanitized capture.strict.json
```

`--strict` creates a minimal structural snapshot containing sanitized request URLs, numeric response status/sizes and generated creator metadata. It deliberately omits headers, cookies, bodies, pages, comments and extension fields; it is not a full-fidelity HAR replay file. The audit lists retained field categories. Standard mode keeps the original structure. Both modes retain URL paths and query names, which still require review before sharing. Existing output files and source/output aliases are refused.


## 1.2.0 — 2026-10-16: URL-free strict snapshots

Add an explicit URL-free strict snapshot while preserving standard export and the existing strict URL behavior by default.

Use `har-privacy-inspector capture.har --strict --strict-url-mode omit --audit audit.json --format json --sanitized snapshot.json`. The new snapshot omits request URLs entirely and retains generated `_entryId` values in original entry order plus integer response `status`, `headersSize` and `bodySize` fields. Redirects, headers, bodies, names and extension fields are omitted through the strict allowlist. `--strict-url-mode sanitized` remains the default; `omit` requires `--strict`. Snapshot entry counts, order and numeric response fields can still be sensitive. Audit reports retain the source filename and fingerprints, and output filenames can reveal context. Review both files and their names before sharing: this is not a universal safe-to-share guarantee or a replayable full HAR.
