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

Python 3.10+ on Windows, macOS, and Linux. Current release: **v1.0.0**. Pull requests are reviewed. MIT licensed.
