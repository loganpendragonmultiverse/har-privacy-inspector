# Development handoff

HAR Privacy Inspector is local, source-preserving, and redacted-by-default. Audits must remain value-free. Version 1 does not promise complete anonymization, fetch the Public Suffix List, decode bodies, or contact captured destinations. Sanitization changes require fixtures proving source preservation and absence of secret values.

## 1.1.0 improvement session

Sanitize URL credentials, fragments, redirects and URL-bearing headers; add a strict structural export and protect all source/output paths.

`--strict` creates a minimal structural snapshot containing sanitized request URLs, numeric response status/sizes and generated creator metadata. It deliberately omits headers, cookies, bodies, pages, comments and extension fields; it is not a full-fidelity HAR replay file. The audit lists retained field categories. Standard mode keeps the original structure. Both modes retain URL paths and query names, which still require review before sharing. Existing output files and source/output aliases are refused.

Local formatting, lint, strict types and regression tests pass. Public release completion requires the protected CI/CodeQL matrix, tagged artifacts and matching Forge catalog/detail deployment.

## 1.2.0 — 2026-10-16

Use `har-privacy-inspector capture.har --strict --strict-url-mode omit --audit audit.json --format json --sanitized snapshot.json`. The new snapshot omits request URLs entirely and retains generated `_entryId` values in original entry order plus integer response `status`, `headersSize` and `bodySize` fields. Redirects, headers, bodies, names and extension fields are omitted through the strict allowlist. `--strict-url-mode sanitized` remains the default; `omit` requires `--strict`. Snapshot entry counts, order and numeric response fields can still be sensitive. Audit reports retain the source filename and fingerprints, and output filenames can reveal context. Review both files and their names before sharing: this is not a universal safe-to-share guarantee or a replayable full HAR.

## 1.2.1 acceptance

Preserve all three export modes and their privacy/source-preservation canaries. Regress malformed entry/body/list containers, duplicate keys, non-finite numbers, byte/depth/value/entry boundaries, braces and escaped quotes inside strings, dangling links and a raced regular output. Keep full format/lint/strict-type, coverage, dependency-audit, native matrix, CodeQL and tagged-build gates. Install the actual tagged wheel and source distribution independently, run the complete tests outside the source tree, verify the four packaged documents and synthetic example, and execute its documented CLI flow. Resource limits are explicit; this does not certify full HAR schema or universal sharing safety.
