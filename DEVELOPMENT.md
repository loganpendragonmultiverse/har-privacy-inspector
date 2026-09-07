# Development handoff

HAR Privacy Inspector is local, source-preserving, and redacted-by-default. Audits must remain value-free. Version 1 does not promise complete anonymization, fetch the Public Suffix List, decode bodies, or contact captured destinations. Sanitization changes require fixtures proving source preservation and absence of secret values.

## 1.1.0 improvement session

Sanitize URL credentials, fragments, redirects and URL-bearing headers; add a strict structural export and protect all source/output paths.

`--strict` creates a minimal structural snapshot containing sanitized request URLs, numeric response status/sizes and generated creator metadata. It deliberately omits headers, cookies, bodies, pages, comments and extension fields; it is not a full-fidelity HAR replay file. The audit lists retained field categories. Standard mode keeps the original structure. Both modes retain URL paths and query names, which still require review before sharing. Existing output files and source/output aliases are refused.

Local formatting, lint, strict types and regression tests pass. Public release completion requires the protected CI/CodeQL matrix, tagged artifacts and matching Forge catalog/detail deployment.
