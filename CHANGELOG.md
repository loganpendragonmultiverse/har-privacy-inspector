# Changelog

## 1.2.1 - 2026-10-20

- Reject malformed sanitization containers, ambiguous duplicate keys and non-finite JSON numbers; bound input bytes, nesting, values and entries.
- Preserve existing outputs and dangling links; use exclusive creation for accidental regular-file races and report write failures cleanly.
- Count query-string fields and form-value redactions, and ship a synthetic CLI example with installed documentation.

## 1.2.0 - 2026-10-16

- Add an explicit URL-free strict snapshot while preserving standard export and the existing strict URL behavior by default.
- Add synthetic regression coverage and packaged development/testing documentation.

## 1.1.0 - 2026-09-07

- Sanitize URL credentials, fragments, redirects and URL-bearing headers; add a strict structural export and protect all source/output paths.
- Added regression coverage for the audited behavior and invalid inputs.

## 1.0.0 - 2026-08-10

- Added local HAR structure inspection and privacy-safe copy generation.
- Added header, cookie, query, request-body, response-body, and third-party findings.
- Added value-free JSON and Markdown audits with source and sanitized fingerprints.
