# Testing

Run `ruff format --check .`, `ruff check .`, `mypy src`, `pytest`, `python -m build`, and `python -m pip_audit .`. Fixtures cover sensitive headers, cookies, URL/query values, post data, response content, third-party classification, hashes, value-free audits, safe output, and invalid roots.

## 1.1.0 regression acceptance

Run the complete existing suite plus the new regression fixtures. Confirm the documented command produces the selected output, malformed input remains actionable, and source files remain unchanged. Sanitize URL credentials, fragments, redirects and URL-bearing headers; add a strict structural export and protect all source/output paths.

## 1.2.0 — 2026-10-16

Use synthetic canaries in URL host, userinfo, path, query names and values, fragments, redirects and extension fields. Check snapshot and audit canary absence, generated identity/order, numeric response preservation, invalid modes, default parity and unchanged source bytes.

## 1.2.1 acceptance

Preserve all three export modes and their privacy/source-preservation canaries. Regress malformed entry/body/list containers, duplicate keys, non-finite numbers, byte/depth/value/entry boundaries, braces and escaped quotes inside strings, dangling links and a raced regular output. Keep full format/lint/strict-type, coverage, dependency-audit, native matrix, CodeQL and tagged-build gates. Install the actual tagged wheel and source distribution independently, run the complete tests outside the source tree, verify the four packaged documents and synthetic example, and execute its documented CLI flow. Resource limits are explicit; this does not certify full HAR schema or universal sharing safety.
