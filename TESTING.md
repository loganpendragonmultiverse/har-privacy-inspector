# Testing

Run `ruff format --check .`, `ruff check .`, `mypy src`, `pytest`, `python -m build`, and `python -m pip_audit .`. Fixtures cover sensitive headers, cookies, URL/query values, post data, response content, third-party classification, hashes, value-free audits, safe output, and invalid roots.

## 1.1.0 regression acceptance

Run the complete existing suite plus the new regression fixtures. Confirm the documented command produces the selected output, malformed input remains actionable, and source files remain unchanged. Sanitize URL credentials, fragments, redirects and URL-bearing headers; add a strict structural export and protect all source/output paths.

## 1.2.0 — 2026-10-16

Use synthetic canaries in URL host, userinfo, path, query names and values, fragments, redirects and extension fields. Check snapshot and audit canary absence, generated identity/order, numeric response preservation, invalid modes, default parity and unchanged source bytes.
