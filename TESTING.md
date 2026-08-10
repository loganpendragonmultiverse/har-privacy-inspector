# Testing

Run `ruff format --check .`, `ruff check .`, `mypy src`, `pytest`, `python -m build`, and `python -m pip_audit .`. Fixtures cover sensitive headers, cookies, URL/query values, post data, response content, third-party classification, hashes, value-free audits, safe output, and invalid roots.
