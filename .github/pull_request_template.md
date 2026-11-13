## What

<!-- One or two lines on what this PR changes. -->

## Why

<!-- Which task/card does this close? Link the issue if there is one. -->

## How to test

<!-- Commands a reviewer can run, e.g. `pytest tests/test_zw.py`. -->

## Checklist

- [ ] Small, focused PR (one task)
- [ ] Tests added or updated, `pytest` passes
- [ ] `ruff check . && ruff format --check .` is clean
- [ ] Docs / README updated if behaviour changed
- [ ] No keys, `.env` files or databases committed
- [ ] Tags compared with `hmac.compare_digest`, never `==` (if touching crypto)
