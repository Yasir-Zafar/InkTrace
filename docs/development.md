# Development

## With Nix (recommended)

1. Install Nix with flakes enabled, and direnv.
2. In the repo: `direnv allow` (or `nix develop` without direnv).

The shell gives Python 3.12 with pytest, hypothesis and flask, plus ruff, sqlite3 and gh.
New tools go in `flake.nix`.

## Without Nix

```
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
```

## Checks

```
ruff check . && ruff format --check . && pytest
```

## Workflow

- Never push to `main`. Branch, then open a PR.
- Small commits, short messages.
- No keys, `.env` or `.db` files in git.
