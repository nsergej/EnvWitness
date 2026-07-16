#!/usr/bin/env sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python_command=${PYTHON:-$repository_root/.venv/bin/python}

cd "$repository_root"
"$python_command" -m ruff format --check src tests examples scripts
"$python_command" -m ruff check src tests examples scripts
"$python_command" -m mypy src
"$python_command" -m pytest
"$python_command" -m bandit -c pyproject.toml -r src
"$python_command" scripts/validate_repository.py
"$python_command" -m build
"$python_command" -m pip_audit
