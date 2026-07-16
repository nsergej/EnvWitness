#!/usr/bin/env sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python_command=${PYTHON:-python3}

if [ ! -x "$repository_root/.venv/bin/python" ]; then
    "$python_command" -m venv "$repository_root/.venv"
fi

"$repository_root/.venv/bin/python" -m pip install --upgrade pip
"$repository_root/.venv/bin/python" -m pip install -e "$repository_root[development]"
printf 'Development environment ready: %s\n' "$repository_root/.venv"
