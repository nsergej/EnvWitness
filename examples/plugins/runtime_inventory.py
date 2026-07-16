"""Example EnvWitness plugin that reports the running Python executable."""

from __future__ import annotations

import json
import platform
import sys
from pathlib import Path
from typing import Any


def read_request() -> dict[str, Any]:
    """Read and minimally validate the versioned plugin request."""
    request = json.load(sys.stdin)
    if not isinstance(request, dict) or request.get("protocol_version") != "1.0":
        raise ValueError("Unsupported EnvWitness plugin request")
    project_root = request.get("project_root")
    if not isinstance(project_root, str) or not Path(project_root).is_dir():
        raise ValueError("Plugin request does not contain a valid project root")
    return request


def build_response() -> dict[str, object]:
    """Build a complete protocol response with namespaced fact keys."""
    return {
        "protocol_version": "1.0",
        "facts": [
            {
                "key": "plugin.runtime-inventory.python-version",
                "value": platform.python_version(),
                "source": "platform.python_version",
                "sensitivity": "public",
            },
            {
                "key": "plugin.runtime-inventory.implementation",
                "value": platform.python_implementation(),
                "source": "platform.python_implementation",
                "sensitivity": "public",
            },
        ],
    }


def main() -> None:
    """Validate the request and write exactly one JSON response."""
    read_request()
    json.dump(build_response(), sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
