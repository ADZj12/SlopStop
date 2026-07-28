"""Manifest scanning.

Parses a project's dependency manifests and yields the declared package names
so the checker can vet each one. Supporting requirements.txt and package.json
lets Slopstop meet a developer inside tools they already run, rather than
asking them to adopt a new workflow.

Parsing is intentionally forgiving: a manifest we cannot fully understand
should still surrender the names it clearly contains.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Ecosystem

# Strip everything from the first version or marker character onward.
_REQ_SPLIT = re.compile(r"[<>=!~;\[\s]")


def scan_requirements(path: Path) -> list[tuple[Ecosystem, str]]:
    """Extract package names from a pip style requirements file."""
    found: list[tuple[Ecosystem, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-")):
            continue  # skip comments and pip options such as -r or --index-url
        if stripped.startswith(("http://", "https://", "git+")):
            continue  # direct url installs are out of scope here
        name = _REQ_SPLIT.split(stripped, maxsplit=1)[0].strip()
        if name:
            found.append((Ecosystem.PYPI, name))
    return found


def scan_package_json(path: Path) -> list[tuple[Ecosystem, str]]:
    """Extract dependency names from an npm package.json."""
    data = json.loads(path.read_text(encoding="utf-8"))
    found: list[tuple[Ecosystem, str]] = []
    fields = (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    )
    for field in fields:
        section = data.get(field)
        if isinstance(section, dict):
            for name in section:
                found.append((Ecosystem.NPM, name))
    return found


def scan_path(path: Path) -> list[tuple[Ecosystem, str]]:
    """Dispatch by filename. Returns a de duplicated list of names."""
    if path.name == "package.json":
        pairs = scan_package_json(path)
    elif path.name.endswith(".txt") or path.name.startswith("requirements"):
        pairs = scan_requirements(path)
    else:
        raise ValueError(f"unsupported manifest: {path.name}")

    seen: set[tuple[str, str]] = set()
    unique: list[tuple[Ecosystem, str]] = []
    for eco, name in pairs:
        key = (eco.value, name.lower())
        if key not in seen:
            seen.add(key)
            unique.append((eco, name))
    return unique
