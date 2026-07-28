"""Package name validation and normalization.

A package name is untrusted input that ends up inside a registry URL. If we
place an unchecked string into a URL path we risk request forgery, path
traversal, or a lookup against the wrong host. So every name is validated
against the strict rules of its ecosystem before it is ever used, and callers
must treat an invalid name as a hard failure, not as a package to look up.
"""

from __future__ import annotations

import re
from urllib.parse import quote

from .models import Ecosystem

# npm: optional @scope/ prefix, url safe characters, max 214 chars, may not
# begin with a dot or an underscore. This is deliberately conservative.
_NPM_UNSCOPED = r"[a-z0-9][a-z0-9._~-]*"
_NPM_RE = re.compile(
    rf"^(?:@{_NPM_UNSCOPED}/)?{_NPM_UNSCOPED}$"
)

# PyPI: letters, digits, and the separators . _ - with a leading and trailing
# alphanumeric. Names are compared in normalized form per PEP 503.
_PYPI_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$", re.IGNORECASE)


class InvalidPackageName(ValueError):
    """Raised when a name cannot be trusted enough to look up."""


def normalize(ecosystem: Ecosystem, name: str) -> str:
    """Return the canonical form used for lookups and corpus keys."""
    stripped = name.strip()
    if ecosystem is Ecosystem.PYPI:
        # PEP 503 normalization: lowercase, runs of . _ - collapse to one dash.
        return re.sub(r"[-_.]+", "-", stripped).lower()
    return stripped.lower()


def validate(ecosystem: Ecosystem, name: str) -> str:
    """Validate and normalize a name, or raise InvalidPackageName.

    The check runs before normalization on the raw string so that hostile
    input such as a name containing a slash traversal or a scheme is rejected
    outright rather than being reshaped into something that passes.
    """
    raw = name.strip()
    if not raw or len(raw) > 214:
        raise InvalidPackageName(f"length out of range: {name!r}")
    if any(ch.isspace() for ch in raw):
        raise InvalidPackageName(f"whitespace in name: {name!r}")
    if ".." in raw or raw.startswith((".", "_", "/")):
        raise InvalidPackageName(f"illegal leading or traversal chars: {name!r}")

    if ecosystem is Ecosystem.NPM:
        if not _NPM_RE.match(raw):
            raise InvalidPackageName(f"not a valid npm name: {name!r}")
    elif ecosystem is Ecosystem.PYPI:
        if not _PYPI_RE.match(raw):
            raise InvalidPackageName(f"not a valid pypi name: {name!r}")
    else:  # pragma: no cover
        raise InvalidPackageName(f"unknown ecosystem: {ecosystem!r}")

    return normalize(ecosystem, raw)


def url_path_segment(name: str) -> str:
    """Percent encode a validated name for safe placement in a URL path.

    The @ and / used by npm scopes are preserved because the registry path
    grammar expects them. Everything else that is not URL safe is encoded.
    """
    return quote(name, safe="@/")
