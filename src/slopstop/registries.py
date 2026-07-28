"""Registry clients for npm and PyPI.

Design choices, all security driven:

  * Zero third party runtime dependencies. A tool that defends the software
    supply chain must not enlarge it. We use only the standard library, so
    installing Slopstop adds no new packages to trust.
  * A fixed allowlist of hosts. The opener refuses any redirect that would
    leave the known registry host, which blocks a lookup being bounced to an
    attacker controlled endpoint.
  * A capped response read, a timeout, and a declared user agent, so a hostile
    or broken registry response cannot exhaust memory or hang the caller.

The clients return PackageFacts. They never decide safety themselves; scoring
lives in signature.py so the policy is testable in isolation.
"""

from __future__ import annotations

import json
import random
import socket
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlsplit

from . import names
from .models import Ecosystem, Existence, PackageFacts

# Bytes we are willing to read from a single registry response. Popular
# packages carry large metadata documents, so the cap is generous. A response
# that still exceeds it is itself a signal: the package is real and large,
# which is the opposite of a hollow slopsquat.
_MAX_BYTES = 25 * 1024 * 1024

_NPM_HOST = "registry.npmjs.org"
_PYPI_HOST = "pypi.org"


class OversizeResponse(Exception):
    """The registry document exists but is too large to parse fully."""


class _HostLockedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Allow redirects only when they stay on the original host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        original_host = urlsplit(req.full_url).hostname
        target_host = urlsplit(newurl).hostname
        if target_host != original_host:
            raise urllib.error.URLError(
                f"refusing cross host redirect to {target_host!r}"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _build_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_HostLockedRedirectHandler())


def _iso_to_age_days(iso_value: Optional[str]) -> Optional[float]:
    if not iso_value:
        return None
    try:
        cleaned = iso_value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - dt
        return max(delta.total_seconds() / 86400.0, 0.0)
    except ValueError:
        return None


class RegistryClient:
    """Fetches package facts. Injectable so tests never touch the network."""

    def __init__(
        self,
        user_agent: str,
        timeout: int,
        retries: int = 2,
        backoff: float = 0.4,
    ) -> None:
        self._user_agent = user_agent
        self._timeout = timeout
        self._retries = max(retries, 0)
        self._backoff = max(backoff, 0.0)
        self._opener = _build_opener()

    def _fetch_json(self, url: str) -> Optional[dict]:
        """Return parsed JSON, None for a 404, or raise for other failures.

        Transient failures (timeouts, connection errors, and 5xx responses) are
        retried with exponential backoff, since a single dropped request should
        not read as a package that could not be verified. A 404 is a clean
        absence and returns immediately; a non 404 client error is not
        transient and is not retried.
        """
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": self._user_agent,
                "Accept": "application/json",
            },
            method="GET",
        )
        last_exc: Optional[Exception] = None
        for attempt in range(self._retries + 1):
            try:
                with self._opener.open(request, timeout=self._timeout) as response:
                    body = response.read(_MAX_BYTES + 1)
                if len(body) > _MAX_BYTES:
                    raise OversizeResponse("registry document larger than cap")
                return json.loads(body.decode("utf-8"))
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    return None  # a clean absence, the key hallucination signal
                if exc.code < 500:
                    raise  # a client error is not transient
                last_exc = exc  # a server error may pass on retry
            except (urllib.error.URLError, socket.timeout, TimeoutError,
                    ConnectionError) as exc:
                last_exc = exc

            if attempt < self._retries:
                delay = self._backoff * (2 ** attempt) + random.uniform(0, 0.1)
                time.sleep(delay)

        assert last_exc is not None
        raise last_exc

    def lookup(self, ecosystem: Ecosystem, name: str) -> PackageFacts:
        validated = names.validate(ecosystem, name)
        if ecosystem is Ecosystem.NPM:
            return self._lookup_npm(validated)
        if ecosystem is Ecosystem.PYPI:
            return self._lookup_pypi(validated)
        raise ValueError(f"unsupported ecosystem: {ecosystem!r}")

    def _lookup_npm(self, name: str) -> PackageFacts:
        segment = names.url_path_segment(name)
        url = f"https://{_NPM_HOST}/{segment}"
        try:
            data = self._fetch_json(url)
        except OversizeResponse:
            # A document this large belongs to a real, heavily versioned
            # package. Existence is certain; age is left unknown.
            return PackageFacts(
                ecosystem=Ecosystem.NPM,
                name=name,
                existence=Existence.PRESENT,
                release_count=None,
                has_description=True,
                has_repository=True,
            )
        except Exception as exc:  # noqa: BLE001
            return PackageFacts(
                ecosystem=Ecosystem.NPM,
                name=name,
                existence=Existence.UNKNOWN,
                lookup_error=str(exc),
            )
        if data is None:
            return PackageFacts(
                ecosystem=Ecosystem.NPM,
                name=name,
                existence=Existence.ABSENT,
            )

        time_map = data.get("time", {}) if isinstance(data, dict) else {}
        created = time_map.get("created")
        modified = time_map.get("modified")
        versions = data.get("versions", {}) if isinstance(data, dict) else {}
        repo = data.get("repository")
        description = data.get("description")

        return PackageFacts(
            ecosystem=Ecosystem.NPM,
            name=name,
            existence=Existence.PRESENT,
            first_release_iso=created,
            latest_release_iso=modified,
            release_count=len(versions) if isinstance(versions, dict) else None,
            has_description=bool(description),
            has_repository=bool(repo),
            age_days=_iso_to_age_days(created),
        )

    def _lookup_pypi(self, name: str) -> PackageFacts:
        segment = names.url_path_segment(name)
        url = f"https://{_PYPI_HOST}/pypi/{segment}/json"
        try:
            data = self._fetch_json(url)
        except OversizeResponse:
            return PackageFacts(
                ecosystem=Ecosystem.PYPI,
                name=name,
                existence=Existence.PRESENT,
                release_count=None,
                has_description=True,
                has_repository=True,
            )
        except Exception as exc:  # noqa: BLE001
            return PackageFacts(
                ecosystem=Ecosystem.PYPI,
                name=name,
                existence=Existence.UNKNOWN,
                lookup_error=str(exc),
            )
        if data is None:
            return PackageFacts(
                ecosystem=Ecosystem.PYPI,
                name=name,
                existence=Existence.ABSENT,
            )

        info = data.get("info", {}) if isinstance(data, dict) else {}
        releases = data.get("releases", {}) if isinstance(data, dict) else {}

        first_iso = _earliest_pypi_upload(releases)
        description = info.get("summary") or info.get("description")
        urls = info.get("project_urls") or {}
        home = info.get("home_page")

        return PackageFacts(
            ecosystem=Ecosystem.PYPI,
            name=name,
            existence=Existence.PRESENT,
            first_release_iso=first_iso,
            latest_release_iso=None,
            release_count=len(releases) if isinstance(releases, dict) else None,
            has_description=bool(description),
            has_repository=bool(urls) or bool(home),
            age_days=_iso_to_age_days(first_iso),
        )


def _earliest_pypi_upload(releases: dict) -> Optional[str]:
    """Find the oldest upload timestamp across all releases."""
    earliest: Optional[str] = None
    if not isinstance(releases, dict):
        return None
    for files in releases.values():
        if not isinstance(files, list):
            continue
        for file_info in files:
            if not isinstance(file_info, dict):
                continue
            uploaded = file_info.get("upload_time_iso_8601") or file_info.get(
                "upload_time"
            )
            if uploaded and (earliest is None or uploaded < earliest):
                earliest = uploaded
    return earliest