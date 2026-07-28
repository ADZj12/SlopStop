"""The agent hook: a FastMCP stdio server.

This is a thin transport shell. All real logic lives in the checker (scoring),
the cache and registry client (lookups), and advisories.py (advice and the log).
The server wires them to the two tools an agent calls.

Modes, set with the SLOPSTOP_MODE environment variable:

  * advisory (default): every result is returned as data, including flagged
    ones. The agent decides. Nothing is blocked, which protects adoption.
  * block: a flagged package (hallucinated or suspicious) raises an error the
    client sees as a failed tool call, so a careless agent cannot walk past it.

Either way, a flagged package is written to the advisory log, so the ignored
rundown works in both modes.

This module imports the mcp package and so is only usable when the optional
mcp extra is installed (pip install slopstop[mcp]). The core tool never imports
it, keeping the base install dependency free.
"""

from __future__ import annotations

import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .advisories import AdvisoryLog, build_advice
from .cache import VerdictCache
from .checker import Checker, load_popular
from .config import load_settings
from .corpus import Corpus
from .models import Ecosystem
from .registries import RegistryClient


def _seed_data_path() -> Path:
    return Path(__file__).resolve().parent.parent.parent / "data" / "seed_popular.json"


def _load_popular_safe() -> list[str]:
    try:
        return load_popular(_seed_data_path())
    except Exception:  # noqa: BLE001
        return []


def _mode() -> str:
    mode = os.environ.get("SLOPSTOP_MODE", "advisory").strip().lower()
    return "block" if mode == "block" else "advisory"


class BlockedPackage(Exception):
    """Raised in block mode so the client sees a failed tool call."""


def build_server() -> FastMCP:
    settings = load_settings()
    client = RegistryClient(
        user_agent=settings.user_agent, timeout=settings.http_timeout
    )
    corpus = Corpus(settings.db_path)
    cache = VerdictCache()
    checker = Checker(
        client, popular=_load_popular_safe(), corpus=corpus, cache=cache
    )
    advisories = AdvisoryLog(settings.db_path)

    mcp = FastMCP("slopstop")

    @mcp.tool()
    def check_package(ecosystem: str, name: str) -> dict:
        """Verify a package name before installing it.

        ecosystem must be npm or pypi. Returns a verdict, a risk score from 0
        to 100, whether it is safe to install, and plain advice. Call this the
        moment a package name is suggested, before running any install command.
        """
        eco = _parse_ecosystem(ecosystem)
        assessment = checker.check(eco, name, source="agent")
        advisories.record(assessment, _mode())
        advice = build_advice(assessment, _mode())
        if _mode() == "block" and assessment.is_blocking():
            raise BlockedPackage(
                f"Slopstop blocked {eco.value}:{name}. {advice['advice']} "
                "Set SLOPSTOP_MODE=advisory to allow with a warning instead."
            )
        return advice

    @mcp.tool()
    def list_advisories(limit: int = 20) -> list[dict]:
        """List recent flagged packages the hook has advised against."""
        rows = advisories.recent(limit)
        return [
            {
                "ecosystem": r["ecosystem"],
                "name": r["name"],
                "verdict": r["verdict"],
                "score": r["score"],
                "mode": r["mode"],
                "when": r["created_at"],
            }
            for r in rows
        ]

    return mcp


def _parse_ecosystem(value: str) -> Ecosystem:
    try:
        return Ecosystem(value.strip().lower())
    except ValueError:
        raise ValueError(f"ecosystem must be npm or pypi, got {value!r}")


def run_server() -> None:
    """Entry point used by the slopstop serve command."""
    build_server().run(transport="stdio")


if __name__ == "__main__":
    run_server()
