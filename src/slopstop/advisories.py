"""Advisories: the record of what the hook flagged, and whether it was ignored.

The hook runs in advisory mode by default: it returns a verdict and a plain
recommendation, and never blocks. That protects adoption, but it means a
flagged package can still be installed. So every blocking verdict the hook
issues is logged here, and the log can be cross referenced against a project's
manifest to surface the ones that were installed anyway.

The honest limit: an MCP tool cannot observe what the agent does after it
answers, so "ignored" does not mean "the agent proceeded" with certainty. It
means the flagged package later appears in the manifest, which is the strongest
signal available from outside the agent.

This module carries no MCP dependency so its logic is unit tested directly. The
server in mcp_server.py is a thin shell over build_advice and AdvisoryLog.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from .models import Ecosystem, RiskAssessment, Verdict

_SCHEMA = """
CREATE TABLE IF NOT EXISTS advisories (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem   TEXT NOT NULL,
    name        TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    score       INTEGER NOT NULL,
    mode        TEXT NOT NULL,
    reasons     TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_advisories_name ON advisories (ecosystem, name);
"""

_ADVICE = {
    Verdict.HALLUCINATED: (
        "This name does not exist in the registry. A model likely invented it. "
        "Do not install it, and check the intended package name."
    ),
    Verdict.SUSPICIOUS: (
        "This package exists but shows slopsquat signals. Review it carefully "
        "before installing, and confirm it is the package you meant."
    ),
    Verdict.DEPRECATED: (
        "This package is real but deprecated by its maintainer. Do not adopt it "
        "for new work. Find a maintained alternative."
    ),
    Verdict.UNKNOWN: (
        "This package could not be verified. Retry, or check it manually before "
        "installing."
    ),
    Verdict.SAFE: "Established package with no slopsquat signals. Safe to install.",
}


def build_advice(assessment: RiskAssessment, mode: str) -> dict:
    """Turn an assessment into the structured answer the agent receives.

    Pure and dependency free so it is unit testable. The caller decides, based
    on mode, whether a blocking verdict is returned as data (advisory) or
    raised as an error (block).
    """
    return {
        "ecosystem": assessment.ecosystem.value,
        "name": assessment.name,
        "verdict": assessment.verdict.value,
        "score": assessment.score,
        "safe_to_install": assessment.verdict is Verdict.SAFE,
        "flagged": assessment.is_flagged(),
        "mode": mode,
        "advice": _ADVICE.get(assessment.verdict, "No advice available."),
        "reasons": list(assessment.reasons),
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AdvisoryLog:
    """Durable record of blocking advisories the hook has issued."""

    def __init__(self, db_path: Path) -> None:
        self._path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def record(self, assessment: RiskAssessment, mode: str) -> bool:
        """Log a flagged advisory. Returns True if one was recorded."""
        if not assessment.is_flagged():
            return False
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute(
                """INSERT INTO advisories
                   (ecosystem, name, verdict, score, mode, reasons, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    assessment.ecosystem.value, assessment.name,
                    assessment.verdict.value, assessment.score, mode,
                    "; ".join(assessment.reasons), _now(),
                ),
            )
            conn.commit()
        return True

    def recent(self, limit: int = 50) -> list[sqlite3.Row]:
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute(
                """SELECT ecosystem, name, verdict, score, mode, reasons, created_at
                   FROM advisories ORDER BY id DESC LIMIT ?""",
                (limit,),
            )
            return cur.fetchall()

    def cross_reference(
        self, installed: set[tuple[str, str]], limit: int = 200
    ) -> list[tuple[sqlite3.Row, bool]]:
        """Pair each recent advisory with whether its package is now installed.

        `installed` is a set of (ecosystem, lowercased name) taken from a
        manifest scan. A True flag means the flagged package appears in the
        manifest, so the advisory was ignored.
        """
        out: list[tuple[sqlite3.Row, bool]] = []
        for row in self.recent(limit):
            key = (row["ecosystem"], row["name"].lower())
            out.append((row, key in installed))
        return out