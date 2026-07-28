"""Local corpus persistence.

The corpus records every name we have checked, its last known existence, and
an audit trail of events. It is the memory that powers Loop 1: names that were
absent yesterday and are present today are flips, and a flip on a name a model
hallucinates is a slopsquat being planted.

The database file lives under the local data directory and is git ignored. It
can contain names pulled from a developer workspace, so it is treated as
private state and must never be committed.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from .models import Ecosystem, Existence, RiskAssessment

_SCHEMA = """
CREATE TABLE IF NOT EXISTS packages (
    ecosystem      TEXT NOT NULL,
    name           TEXT NOT NULL,
    existence      TEXT NOT NULL,
    verdict        TEXT NOT NULL,
    score          INTEGER NOT NULL,
    first_seen     TEXT NOT NULL,
    last_checked   TEXT NOT NULL,
    source         TEXT NOT NULL DEFAULT 'manual',
    PRIMARY KEY (ecosystem, name)
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem   TEXT NOT NULL,
    name        TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_packages_existence
    ON packages (existence);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Corpus:
    """A thin, safe wrapper over SQLite. All writes are parameterized."""

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

    def record(self, assessment: RiskAssessment, source: str = "manual") -> str:
        """Upsert a checked package and log any change of existence.

        Returns the event type recorded: 'new', 'flip', or 'update'. A 'flip'
        is the high value signal: a name that was absent is now present.
        """
        eco = assessment.ecosystem.value
        name = assessment.name
        new_existence = (
            assessment.facts.existence.value
            if assessment.facts
            else Existence.UNKNOWN.value
        )
        now = _now()

        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute(
                "SELECT existence FROM packages WHERE ecosystem = ? AND name = ?",
                (eco, name),
            )
            row = cur.fetchone()

            if row is None:
                event_type = "new"
                cur.execute(
                    """INSERT INTO packages
                       (ecosystem, name, existence, verdict, score,
                        first_seen, last_checked, source)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        eco, name, new_existence, assessment.verdict.value,
                        assessment.score, now, now, source,
                    ),
                )
            else:
                prior = row["existence"]
                if prior == Existence.ABSENT.value and new_existence == Existence.PRESENT.value:
                    event_type = "flip"
                else:
                    event_type = "update"
                cur.execute(
                    """UPDATE packages
                       SET existence = ?, verdict = ?, score = ?, last_checked = ?
                       WHERE ecosystem = ? AND name = ?""",
                    (
                        new_existence, assessment.verdict.value,
                        assessment.score, now, eco, name,
                    ),
                )

            cur.execute(
                """INSERT INTO events (ecosystem, name, event_type, detail, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (eco, name, event_type, "; ".join(assessment.reasons), now),
            )
            conn.commit()

        return event_type

    def absent_names(self, ecosystem: Optional[Ecosystem] = None) -> Iterator[tuple[str, str]]:
        """Yield (ecosystem, name) for every name currently recorded absent.

        This is the working set for the Loop 1 flip monitor.
        """
        query = "SELECT ecosystem, name FROM packages WHERE existence = ?"
        params: list[str] = [Existence.ABSENT.value]
        if ecosystem is not None:
            query += " AND ecosystem = ?"
            params.append(ecosystem.value)
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute(query, params)
            for row in cur.fetchall():
                yield row["ecosystem"], row["name"]

    def recent_flips(self, limit: int = 50) -> list[sqlite3.Row]:
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute(
                """SELECT ecosystem, name, detail, created_at FROM events
                   WHERE event_type = 'flip'
                   ORDER BY id DESC LIMIT ?""",
                (limit,),
            )
            return cur.fetchall()

    def count(self) -> int:
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute("SELECT COUNT(*) AS n FROM packages")
            return cur.fetchone()["n"]
