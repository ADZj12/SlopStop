"""Runtime configuration.

All configuration comes from environment variables with safe defaults.
No secret ever lives in source. The two privacy sensitive defaults are:

  * telemetry is OFF unless explicitly enabled
  * local state lives outside the repo, under the user home directory

so that nothing collected on a developer machine can leak into git.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _get_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    """Immutable settings resolved once at startup."""

    data_dir: Path
    telemetry_enabled: bool
    http_timeout: int
    user_agent: str

    @property
    def db_path(self) -> Path:
        return self.data_dir / "corpus_local" / "slopstop.db"


def load_settings() -> Settings:
    """Resolve settings from the environment.

    The data directory is created if missing so the local corpus has a
    home. That directory sits outside the working tree and is git ignored.
    """
    raw_dir = os.environ.get("SLOPSTOP_DATA_DIR", "").strip()
    if raw_dir:
        data_dir = Path(raw_dir).expanduser().resolve()
    else:
        data_dir = Path.home() / ".slopstop"

    (data_dir / "corpus_local").mkdir(parents=True, exist_ok=True)

    return Settings(
        data_dir=data_dir,
        telemetry_enabled=_get_bool("SLOPSTOP_TELEMETRY", False),
        http_timeout=_get_int("SLOPSTOP_HTTP_TIMEOUT", 8),
        user_agent="slopstop/0.1 (supply chain safety checker)",
    )
