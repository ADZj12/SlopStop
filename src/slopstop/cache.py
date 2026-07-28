"""In memory verdict cache.

The agent hook vets a package every time a model suggests one, and models
suggest the same popular packages constantly. Re looking up react on every
suggestion is wasteful and slow, so verdicts are cached with a time to live.

The time to live depends on the verdict, which is the important design point:

  * a SAFE verdict for an established package is stable, so it caches for hours
  * a HALLUCINATED or SUSPICIOUS verdict caches only briefly, because the whole
    threat is a name that gets registered between checks, and a stale block or
    a stale allow on such a name is exactly what we must not serve
  * an UNKNOWN verdict caches for a very short time, since it usually means a
    transient failure worth retrying soon

The cache is in memory and per process, which suits a long running server. It
is deliberately not persisted: the durable record is the corpus, and a cache
that outlived the process could serve a stale block after a name changed.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Optional

from .models import Ecosystem, RiskAssessment, Verdict

# Seconds each verdict stays fresh.
_DEFAULT_TTL: dict[Verdict, float] = {
    Verdict.SAFE: 6 * 60 * 60.0,     # 6 hours
    Verdict.DEPRECATED: 6 * 60 * 60.0,  # 6 hours: deprecation is stable
    Verdict.HALLUCINATED: 15 * 60.0,  # 15 minutes
    Verdict.SUSPICIOUS: 15 * 60.0,    # 15 minutes
    Verdict.UNKNOWN: 2 * 60.0,        # 2 minutes
}
_FALLBACK_TTL = 5 * 60.0


@dataclass
class _Entry:
    assessment: RiskAssessment
    expires_at: float


class VerdictCache:
    """A small time to live cache keyed by ecosystem and name.

    The clock is injectable so tests can advance time without sleeping.
    """

    def __init__(
        self,
        ttl_by_verdict: Optional[dict[Verdict, float]] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = dict(_DEFAULT_TTL)
        if ttl_by_verdict:
            self._ttl.update(ttl_by_verdict)
        self._clock = clock
        self._store: dict[tuple[str, str], _Entry] = {}

    def get(self, ecosystem: Ecosystem, name: str) -> Optional[RiskAssessment]:
        key = (ecosystem.value, name)
        entry = self._store.get(key)
        if entry is None:
            return None
        if self._clock() >= entry.expires_at:
            del self._store[key]
            return None
        return entry.assessment

    def put(self, ecosystem: Ecosystem, name: str, assessment: RiskAssessment) -> None:
        ttl = self._ttl.get(assessment.verdict, _FALLBACK_TTL)
        key = (ecosystem.value, name)
        self._store[key] = _Entry(assessment, self._clock() + ttl)

    def clear(self) -> None:
        self._store.clear()

    def __len__(self) -> int:
        return len(self._store)