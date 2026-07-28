"""Typed domain models shared across the checker, corpus, and monitor."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Ecosystem(str, Enum):
    NPM = "npm"
    PYPI = "pypi"


class Existence(str, Enum):
    """Whether a name resolves in its registry right now."""

    PRESENT = "present"
    ABSENT = "absent"
    UNKNOWN = "unknown"  # lookup failed, not a safety signal on its own


class Verdict(str, Enum):
    """The label a developer or an agent acts on."""

    SAFE = "safe"            # exists, established, no slopsquat signal
    UNKNOWN = "unknown"      # could not determine, treat with caution
    SUSPICIOUS = "suspicious"  # exists but carries slopsquat signature
    HALLUCINATED = "hallucinated"  # does not exist at all
    DEPRECATED = "deprecated"  # exists and is not a slopsquat, but abandoned


@dataclass
class PackageFacts:
    """Raw facts pulled from a registry for one package.

    Every field is optional because registries differ in what they expose
    and because a lookup can partially fail. The scorer treats missing data
    conservatively rather than assuming safety.
    """

    ecosystem: Ecosystem
    name: str
    existence: Existence
    first_release_iso: Optional[str] = None
    latest_release_iso: Optional[str] = None
    release_count: Optional[int] = None
    has_description: Optional[bool] = None
    has_repository: Optional[bool] = None
    age_days: Optional[float] = None
    deprecated: Optional[bool] = None
    deprecated_reason: Optional[str] = None
    lookup_error: Optional[str] = None


@dataclass
class RiskAssessment:
    """The scored result the rest of the system consumes."""

    ecosystem: Ecosystem
    name: str
    verdict: Verdict
    score: int  # 0 (clearly safe) to 100 (clearly dangerous)
    reasons: list[str] = field(default_factory=list)
    facts: Optional[PackageFacts] = None

    def is_blocking(self) -> bool:
        """True for a security concern that block mode should hard stop.

        Deprecation is deliberately not here: an abandoned package is a quality
        problem, not a security threat, so it is advised against but never hard
        blocked.
        """
        return self.verdict in {Verdict.HALLUCINATED, Verdict.SUSPICIOUS}

    def is_flagged(self) -> bool:
        """True for anything a developer should not install as is.

        This is the set the advisory log records and that the advice marks as
        flagged: the security concerns plus deprecation.
        """
        return self.verdict in {
            Verdict.HALLUCINATED, Verdict.SUSPICIOUS, Verdict.DEPRECATED,
        }