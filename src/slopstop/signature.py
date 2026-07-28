"""Slopsquat signature scoring.

This is the policy layer. Given raw PackageFacts and a set of known popular
package names, it produces a RiskAssessment. Keeping this separate from the
registry client means the policy is deterministic and fully unit testable
without any network access.

The signals, in order of strength:

  1. The name does not exist at all. This is a pure hallucination. An agent
     that was told to install it would either fail today or install whatever
     an attacker registers under that name tomorrow. Highest risk.

  2. The name exists but was registered very recently. A brand new package
     that a model already hallucinates is the classic planted slopsquat.

  3. The name is a plausible fusion of two established packages (for example
     a model conflating two real tools into one that never shipped). We detect
     this with token overlap against the popular set.

  4. Weak project signals: a single release, no description, no repository.
     Individually harmless, but together they describe a hollow package.

Missing data is treated conservatively. Absence of a signal is never read as
proof of safety.
"""

from __future__ import annotations

from typing import Iterable

from .models import Existence, PackageFacts, RiskAssessment, Verdict

# Thresholds. Kept as named constants so they can be tuned and tested.
_RECENT_DAYS = 60.0
_VERY_RECENT_DAYS = 14.0
_SUSPICIOUS_SCORE = 45
_SAFE_MAX_SCORE = 20


def _tokens(name: str) -> set[str]:
    """Split a package name into comparable word tokens."""
    cleaned = name.replace("@", " ").replace("/", " ")
    for sep in ("-", "_", "."):
        cleaned = cleaned.replace(sep, " ")
    return {tok for tok in cleaned.lower().split() if len(tok) >= 3}


_MIN_OVERLAP = 4


def _overlaps(candidate_tokens: set[str], pop: str) -> bool:
    """True when a candidate token overlaps a popular name by a real segment.

    We accept a whole token match or a substring match of at least
    _MIN_OVERLAP characters in either direction. The substring case is what
    catches a fusion like codeshift borrowed from jscodeshift, where the
    shared segment is not a standalone token in the popular name.
    """
    pop_tokens = _tokens(pop)
    pop_flat = pop.lower()
    for tok in candidate_tokens:
        if tok in pop_tokens:
            return True
        if len(tok) >= _MIN_OVERLAP and tok in pop_flat:
            return True
        for ptok in pop_tokens:
            if len(ptok) >= _MIN_OVERLAP and ptok in tok:
                return True
    return False


def _conflation_match(name: str, popular: Iterable[str]) -> tuple[bool, list[str]]:
    """Detect a name that fuses segments from two distinct popular packages.

    A slopsquat conflation borrows a segment from one real package and a
    segment from another. If a candidate overlaps two or more different popular
    names, and is not itself one of them, that is the fusion signature.
    """
    popular = list(popular)
    if name in popular:
        return False, []  # it is itself a known package, not a fusion

    candidate_tokens = _tokens(name)
    if len(candidate_tokens) < 2:
        return False, []

    contributors = [pop for pop in popular if _overlaps(candidate_tokens, pop)]
    distinct = sorted(set(contributors))
    return (len(distinct) >= 2), distinct[:4]


def assess(
    facts: PackageFacts,
    popular: Iterable[str] = (),
) -> RiskAssessment:
    popular = list(popular)
    reasons: list[str] = []

    # Signal 1: does not exist.
    if facts.existence is Existence.ABSENT:
        reasons.append(
            "name does not exist in the registry, which is the direct "
            "hallucination signature"
        )
        return RiskAssessment(
            ecosystem=facts.ecosystem,
            name=facts.name,
            verdict=Verdict.HALLUCINATED,
            score=95,
            reasons=reasons,
            facts=facts,
        )

    # Lookup failed. Do not guess safe.
    if facts.existence is Existence.UNKNOWN:
        detail = facts.lookup_error or "unknown lookup failure"
        reasons.append(f"could not verify against the registry: {detail}")
        return RiskAssessment(
            ecosystem=facts.ecosystem,
            name=facts.name,
            verdict=Verdict.UNKNOWN,
            score=50,
            reasons=reasons,
            facts=facts,
        )

    # It exists. Accumulate slopsquat signals.
    score = 0

    # An established package (old enough, many releases, with a source repo)
    # is not a slopsquat even when its name fuses ecosystem tokens, because a
    # real conflation attack is fresh and hollow. So we decide establishment
    # first and let it suppress the conflation signal.
    established = (
        (facts.age_days is None or facts.age_days > _RECENT_DAYS)
        and (facts.release_count is None or facts.release_count > 3)
        and bool(facts.has_repository)
    )

    if facts.age_days is not None:
        if facts.age_days <= _VERY_RECENT_DAYS:
            score += 45
            reasons.append(
                f"registered only {facts.age_days:.0f} days ago, a fresh "
                "registration is the planted slopsquat pattern"
            )
        elif facts.age_days <= _RECENT_DAYS:
            score += 25
            reasons.append(
                f"registered {facts.age_days:.0f} days ago, still recent"
            )

    if not established:
        fused, contributors = _conflation_match(facts.name, popular)
        if fused:
            score += 35
            joined = " and ".join(contributors)
            reasons.append(
                f"name fuses tokens from established packages ({joined}), the "
                "conflation pattern models produce"
            )

        if facts.release_count is not None and facts.release_count <= 1:
            score += 10
            reasons.append("only a single release exists")

        if facts.has_description is False:
            score += 5
            reasons.append("no description")

        if facts.has_repository is False:
            score += 5
            reasons.append("no linked source repository")

    score = min(score, 90)

    if score >= _SUSPICIOUS_SCORE:
        verdict = Verdict.SUSPICIOUS
    elif score <= _SAFE_MAX_SCORE:
        verdict = Verdict.SAFE
        if not reasons:
            reasons.append("established package with no slopsquat signals")
    else:
        verdict = Verdict.UNKNOWN
        reasons.append("mixed signals, review before installing")

    return RiskAssessment(
        ecosystem=facts.ecosystem,
        name=facts.name,
        verdict=verdict,
        score=score,
        reasons=reasons,
        facts=facts,
    )
