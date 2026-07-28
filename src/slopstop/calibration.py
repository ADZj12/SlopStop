"""Calibration.

The scorer is only trustworthy once its error rate is measured, not guessed.
This module runs the checker over a labeled set of known good and known bad
package names and reports the numbers that decide whether the Stage 1 gate is
met: the false positive rate on real packages and the recall on bad ones.

Two halves, deliberately separated:

  * compute_metrics is pure arithmetic over already scored cases, so the math
    is unit tested with no network.
  * run_calibration performs the live lookups.

A verdict maps to a binary action: block (hallucinated or suspicious) or allow
(safe or unknown). A lookup that could not resolve is reported on its own and
excluded from the rates, because an unreachable registry is a reliability
problem, not a scoring error.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .models import Ecosystem, RiskAssessment, Verdict


@dataclass
class Case:
    ecosystem: Ecosystem
    name: str
    label: str  # "good" (should allow) or "bad" (should block)


@dataclass
class CaseResult:
    case: Case
    verdict: Verdict
    blocked: bool
    resolved: bool  # False when the registry lookup did not resolve


@dataclass
class Metrics:
    true_positive: int = 0   # bad and blocked
    false_negative: int = 0  # bad and allowed (a miss)
    true_negative: int = 0   # good and allowed
    false_positive: int = 0  # good and blocked (a false alarm)
    unresolved: int = 0
    misclassified: list[CaseResult] = field(default_factory=list)

    @property
    def recall(self) -> float:
        denom = self.true_positive + self.false_negative
        return self.true_positive / denom if denom else 0.0

    @property
    def precision(self) -> float:
        denom = self.true_positive + self.false_positive
        return self.true_positive / denom if denom else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.false_positive + self.true_negative
        return self.false_positive / denom if denom else 0.0

    def gate_met(self, max_fpr: float, min_recall: float) -> bool:
        return (
            self.false_positive_rate <= max_fpr
            and self.recall >= min_recall
        )


def compute_metrics(results: Iterable[CaseResult]) -> Metrics:
    m = Metrics()
    for r in results:
        if not r.resolved:
            m.unresolved += 1
            continue
        if r.case.label == "bad":
            if r.blocked:
                m.true_positive += 1
            else:
                m.false_negative += 1
                m.misclassified.append(r)
        elif r.case.label == "good":
            if r.blocked:
                m.false_positive += 1
                m.misclassified.append(r)
            else:
                m.true_negative += 1
    return m


def _is_resolved(assessment: RiskAssessment) -> bool:
    if assessment.facts is None:
        return False
    return assessment.facts.existence.value != "unknown"


def load_cases(path: Path) -> list[Case]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    cases: list[Case] = []
    for raw in payload.get("cases", []):
        cases.append(
            Case(
                ecosystem=Ecosystem(raw["ecosystem"]),
                name=raw["name"],
                label=raw["label"],
            )
        )
    return cases


def run_calibration(checker, cases: Iterable[Case]) -> tuple[Metrics, list[CaseResult]]:
    """Score every case against the checker and return metrics and details.

    The corpus is not written during calibration so the labeled set does not
    pollute the local state used by the live monitor.
    """
    results: list[CaseResult] = []
    for case in cases:
        assessment = checker.check(
            case.ecosystem, case.name, record=False, source="calibration"
        )
        results.append(
            CaseResult(
                case=case,
                verdict=assessment.verdict,
                blocked=assessment.is_blocking(),
                resolved=_is_resolved(assessment),
            )
        )
    return compute_metrics(results), results
