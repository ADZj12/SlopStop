"""The checker ties the pieces together.

Given an ecosystem and a name it validates the name, looks up registry facts,
scores them against the slopsquat signature, and optionally records the result
in the corpus. It is the single entry point the CLI and the future agent hook
both call, so the safety logic has exactly one home.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Optional

from . import signature
from .corpus import Corpus
from .models import Ecosystem, RiskAssessment, Verdict
from .names import InvalidPackageName
from .registries import RegistryClient


def load_popular(data_file: Path) -> list[str]:
    """Load the shipped list of popular package names used for conflation.

    This file is curated and safe to commit. It is not user data.
    """
    if not data_file.exists():
        return []
    try:
        payload = json.loads(data_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    names: list[str] = []
    for eco in ("npm", "pypi"):
        names.extend(payload.get(eco, []))
    return names


class Checker:
    def __init__(
        self,
        client: RegistryClient,
        popular: Iterable[str] = (),
        corpus: Optional[Corpus] = None,
    ) -> None:
        self._client = client
        self._popular = list(popular)
        self._corpus = corpus

    def check(
        self,
        ecosystem: Ecosystem,
        name: str,
        record: bool = True,
        source: str = "manual",
    ) -> RiskAssessment:
        try:
            facts = self._client.lookup(ecosystem, name)
        except InvalidPackageName as exc:
            # An unparseable name is itself a red flag: real packages have
            # legal names. We surface it as suspicious rather than crashing.
            return RiskAssessment(
                ecosystem=ecosystem,
                name=name,
                verdict=Verdict.SUSPICIOUS,
                score=70,
                reasons=[f"name failed validation: {exc}"],
                facts=None,
            )

        assessment = signature.assess(facts, self._popular)

        if record and self._corpus is not None:
            self._corpus.record(assessment, source=source)

        return assessment
