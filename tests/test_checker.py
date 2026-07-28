from pathlib import Path

from slopstop.checker import Checker
from slopstop.corpus import Corpus
from slopstop.models import Ecosystem, Existence, PackageFacts, Verdict


class FakeClient:
    """A registry client stand in driven by a scripted facts map.

    Keyed by (ecosystem, name) so a test can flip a name from absent to
    present between calls, which is exactly the Loop 1 scenario.
    """

    def __init__(self, facts_map):
        self._facts = facts_map

    def lookup(self, ecosystem, name):
        key = (ecosystem, name)
        if key in self._facts:
            return self._facts[key]
        return PackageFacts(
            ecosystem=ecosystem, name=name, existence=Existence.ABSENT
        )


def test_check_hallucinated_records_new(tmp_path: Path):
    corpus = Corpus(tmp_path / "c.db")
    client = FakeClient({})  # everything absent
    checker = Checker(client, popular=[], corpus=corpus)

    result = checker.check(Ecosystem.PYPI, "nonexistent-xyz")
    assert result.verdict is Verdict.HALLUCINATED
    assert corpus.count() == 1


def test_flip_is_detected_when_absent_name_appears(tmp_path: Path):
    db = tmp_path / "c.db"
    corpus = Corpus(db)

    # First pass: the name is absent, gets recorded as absent.
    absent_client = FakeClient({})
    Checker(absent_client, corpus=corpus).check(Ecosystem.NPM, "slop-target")

    # Second pass: an attacker has now registered it. Same name, now present.
    present_facts = PackageFacts(
        ecosystem=Ecosystem.NPM,
        name="slop-target",
        existence=Existence.PRESENT,
        age_days=1,
        release_count=1,
    )
    present_client = FakeClient({(Ecosystem.NPM, "slop-target"): present_facts})
    assessment = Checker(present_client, corpus=corpus).check(
        Ecosystem.NPM, "slop-target"
    )

    # The corpus should have logged a flip event.
    flips = corpus.recent_flips()
    assert len(flips) == 1
    assert flips[0]["name"] == "slop-target"
    assert assessment.facts.existence is Existence.PRESENT


def test_absent_names_working_set(tmp_path: Path):
    corpus = Corpus(tmp_path / "c.db")
    client = FakeClient({})
    checker = Checker(client, corpus=corpus)
    checker.check(Ecosystem.PYPI, "ghost-a")
    checker.check(Ecosystem.PYPI, "ghost-b")

    names = sorted(name for _, name in corpus.absent_names())
    assert names == ["ghost-a", "ghost-b"]
