from slopstop.models import Ecosystem, Existence, PackageFacts, Verdict
from slopstop.signature import assess

POPULAR = ["jscodeshift", "react-codemod", "requests", "huggingface-hub"]


def _facts(**kw):
    base = dict(
        ecosystem=Ecosystem.NPM,
        name="x",
        existence=Existence.PRESENT,
    )
    base.update(kw)
    return PackageFacts(**base)


def test_absent_name_is_hallucinated():
    facts = _facts(name="totally-made-up-pkg", existence=Existence.ABSENT)
    result = assess(facts, POPULAR)
    assert result.verdict is Verdict.HALLUCINATED
    assert result.is_blocking()
    assert result.score >= 90


def test_unknown_lookup_is_not_treated_as_safe():
    facts = _facts(existence=Existence.UNKNOWN, lookup_error="timeout")
    result = assess(facts, POPULAR)
    assert result.verdict is Verdict.UNKNOWN
    assert not result.is_blocking()


def test_established_package_is_safe():
    facts = _facts(
        name="requests",
        age_days=4000,
        release_count=150,
        has_description=True,
        has_repository=True,
    )
    result = assess(facts, POPULAR)
    assert result.verdict is Verdict.SAFE
    assert result.score <= 20


def test_fresh_registration_is_suspicious():
    facts = _facts(
        name="fresh-thing",
        age_days=3,
        release_count=1,
        has_description=False,
        has_repository=False,
    )
    result = assess(facts, POPULAR)
    assert result.verdict is Verdict.SUSPICIOUS
    assert result.is_blocking()


def test_conflation_of_two_popular_names_is_flagged():
    facts = _facts(
        name="react-codeshift",
        age_days=90,
        release_count=2,
        has_description=True,
        has_repository=True,
    )
    result = assess(facts, POPULAR)
    assert any("fuses tokens" in r for r in result.reasons)
    assert result.score >= 35


def test_established_convention_name_is_not_flagged():
    popular = ["react", "react-dom", "react-router", "react-codemod"]
    facts = _facts(
        name="react-router-dom",
        age_days=2500,
        release_count=40,
        has_description=True,
        has_repository=True,
    )
    result = assess(facts, popular)
    assert result.verdict is Verdict.SAFE
    assert not any("fuses tokens" in r for r in result.reasons)