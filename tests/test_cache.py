from slopstop.cache import VerdictCache
from slopstop.models import Ecosystem, RiskAssessment, Verdict


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def _assessment(verdict=Verdict.SAFE):
    return RiskAssessment(
        ecosystem=Ecosystem.PYPI, name="requests", verdict=verdict, score=0
    )


def test_miss_then_hit():
    cache = VerdictCache(clock=FakeClock())
    assert cache.get(Ecosystem.PYPI, "requests") is None
    cache.put(Ecosystem.PYPI, "requests", _assessment())
    hit = cache.get(Ecosystem.PYPI, "requests")
    assert hit is not None
    assert hit.verdict is Verdict.SAFE


def test_entry_expires_after_ttl():
    clock = FakeClock()
    cache = VerdictCache(clock=clock)
    cache.put(Ecosystem.PYPI, "requests", _assessment(Verdict.SAFE))
    clock.advance(6 * 60 * 60 - 1)
    assert cache.get(Ecosystem.PYPI, "requests") is not None
    clock.advance(2)
    assert cache.get(Ecosystem.PYPI, "requests") is None


def test_dangerous_verdicts_expire_sooner_than_safe():
    clock = FakeClock()
    cache = VerdictCache(clock=clock)
    cache.put(Ecosystem.NPM, "safe-pkg", _assessment(Verdict.SAFE))
    cache.put(Ecosystem.NPM, "bad-pkg", _assessment(Verdict.HALLUCINATED))
    clock.advance(20 * 60)  # 20 minutes
    # the hallucinated verdict (15 min ttl) is gone, the safe one remains
    assert cache.get(Ecosystem.NPM, "bad-pkg") is None
    assert cache.get(Ecosystem.NPM, "safe-pkg") is not None


def test_clear_empties_the_cache():
    cache = VerdictCache(clock=FakeClock())
    cache.put(Ecosystem.PYPI, "requests", _assessment())
    assert len(cache) == 1
    cache.clear()
    assert len(cache) == 0
