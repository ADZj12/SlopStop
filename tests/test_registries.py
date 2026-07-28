import urllib.error

from slopstop.models import Ecosystem
from slopstop.registries import RegistryClient


class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, n: int = -1):
        return self._body


class _FlakyOpener:
    """Fails the first `fail_times` opens, then succeeds."""

    def __init__(self, fail_times: int, body: bytes):
        self.calls = 0
        self.fail_times = fail_times
        self.body = body

    def open(self, request, timeout=None):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise urllib.error.URLError("transient boom")
        return _FakeResponse(self.body)


_VALID_PYPI = b'{"info": {"summary": "x"}, "releases": {"1.0": []}}'


def test_retry_recovers_from_transient_failure():
    client = RegistryClient("test", timeout=1, retries=2, backoff=0.0)
    client._opener = _FlakyOpener(fail_times=2, body=_VALID_PYPI)
    facts = client.lookup(Ecosystem.PYPI, "requests")
    assert facts.existence.value == "present"
    assert client._opener.calls == 3  # one initial attempt plus two retries


def test_gives_up_and_reports_unknown_after_retries():
    client = RegistryClient("test", timeout=1, retries=1, backoff=0.0)
    client._opener = _FlakyOpener(fail_times=5, body=_VALID_PYPI)
    facts = client.lookup(Ecosystem.PYPI, "requests")
    # The lookup wrapper catches the final failure and reports unknown rather
    # than crashing, which calibration counts as unresolved, not a miss.
    assert facts.existence.value == "unknown"
    assert client._opener.calls == 2  # one initial attempt plus one retry
