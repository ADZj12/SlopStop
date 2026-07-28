from slopstop.calibration import Case, CaseResult, compute_metrics
from slopstop.models import Ecosystem, Verdict


def _result(label, blocked, resolved=True, verdict=Verdict.SAFE):
    case = Case(ecosystem=Ecosystem.NPM, name="x", label=label)
    return CaseResult(case=case, verdict=verdict, blocked=blocked, resolved=resolved)


def test_perfect_classification():
    results = [
        _result("bad", True),
        _result("bad", True),
        _result("good", False),
        _result("good", False),
    ]
    m = compute_metrics(results)
    assert m.recall == 1.0
    assert m.false_positive_rate == 0.0
    assert m.precision == 1.0
    assert m.gate_met(0.05, 0.90)


def test_false_positive_counts_and_fails_gate():
    results = [
        _result("bad", True),
        _result("good", True),   # false alarm
        _result("good", False),
    ]
    m = compute_metrics(results)
    assert m.false_positive == 1
    assert m.false_positive_rate == 0.5
    assert not m.gate_met(0.05, 0.90)
    assert len(m.misclassified) == 1


def test_missed_bad_lowers_recall():
    results = [
        _result("bad", True),
        _result("bad", False),   # missed
    ]
    m = compute_metrics(results)
    assert m.recall == 0.5
    assert m.false_negative == 1


def test_unresolved_excluded_from_rates():
    results = [
        _result("bad", True),
        _result("good", False, resolved=False),  # lookup failed
    ]
    m = compute_metrics(results)
    assert m.unresolved == 1
    assert m.true_negative == 0
    assert m.recall == 1.0
