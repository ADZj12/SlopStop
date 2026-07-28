from slopstop.advisories import AdvisoryLog, build_advice
from slopstop.models import Ecosystem, RiskAssessment, Verdict


def _assessment(verdict, name="ghost", score=95):
    return RiskAssessment(
        ecosystem=Ecosystem.NPM, name=name, verdict=verdict, score=score,
        reasons=["name does not exist in the registry"],
    )


def test_build_advice_marks_hallucinated_unsafe():
    advice = build_advice(_assessment(Verdict.HALLUCINATED), "advisory")
    assert advice["flagged"] is True
    assert advice["safe_to_install"] is False
    assert "do not install" in advice["advice"].lower()
    assert advice["mode"] == "advisory"


def test_build_advice_marks_safe():
    advice = build_advice(_assessment(Verdict.SAFE, name="react", score=0), "advisory")
    assert advice["flagged"] is False
    assert advice["safe_to_install"] is True


def test_only_blocking_verdicts_are_logged(tmp_path):
    log = AdvisoryLog(tmp_path / "adv.db")
    assert log.record(_assessment(Verdict.SAFE, name="react", score=0), "advisory") is False
    assert log.record(_assessment(Verdict.HALLUCINATED), "advisory") is True
    assert len(log.recent()) == 1


def test_cross_reference_flags_ignored(tmp_path):
    log = AdvisoryLog(tmp_path / "adv.db")
    log.record(_assessment(Verdict.HALLUCINATED, name="ghost-pkg"), "advisory")
    log.record(_assessment(Verdict.SUSPICIOUS, name="clean-pkg"), "advisory")

    # ghost-pkg is present in the manifest, clean-pkg is not
    installed = {("npm", "ghost-pkg")}
    pairs = log.cross_reference(installed)
    result = {row["name"]: was_ignored for row, was_ignored in pairs}
    assert result["ghost-pkg"] is True
    assert result["clean-pkg"] is False
