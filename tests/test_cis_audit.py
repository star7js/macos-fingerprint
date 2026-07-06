"""Tests for the CIS audit checks and scoring.

A fake runner maps each check's command to canned output, so the whole audit is
exercised without touching macOS. ``run_command`` returns ``None`` when a probe
is unavailable, so the tests use ``None`` for that case.
"""

from macos_fingerprint.audit import cis as ca


def _runner_from(mapping, default=None):
    """Build a runner that returns canned output keyed by the command tuple,
    falling back to ``default`` (None = unavailable)."""

    def runner(command, timeout=15):
        return mapping.get(tuple(command), default)

    return runner


def test_filevault_predicate():
    assert ca._filevault_on("FileVault is On.") is True
    assert ca._filevault_on("FileVault is Off.") is False


def test_equals_predicate():
    pred = ca._equals("1", "2")
    assert pred("1") is True
    assert pred(" 2 ") is True
    assert pred("0") is False


def test_automatic_login_disabled_predicate():
    assert ca._automatic_login_disabled("") is True
    assert ca._automatic_login_disabled("alice") is False


def test_absent_predicate():
    pred = ca._absent("com.apple.smbd")
    assert pred("com.apple.other\ncom.apple.foo") is True
    assert pred("123\tcom.apple.smbd") is False


def test_int_in_predicate():
    pred = ca._int_in(1, 1200)
    assert pred("600") is True
    assert pred("1200") is True
    assert pred("0") is False  # 0 = "never", non-compliant
    assert pred("3600") is False
    assert pred("not-a-number") is None  # indeterminate, not a failure


def test_expanded_check_set_size():
    # The batch of §2.4 Sharing + §6 app checks roughly doubled the set.
    assert len(ca.CHECKS) >= 20


def test_check_evaluate_pass_fail_unknown():
    check = ca.Check(
        cis_id="X",
        title="t",
        level=1,
        remediation="do the thing",
        command=["dummy"],
        predicate=ca._equals("1"),
    )
    assert check.evaluate(runner=lambda c, timeout=15: "1")["status"] == ca.PASS
    failed = check.evaluate(runner=lambda c, timeout=15: "0")
    assert failed["status"] == ca.FAIL
    assert failed["remediation"] == "do the thing"  # surfaced on failure
    unknown = check.evaluate(runner=lambda c, timeout=15: None)
    assert unknown["status"] == ca.UNKNOWN


def test_run_audit_scoring_excludes_unknown():
    checks = [
        ca.Check("A", "a", 1, "fix", ["a"], ca._equals("1")),
        ca.Check("B", "b", 1, "fix", ["b"], ca._equals("1")),
        ca.Check("C", "c", 1, "fix", ["c"], ca._equals("1")),
    ]
    runner = _runner_from({("a",): "1", ("b",): "0", ("c",): None})
    report = ca.run_audit(checks=checks, runner=runner)
    s = report["summary"]
    assert (s["passed"], s["failed"], s["unknown"]) == (1, 1, 1)
    # 1 pass / (1 pass + 1 fail) -> 50%, unknown excluded from denominator.
    assert s["compliance_score"] == 50
    assert s["grade"] == "F"


def test_run_audit_all_unknown_scores_na():
    checks = [ca.Check("A", "a", 1, "fix", ["a"], ca._equals("1"))]
    report = ca.run_audit(checks=checks, runner=lambda c, timeout=15: None)
    assert report["summary"]["compliance_score"] is None
    assert report["summary"]["grade"] == "N/A"


def test_level_filter():
    checks = [
        ca.Check("A", "a", 1, "fix", ["a"], ca._equals("1")),
        ca.Check("B", "b", 2, "fix", ["b"], ca._equals("1")),
    ]
    runner = _runner_from({("a",): "1", ("b",): "1"})
    report = ca.run_audit(checks=checks, level=1, runner=runner)
    assert report["summary"]["total"] == 1


def test_grade_boundaries():
    assert ca._grade(90) == "A"
    assert ca._grade(89) == "B"
    assert ca._grade(59) == "F"
    assert ca._grade(None) == "N/A"


def test_format_report_is_readable():
    checks = [
        ca.Check(
            "2.5.1",
            "Enable FileVault",
            1,
            "sudo fdesetup enable",
            ["fv"],
            ca._filevault_on,
        ),
    ]
    report = ca.run_audit(
        checks=checks, runner=lambda c, timeout=15: "FileVault is Off."
    )
    text = ca.format_report(report)
    assert "CIS Benchmark" in text
    assert "FAIL" in text
    assert "sudo fdesetup enable" in text  # remediation shown for failures


def test_bundled_checks_all_evaluate_without_macos():
    # Every real check must degrade to 'unknown' (not crash) off-macOS.
    report = ca.run_audit(runner=lambda c, timeout=15: None)
    assert report["summary"]["total"] == len(ca.CHECKS)
    assert report["summary"]["unknown"] == len(ca.CHECKS)
