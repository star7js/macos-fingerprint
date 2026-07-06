"""Tests for the HTML scorecard renderer."""

from macos_fingerprint.audit import cis as ca
from macos_fingerprint.audit import html_report


def test_render_contains_score_and_rows():
    checks = [
        ca.Check(
            "2.5.1",
            "Enable FileVault",
            1,
            "sudo fdesetup enable",
            ["fv"],
            ca._filevault_on,
        ),
        ca.Check("2.2.1", "Enable firewall", 1, "sudo ...", ["fw"], ca._equals("1")),
    ]

    def runner(c, timeout=15):
        return {("fv",): "FileVault is On.", ("fw",): "0"}[tuple(c)]

    report = ca.run_audit(checks=checks, runner=runner)
    out = html_report.render_html(report)
    assert out.startswith("<!doctype html>")
    assert "Enable FileVault" in out
    assert "Enable firewall" in out
    assert "PASS" in out and "FAIL" in out
    # Grade shown; 1 of 2 passed -> 50% -> F
    assert ">F<" in out


def test_failure_remediation_is_rendered_and_escaped():
    checks = [
        ca.Check("X", "Do <a> thing", 1, "run <cmd> & fix", ["x"], ca._equals("1")),
    ]
    report = ca.run_audit(checks=checks, runner=lambda c, timeout=15: "0")
    out = html_report.render_html(report)
    assert "run &lt;cmd&gt; &amp; fix" in out  # HTML-escaped remediation
    assert "Do &lt;a&gt; thing" in out


def test_unknown_status_renders_na():
    checks = [ca.Check("X", "t", 1, "fix", ["x"], ca._equals("1"))]
    report = ca.run_audit(checks=checks, runner=lambda c, timeout=15: None)
    out = html_report.render_html(report)
    assert "N/A" in out
