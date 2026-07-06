"""CIS-style macOS security benchmark checks with a scored, exportable report.

This turns the fingerprint tool from "here's what changed" into "here's how your
Mac scores against a hardening baseline" - compliance reporting for Mac-first
small businesses / MSPs.

Each :class:`Check` is a small, independently testable unit: it names a CIS
control, runs one probe command, and a pure predicate decides pass/fail from the
output. ``run_command`` returns ``None`` when the evidence is unavailable (tool
missing, permission denied, not macOS) so "couldn't tell" is never scored as a
pass or a failure.

The check set here is a pragmatic subset of the CIS Apple macOS Benchmark, not a
certified full implementation; control numbers track the benchmark's structure
but the exact numbering drifts between macOS releases.
"""

from dataclasses import dataclass
from typing import Callable, List, Optional

from ..utils.commands import run_command

PASS = "pass"
FAIL = "fail"
UNKNOWN = "unknown"


@dataclass
class Check:
    """A single benchmark control."""

    cis_id: str
    title: str
    level: int  # CIS profile level: 1 (baseline) or 2 (stricter)
    remediation: str
    command: list
    predicate: Callable[[str], Optional[bool]]
    timeout: int = 15

    def evaluate(self, runner=run_command) -> dict:
        raw = runner(self.command, timeout=self.timeout)
        if raw is None:
            status, verdict = UNKNOWN, None
        else:
            verdict = self.predicate(raw)
            status = UNKNOWN if verdict is None else (PASS if verdict else FAIL)
        return {
            "cis_id": self.cis_id,
            "title": self.title,
            "level": self.level,
            "status": status,
            "evidence": raw,
            "remediation": None if status == PASS else self.remediation,
        }


# --- predicates ------------------------------------------------------------
# Each takes the raw command output and returns True (compliant) / False
# (non-compliant) / None (indeterminate).


def _contains(needle):
    return lambda raw: needle.lower() in raw.lower()


def _equals(*allowed):
    return lambda raw: raw.strip() in allowed


def _filevault_on(raw):
    return "filevault is on" in raw.lower()


def _automatic_login_disabled(raw):
    # `defaults read ... autoLoginUser` errors (-> None, handled upstream) when
    # unset. If it returns a value, auto-login is enabled -> fail.
    return not raw.strip()


def _absent(label):
    """Pass when a launchd service label is NOT present in `launchctl list`."""
    return lambda raw: label not in raw


def _int_in(low, high):
    """Pass when the output parses to an int within [low, high]; None if not an int."""

    def predicate(raw):
        try:
            value = int(raw.strip())
        except ValueError:
            return None
        return low <= value <= high

    return predicate


# --- the benchmark ---------------------------------------------------------

CHECKS = [
    Check(
        cis_id="1.2",
        title="Enable automatic software update checks",
        level=1,
        remediation="System Settings > General > Software Update > enable "
        "'Check for updates'. CLI: sudo defaults write "
        "/Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true",
        command=[
            "defaults",
            "read",
            "/Library/Preferences/com.apple.SoftwareUpdate",
            "AutomaticCheckEnabled",
        ],
        predicate=_equals("1"),
    ),
    Check(
        cis_id="2.2.1",
        title="Enable the application firewall",
        level=1,
        remediation="System Settings > Network > Firewall > On. CLI: sudo "
        "defaults write /Library/Preferences/com.apple.alf globalstate -int 1",
        command=[
            "defaults",
            "read",
            "/Library/Preferences/com.apple.alf",
            "globalstate",
        ],
        predicate=_equals("1", "2"),
    ),
    Check(
        cis_id="2.2.2",
        title="Enable firewall stealth mode",
        level=1,
        remediation="sudo /usr/libexec/ApplicationFirewall/socketfilterfw "
        "--setstealthmode on",
        command=[
            "defaults",
            "read",
            "/Library/Preferences/com.apple.alf",
            "stealthenabled",
        ],
        predicate=_equals("1"),
    ),
    Check(
        cis_id="2.3.1",
        title="Require a password after sleep or screen saver begins",
        level=1,
        remediation="System Settings > Lock Screen > Require password after "
        "screen saver. CLI: defaults write com.apple.screensaver "
        "askForPassword -int 1",
        command=["defaults", "read", "com.apple.screensaver", "askForPassword"],
        predicate=_equals("1"),
    ),
    Check(
        cis_id="2.4.1",
        title="Disable Remote Login (SSH)",
        level=1,
        remediation="System Settings > General > Sharing > turn off Remote "
        "Login. CLI: sudo systemsetup -setremotelogin off",
        command=["systemsetup", "-getremotelogin"],
        predicate=_contains("off"),
    ),
    Check(
        cis_id="2.4.2",
        title="Disable Remote Apple Events",
        level=1,
        remediation="sudo systemsetup -setremoteappleevents off",
        command=["systemsetup", "-getremoteappleevents"],
        predicate=_contains("off"),
    ),
    Check(
        cis_id="2.5.1",
        title="Enable FileVault full-disk encryption",
        level=1,
        remediation="System Settings > Privacy & Security > FileVault > Turn "
        "On. CLI: sudo fdesetup enable",
        command=["fdesetup", "status"],
        predicate=_filevault_on,
    ),
    Check(
        cis_id="2.5.2",
        title="Enable Gatekeeper",
        level=1,
        remediation="sudo spctl --master-enable",
        command=["spctl", "--status"],
        predicate=_contains("assessments enabled"),
    ),
    Check(
        cis_id="2.6.1",
        title="Disable the guest account",
        level=1,
        remediation="sudo defaults write "
        "/Library/Preferences/com.apple.loginwindow GuestEnabled -bool false",
        command=[
            "defaults",
            "read",
            "/Library/Preferences/com.apple.loginwindow",
            "GuestEnabled",
        ],
        predicate=_equals("0"),
    ),
    Check(
        cis_id="2.6.2",
        title="Disable automatic login",
        level=1,
        remediation="System Settings > Lock Screen > Automatic login as > "
        "Never. CLI: sudo defaults delete "
        "/Library/Preferences/com.apple.loginwindow autoLoginUser",
        command=[
            "defaults",
            "read",
            "/Library/Preferences/com.apple.loginwindow",
            "autoLoginUser",
        ],
        predicate=_automatic_login_disabled,
    ),
    Check(
        cis_id="5.1",
        title="Enable System Integrity Protection (SIP)",
        level=1,
        remediation="Boot into Recovery and run: csrutil enable",
        command=["csrutil", "status"],
        predicate=_contains("enabled"),
    ),
    # --- Additional Level 1 controls -------------------------------------
    # These broaden coverage toward a fuller CIS Level 1 profile. The Sharing
    # checks read system launchd state via `sudo -n` so a scan can never hang on
    # a password prompt; without root they report 'unknown' rather than a wrong
    # pass. CIS numbering is approximate and drifts across macOS releases.
    Check(
        cis_id="2.1.1",
        title="Set time and date automatically",
        level=1,
        remediation="sudo systemsetup -setusingnetworktime on",
        command=["systemsetup", "-getusingnetworktime"],
        predicate=_contains("on"),
    ),
    Check(
        cis_id="2.3.2",
        title="Set screen saver to start within 20 minutes",
        level=1,
        remediation="System Settings > Lock Screen > Start Screen Saver when "
        "inactive. CLI: defaults -currentHost write com.apple.screensaver "
        "idleTime -int 1200",
        command=["defaults", "read", "com.apple.screensaver", "idleTime"],
        predicate=_int_in(1, 1200),
    ),
    Check(
        cis_id="2.4.3",
        title="Disable Screen Sharing",
        level=1,
        remediation="System Settings > General > Sharing > turn off Screen "
        "Sharing. CLI: sudo launchctl disable system/com.apple.screensharing",
        command=["sudo", "-n", "launchctl", "list"],
        predicate=_absent("com.apple.screensharing"),
    ),
    Check(
        cis_id="2.4.4",
        title="Disable Printer Sharing",
        level=1,
        remediation="System Settings > General > Sharing > turn off Printer "
        "Sharing. CLI: sudo cupsctl --no-share-printers",
        command=["cupsctl"],
        predicate=_contains("_share_printers=0"),
    ),
    Check(
        cis_id="2.4.5",
        title="Disable Remote Management (ARD)",
        level=1,
        remediation="Disable Remote Management in System Settings > General > "
        "Sharing.",
        command=["sudo", "-n", "launchctl", "list"],
        predicate=_absent("com.apple.RemoteDesktop"),
    ),
    Check(
        cis_id="2.4.6",
        title="Disable File Sharing (SMB)",
        level=1,
        remediation="System Settings > General > Sharing > turn off File "
        "Sharing. CLI: sudo launchctl disable system/com.apple.smbd",
        command=["sudo", "-n", "launchctl", "list"],
        predicate=_absent("com.apple.smbd"),
    ),
    Check(
        cis_id="2.4.7",
        title="Disable Internet Sharing",
        level=1,
        remediation="System Settings > General > Sharing > turn off Internet "
        "Sharing.",
        command=[
            "defaults",
            "read",
            "/Library/Preferences/SystemConfiguration/com.apple.nat",
            "NAT",
        ],
        predicate=_contains("Enabled = 0"),
    ),
    Check(
        cis_id="2.4.8",
        title="Disable Content Caching",
        level=1,
        remediation="System Settings > General > Sharing > turn off Content "
        "Caching. CLI: sudo AssetCacheManagerUtil deactivate",
        command=[
            "defaults",
            "read",
            "/Library/Preferences/com.apple.AssetCache",
            "Activated",
        ],
        predicate=_equals("0"),
    ),
    Check(
        cis_id="2.4.9",
        title="Disable Media Sharing",
        level=1,
        remediation="System Settings > General > Sharing > turn off Media " "Sharing.",
        command=[
            "defaults",
            "read",
            "com.apple.amp.mediasharingd",
            "home-sharing-enabled",
        ],
        predicate=_equals("0"),
    ),
    Check(
        cis_id="6.1",
        title="Safari: disable automatic opening of 'safe' downloads",
        level=1,
        remediation="Safari > Settings > General > uncheck 'Open safe files "
        "after downloading'. CLI: defaults write com.apple.Safari "
        "AutoOpenSafeDownloads -bool false",
        command=["defaults", "read", "com.apple.Safari", "AutoOpenSafeDownloads"],
        predicate=_equals("0"),
    ),
    Check(
        cis_id="6.2",
        title="Safari: warn when visiting fraudulent websites",
        level=1,
        remediation="Safari > Settings > Security > enable 'Warn when visiting "
        "a fraudulent website'.",
        command=[
            "defaults",
            "read",
            "com.apple.Safari",
            "WarnAboutFraudulentWebsites",
        ],
        predicate=_equals("1"),
    ),
    Check(
        cis_id="6.3",
        title="Terminal: require secure keyboard entry",
        level=1,
        remediation="Terminal > Settings > Profiles > enable 'Secure Keyboard "
        "Entry'. CLI: defaults write com.apple.Terminal SecureKeyboardEntry "
        "-bool true",
        command=["defaults", "read", "com.apple.Terminal", "SecureKeyboardEntry"],
        predicate=_equals("1"),
    ),
]


def run_audit(checks=None, level=None, runner=run_command) -> dict:
    """Evaluate the benchmark and return a scored report dict.

    ``level`` optionally restricts to CIS profile level 1 or 2. The
    ``compliance_score`` is the share of *determinable* checks that pass;
    ``unknown`` checks are excluded from the denominator so a locked-down probe
    can't inflate or deflate the score.
    """
    checks = checks if checks is not None else CHECKS
    if level is not None:
        checks = [c for c in checks if c.level <= level]

    results = [c.evaluate(runner=runner) for c in checks]
    passed = sum(1 for r in results if r["status"] == PASS)
    failed = sum(1 for r in results if r["status"] == FAIL)
    unknown = sum(1 for r in results if r["status"] == UNKNOWN)
    scored = passed + failed
    score = round(100 * passed / scored) if scored else None

    return {
        "summary": {
            "total": len(results),
            "passed": passed,
            "failed": failed,
            "unknown": unknown,
            "compliance_score": score,
            "grade": _grade(score),
        },
        "results": results,
    }


def _grade(score):
    if score is None:
        return "N/A"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


_STATUS_MARK = {PASS: "PASS", FAIL: "FAIL", UNKNOWN: "  ? "}


def format_report(report) -> str:
    """Render an audit report as a readable plain-text scorecard."""
    s = report["summary"]
    lines: List[str] = ["macOS CIS Benchmark Audit", "=" * 60]
    score = s["compliance_score"]
    score_text = "N/A" if score is None else f"{score}%  (grade {s['grade']})"
    lines.append(f"Compliance score: {score_text}")
    lines.append(
        f"Passed {s['passed']}  |  Failed {s['failed']}  |  "
        f"Unknown {s['unknown']}  |  Total {s['total']}"
    )
    lines.append("-" * 60)
    for r in report["results"]:
        lines.append(f"[{_STATUS_MARK[r['status']]}] {r['cis_id']:<6} {r['title']}")
        if r["status"] == FAIL and r["remediation"]:
            lines.append(f"        fix: {r['remediation']}")
        if r["status"] == UNKNOWN:
            lines.append(
                "        (could not determine - run with sufficient privileges on macOS)"
            )
    return "\n".join(lines)
