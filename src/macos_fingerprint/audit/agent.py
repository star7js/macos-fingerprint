"""Headless scheduled monitoring: run audits/drift checks unattended and append
results to a tamper-evident local history.

This turns the tool from "something you run manually" into "something that
watches a machine". Two pieces:

* an append-only, hash-chained history log (each record commits to the previous
  record's hash, so a silently edited or deleted record breaks the chain and is
  detectable); and
* a launchd agent that runs a monitoring cycle on a schedule.

The pure functions here (record building, chaining, verification, plist
generation) are unit-tested without touching macOS; only install/uninstall shell
out to ``launchctl``.
"""

import hashlib
import json
import os
import sys

from ..utils.commands import run_command

LABEL = "com.macosfingerprint.agent"
HISTORY_DIR = os.path.expanduser("~/.macos_fingerprint")
HISTORY_FILE = os.path.join(HISTORY_DIR, "history.jsonl")
PLIST_PATH = os.path.expanduser(f"~/Library/LaunchAgents/{LABEL}.plist")

GENESIS = "0" * 64


def _hash_record(record):
    """SHA-256 over the record excluding its own ``hash`` field."""
    payload = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def load_history(history_file=HISTORY_FILE):
    """Return the list of history records (empty if the file doesn't exist)."""
    try:
        with open(history_file) as f:
            return [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        return []


def append_history(record, history_file=HISTORY_FILE):
    """Append ``record`` to the chained history and return it with hash fields set.

    ``prev`` links to the previous record's hash (or the genesis value for the
    first record); ``hash`` commits to the whole record including ``prev``.
    """
    history = load_history(history_file)
    record = dict(record)
    record["prev"] = history[-1]["hash"] if history else GENESIS
    record["hash"] = _hash_record(record)

    os.makedirs(os.path.dirname(history_file) or ".", exist_ok=True)
    with open(history_file, "a") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")
    return record


def verify_history_chain(history_file=HISTORY_FILE):
    """Verify the hash chain. Returns ``(ok, index)``.

    ``ok`` is True when every record's hash recomputes and links correctly.
    On failure ``index`` is the 0-based position of the first bad record;
    on success ``index`` is None.
    """
    history = load_history(history_file)
    expected_prev = GENESIS
    for i, record in enumerate(history):
        if record.get("prev") != expected_prev:
            return False, i
        if _hash_record(record) != record.get("hash"):
            return False, i
        expected_prev = record["hash"]
    return True, None


def build_record(timestamp, audit_summary=None, drift_sections=None):
    """Build a monitoring record from an audit summary and/or drift sections.

    ``drift_sections`` is the list of fingerprint collectors that changed vs the
    baseline (keys of the compare_fingerprints() result's ``changes``), or None
    if no baseline comparison ran.
    """
    return {
        "timestamp": timestamp,
        "audit": audit_summary,
        "drift": {
            "changed": drift_sections is not None and len(drift_sections) > 0,
            "sections": sorted(drift_sections) if drift_sections else [],
        },
    }


def build_launchd_plist(program_args, interval_seconds=86400, label=LABEL):
    """Return a launchd plist XML string that runs ``program_args`` on an interval."""
    args_xml = "\n".join(f"        <string>{a}</string>" for a in program_args)
    log_out = os.path.join(HISTORY_DIR, "agent.out.log")
    log_err = os.path.join(HISTORY_DIR, "agent.err.log")
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
{args_xml}
    </array>
    <key>StartInterval</key>
    <integer>{int(interval_seconds)}</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log_out}</string>
    <key>StandardErrorPath</key>
    <string>{log_err}</string>
</dict>
</plist>
"""


def run_cycle(timestamp, history_file=HISTORY_FILE, baseline_file=None):
    """Run an audit (and a drift check if a baseline exists), append a record.

    Imports the collectors lazily so this module stays importable off-macOS.
    Returns the appended record.
    """
    from .cis import run_audit
    from ..core.fingerprint import create_fingerprint
    from ..core.comparison import compare_fingerprints
    from ..core.storage import load_fingerprint

    audit = run_audit()
    drift_sections = None
    if baseline_file and os.path.exists(baseline_file):
        baseline = load_fingerprint(baseline_file)
        if baseline is not None:
            current = create_fingerprint()
            drift_sections = list(
                compare_fingerprints(baseline, current)["changes"].keys()
            )

    record = build_record(timestamp, audit["summary"], drift_sections)
    return append_history(record, history_file)


def install(interval_hours=24, python=None):
    """Write and load the launchd agent. Returns ``(plist_path, loaded)``."""
    python = python or sys.executable
    plist = build_launchd_plist(
        [python, "-m", "macos_fingerprint", "agent", "run"],
        interval_seconds=interval_hours * 3600,
    )
    os.makedirs(os.path.dirname(PLIST_PATH), exist_ok=True)
    with open(PLIST_PATH, "w") as f:
        f.write(plist)
    # unload first in case an old copy is loaded; ignore failure.
    run_command(["launchctl", "unload", PLIST_PATH])
    loaded = run_command(["launchctl", "load", PLIST_PATH])
    return PLIST_PATH, loaded is not None


def uninstall():
    """Unload and remove the launchd agent. Returns True if the plist existed."""
    run_command(["launchctl", "unload", PLIST_PATH])
    if os.path.exists(PLIST_PATH):
        os.remove(PLIST_PATH)
        return True
    return False
