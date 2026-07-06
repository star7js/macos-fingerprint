"""
Command-line interface for macOS Fingerprint.
"""

import argparse
import getpass
import json
import sys
from datetime import datetime, timezone
from typing import Any, Dict

from .core.fingerprint import create_fingerprint, hash_fingerprint, ALL_COLLECTOR_NAMES
from .core.storage import save_fingerprint, load_fingerprint
from .core.comparison import (
    compare_fingerprints,
    export_comparison_html,
    export_comparison_json,
)
from .utils.config import load_config, init_config, apply_config_to_args


def _resolve_password(args) -> str:
    """Resolve password from --password, --password-file, or interactive prompt.

    Returns:
        The resolved password string.
    """
    if args.password:
        return args.password
    if getattr(args, "password_file", None):
        try:
            with open(args.password_file, "r") as f:
                return f.read().strip()
        except OSError as e:
            print(f"Error: Cannot read password file: {e}", file=sys.stderr)
            sys.exit(1)
    # Interactive prompt (only when stdin is a terminal)
    if sys.stdin.isatty():
        return getpass.getpass("Password: ")
    print(
        "Error: --password or --password-file is required in non-interactive mode",
        file=sys.stderr,
    )
    sys.exit(1)


def _parse_collector_names(raw: str) -> list:
    """Split a comma-separated collector string into a list of names."""
    return [name.strip() for name in raw.split(",") if name.strip()]


def _collector_kwargs(args) -> dict:
    """Extract collectors/exclude/parallel kwargs from parsed args."""
    kwargs: Dict[str, Any] = {}
    if getattr(args, "collectors", None):
        kwargs["collectors"] = _parse_collector_names(args.collectors)
    if getattr(args, "exclude", None):
        kwargs["exclude"] = _parse_collector_names(args.exclude)
    if getattr(args, "parallel", False):
        kwargs["parallel"] = True
    return kwargs


def _is_json_mode(args) -> bool:
    """Return True when the user requested --json output."""
    return getattr(args, "json", False)


def cmd_create(args):
    """Create a new fingerprint."""
    password = None
    if args.encrypt:
        password = _resolve_password(args)

    json_mode = _is_json_mode(args)
    if not json_mode:
        print("Creating fingerprint...")

    fingerprint = create_fingerprint(
        hash_sensitive=not args.no_hash,
        **_collector_kwargs(args),
    )

    if save_fingerprint(
        fingerprint, args.output, encrypt=args.encrypt, password=password
    ):
        if json_mode:
            result = {
                "status": "ok",
                "output": args.output,
                "hash": hash_fingerprint(fingerprint),
                "collectors": list(fingerprint.get("collectors", {}).keys()),
            }
            print(json.dumps(result))
        else:
            print(f"Fingerprint saved to: {args.output}")
            print(f"Hash: {hash_fingerprint(fingerprint)}")
    else:
        if json_mode:
            print(json.dumps({"status": "error", "message": "Failed to save"}))
        else:
            print("Error: Failed to save fingerprint", file=sys.stderr)
        sys.exit(1)


def cmd_compare(args):
    """Compare fingerprints."""
    password = None
    if args.encrypted:
        password = _resolve_password(args)

    json_mode = _is_json_mode(args)
    if not json_mode:
        print("Loading baseline fingerprint...")

    baseline = load_fingerprint(
        args.baseline, encrypted=args.encrypted, password=password
    )

    if not baseline:
        if json_mode:
            print(json.dumps({"status": "error", "message": "Could not load baseline"}))
        else:
            print("Error: Could not load baseline fingerprint", file=sys.stderr)
        sys.exit(1)

    if not json_mode:
        print("Creating current fingerprint...")

    current = create_fingerprint(
        hash_sensitive=not args.no_hash,
        **_collector_kwargs(args),
    )

    if not json_mode:
        print("Comparing fingerprints...")

    # Get ignore_collectors from --ignore-collectors or config
    ignore_collectors = None
    raw_ignore = getattr(args, "ignore_collectors", None)
    if raw_ignore:
        ignore_collectors = _parse_collector_names(raw_ignore)

    differences = compare_fingerprints(
        baseline, current, ignore_collectors=ignore_collectors
    )

    if json_mode:
        # Machine-readable: just dump the entire comparison
        print(json.dumps(differences, indent=2))
    else:
        # Display summary
        summary = differences["summary"]
        print("\nComparison Summary:")
        print(f"  Total Changes: {summary['total_changes']}")
        print(f"  Critical: {summary['critical']}")
        print(f"  High: {summary['high']}")
        print(f"  Medium: {summary['medium']}")
        print(f"  Low: {summary['low']}")

        if summary["total_changes"] == 0:
            print("\nNo differences found.")
        else:
            print(f"\nFound {summary['total_changes']} changes.")

            # Show brief details
            for collector, change in differences["changes"].items():
                severity = change["severity"]
                print(f"  [{severity.upper()}] {collector}")

    # Export if requested
    if args.output:
        if args.format == "html":
            if export_comparison_html(differences, args.output):
                if not json_mode:
                    print(f"\nComparison exported to: {args.output}")
        else:
            if export_comparison_json(differences, args.output):
                if not json_mode:
                    print(f"\nComparison exported to: {args.output}")


def cmd_hash(args):
    """Calculate hash of existing fingerprint."""
    password = None
    if args.encrypted:
        password = _resolve_password(args)

    json_mode = _is_json_mode(args)
    if not json_mode:
        print("Loading fingerprint...")

    fingerprint = load_fingerprint(
        args.file, encrypted=args.encrypted, password=password
    )

    if not fingerprint:
        if json_mode:
            print(
                json.dumps({"status": "error", "message": "Could not load fingerprint"})
            )
        else:
            print("Error: Could not load fingerprint", file=sys.stderr)
        sys.exit(1)

    h = hash_fingerprint(fingerprint)
    if json_mode:
        print(json.dumps({"hash": h}))
    else:
        print(f"Hash: {h}")


def cmd_list_collectors(args):
    """List all available collectors."""
    json_mode = _is_json_mode(args)
    if json_mode:
        print(json.dumps({"collectors": ALL_COLLECTOR_NAMES}))
    else:
        print("Available collectors:")
        for name in ALL_COLLECTOR_NAMES:
            print(f"  {name}")


def cmd_init(args):
    """Create a default config file."""
    path = init_config()
    json_mode = _is_json_mode(args)
    if json_mode:
        print(json.dumps({"config_path": path}))
    else:
        print(f"Config file: {path}")


def _add_password_args(parser):
    """Add --password and --password-file arguments to a parser."""
    parser.add_argument("--password", help="Password (prefer --password-file)")
    parser.add_argument(
        "--password-file",
        help="Read password from file (avoids exposing password in process table)",
    )


def _report_timestamp() -> str:
    """Current UTC time as an ISO-8601 string, for report/record stamps."""
    return datetime.now(timezone.utc).isoformat()


def cmd_audit(args):
    """Score the system against the CIS macOS benchmark."""
    from .audit.cis import run_audit, format_report
    from .audit.html_report import render_html

    report = run_audit(level=args.level)

    if args.output:
        if args.format == "html":
            content = render_html(report, generated_at=_report_timestamp())
        else:
            content = json.dumps(report, indent=2)
        with open(args.output, "w") as f:
            f.write(content)
        print(f"Report written to {args.output}")

    if args.format == "json":
        print(json.dumps(report, indent=2))
    elif args.format == "html" and not args.output:
        print(render_html(report, generated_at=_report_timestamp()))
    elif args.format == "text":
        print(format_report(report))

    # Non-zero exit when any determinable check failed, for CI/monitoring.
    if report["summary"]["failed"]:
        sys.exit(2)


def cmd_agent(args):
    """Headless scheduled monitoring with a tamper-evident history."""
    from .audit import agent

    history_file = args.history_file or agent.HISTORY_FILE

    if args.agent_command is None:
        print(
            "Specify an agent subcommand: run | history | verify | install | uninstall"
        )
        sys.exit(1)

    if args.agent_command == "run":
        record = agent.run_cycle(
            _report_timestamp(),
            history_file=history_file,
            baseline_file=args.baseline_file,
        )
        a = record.get("audit") or {}
        drift = record["drift"]
        print(f"Recorded {record['timestamp']}")
        if a:
            print(
                f"  audit: score={a.get('compliance_score')} "
                f"grade={a.get('grade')} failed={a.get('failed')}"
            )
        print(
            "  drift: " + (", ".join(drift["sections"]) if drift["changed"] else "none")
        )
        return

    if args.agent_command == "history":
        history = agent.load_history(history_file)
        if not history:
            print("No history yet.")
            return
        for record in history[-args.limit :]:
            a = record.get("audit") or {}
            drift = record["drift"]
            drift_text = ",".join(drift["sections"]) if drift["changed"] else "none"
            print(
                f"{record['timestamp']}  grade={a.get('grade', '?')}  "
                f"score={a.get('compliance_score', '?')}  drift={drift_text}"
            )
        return

    if args.agent_command == "verify":
        ok, index = agent.verify_history_chain(history_file)
        if ok:
            print("History chain intact.")
            return
        print(f"History chain BROKEN at record index {index} (possible tampering).")
        sys.exit(2)

    if args.agent_command == "install":
        path, loaded = agent.install(interval_hours=args.interval_hours)
        print(f"Agent plist written to {path}")
        print("Loaded into launchd." if loaded else "Written (load it on macOS).")
        return

    if args.agent_command == "uninstall":
        removed = agent.uninstall()
        print("Agent removed." if removed else "No agent was installed.")
        return


def _add_collector_args(parser):
    """Add --collectors, --exclude, --parallel, and --json arguments."""
    parser.add_argument(
        "--collectors",
        metavar="NAMES",
        help="Comma-separated list of collector names to run (whitelist)",
    )
    parser.add_argument(
        "--exclude",
        metavar="NAMES",
        help="Comma-separated list of collector names to skip (blacklist)",
    )
    parser.add_argument(
        "--parallel",
        action="store_true",
        default=False,
        help="Run collectors in parallel for faster scans",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output machine-readable JSON instead of human-readable text",
    )


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="macOS Fingerprint - Comprehensive macOS system fingerprinting tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create a baseline fingerprint
  macos-fingerprint create -o baseline.json

  # Compare current system to baseline
  macos-fingerprint compare -b baseline.json

  # Create encrypted fingerprint (prompts for password)
  macos-fingerprint create -o secure.json --encrypt

  # Create encrypted fingerprint with password file
  macos-fingerprint create -o secure.json --encrypt --password-file ~/.fp-pass

  # Export comparison as HTML
  macos-fingerprint compare -b baseline.json -o report.html --format html

  # Only run specific collectors
  macos-fingerprint create -o partial.json --collectors SystemInfoCollector,NetworkConfigCollector

  # Skip slow collectors
  macos-fingerprint create -o fast.json --exclude BluetoothDevicesCollector,PrintersCollector

  # Machine-readable JSON output
  macos-fingerprint create -o fp.json --json

  # List all available collectors
  macos-fingerprint list-collectors
""",
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Create command
    create_parser = subparsers.add_parser("create", help="Create a new fingerprint")
    create_parser.add_argument(
        "-o",
        "--output",
        default="fingerprint.json",
        help="Output file (default: fingerprint.json)",
    )
    create_parser.add_argument(
        "--no-hash", action="store_true", help="Do not hash sensitive fields"
    )
    create_parser.add_argument(
        "--encrypt", action="store_true", help="Encrypt the fingerprint"
    )
    _add_password_args(create_parser)
    _add_collector_args(create_parser)
    create_parser.set_defaults(func=cmd_create)

    # Compare command
    compare_parser = subparsers.add_parser("compare", help="Compare with baseline")
    compare_parser.add_argument(
        "-b", "--baseline", required=True, help="Baseline fingerprint file"
    )
    compare_parser.add_argument(
        "-o", "--output", help="Export comparison results to file"
    )
    compare_parser.add_argument(
        "--format",
        choices=["json", "html"],
        default="json",
        help="Export format (default: json)",
    )
    compare_parser.add_argument(
        "--no-hash", action="store_true", help="Do not hash sensitive fields"
    )
    compare_parser.add_argument(
        "--encrypted", action="store_true", help="Baseline is encrypted"
    )
    compare_parser.add_argument(
        "--ignore-collectors",
        metavar="NAMES",
        help="Comma-separated list of collectors whose changes are ignored",
    )
    _add_password_args(compare_parser)
    _add_collector_args(compare_parser)
    compare_parser.set_defaults(func=cmd_compare)

    # Hash command
    hash_parser = subparsers.add_parser("hash", help="Calculate fingerprint hash")
    hash_parser.add_argument("file", help="Fingerprint file")
    hash_parser.add_argument(
        "--encrypted", action="store_true", help="File is encrypted"
    )
    hash_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output machine-readable JSON",
    )
    _add_password_args(hash_parser)
    hash_parser.set_defaults(func=cmd_hash)

    # List-collectors command
    list_parser = subparsers.add_parser(
        "list-collectors", help="List all available collectors"
    )
    list_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output machine-readable JSON",
    )
    list_parser.set_defaults(func=cmd_list_collectors)

    # Init command
    init_parser = subparsers.add_parser("init", help="Create a default config file")
    init_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output machine-readable JSON",
    )
    init_parser.set_defaults(func=cmd_init)

    # Audit command
    audit_parser = subparsers.add_parser(
        "audit", help="Score the system against the CIS macOS benchmark"
    )
    audit_parser.add_argument("-o", "--output", help="Write the report to this file")
    audit_parser.add_argument(
        "--level",
        type=int,
        choices=(1, 2),
        help="Restrict to CIS profile level 1 or 2",
    )
    audit_parser.add_argument(
        "--format",
        choices=("text", "json", "html"),
        default="text",
        help="Output format (default: text). 'html' renders a shareable scorecard.",
    )
    audit_parser.set_defaults(func=cmd_audit)

    # Agent command
    agent_parser = subparsers.add_parser(
        "agent", help="Headless scheduled monitoring with tamper-evident history"
    )
    agent_parser.add_argument(
        "--history-file",
        default=None,
        help="History log path (default: ~/.macos_fingerprint/history.jsonl)",
    )
    agent_sub = agent_parser.add_subparsers(dest="agent_command")
    agent_run = agent_sub.add_parser(
        "run", help="Run one monitoring cycle and record it"
    )
    agent_run.add_argument(
        "--baseline-file",
        default=None,
        help="Baseline fingerprint to diff against for drift detection",
    )
    agent_hist = agent_sub.add_parser("history", help="Show recent monitoring records")
    agent_hist.add_argument(
        "-n", "--limit", type=int, default=20, help="Records to show (default: 20)"
    )
    agent_sub.add_parser("verify", help="Verify the history hash chain")
    agent_install = agent_sub.add_parser("install", help="Install the launchd agent")
    agent_install.add_argument(
        "--interval-hours",
        type=int,
        default=24,
        help="How often to run, in hours (default: 24)",
    )
    agent_sub.add_parser("uninstall", help="Remove the launchd agent")
    agent_parser.set_defaults(func=cmd_agent)

    # Parse arguments
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Load config and apply as defaults (CLI flags override)
    config = load_config()
    if hasattr(args, "output") or hasattr(args, "collectors"):
        apply_config_to_args(args, config)

    # Execute command
    args.func(args)


if __name__ == "__main__":
    main()
