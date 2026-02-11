"""
Command-line interface for macOS Fingerprint.
"""

import argparse
import getpass
import json
import sys

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
    kwargs = {}
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
            print(json.dumps({"status": "error", "message": "Could not load fingerprint"}))
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
    init_parser = subparsers.add_parser(
        "init", help="Create a default config file"
    )
    init_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output machine-readable JSON",
    )
    init_parser.set_defaults(func=cmd_init)

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
