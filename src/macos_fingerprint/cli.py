"""
Command-line interface for macOS Fingerprint.
"""

import argparse
import getpass
import sys

from .core.fingerprint import create_fingerprint, hash_fingerprint
from .core.storage import save_fingerprint, load_fingerprint
from .core.comparison import (
    compare_fingerprints,
    export_comparison_html,
    export_comparison_json,
)


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


def cmd_create(args):
    """Create a new fingerprint."""
    password = None
    if args.encrypt:
        password = _resolve_password(args)

    print("Creating fingerprint...")

    fingerprint = create_fingerprint(hash_sensitive=not args.no_hash)

    if save_fingerprint(
        fingerprint, args.output, encrypt=args.encrypt, password=password
    ):
        print(f"Fingerprint saved to: {args.output}")
        print(f"Hash: {hash_fingerprint(fingerprint)}")
    else:
        print("Error: Failed to save fingerprint", file=sys.stderr)
        sys.exit(1)


def cmd_compare(args):
    """Compare fingerprints."""
    password = None
    if args.encrypted:
        password = _resolve_password(args)

    print("Loading baseline fingerprint...")
    baseline = load_fingerprint(
        args.baseline, encrypted=args.encrypted, password=password
    )

    if not baseline:
        print("Error: Could not load baseline fingerprint", file=sys.stderr)
        sys.exit(1)

    print("Creating current fingerprint...")
    current = create_fingerprint(hash_sensitive=not args.no_hash)

    print("Comparing fingerprints...")
    differences = compare_fingerprints(baseline, current)

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
                print(f"\nComparison exported to: {args.output}")
        else:
            if export_comparison_json(differences, args.output):
                print(f"\nComparison exported to: {args.output}")


def cmd_hash(args):
    """Calculate hash of existing fingerprint."""
    password = None
    if args.encrypted:
        password = _resolve_password(args)

    print("Loading fingerprint...")
    fingerprint = load_fingerprint(
        args.file, encrypted=args.encrypted, password=password
    )

    if not fingerprint:
        print("Error: Could not load fingerprint", file=sys.stderr)
        sys.exit(1)

    print(f"Hash: {hash_fingerprint(fingerprint)}")


def _add_password_args(parser):
    """Add --password and --password-file arguments to a parser."""
    parser.add_argument("--password", help="Password (prefer --password-file)")
    parser.add_argument(
        "--password-file",
        help="Read password from file (avoids exposing password in process table)",
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
    _add_password_args(compare_parser)
    compare_parser.set_defaults(func=cmd_compare)

    # Hash command
    hash_parser = subparsers.add_parser("hash", help="Calculate fingerprint hash")
    hash_parser.add_argument("file", help="Fingerprint file")
    hash_parser.add_argument(
        "--encrypted", action="store_true", help="File is encrypted"
    )
    _add_password_args(hash_parser)
    hash_parser.set_defaults(func=cmd_hash)

    # Parse arguments
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Execute command
    args.func(args)


if __name__ == "__main__":
    main()
