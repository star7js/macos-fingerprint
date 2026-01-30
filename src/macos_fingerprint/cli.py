"""
Command-line interface for macOS Fingerprint.
"""

import argparse
import sys
from typing import Optional

from .core.fingerprint import create_fingerprint, hash_fingerprint
from .core.storage import save_fingerprint, load_fingerprint
from .core.comparison import compare_fingerprints, export_comparison_html, export_comparison_json


def cmd_create(args):
    """Create a new fingerprint."""
    print("Creating fingerprint...")

    fingerprint = create_fingerprint(hash_sensitive=not args.no_hash)

    if save_fingerprint(
        fingerprint,
        args.output,
        encrypt=args.encrypt,
        password=args.password
    ):
        print(f"Fingerprint saved to: {args.output}")
        print(f"Hash: {hash_fingerprint(fingerprint)}")
    else:
        print("Error: Failed to save fingerprint", file=sys.stderr)
        sys.exit(1)


def cmd_compare(args):
    """Compare fingerprints."""
    print("Loading baseline fingerprint...")
    baseline = load_fingerprint(
        args.baseline,
        encrypted=args.encrypted,
        password=args.password
    )

    if not baseline:
        print("Error: Could not load baseline fingerprint", file=sys.stderr)
        sys.exit(1)

    print("Creating current fingerprint...")
    current = create_fingerprint(hash_sensitive=not args.no_hash)

    print("Comparing fingerprints...")
    differences = compare_fingerprints(baseline, current)

    # Display summary
    summary = differences['summary']
    print(f"\nComparison Summary:")
    print(f"  Total Changes: {summary['total_changes']}")
    print(f"  Critical: {summary['critical']}")
    print(f"  High: {summary['high']}")
    print(f"  Medium: {summary['medium']}")
    print(f"  Low: {summary['low']}")

    if summary['total_changes'] == 0:
        print("\nNo differences found.")
    else:
        print(f"\nFound {summary['total_changes']} changes.")

        # Show brief details
        for collector, change in differences['changes'].items():
            severity = change['severity']
            print(f"  [{severity.upper()}] {collector}")

    # Export if requested
    if args.output:
        if args.format == 'html':
            if export_comparison_html(differences, args.output):
                print(f"\nComparison exported to: {args.output}")
        else:
            if export_comparison_json(differences, args.output):
                print(f"\nComparison exported to: {args.output}")


def cmd_hash(args):
    """Calculate hash of existing fingerprint."""
    print("Loading fingerprint...")
    fingerprint = load_fingerprint(
        args.file,
        encrypted=args.encrypted,
        password=args.password
    )

    if not fingerprint:
        print("Error: Could not load fingerprint", file=sys.stderr)
        sys.exit(1)

    print(f"Hash: {hash_fingerprint(fingerprint)}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='macOS Fingerprint - Comprehensive macOS system fingerprinting tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create a baseline fingerprint
  macos-fingerprint create -o baseline.json

  # Compare current system to baseline
  macos-fingerprint compare -b baseline.json

  # Create encrypted fingerprint
  macos-fingerprint create -o secure.json --encrypt --password mypass

  # Export comparison as HTML
  macos-fingerprint compare -b baseline.json -o report.html --format html
"""
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Create command
    create_parser = subparsers.add_parser('create', help='Create a new fingerprint')
    create_parser.add_argument(
        '-o', '--output',
        default='fingerprint.json',
        help='Output file (default: fingerprint.json)'
    )
    create_parser.add_argument(
        '--no-hash',
        action='store_true',
        help='Do not hash sensitive fields'
    )
    create_parser.add_argument(
        '--encrypt',
        action='store_true',
        help='Encrypt the fingerprint'
    )
    create_parser.add_argument(
        '--password',
        help='Password for encryption'
    )
    create_parser.set_defaults(func=cmd_create)

    # Compare command
    compare_parser = subparsers.add_parser('compare', help='Compare with baseline')
    compare_parser.add_argument(
        '-b', '--baseline',
        required=True,
        help='Baseline fingerprint file'
    )
    compare_parser.add_argument(
        '-o', '--output',
        help='Export comparison results to file'
    )
    compare_parser.add_argument(
        '--format',
        choices=['json', 'html'],
        default='json',
        help='Export format (default: json)'
    )
    compare_parser.add_argument(
        '--no-hash',
        action='store_true',
        help='Do not hash sensitive fields'
    )
    compare_parser.add_argument(
        '--encrypted',
        action='store_true',
        help='Baseline is encrypted'
    )
    compare_parser.add_argument(
        '--password',
        help='Password for decryption'
    )
    compare_parser.set_defaults(func=cmd_compare)

    # Hash command
    hash_parser = subparsers.add_parser('hash', help='Calculate fingerprint hash')
    hash_parser.add_argument(
        'file',
        help='Fingerprint file'
    )
    hash_parser.add_argument(
        '--encrypted',
        action='store_true',
        help='File is encrypted'
    )
    hash_parser.add_argument(
        '--password',
        help='Password for decryption'
    )
    hash_parser.set_defaults(func=cmd_hash)

    # Parse arguments
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Execute command
    args.func(args)


if __name__ == '__main__':
    main()
