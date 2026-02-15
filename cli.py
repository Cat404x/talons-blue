#!/usr/bin/env python3
"""
Command-line interface for Talons Blue scanner.
"""

import argparse
import sys
from talons_blue.scanner import Scanner
from talons_blue.utils import format_scan_result, parse_target_list


def main():
    """
    Main entry point for the CLI.
    """
    parser = argparse.ArgumentParser(
        description='Talons Blue - Defensive surface validation for owned or authorized assets',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        'targets',
        nargs='*',
        help='Target URLs or IP addresses to scan'
    )
    
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=5,
        help='Connection timeout in seconds (default: 5)'
    )
    
    parser.add_argument(
        '-f', '--file',
        type=str,
        help='Read targets from a file (one per line)'
    )
    
    parser.add_argument(
        '-v', '--version',
        action='version',
        version='%(prog)s 0.1.0'
    )
    
    args = parser.parse_args()
    
    # Collect targets
    targets = []
    
    if args.targets:
        for target in args.targets:
            targets.extend(parse_target_list(target))
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line)
        except FileNotFoundError:
            print(f"Error: File '{args.file}' not found", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            return 1
    
    if not targets:
        parser.print_help()
        print("\nError: No targets specified", file=sys.stderr)
        return 1
    
    # Initialize scanner
    scanner = Scanner(timeout=args.timeout)
    
    print(f"Talons Blue - Scanning {len(targets)} target(s)...\n")
    
    # Scan targets
    for target in targets:
        print(f"Scanning: {target}")
        result = scanner.scan_target(target)
        print(format_scan_result(result))
        print("-" * 60)
    
    # Summary
    print(f"\nScan completed. Total targets scanned: {len(scanner.get_results())}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
