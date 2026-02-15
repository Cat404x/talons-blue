#!/usr/bin/env python3
"""
Talons Blue - Defensive Web Surface Monitoring Tool

Copyright (c) 2026 Cat404x
Licensed under the MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

This tool is intended only for:
- Assets you own
- Systems you have explicit written authorization to test
- Compliance and defensive validation purposes

Unauthorized use may violate local laws and platform policies.
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup


class TalonsBlue:
    """Defensive Web Surface Monitoring Tool"""

    def __init__(self, allowed_domain, delay=2):
        """
        Initialize TalonsBlue scanner.

        Args:
            allowed_domain: Domain to restrict scanning to
            delay: Fixed delay between requests in seconds
        """
        self.allowed_domain = allowed_domain
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'TalonsBlue/1.0 (Defensive Security Scanner)'
        })

    def validate_domain(self, url):
        """
        Validate that URL belongs to allowed domain.

        Args:
            url: URL to validate

        Returns:
            bool: True if domain is allowed, False otherwise
        """
        parsed = urlparse(url)
        domain = parsed.netloc

        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]

        return domain == self.allowed_domain or domain.endswith(f'.{self.allowed_domain}')

    def check_robots_txt(self, url):
        """
        Check if URL is allowed by robots.txt.

        Args:
            url: URL to check

        Returns:
            bool: True if allowed, False otherwise
        """
        try:
            parsed = urlparse(url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

            rp = RobotFileParser()
            rp.set_url(robots_url)
            rp.read()

            return rp.can_fetch(self.session.headers['User-Agent'], url)
        except Exception:
            # If robots.txt doesn't exist or can't be parsed, allow access
            return True

    def check_security_headers(self, headers):
        """
        Check for important security headers.

        Args:
            headers: Response headers dictionary

        Returns:
            dict: Dictionary with security header status
        """
        security_headers = {
            'X-Frame-Options': headers.get('X-Frame-Options'),
            'Content-Security-Policy': headers.get('Content-Security-Policy'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
            'Referrer-Policy': headers.get('Referrer-Policy')
        }

        missing_headers = [name for name, value in security_headers.items() if not value]

        return {
            'headers': security_headers,
            'missing': missing_headers
        }

    def detect_forms(self, html_content):
        """
        Detect HTML forms in page content.

        Args:
            html_content: HTML content to parse

        Returns:
            list: List of form information dictionaries
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            forms = soup.find_all('form')

            form_data = []
            for form in forms:
                form_info = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').upper(),
                    'inputs': len(form.find_all('input'))
                }
                form_data.append(form_info)

            return form_data
        except Exception:
            # If HTML parsing fails, return empty list
            # The scan will continue but forms_detected will be 0
            return []

    def scan_url(self, url):
        """
        Perform passive scan of a URL.

        Args:
            url: URL to scan

        Returns:
            dict: Scan results
        """
        result = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'url': url,
            'status': 'failed',
            'error': None
        }

        # Validate URL scheme
        parsed = urlparse(url)
        if parsed.scheme not in ['http', 'https']:
            result['error'] = 'Invalid URL scheme. Must be http or https.'
            return result

        # Validate domain
        if not self.validate_domain(url):
            result['error'] = f'Domain not in allowlist: {self.allowed_domain}'
            return result

        # Check robots.txt
        if not self.check_robots_txt(url):
            result['error'] = 'URL disallowed by robots.txt'
            return result

        # Apply fixed delay
        time.sleep(self.delay)

        # Retrieve page
        try:
            response = self.session.get(url, timeout=30, allow_redirects=True)
            result['status_code'] = response.status_code
            result['content_length'] = len(response.content)
            result['https_enforced'] = response.url.startswith('https://')
            result['server_header'] = response.headers.get('Server', 'Not disclosed')

            # Check security headers
            security_check = self.check_security_headers(response.headers)
            result['security_headers'] = security_check['headers']
            result['missing_security_headers'] = security_check['missing']

            # Detect forms
            if 'text/html' in response.headers.get('Content-Type', ''):
                forms = self.detect_forms(response.text)
                result['forms_detected'] = len(forms)
                result['forms'] = forms
            else:
                result['forms_detected'] = 0
                result['forms'] = []

            result['status'] = 'success'

        except requests.exceptions.RequestException as e:
            result['error'] = f'Request failed: {str(e)}'

        return result


def main():
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description='Talons Blue - Defensive Web Surface Monitoring Tool',
        epilog='For authorized security validation and compliance auditing only.'
    )

    parser.add_argument(
        '--url',
        required=True,
        help='Target URL to scan'
    )

    parser.add_argument(
        '--domain',
        required=True,
        help='Allowed domain for scanning (enforced allowlist)'
    )

    parser.add_argument(
        '--delay',
        type=int,
        default=2,
        help='Fixed delay between requests in seconds (default: 2)'
    )

    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results in JSON format'
    )

    args = parser.parse_args()

    # Initialize scanner
    scanner = TalonsBlue(allowed_domain=args.domain, delay=args.delay)

    # Perform scan
    result = scanner.scan_url(args.url)

    # Output results
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n{'='*60}")
        print(f"Talons Blue - Scan Report")
        print(f"{'='*60}")
        print(f"Timestamp: {result['timestamp']}")
        print(f"URL: {result['url']}")
        print(f"Status: {result['status']}")

        if result.get('error'):
            print(f"Error: {result['error']}")
        else:
            print(f"Status Code: {result['status_code']}")
            print(f"Content Length: {result['content_length']} bytes")
            print(f"HTTPS Enforced: {result['https_enforced']}")
            print(f"Server: {result['server_header']}")
            print(f"Forms Detected: {result['forms_detected']}")

            if result['missing_security_headers']:
                print(f"\nMissing Security Headers:")
                for header in result['missing_security_headers']:
                    print(f"  - {header}")
            else:
                print(f"\n✓ All recommended security headers present")

        print(f"{'='*60}\n")

    # Exit with appropriate code
    sys.exit(0 if result['status'] == 'success' else 1)


if __name__ == '__main__':
    main()
