#!/usr/bin/env python3
"""
Talons Blue - Scoped Defensive Web Surface Monitoring Tool

A passive security validation tool designed for authorized compliance auditing.
Enforces strict safeguards including domain allowlisting and robots.txt compliance.
"""

import argparse
import json
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse, urljoin
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup


class TalonsBlue:
    """
    Web surface monitoring tool with built-in safeguards.
    
    Enforces:
    - Domain allowlist
    - robots.txt compliance
    - Fixed rate limiting
    - Passive-only analysis
    """
    
    # Security headers to check
    SECURITY_HEADERS = [
        'X-Frame-Options',
        'Content-Security-Policy',
        'Strict-Transport-Security',
        'X-Content-Type-Options',
        'Referrer-Policy'
    ]
    
    def __init__(self, allowed_domain: str, delay: float = 2.0):
        """
        Initialize TalonsBlue scanner.
        
        Args:
            allowed_domain: Domain that is allowed to be scanned (safeguard)
            delay: Delay in seconds between requests (rate limiting)
        """
        self.allowed_domain = allowed_domain.lower()
        self.delay = max(delay, 1.0)  # Minimum 1 second delay
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'TalonsBlue/1.0 (Authorized Security Scanner)'
        })
    
    def validate_url(self, url: str) -> bool:
        """
        Validate URL against allowlist.
        
        Args:
            url: URL to validate
            
        Returns:
            True if URL is valid and on allowlist, False otherwise
        """
        try:
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme not in ['http', 'https']:
                print(f"Error: Invalid URL scheme. Only http/https allowed.", file=sys.stderr)
                return False
            
            # Check domain against allowlist
            domain = parsed.netloc.lower()
            if domain != self.allowed_domain and not domain.endswith(f'.{self.allowed_domain}'):
                print(f"Error: Domain '{domain}' not in allowlist. Only '{self.allowed_domain}' is allowed.", 
                      file=sys.stderr)
                return False
            
            return True
        except Exception as e:
            print(f"Error: Invalid URL format: {e}", file=sys.stderr)
            return False
    
    def check_robots_txt(self, url: str) -> bool:
        """
        Check if URL is allowed by robots.txt.
        
        Args:
            url: URL to check
            
        Returns:
            True if allowed or robots.txt not found, False if disallowed
        """
        try:
            parsed = urlparse(url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            
            rp = RobotFileParser()
            rp.set_url(robots_url)
            
            # Try to read robots.txt, but don't fail if it doesn't exist
            try:
                rp.read()
            except Exception:
                # If robots.txt doesn't exist or can't be read, allow by default
                return True
            
            # Check if our user agent can fetch this URL
            can_fetch = rp.can_fetch(self.session.headers['User-Agent'], url)
            
            if not can_fetch:
                print(f"Error: URL disallowed by robots.txt", file=sys.stderr)
                return False
            
            return True
        except Exception as e:
            print(f"Warning: Could not check robots.txt: {e}", file=sys.stderr)
            # Allow by default if we can't check
            return True
    
    def scan_url(self, url: str) -> Optional[Dict]:
        """
        Perform passive security scan of URL.
        
        Args:
            url: URL to scan
            
        Returns:
            Dictionary with scan results, or None on error
        """
        # Validate URL against allowlist
        if not self.validate_url(url):
            return None
        
        # Check robots.txt compliance
        if not self.check_robots_txt(url):
            return None
        
        # Apply rate limiting delay
        time.sleep(self.delay)
        
        try:
            # Fetch the page
            response = self.session.get(url, timeout=10, allow_redirects=True)
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for missing security headers
            missing_headers = []
            for header in self.SECURITY_HEADERS:
                if header not in response.headers:
                    missing_headers.append(header)
            
            # Count forms
            forms = soup.find_all('form')
            forms_detected = len(forms)
            
            # Check HTTPS enforcement
            https_enforced = response.url.startswith('https://')
            
            # Get server header
            server_header = response.headers.get('Server', 'Unknown')
            
            # Build result
            result = {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'url': response.url,
                'status_code': response.status_code,
                'content_length': len(response.content),
                'https_enforced': https_enforced,
                'forms_detected': forms_detected,
                'missing_security_headers': missing_headers,
                'server_header': server_header
            }
            
            return result
            
        except requests.exceptions.Timeout:
            print(f"Error: Request timeout for {url}", file=sys.stderr)
            return None
        except requests.exceptions.ConnectionError:
            print(f"Error: Connection failed for {url}", file=sys.stderr)
            return None
        except requests.exceptions.RequestException as e:
            print(f"Error: Request failed: {e}", file=sys.stderr)
            return None
        except Exception as e:
            print(f"Error: Unexpected error during scan: {e}", file=sys.stderr)
            return None


def main():
    """
    Main entry point for Talons Blue CLI.
    """
    parser = argparse.ArgumentParser(
        description='Talons Blue - Scoped Defensive Web Surface Monitoring Tool',
        epilog='Only use on systems you own or have explicit authorization to test.'
    )
    
    parser.add_argument(
        '--url',
        required=True,
        help='URL to scan (must be on allowed domain)'
    )
    
    parser.add_argument(
        '--domain',
        required=True,
        help='Allowed domain (safeguard - only this domain can be scanned)'
    )
    
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results in JSON format'
    )
    
    parser.add_argument(
        '--delay',
        type=float,
        default=2.0,
        help='Delay between requests in seconds (minimum 1.0, default 2.0)'
    )
    
    args = parser.parse_args()
    
    # Create scanner instance
    scanner = TalonsBlue(allowed_domain=args.domain, delay=args.delay)
    
    # Perform scan
    result = scanner.scan_url(args.url)
    
    if result is None:
        sys.exit(1)
    
    # Output results
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("\n=== Talons Blue Scan Results ===\n")
        print(f"Timestamp:           {result['timestamp']}")
        print(f"URL:                 {result['url']}")
        print(f"Status Code:         {result['status_code']}")
        print(f"Content Length:      {result['content_length']} bytes")
        print(f"HTTPS Enforced:      {result['https_enforced']}")
        print(f"Forms Detected:      {result['forms_detected']}")
        print(f"Server Header:       {result['server_header']}")
        
        if result['missing_security_headers']:
            print(f"\nMissing Security Headers:")
            for header in result['missing_security_headers']:
                print(f"  - {header}")
        else:
            print(f"\nMissing Security Headers: None")
        
        print("\n================================\n")
    
    sys.exit(0)


if __name__ == '__main__':
    main()
