#!/usr/bin/env python3
"""
Talons Blue - Scoped Defensive Web Surface Monitoring Tool

A passive security validation tool for authorized compliance auditing.
Enforces domain allowlisting, robots.txt compliance, and rate limiting.
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional, Tuple

import requests
from bs4 import BeautifulSoup


class TalonsBlue:
    """Main class for Talons Blue web surface monitoring."""
    
    SECURITY_HEADERS = [
        'X-Frame-Options',
        'Content-Security-Policy',
        'Strict-Transport-Security',
        'X-Content-Type-Options',
        'Referrer-Policy'
    ]
    
    def __init__(self, url: str, allowed_domain: str, delay: int = 2):
        """
        Initialize Talons Blue scanner.
        
        Args:
            url: Target URL to scan
            allowed_domain: Domain that is allowed to be scanned
            delay: Delay in seconds between requests (default: 2)
        """
        self.url = url
        self.allowed_domain = allowed_domain
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'TalonsBlue/1.0 (Security Validation Tool)'
        })
    
    def validate_url_scheme(self) -> bool:
        """
        Validate that the URL uses http or https scheme.
        
        Returns:
            True if URL scheme is valid, False otherwise
        """
        parsed = urlparse(self.url)
        if parsed.scheme not in ('http', 'https'):
            print(f"Error: Invalid URL scheme '{parsed.scheme}'. Only http and https are supported.", file=sys.stderr)
            return False
        return True
    
    def validate_domain(self) -> bool:
        """
        Validate that the target URL domain matches the allowed domain.
        
        Returns:
            True if domain is allowed, False otherwise
        """
        parsed = urlparse(self.url)
        domain = parsed.netloc
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        if domain != self.allowed_domain:
            print(f"Error: Domain '{domain}' is not in the allowlist. Expected '{self.allowed_domain}'.", file=sys.stderr)
            return False
        return True
    
    def check_robots_txt(self) -> Tuple[bool, Optional[str]]:
        """
        Check robots.txt for permission to access the URL.
        
        Returns:
            Tuple of (allowed, error_message)
        """
        parsed = urlparse(self.url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        
        try:
            response = self.session.get(robots_url, timeout=10)
            if response.status_code == 200:
                # Simple robots.txt parsing - check for Disallow rules
                lines = response.text.split('\n')
                user_agent_applies = False
                
                for line in lines:
                    line = line.strip()
                    
                    # Check User-agent directive and set flag accordingly
                    if line.lower().startswith('user-agent:'):
                        agent = line.split(':', 1)[1].strip()
                        # Only apply rules if user-agent is '*' or 'talonsblue'
                        user_agent_applies = agent == '*' or 'talonsblue' in agent.lower()
                    
                    # Check Disallow rules only if current user-agent section applies
                    elif user_agent_applies and line.lower().startswith('disallow:'):
                        disallow_path = line.split(':', 1)[1].strip()
                        if disallow_path and disallow_path != '/':
                            target_path = urlparse(self.url).path or '/'
                            if target_path.startswith(disallow_path):
                                return False, f"robots.txt disallows access to {disallow_path}"
                        elif disallow_path == '/':
                            return False, "robots.txt disallows all access"
            
            # If robots.txt doesn't exist or doesn't disallow, proceed
            return True, None
            
        except requests.RequestException as e:
            # If robots.txt is not accessible, we assume it's okay to proceed
            return True, None
    
    def apply_delay(self):
        """Apply configured delay before making request."""
        if self.delay > 0:
            time.sleep(self.delay)
    
    def fetch_page(self) -> Optional[requests.Response]:
        """
        Fetch the target page.
        
        Returns:
            Response object or None if request fails
        """
        try:
            response = self.session.get(self.url, timeout=15, allow_redirects=True)
            return response
        except requests.RequestException as e:
            print(f"Error: Failed to fetch page: {e}", file=sys.stderr)
            return None
    
    def check_https_enforced(self) -> bool:
        """
        Check if HTTPS is enforced by attempting HTTP connection.
        
        Returns:
            True if HTTPS is enforced, False otherwise
        """
        parsed = urlparse(self.url)
        
        # If original URL is HTTPS, check if HTTP redirects to HTTPS
        if parsed.scheme == 'https':
            http_url = self.url.replace('https://', 'http://')
            try:
                response = self.session.get(http_url, timeout=10, allow_redirects=True)
                return urlparse(response.url).scheme == 'https'
            except requests.RequestException:
                # If HTTP fails, assume HTTPS is enforced
                return True
        
        return False
    
    def analyze_security_headers(self, response: requests.Response) -> List[str]:
        """
        Analyze security headers in the response.
        
        Args:
            response: Response object to analyze
            
        Returns:
            List of missing security headers
        """
        missing_headers = []
        
        for header in self.SECURITY_HEADERS:
            if header not in response.headers:
                missing_headers.append(header)
        
        return missing_headers
    
    def detect_forms(self, response: requests.Response) -> int:
        """
        Detect HTML forms in the page.
        
        Args:
            response: Response object to analyze
            
        Returns:
            Number of forms detected
        """
        try:
            soup = BeautifulSoup(response.content, 'html.parser')
            forms = soup.find_all('form')
            return len(forms)
        except Exception as e:
            print(f"Warning: Failed to parse HTML for form detection: {e}", file=sys.stderr)
            return 0
    
    def get_server_header(self, response: requests.Response) -> Optional[str]:
        """
        Extract Server header from response.
        
        Args:
            response: Response object to analyze
            
        Returns:
            Server header value or None
        """
        return response.headers.get('Server')
    
    def scan(self) -> Optional[Dict]:
        """
        Perform complete scan workflow.
        
        Returns:
            Dictionary with scan results or None if scan fails
        """
        # Step 1: Validate URL scheme
        if not self.validate_url_scheme():
            return None
        
        # Step 2: Validate domain against allowlist
        if not self.validate_domain():
            return None
        
        # Step 3: Validate robots.txt permission
        allowed, error_msg = self.check_robots_txt()
        if not allowed:
            print(f"Error: {error_msg}", file=sys.stderr)
            return None
        
        # Step 4: Apply fixed delay
        self.apply_delay()
        
        # Step 5: Retrieve page content
        response = self.fetch_page()
        if response is None:
            return None
        
        # Step 6: Perform passive analysis
        https_enforced = self.check_https_enforced()
        missing_headers = self.analyze_security_headers(response)
        forms_detected = self.detect_forms(response)
        server_header = self.get_server_header(response)
        
        # Step 7: Return structured result
        result = {
            'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'url': self.url,
            'status_code': response.status_code,
            'content_length': len(response.content),
            'https_enforced': https_enforced,
            'forms_detected': forms_detected,
            'missing_security_headers': missing_headers,
            'server_header': server_header
        }
        
        return result


def format_output_human_readable(result: Dict) -> str:
    """
    Format scan results in human-readable format.
    
    Args:
        result: Dictionary with scan results
        
    Returns:
        Formatted string
    """
    output = []
    output.append("=" * 60)
    output.append("Talons Blue - Scan Results")
    output.append("=" * 60)
    output.append(f"Timestamp:       {result['timestamp']}")
    output.append(f"URL:             {result['url']}")
    output.append(f"Status Code:     {result['status_code']}")
    output.append(f"Content Length:  {result['content_length']} bytes")
    output.append(f"HTTPS Enforced:  {'Yes' if result['https_enforced'] else 'No'}")
    output.append(f"Forms Detected:  {result['forms_detected']}")
    
    if result['missing_security_headers']:
        output.append("\nMissing Security Headers:")
        for header in result['missing_security_headers']:
            output.append(f"  - {header}")
    else:
        output.append("\nMissing Security Headers: None")
    
    if result['server_header']:
        output.append(f"\nServer:          {result['server_header']}")
    else:
        output.append("\nServer:          Not disclosed")
    
    output.append("=" * 60)
    
    return "\n".join(output)


def main():
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description='Talons Blue - Scoped Defensive Web Surface Monitoring Tool',
        epilog='For authorized security validation and compliance auditing only.'
    )
    
    parser.add_argument(
        '--url',
        required=True,
        help='Target URL to scan (must use http or https scheme)'
    )
    
    parser.add_argument(
        '--domain',
        required=True,
        help='Allowed domain for scanning (domain allowlist enforcement)'
    )
    
    parser.add_argument(
        '--delay',
        type=int,
        default=2,
        help='Delay in seconds before making request (default: 2)'
    )
    
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results in JSON format'
    )
    
    args = parser.parse_args()
    
    # Create scanner instance
    scanner = TalonsBlue(args.url, args.domain, args.delay)
    
    # Perform scan
    result = scanner.scan()
    
    if result is None:
        sys.exit(1)
    
    # Output results
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(format_output_human_readable(result))
    
    sys.exit(0)


if __name__ == '__main__':
    main()
