#!/usr/bin/env python3
"""
Talons Blue - Scoped Defensive Web Surface Monitoring Tool

DESCRIPTION:
    Talons Blue is a scoped defensive web surface monitoring tool designed for 
    authorized security validation and compliance auditing. It performs passive 
    analysis of publicly accessible web pages while enforcing strict safeguards 
    such as domain allowlisting and robots.txt compliance.

AUTHOR:
    Cat404x

VERSION:
    1.0.0

LICENSE:
    MIT License
    Copyright (c) 2026 Cat404x
    
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

USAGE POLICY & LEGAL NOTICE:
    Talons Blue is intended ONLY for:
    • Assets you own
    • Systems you have explicit written authorization to test
    • Compliance and defensive validation purposes
    
    Unauthorized use may violate local laws and platform policies.
    
    This tool is strictly passive and does NOT perform:
    • Crawling
    • Brute-force enumeration
    • Evasion techniques

REQUIREMENTS:
    • Python 3.9+
    • requests
    • beautifulsoup4

USAGE:
    Basic scan:
        python talons_blue.py --url https://example.com --domain example.com
    
    JSON output:
        python talons_blue.py --url https://example.com --domain example.com --json
    
    Custom delay:
        python talons_blue.py --url https://example.com --domain example.com --delay 3

ARCHITECTURE & WORKFLOW:
    Talons Blue operates in the following sequence:
    1. Validate URL scheme (http/https)
    2. Validate domain against allowlist
    3. Validate robots.txt permission
    4. Apply fixed delay
    5. Retrieve page content
    6. Perform passive header and surface analysis
    7. Return structured result

FEATURES:
    • Domain allowlist enforcement
    • robots.txt compliance validation
    • Fixed request rate limiting
    • Security header validation:
        - X-Frame-Options
        - Content-Security-Policy
        - Strict-Transport-Security
        - X-Content-Type-Options
        - Referrer-Policy
    • HTML <form> detection
    • Server header reporting
    • JSON formatted output option
    • CLI support

STRUCTURAL LAYOUT:
    - validate_url_scheme(url): Validates URL uses http or https
    - validate_domain(url, allowed_domain): Validates domain against allowlist
    - check_robots_txt(url): Validates robots.txt permissions
    - fetch_page(url, delay): Retrieves page with rate limiting
    - analyze_security_headers(headers): Checks for security headers
    - detect_forms(html_content): Detects HTML forms
    - scan_url(url, domain, delay, json_output): Main scanning function
    - main(): CLI entry point
"""

import sys
import time
import json
import argparse
from datetime import datetime
from urllib.parse import urlparse, urljoin
from urllib.robotparser import RobotFileParser

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError as e:
    print(f"Error: Missing required dependency - {e}")
    print("Install dependencies with: pip install requests beautifulsoup4")
    sys.exit(1)


# Constants
VERSION = "1.0.0"
DEFAULT_DELAY = 2
SECURITY_HEADERS = [
    "X-Frame-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy"
]


def validate_url_scheme(url):
    """
    Validates that the URL uses http or https scheme.
    
    Args:
        url (str): The URL to validate
        
    Returns:
        bool: True if scheme is valid, False otherwise
    """
    parsed = urlparse(url)
    return parsed.scheme in ('http', 'https')


def validate_domain(url, allowed_domain):
    """
    Validates that the URL domain matches the allowed domain.
    
    Args:
        url (str): The URL to validate
        allowed_domain (str): The allowed domain
        
    Returns:
        bool: True if domain is allowed, False otherwise
    """
    parsed = urlparse(url)
    return parsed.netloc == allowed_domain or parsed.netloc.endswith(f'.{allowed_domain}')


def check_robots_txt(url):
    """
    Checks robots.txt to ensure the URL is allowed for crawling.
    
    Args:
        url (str): The URL to check
        
    Returns:
        bool: True if allowed, False otherwise
    """
    try:
        parsed = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        
        rp = RobotFileParser()
        rp.set_url(robots_url)
        rp.read()
        
        return rp.can_fetch("*", url)
    except Exception as e:
        print(f"Warning: Could not fetch robots.txt: {e}")
        return True


def fetch_page(url, delay=DEFAULT_DELAY):
    """
    Fetches the page content with rate limiting.
    
    Args:
        url (str): The URL to fetch
        delay (int): Delay in seconds before fetching
        
    Returns:
        tuple: (response object, error message)
    """
    time.sleep(delay)
    
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        return response, None
    except requests.RequestException as e:
        return None, str(e)


def analyze_security_headers(headers):
    """
    Analyzes HTTP headers for security-related headers.
    
    Args:
        headers (dict): HTTP response headers
        
    Returns:
        list: List of missing security headers
    """
    missing_headers = []
    for header in SECURITY_HEADERS:
        if header not in headers:
            missing_headers.append(header)
    return missing_headers


def detect_forms(html_content):
    """
    Detects HTML forms in the page content.
    
    Args:
        html_content (str): HTML content to analyze
        
    Returns:
        int: Number of forms detected
    """
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        forms = soup.find_all('form')
        return len(forms)
    except Exception as e:
        print(f"Warning: Error parsing HTML: {e}")
        return 0


def scan_url(url, domain, delay=DEFAULT_DELAY, json_output=False):
    """
    Main scanning function that orchestrates the entire validation and analysis workflow.
    
    Args:
        url (str): The URL to scan
        domain (str): The allowed domain
        delay (int): Delay in seconds before fetching
        json_output (bool): Whether to output in JSON format
        
    Returns:
        dict: Scan results
    """
    # Step 1: Validate URL scheme
    if not validate_url_scheme(url):
        error = "Error: Invalid URL scheme. Must use http or https."
        if json_output:
            return {"error": error}
        print(error)
        return None
    
    # Step 2: Validate domain against allowlist
    if not validate_domain(url, domain):
        error = f"Error: Domain not in allowlist. Only {domain} is allowed."
        if json_output:
            return {"error": error}
        print(error)
        return None
    
    # Step 3: Validate robots.txt permission
    if not check_robots_txt(url):
        error = "Error: Access denied by robots.txt"
        if json_output:
            return {"error": error}
        print(error)
        return None
    
    # Step 4 & 5: Apply delay and fetch page
    response, error = fetch_page(url, delay)
    if error:
        error_msg = f"Error: Failed to fetch URL: {error}"
        if json_output:
            return {"error": error_msg}
        print(error_msg)
        return None
    
    # Step 6: Perform passive analysis
    missing_headers = analyze_security_headers(response.headers)
    forms_count = detect_forms(response.text)
    
    # Step 7: Return structured result
    result = {
        "timestamp": datetime.now().isoformat(),
        "url": url,
        "status_code": response.status_code,
        "content_length": len(response.content),
        "https_enforced": url.startswith("https://"),
        "forms_detected": forms_count,
        "missing_security_headers": missing_headers,
        "server_header": response.headers.get("Server", "Not disclosed")
    }
    
    return result


def main():
    """
    CLI entry point for Talons Blue.
    """
    parser = argparse.ArgumentParser(
        description="Talons Blue - Scoped Defensive Web Surface Monitoring Tool",
        epilog="For authorized security validation and compliance auditing only."
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Target URL to scan"
    )
    parser.add_argument(
        "--domain",
        required=True,
        help="Allowed domain for scanning"
    )
    parser.add_argument(
        "--delay",
        type=int,
        default=DEFAULT_DELAY,
        help=f"Request delay in seconds (default: {DEFAULT_DELAY})"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"Talons Blue {VERSION}"
    )
    
    args = parser.parse_args()
    
    # Perform scan
    result = scan_url(args.url, args.domain, args.delay, args.json)
    
    # Output results
    if result:
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print("\n=== Talons Blue Scan Results ===")
            print(f"Timestamp: {result.get('timestamp', 'N/A')}")
            print(f"URL: {result.get('url', 'N/A')}")
            print(f"Status Code: {result.get('status_code', 'N/A')}")
            print(f"Content Length: {result.get('content_length', 'N/A')} bytes")
            print(f"HTTPS Enforced: {result.get('https_enforced', False)}")
            print(f"Forms Detected: {result.get('forms_detected', 0)}")
            print(f"Server Header: {result.get('server_header', 'N/A')}")
            
            missing_headers = result.get('missing_security_headers', [])
            if missing_headers:
                print(f"\nMissing Security Headers ({len(missing_headers)}):")
                for header in missing_headers:
                    print(f"  - {header}")
            else:
                print("\nAll security headers present!")
            print("\n================================\n")
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
