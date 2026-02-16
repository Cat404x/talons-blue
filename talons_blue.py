#!/usr/bin/env python3

"""
Talons Blue
Defensive Web Surface Monitor

Author: Cat404x
License: MIT

Purpose:
Passive surface validation for owned or authorized domains only.

Safeguards:
- Domain allowlist enforcement
- robots.txt compliance
- Fixed delay rate limiting
- No crawling
- No evasion
"""

import argparse
import requests
import urllib.robotparser
import time
import json
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime


class TalonsBlue:

    REQUIRED_HEADERS = [
        "X-Frame-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "Referrer-Policy"
    ]

    def __init__(self, allowed_domains, delay=5):

        if not allowed_domains:
            raise ValueError("allowed_domains cannot be empty")

        if delay < 0:
            raise ValueError("Delay cannot be negative")

        self.allowed_domains = [d.lower() for d in allowed_domains]
        self.delay = delay

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "TalonsBlue/1.0 (Defensive Surface Monitor)"
        })

    # --------------------------------------------------
    # Domain Validation
    # --------------------------------------------------
    def _allowed_domain(self, url):
        domain = urlparse(url).netloc.lower()
        return any(domain.endswith(d) for d in self.allowed_domains)

    # --------------------------------------------------
    # robots.txt Validation
    # --------------------------------------------------
    def _robots_allowed(self, url):
        parsed = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

        rp = urllib.robotparser.RobotFileParser()
        rp.set_url(robots_url)

        try:
            rp.read()
            return rp.can_fetch(self.session.headers["User-Agent"], url)
        except Exception:
            return False

    # --------------------------------------------------
    # Header Validation
    # --------------------------------------------------
    def _check_security_headers(self, headers):
        return [
            header for header in self.REQUIRED_HEADERS
            if header not in headers
        ]

    # --------------------------------------------------
    # Main Scan
    # --------------------------------------------------
    def scan(self, url):

        if not url.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")

        if not self._allowed_domain(url):
            raise PermissionError("Domain not in approved allowlist")

        if not self._robots_allowed(url):
            raise PermissionError("Blocked by robots.txt")

        time.sleep(self.delay)

        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Request failed: {e}")

        soup = BeautifulSoup(response.text, "html.parser")

        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "url": url,
            "status_code": response.status_code,
            "content_length": len(response.content),
            "https_enforced": url.startswith("https://"),
            "forms_detected": len(soup.find_all("form")),
            "missing_security_headers": self._check_security_headers(response.headers),
            "server_header": response.headers.get("Server", "Unknown")
        }

        return result

    # --------------------------------------------------
    # Cleanup
    # --------------------------------------------------
    def close(self):
        self.session.close()


# ==================================================
# CLI Entry
# ==================================================

def main():

    parser = argparse.ArgumentParser(
        description="Talons Blue - Defensive Web Surface Monitor"
    )

    parser.add_argument(
        "--url",
        required=True,
        help="Target URL"
    )

    parser.add_argument(
        "--domain",
        required=True,
        help="Authorized domain (example.com)"
    )

    parser.add_argument(
        "--delay",
        type=int,
        default=5,
        help="Delay between requests (seconds)"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output formatted JSON"
    )

    args = parser.parse_args()

    scanner = TalonsBlue(
        allowed_domains=[args.domain],
        delay=args.delay
    )

    try:
        result = scanner.scan(args.url)

        if args.json:
            print(json.dumps(result, indent=4))
        else:
            print(result)

    except PermissionError as e:
        print(f"[Permission Error] {e}")
    except Exception as e:
        print(f"[Error] {e}")
    finally:
        scanner.close()


if __name__ == "__main__":
    main()