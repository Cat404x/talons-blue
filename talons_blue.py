import requests
import urllib.robotparser
import time
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime, timezone


class TalonsBlue:

    def __init__(self, allowed_domains, delay=5):
        self.allowed_domains = allowed_domains
        self.delay = delay

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "TalonsBlue/1.0 (Defensive Surface Monitor)"
        })

    def _allowed_domain(self, url):
        domain = urlparse(url).netloc
        return any(d in domain for d in self.allowed_domains)

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

    def scan(self, url):

        if not self._allowed_domain(url):
            raise PermissionError("Domain not allowed.")

        if not self._robots_allowed(url):
            raise PermissionError("Blocked by robots.txt.")

        time.sleep(self.delay)

        r = self.session.get(url, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")

        required = [
            "X-Frame-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security"
        ]

        missing = [h for h in required if h not in r.headers]

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "url": url,
            "status": r.status_code,
            "missing_security_headers": missing,
            "forms_detected": len(soup.find_all("form"))
        }
