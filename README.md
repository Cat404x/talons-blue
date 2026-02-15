

# Talons Blue

Talons Blue is a scoped defensive web surface monitoring tool designed for authorized security validation and compliance auditing.

It performs passive analysis of publicly accessible web pages while enforcing strict safeguards such as domain allowlisting and robots.txt compliance.

---

## Overview

Talons Blue helps security teams validate surface exposure by:

- Ensuring scans only target approved domains
- Respecting robots.txt restrictions
- Applying fixed request delay to reduce load
- Inspecting HTTP security headers
- Detecting exposed HTML forms
- Reporting HTTPS enforcement status

This tool is strictly passive and does not perform crawling, brute-force enumeration, or evasion techniques.

---

## Features

- Domain allowlist enforcement
- robots.txt compliance validation
- Fixed request rate limiting
- Security header validation:
  - X-Frame-Options
  - Content-Security-Policy
  - Strict-Transport-Security
  - X-Content-Type-Options
  - Referrer-Policy
- HTML `<form>` detection
- Server header reporting
- JSON formatted output option
- CLI support

---

## Installation

Clone the repository:

```bash
git clone https://github.com/Cat404x/talons-blue.git
cd talons-blue

Install dependencies:

pip install -r requirements.txt


⸻

Requirements
	•	Python 3.9+
	•	requests
	•	beautifulsoup4

⸻

Usage

Basic scan:

python talons_blue.py --url https://example.com --domain example.com

JSON output:

python talons_blue.py --url https://example.com --domain example.com --json

Custom delay:

python talons_blue.py --url https://example.com --domain example.com --delay 3


⸻

Example Output

{
    "timestamp": "2026-01-01T12:00:00",
    "url": "https://example.com",
    "status_code": 200,
    "content_length": 12564,
    "https_enforced": true,
    "forms_detected": 1,
    "missing_security_headers": [],
    "server_header": "nginx"
}


⸻

Architecture

Talons Blue operates in the following sequence:
	1.	Validate URL scheme (http/https)
	2.	Validate domain against allowlist
	3.	Validate robots.txt permission
	4.	Apply fixed delay
	5.	Retrieve page content
	6.	Perform passive header and surface analysis
	7.	Return structured result

⸻

Legal Notice

Talons Blue is intended only for:
	•	Assets you own
	•	Systems you have explicit written authorization to test
	•	Compliance and defensive validation purposes

Unauthorized use may violate local laws and platform policies.

⸻

License

MIT License
Copyright (c) 2026 
