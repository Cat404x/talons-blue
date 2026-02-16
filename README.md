

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
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Requirements

- Python 3.9+
- requests
- beautifulsoup4

---

## Usage

The `talons_blue.py` script provides a command-line interface for scanning authorized domains. Below are detailed examples of how to run the script with different arguments.

### Command-Line Arguments

- `--url` (required): The target URL to scan
- `--domain` (required): The authorized domain (e.g., example.com)
- `--delay` (optional): Delay between requests in seconds (default: 5)
- `--json` (optional): Output results in formatted JSON

### Basic Single-Domain Scan

Scan a single URL on an authorized domain with default settings:

```bash
python talons_blue.py --url https://example.com --domain example.com
```

**Output:**
```
{'timestamp': '2026-02-16T04:30:00.123456', 'url': 'https://example.com', 'status_code': 200, 'content_length': 12564, 'https_enforced': True, 'forms_detected': 1, 'missing_security_headers': ['X-Frame-Options'], 'server_header': 'nginx'}
```

### Single-Domain Scan with JSON Output

Enable JSON formatting for easier parsing and integration:

```bash
python talons_blue.py --url https://example.com --domain example.com --json
```

**Output:**
```json
{
    "timestamp": "2026-02-16T04:30:00.123456",
    "url": "https://example.com",
    "status_code": 200,
    "content_length": 12564,
    "https_enforced": true,
    "forms_detected": 1,
    "missing_security_headers": [
        "X-Frame-Options"
    ],
    "server_header": "nginx"
}
```

### Scan with Custom Delay

Adjust the delay between requests (useful for respecting rate limits):

```bash
python talons_blue.py --url https://example.com --domain example.com --delay 3
```

### Multiple URL Scans on the Same Domain

To scan multiple URLs on the same domain, run the script multiple times or use a shell script:

```bash
# Using a simple loop
for url in https://example.com https://example.com/about https://example.com/contact; do
    python talons_blue.py --url "$url" --domain example.com --json
    echo "---"
done
```

Or create a shell script:

```bash
#!/bin/bash
# multi_scan.sh

DOMAIN="example.com"
URLS=(
    "https://example.com"
    "https://example.com/about"
    "https://example.com/contact"
    "https://example.com/products"
)

for url in "${URLS[@]}"; do
    echo "Scanning: $url"
    python talons_blue.py --url "$url" --domain "$DOMAIN" --json
    echo "---"
done
```

Make it executable and run:

```bash
chmod +x multi_scan.sh
./multi_scan.sh
```

### Scanning Subdomains

The domain allowlist supports subdomains. To scan subdomains, specify the parent domain:

```bash
# Scanning www subdomain
python talons_blue.py --url https://www.example.com --domain example.com --json

# Scanning api subdomain
python talons_blue.py --url https://api.example.com --domain example.com --json
```

### Combining Options

You can combine multiple options for more control:

```bash
# JSON output with custom delay
python talons_blue.py --url https://example.com --domain example.com --json --delay 10
```

---

## Example Output

### Standard Output

```
{'timestamp': '2026-02-16T04:30:00.123456', 'url': 'https://example.com', 'status_code': 200, 'content_length': 12564, 'https_enforced': True, 'forms_detected': 1, 'missing_security_headers': [], 'server_header': 'nginx'}
```

### JSON Output

```json
{
    "timestamp": "2026-02-16T04:30:00.123456",
    "url": "https://example.com",
    "status_code": 200,
    "content_length": 12564,
    "https_enforced": true,
    "forms_detected": 1,
    "missing_security_headers": [],
    "server_header": "nginx"
}
```

---

## Architecture

Talons Blue operates in the following sequence:

1. Validate URL scheme (http/https)
2. Validate domain against allowlist
3. Validate robots.txt permission
4. Apply fixed delay
5. Retrieve page content
6. Perform passive header and surface analysis
7. Return structured result

---

## Legal Notice

Talons Blue is intended only for:

- Assets you own
- Systems you have explicit written authorization to test
- Compliance and defensive validation purposes

Unauthorized use may violate local laws and platform policies.

---

## License

MIT License  
Copyright (c) 2026
