# talons-blue
Purpose: Defensive surface validation for owned or authorized assets.

## Overview

TalonsBlue is a web security scanner designed for defensive surface validation of owned or authorized assets. It checks URLs for security headers and analyzes HTML forms while respecting robots.txt and domain restrictions.

## Features

- Domain whitelisting to ensure scanning only authorized assets
- Robots.txt compliance to respect website crawling policies
- Security header detection (X-Frame-Options, Content-Security-Policy, Strict-Transport-Security)
- HTML form detection
- Configurable delay between requests

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```python
from talons_blue import TalonsBlue

# Initialize scanner with allowed domains
scanner = TalonsBlue(allowed_domains=["example.com", "mysite.com"], delay=5)

# Scan a URL
result = scanner.scan("https://example.com")

print(result)
# Output:
# {
#     "timestamp": "2024-01-01T12:00:00.000000+00:00",
#     "url": "https://example.com",
#     "status": 200,
#     "missing_security_headers": ["Content-Security-Policy"],
#     "forms_detected": 2
# }
```

## Running Tests

```bash
python3 -m unittest test_talons_blue.py -v
```

## Example

See `example.py` for a complete working example.

## License

See LICENSE file for details.

