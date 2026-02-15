#!/usr/bin/env python3
"""
Example usage of TalonsBlue scanner
"""

from talons_blue import TalonsBlue


def main():
    # Example: Scan example.com (a commonly allowed test domain)
    scanner = TalonsBlue(allowed_domains=["example.com"], delay=1)
    
    try:
        result = scanner.scan("https://example.com")
        print("Scan Results:")
        print(f"  Timestamp: {result['timestamp']}")
        print(f"  URL: {result['url']}")
        print(f"  Status: {result['status']}")
        print(f"  Missing Security Headers: {result['missing_security_headers']}")
        print(f"  Forms Detected: {result['forms_detected']}")
    except PermissionError as e:
        print(f"Permission Error: {e}")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
