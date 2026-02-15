"""
Utility functions for Talons Blue scanner.
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse


def validate_url(url: str) -> bool:
    """
    Validate if a string is a valid URL.
    
    Args:
        url: The URL string to validate
        
    Returns:
        bool: True if valid URL, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def validate_ip(ip: str) -> bool:
    """
    Validate if a string is a valid IP address (IPv4).
    
    Args:
        ip: The IP address string to validate
        
    Returns:
        bool: True if valid IP, False otherwise
    """
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    
    parts = ip.split('.')
    return all(0 <= int(part) <= 255 for part in parts)


def format_scan_result(result: Dict[str, Any]) -> str:
    """
    Format scan result for display.
    
    Args:
        result: Dictionary containing scan results
        
    Returns:
        str: Formatted string representation
    """
    lines = []
    lines.append(f"Target: {result.get('target', 'Unknown')}")
    lines.append(f"Status: {result.get('status', 'Unknown')}")
    
    if 'findings' in result:
        lines.append(f"Findings: {len(result['findings'])}")
        for i, finding in enumerate(result['findings'], 1):
            lines.append(f"  {i}. {finding}")
    
    return '\n'.join(lines)


def parse_target_list(target_input: str) -> List[str]:
    """
    Parse a comma-separated list of targets.
    
    Args:
        target_input: Comma-separated string of targets
        
    Returns:
        List[str]: List of individual targets
    """
    return [target.strip() for target in target_input.split(',') if target.strip()]
