"""
Scanner module for defensive surface validation.
"""

import socket
import ssl
from typing import Dict, List, Any, Optional
from datetime import datetime

from .utils import validate_url, validate_ip


class Scanner:
    """
    Main scanner class for performing defensive surface validation.
    """
    
    def __init__(self, timeout: int = 5):
        """
        Initialize the scanner.
        
        Args:
            timeout: Socket timeout in seconds
        """
        self.timeout = timeout
        self.results: List[Dict[str, Any]] = []
    
    def scan_target(self, target: str) -> Dict[str, Any]:
        """
        Scan a single target for security surface validation.
        
        Args:
            target: URL or IP address to scan
            
        Returns:
            Dict containing scan results
        """
        result = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'findings': [],
            'status': 'unknown'
        }
        
        # Validate target format
        if validate_url(target):
            result.update(self._scan_url(target))
        elif validate_ip(target):
            result.update(self._scan_ip(target))
        else:
            result['status'] = 'invalid'
            result['findings'].append('Invalid target format')
        
        self.results.append(result)
        return result
    
    def _scan_url(self, url: str) -> Dict[str, Any]:
        """
        Scan a URL target.
        
        Args:
            url: The URL to scan
            
        Returns:
            Dict with scan findings
        """
        findings = []
        status = 'completed'
        
        # Extract hostname from URL
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.netloc
        
        # Check if using HTTPS
        if parsed.scheme == 'http':
            findings.append('Using insecure HTTP protocol')
        
        # Try to get SSL certificate info if HTTPS
        if parsed.scheme == 'https':
            try:
                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        findings.append(f"SSL certificate found for {hostname}")
            except Exception as e:
                findings.append(f"SSL check failed: {str(e)}")
        
        # Basic port connectivity check
        try:
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            with socket.create_connection((hostname, port), timeout=self.timeout):
                findings.append(f"Port {port} is open")
        except Exception as e:
            findings.append(f"Connection failed: {str(e)}")
            status = 'failed'
        
        return {'status': status, 'findings': findings}
    
    def _scan_ip(self, ip: str) -> Dict[str, Any]:
        """
        Scan an IP address target.
        
        Args:
            ip: The IP address to scan
            
        Returns:
            Dict with scan findings
        """
        findings = []
        status = 'completed'
        
        # Common ports to check
        common_ports = [80, 443, 22, 21, 3306, 5432, 8080]
        
        for port in common_ports:
            try:
                with socket.create_connection((ip, port), timeout=self.timeout):
                    findings.append(f"Port {port} is open")
            except (socket.timeout, ConnectionRefusedError, OSError):
                # Port is closed or filtered
                pass
        
        if not findings:
            findings.append('No common ports found open')
        
        return {'status': status, 'findings': findings}
    
    def scan_multiple(self, targets: List[str]) -> List[Dict[str, Any]]:
        """
        Scan multiple targets.
        
        Args:
            targets: List of URLs or IP addresses to scan
            
        Returns:
            List of scan results
        """
        results = []
        for target in targets:
            result = self.scan_target(target)
            results.append(result)
        return results
    
    def get_results(self) -> List[Dict[str, Any]]:
        """
        Get all scan results.
        
        Returns:
            List of all scan results
        """
        return self.results
    
    def clear_results(self) -> None:
        """
        Clear all stored scan results.
        """
        self.results = []
