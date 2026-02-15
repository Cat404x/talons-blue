#!/usr/bin/env python3
"""
Unit tests for TalonsBlue scanner
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from talons_blue import TalonsBlue
import requests


class TestTalonsBlue(unittest.TestCase):

    def setUp(self):
        self.scanner = TalonsBlue(allowed_domains=["example.com", "test.com"], delay=0)

    def test_init(self):
        """Test initialization"""
        self.assertEqual(self.scanner.allowed_domains, ["example.com", "test.com"])
        self.assertEqual(self.scanner.delay, 0)
        self.assertIsInstance(self.scanner.session, requests.Session)
        self.assertEqual(
            self.scanner.session.headers["User-Agent"],
            "TalonsBlue/1.0 (Defensive Surface Monitor)"
        )

    def test_allowed_domain_true(self):
        """Test domain is allowed"""
        self.assertTrue(self.scanner._allowed_domain("https://example.com/page"))
        self.assertTrue(self.scanner._allowed_domain("https://www.example.com/page"))
        self.assertTrue(self.scanner._allowed_domain("https://test.com"))

    def test_allowed_domain_false(self):
        """Test domain is not allowed"""
        self.assertFalse(self.scanner._allowed_domain("https://notallowed.com/page"))
        self.assertFalse(self.scanner._allowed_domain("https://other.org"))

    @patch('urllib.robotparser.RobotFileParser')
    def test_robots_allowed_true(self, mock_robot_parser):
        """Test robots.txt allows access"""
        mock_rp = MagicMock()
        mock_rp.can_fetch.return_value = True
        mock_robot_parser.return_value = mock_rp
        
        result = self.scanner._robots_allowed("https://example.com/page")
        self.assertTrue(result)

    @patch('urllib.robotparser.RobotFileParser')
    def test_robots_allowed_false(self, mock_robot_parser):
        """Test robots.txt blocks access"""
        mock_rp = MagicMock()
        mock_rp.can_fetch.return_value = False
        mock_robot_parser.return_value = mock_rp
        
        result = self.scanner._robots_allowed("https://example.com/page")
        self.assertFalse(result)

    @patch('urllib.robotparser.RobotFileParser')
    def test_robots_allowed_exception(self, mock_robot_parser):
        """Test robots.txt read exception returns False"""
        mock_rp = MagicMock()
        mock_rp.read.side_effect = Exception("Network error")
        mock_robot_parser.return_value = mock_rp
        
        result = self.scanner._robots_allowed("https://example.com/page")
        self.assertFalse(result)

    def test_scan_domain_not_allowed(self):
        """Test scan raises error for disallowed domain"""
        with self.assertRaises(PermissionError) as context:
            self.scanner.scan("https://notallowed.com")
        self.assertEqual(str(context.exception), "Domain not allowed.")

    @patch.object(TalonsBlue, '_robots_allowed')
    def test_scan_robots_blocked(self, mock_robots):
        """Test scan raises error when blocked by robots.txt"""
        mock_robots.return_value = False
        
        with self.assertRaises(PermissionError) as context:
            self.scanner.scan("https://example.com")
        self.assertEqual(str(context.exception), "Blocked by robots.txt.")

    @patch('time.sleep')
    @patch.object(TalonsBlue, '_robots_allowed')
    @patch.object(TalonsBlue, '_allowed_domain')
    def test_scan_success(self, mock_allowed, mock_robots, mock_sleep):
        """Test successful scan"""
        mock_allowed.return_value = True
        mock_robots.return_value = True
        
        # Mock the HTTP response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '<html><body><form></form><form></form></body></html>'
        mock_response.headers = {
            "X-Frame-Options": "DENY",
            "Content-Type": "text/html"
        }
        
        with patch.object(self.scanner.session, 'get', return_value=mock_response):
            result = self.scanner.scan("https://example.com")
            
            self.assertEqual(result["url"], "https://example.com")
            self.assertEqual(result["status"], 200)
            self.assertEqual(result["forms_detected"], 2)
            self.assertIn("Content-Security-Policy", result["missing_security_headers"])
            self.assertIn("Strict-Transport-Security", result["missing_security_headers"])
            self.assertNotIn("X-Frame-Options", result["missing_security_headers"])
            self.assertIn("timestamp", result)

    @patch('time.sleep')
    @patch.object(TalonsBlue, '_robots_allowed')
    @patch.object(TalonsBlue, '_allowed_domain')
    def test_scan_all_headers_present(self, mock_allowed, mock_robots, mock_sleep):
        """Test scan with all security headers present"""
        mock_allowed.return_value = True
        mock_robots.return_value = True
        
        # Mock the HTTP response with all security headers
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '<html><body></body></html>'
        mock_response.headers = {
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000"
        }
        
        with patch.object(self.scanner.session, 'get', return_value=mock_response):
            result = self.scanner.scan("https://example.com")
            
            self.assertEqual(result["missing_security_headers"], [])
            self.assertEqual(result["forms_detected"], 0)


if __name__ == '__main__':
    unittest.main()
