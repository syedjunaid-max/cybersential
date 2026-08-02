from __future__ import annotations

import tempfile
import unittest
from datetime import date, datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import requests

import services.report_generator as report_generator
from services.header_analyzer import UnsafeRedirectError, _validate_redirect_url, analyze_security_headers
from services.password_analyzer import analyze_password
from services.port_scanner import NMAP_ARGUMENTS, PORT_RANGE, scan_tcp_ports
from services.reconnaissance import (
    TargetValidationError,
    _format_whois_value,
    normalize_assessment_target,
    normalize_target,
)
from services.report_generator import generate_assessment_report, report_path_for_scan_id


class TargetValidationTests(unittest.TestCase):
    def test_keeps_distinct_scan_host_and_complete_web_url(self):
        cases = {
            "http://127.0.0.1:5000": ("127.0.0.1", "http://127.0.0.1:5000"),
            "https://example.com:8443": ("example.com", "https://example.com:8443"),
            "localhost:5000": ("localhost", "https://localhost:5000"),
            "example.com": ("example.com", "https://example.com"),
            " HTTPS://Example.COM/path?q=1 ": ("example.com", "https://example.com/path?q=1"),
            "[2001:db8::1]": ("2001:db8::1", "https://[2001:db8::1]"),
        }
        for submitted, (expected_host, expected_url) in cases.items():
            with self.subTest(submitted=submitted):
                normalized = normalize_assessment_target(submitted)
                self.assertEqual(normalized.scan_host, expected_host)
                self.assertEqual(normalized.web_url, expected_url)
                self.assertEqual(normalize_target(submitted), expected_host)

    def test_rejects_empty_multiple_and_malformed_targets(self):
        malformed_targets = (
            "",
            "example.com evil.test",
            "example.com,evil.test",
            "999.999.1.1",
            "ftp://example.com",
            "http://user:pass@example.com",
            "http://",
            "http://example.com:",
            "localhost:0",
            "https://example.com:99999",
            "http://example.com/%0d%0aInjected",
            "http://example.com/%broken",
        )
        for submitted in malformed_targets:
            with self.subTest(submitted=submitted):
                with self.assertRaises(TargetValidationError):
                    normalize_assessment_target(submitted)

    def test_whois_values_handle_lists_dates_and_none(self):
        self.assertEqual(_format_whois_value(None), "Unavailable or redacted")
        self.assertEqual(_format_whois_value(date(2024, 1, 2)), "2024-01-02")
        self.assertEqual(
            _format_whois_value([datetime(2024, 1, 2, tzinfo=timezone.utc), None, "active"]),
            "2024-01-02T00:00:00+00:00, active",
        )


class PasswordAnalyzerTests(unittest.TestCase):
    def test_weak_password(self):
        result = analyze_password("abc123")
        self.assertEqual(result["strength"], "Weak")
        self.assertIn("At least 8 characters", result["failed_checks"])

    def test_medium_password(self):
        result = analyze_password("Example1")
        self.assertEqual(result["strength"], "Medium")
        self.assertEqual(result["character_classes"], 3)

    def test_strong_password(self):
        result = analyze_password("LongExample1!")
        self.assertEqual(result["strength"], "Strong")
        self.assertEqual(result["character_classes"], 4)

    def test_result_does_not_contain_password(self):
        password = "NeverStoreMe1!"
        self.assertNotIn(password, repr(analyze_password(password)))


class FakeHost(dict):
    def __init__(self, ports=None):
        super().__init__({"tcp": ports or {}})

    def state(self):
        return "up"

    def all_protocols(self):
        return ["tcp"] if self["tcp"] else []


class FakeScanner:
    def __init__(self, ports=None, hosts=None):
        self.hosts = hosts if hosts is not None else ["127.0.0.1"]
        self.host = FakeHost(ports)
        self.scan_call = None

    def scan(self, hosts, ports, arguments, timeout=0):
        self.scan_call = {"hosts": hosts, "ports": ports, "arguments": arguments, "timeout": timeout}

    def all_hosts(self):
        return self.hosts

    def __getitem__(self, _host):
        return self.host


class PortScannerTests(unittest.TestCase):
    def test_scans_only_expected_tcp_range_and_maps_service_fields(self):
        scanner = FakeScanner(
            {
                80: {"state": "open", "name": "http", "product": "Example", "version": "1.0", "extrainfo": ""}
            }
        )
        fake_nmap = SimpleNamespace(PortScanner=lambda: scanner, PortScannerError=RuntimeError)
        with patch("services.port_scanner.nmap", fake_nmap):
            result = scan_tcp_ports("127.0.0.1")
        self.assertTrue(result["success"])
        self.assertEqual(scanner.scan_call["ports"], PORT_RANGE)
        self.assertEqual(scanner.scan_call["arguments"], NMAP_ARGUMENTS)
        self.assertEqual(result["ports"][0]["protocol"], "tcp")
        self.assertEqual(result["ports"][0]["service"], "http")
        self.assertEqual(result["ports"][0]["product_version"], "Example 1.0")

    def test_no_open_ports_is_a_successful_empty_result(self):
        scanner = FakeScanner(ports={})
        fake_nmap = SimpleNamespace(PortScanner=lambda: scanner, PortScannerError=RuntimeError)
        with patch("services.port_scanner.nmap", fake_nmap):
            result = scan_tcp_ports("localhost")
        self.assertTrue(result["success"])
        self.assertEqual(result["ports"], [])
        self.assertIn("no open TCP ports", result["message"])

    def test_missing_nmap_is_friendly(self):
        with patch("services.port_scanner.nmap", None):
            result = scan_tcp_ports("127.0.0.1")
        self.assertFalse(result["success"])
        self.assertTrue(result["setup_required"])

    def test_direct_ipv6_target_adds_safe_nmap_ipv6_flag(self):
        scanner = FakeScanner(ports={})
        fake_nmap = SimpleNamespace(PortScanner=lambda: scanner, PortScannerError=RuntimeError)
        with patch("services.port_scanner.nmap", fake_nmap):
            result = scan_tcp_ports("2001:db8::1")
        self.assertTrue(result["success"])
        self.assertEqual(scanner.scan_call["arguments"], f"{NMAP_ARGUMENTS} -6")


def response_with_headers(headers: dict[str, str]) -> requests.Response:
    response = requests.Response()
    response.status_code = 200
    response.url = "http://example.test/"
    response.headers.update(headers)
    response.raw = Mock()
    return response


class HeaderAnalyzerTests(unittest.TestCase):
    def test_cross_host_and_nonstandard_port_redirects_are_rejected(self):
        with self.assertRaises(UnsafeRedirectError):
            _validate_redirect_url("https://different.example/path", "original.example")
        with self.assertRaises(UnsafeRedirectError):
            _validate_redirect_url("https://original.example:8443/path", "original.example")

    @patch("services.header_analyzer._request_with_safe_redirects")
    def test_detects_required_present_and_missing_headers(self, request_mock: Mock):
        request_mock.return_value = response_with_headers({"Content-Security-Policy": "default-src 'self'"})
        result = analyze_security_headers("example.test")
        statuses = {item["name"]: item["status"] for item in result["headers"]}
        self.assertTrue(result["success"])
        self.assertEqual(statuses["Content-Security-Policy"], "Present")
        self.assertEqual(statuses["X-Frame-Options"], "Missing")
        self.assertEqual(statuses["X-XSS-Protection"], "Missing")

    @patch("services.header_analyzer._request_with_safe_redirects")
    def test_https_failure_falls_back_to_http(self, request_mock: Mock):
        request_mock.side_effect = [requests.exceptions.SSLError(), response_with_headers({})]
        result = analyze_security_headers("example.test")
        self.assertTrue(result["success"])
        self.assertEqual(request_mock.call_count, 2)
        self.assertEqual(request_mock.call_args_list[0].args[1], "https://example.test")
        self.assertEqual(request_mock.call_args_list[1].args[1], "http://example.test")

    @patch("services.header_analyzer._request_with_safe_redirects")
    def test_explicit_http_scheme_port_and_path_are_used_unchanged(self, request_mock: Mock):
        request_mock.return_value = response_with_headers({"X-Frame-Options": "DENY"})
        result = analyze_security_headers("http://127.0.0.1:5000/health?full=1")
        self.assertTrue(result["success"])
        request_mock.assert_called_once()
        self.assertEqual(request_mock.call_args.args[1], "http://127.0.0.1:5000/health?full=1")

    @patch("services.header_analyzer._request_with_safe_redirects")
    def test_explicit_https_nonstandard_port_is_requested_first(self, request_mock: Mock):
        request_mock.return_value = response_with_headers({})
        result = analyze_security_headers("https://example.com:8443")
        self.assertTrue(result["success"])
        self.assertEqual(request_mock.call_args.args[1], "https://example.com:8443")

    @patch("services.header_analyzer._request_with_safe_redirects")
    def test_explicit_https_url_does_not_switch_schemes(self, request_mock: Mock):
        request_mock.side_effect = requests.exceptions.ConnectionError()
        result = analyze_security_headers("https://example.com:8443")
        self.assertFalse(result["success"])
        request_mock.assert_called_once()

    @patch("services.header_analyzer._request_with_safe_redirects")
    def test_host_and_port_without_scheme_try_https_then_http(self, request_mock: Mock):
        request_mock.side_effect = [requests.exceptions.SSLError(), response_with_headers({})]
        result = analyze_security_headers("localhost:5000")
        self.assertTrue(result["success"])
        self.assertEqual(
            [call.args[1] for call in request_mock.call_args_list],
            ["https://localhost:5000", "http://localhost:5000"],
        )

    @patch("services.header_analyzer._request_with_safe_redirects")
    def test_unreachable_target_returns_clean_error(self, request_mock: Mock):
        request_mock.side_effect = requests.exceptions.ConnectionError()
        result = analyze_security_headers("10.255.255.1")
        self.assertFalse(result["success"])
        self.assertEqual(result["headers"], [])
        self.assertIn("could not be reached", result["message"])

    @patch("services.header_analyzer._request_with_safe_redirects")
    def test_direct_ipv6_target_is_bracketed_in_url(self, request_mock: Mock):
        request_mock.return_value = response_with_headers({})
        result = analyze_security_headers("2001:db8::1")
        self.assertTrue(result["success"])
        self.assertEqual(request_mock.call_args.args[1], "https://[2001:db8::1]")


class ReportGeneratorTests(unittest.TestCase):
    def setUp(self):
        workspace_tmp = Path(__file__).resolve().parents[1] / "tmp"
        workspace_tmp.mkdir(exist_ok=True)
        self.temporary_directory = tempfile.TemporaryDirectory(dir=workspace_tmp)
        self.reports_directory = Path(self.temporary_directory.name)
        self.scan_id = "12345678-1234-5678-1234-567812345678"

    def tearDown(self):
        self.temporary_directory.cleanup()

    @staticmethod
    def sample_results():
        reconnaissance = {
            "addresses": [{"address": "127.0.0.1", "version": "IPv4", "reverse_dns": "localhost"}],
            "whois": {
                "message": "WHOIS not applicable.", "registrar": "Unavailable", "creation_date": "Unavailable",
                "expiration_date": "Unavailable", "organization": "Unavailable", "country": "Unavailable",
                "name_servers": "Unavailable", "status": "Unavailable",
            },
            "errors": [],
        }
        port_scan = {
            "success": True,
            "ports": [{"port": 80, "protocol": "tcp", "state": "open", "service": "http", "product_version": "Not detected"}],
            "message": "Found 1 reported open TCP port.",
        }
        header_analysis = {
            "success": True,
            "message": "Security headers were analyzed successfully.", "url": "http://localhost", "status_code": 200,
            "headers": [{"name": "Content-Security-Policy", "status": "Missing", "severity": "High", "value": "Not supplied"}],
            "recommendations": [{"header": "Content-Security-Policy", "severity": "High", "text": "Define a restrictive policy."}],
        }
        return reconnaissance, port_scan, header_analysis

    def test_generates_uuid_named_pdf_without_password_data(self):
        recon, ports, headers = self.sample_results()
        with patch("services.report_generator._paragraph", wraps=report_generator._paragraph) as paragraph_mock:
            result = generate_assessment_report(
                target="http://127.0.0.1:5000/path", scan_host="127.0.0.1",
                authorization_confirmed=True, reconnaissance=recon, port_scan=ports,
                header_analysis=headers, reports_directory=self.reports_directory, scan_id=self.scan_id,
            )
        report_path = Path(result["path"])
        self.assertTrue(report_path.is_file())
        self.assertEqual(report_path, report_path_for_scan_id(self.scan_id, self.reports_directory))
        self.assertTrue(report_path.read_bytes().startswith(b"%PDF"))
        self.assertNotIn(b"NeverStoreMe1!", report_path.read_bytes())
        rendered_values = [str(call.args[0]) for call in paragraph_mock.call_args_list]
        self.assertIn("http://127.0.0.1:5000/path", rendered_values)
        self.assertIn("127.0.0.1", rendered_values)

    def test_refuses_unauthorized_report_and_invalid_download_id(self):
        recon, ports, headers = self.sample_results()
        with self.assertRaises(ValueError):
            generate_assessment_report(
                target="localhost", authorization_confirmed=False, reconnaissance=recon, port_scan=ports,
                header_analysis=headers, reports_directory=self.reports_directory,
            )
        with self.assertRaises(ValueError):
            report_path_for_scan_id("../../secret", self.reports_directory)


if __name__ == "__main__":
    unittest.main()
