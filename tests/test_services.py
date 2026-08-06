from __future__ import annotations

import tempfile
import unittest
import json
from datetime import date, datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import requests

try:
    from scapy.all import DNS, DNSQR, ICMP, IP, IPv6, Raw, TCP, UDP
except ImportError:  # pragma: no cover - dependency is declared in requirements.txt
    DNS = DNSQR = ICMP = IP = IPv6 = Raw = TCP = UDP = None

import services.report_generator as report_generator
import services.packet_inspector as packet_inspector
from services.header_analyzer import UnsafeRedirectError, _validate_redirect_url, analyze_security_headers
from services.blocklist_manager import (
    MANAGED_SECTION_END,
    MANAGED_SECTION_START,
    BlocklistError,
    DomainValidationError,
    affected_domains_for,
    normalize_domain,
)
from services.password_analyzer import analyze_password
from services.packet_inspector import (
    MAX_CAPTURE_DURATION,
    MAX_PACKET_LIMIT,
    MIN_CAPTURE_DURATION,
    MIN_PACKET_LIMIT,
    PacketInspectionError,
    capture_packets,
    extract_packet_metadata,
    validate_capture_request,
)
from services.traffic_analyzer import DPIResultStore, analyze_traffic
from services.website_blocker import WebsiteBlocker
from services.port_scanner import NMAP_ARGUMENTS, PORT_RANGE, scan_tcp_ports
from services.reconnaissance import (
    TargetValidationError,
    _format_whois_value,
    normalize_assessment_target,
    normalize_target,
)
from services.report_generator import (
    dpi_report_path_for_capture_id,
    generate_assessment_report,
    generate_dpi_report,
    report_path_for_scan_id,
)


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


@unittest.skipUnless(IP is not None, "Scapy is required for synthetic packet tests")
class PacketMetadataTests(unittest.TestCase):
    def test_ipv4_tcp_metadata_and_payload_exclusion(self):
        packet = IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=41234, dport=443, flags="S") / Raw(
            b"Authorization: Bearer do-not-store"
        )
        metadata = extract_packet_metadata(packet)
        self.assertEqual(metadata["ip_version"], 4)
        self.assertEqual(metadata["source_ip"], "192.0.2.10")
        self.assertEqual(metadata["destination_ip"], "198.51.100.20")
        self.assertEqual(metadata["transport_protocol"], "TCP")
        self.assertEqual(metadata["destination_port"], 443)
        self.assertEqual(metadata["tcp_flags"], "S")
        self.assertTrue(metadata["encrypted_estimate"])
        self.assertNotIn("do-not-store", repr(metadata))
        self.assertNotIn("payload", metadata)

    def test_ipv6_metadata(self):
        metadata = extract_packet_metadata(
            IPv6(src="2001:db8::10", dst="2001:db8::20") / TCP(sport=1234, dport=8080, flags="SA")
        )
        self.assertEqual(metadata["ip_version"], 6)
        self.assertEqual(metadata["source_ip"], "2001:db8::10")
        self.assertEqual(metadata["destination_ip"], "2001:db8::20")
        self.assertEqual(metadata["tcp_flags"], "SA")

    def test_udp_dns_metadata(self):
        metadata = extract_packet_metadata(
            IP(src="192.0.2.1", dst="192.0.2.53")
            / UDP(sport=53000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.edu."))
        )
        self.assertEqual(metadata["transport_protocol"], "UDP")
        self.assertEqual(metadata["destination_port"], 53)
        self.assertEqual(metadata["dns_query_name"], "example.edu")
        self.assertTrue(metadata["dns_packet"])

    def test_icmp_metadata(self):
        metadata = extract_packet_metadata(IP(src="192.0.2.1", dst="192.0.2.2") / ICMP(type=8))
        self.assertEqual(metadata["transport_protocol"], "ICMP")
        self.assertEqual(metadata["icmp_type"], 8)

    def test_packet_with_missing_layers_is_safe(self):
        metadata = extract_packet_metadata(Raw(b"opaque bytes that are not retained"))
        self.assertIsNone(metadata["ip_version"])
        self.assertEqual(metadata["transport_protocol"], "Other")
        self.assertIsNone(metadata["source_ip"])
        self.assertNotIn("opaque", repr(metadata))


class TrafficAnalyzerTests(unittest.TestCase):
    @staticmethod
    def packet(source, destination, protocol="TCP", source_port=None, destination_port=None, flags=None, **extra):
        result = {
            "timestamp": "2026-01-01T00:00:00+00:00",
            "ip_version": 4,
            "source_ip": source,
            "destination_ip": destination,
            "transport_protocol": protocol,
            "source_port": source_port,
            "destination_port": destination_port,
            "packet_length": 100,
            "tcp_flags": flags,
            "icmp_type": None,
            "dns_query_name": None,
            "dns_packet": False,
            "encrypted_estimate": destination_port in {443, 993},
        }
        result.update(extra)
        return result

    def test_summary_counts_protocols_endpoints_ports_and_flags(self):
        packets = [
            self.packet("192.0.2.1", "198.51.100.1", destination_port=443, flags="S"),
            self.packet("192.0.2.1", "198.51.100.1", destination_port=443, flags="SA"),
            self.packet("192.0.2.2", "198.51.100.2", protocol="UDP", source_port=53000, destination_port=53,
                        dns_query_name="example.edu", dns_packet=True),
            self.packet("192.0.2.3", "198.51.100.3", protocol="ICMP", packet_length=64),
        ]
        result = analyze_traffic(
            packets,
            selected_interface="Wi-Fi",
            capture_duration_seconds=3.5,
            requested_duration_seconds=15,
            packet_limit=200,
            authorization_confirmed=True,
            started_at="2026-01-01T00:00:00+00:00",
            completed_at="2026-01-01T00:00:03+00:00",
        )
        summary = result["summary"]
        self.assertEqual(summary["total_packets"], 4)
        self.assertEqual(summary["tcp_packet_count"], 2)
        self.assertEqual(summary["udp_packet_count"], 1)
        self.assertEqual(summary["icmp_packet_count"], 1)
        self.assertEqual(summary["dns_packet_count"], 1)
        self.assertEqual(summary["total_bytes_observed"], 364)
        self.assertEqual(summary["top_destination_ports"][0]["port"], 443)
        self.assertEqual(summary["tcp_flag_distribution"][0]["value"], "S")
        self.assertLessEqual(len(summary["top_destination_ips"]), 10)

    def test_rule_findings_are_tentative_and_have_required_fields(self):
        packets = [
            self.packet("192.0.2.9", "198.51.100.9", destination_port=port, flags="S")
            for port in range(10000, 10012)
        ]
        result = analyze_traffic(
            packets,
            selected_interface="lab0",
            capture_duration_seconds=5,
            requested_duration_seconds=5,
            packet_limit=50,
            authorization_confirmed=True,
            started_at="",
            completed_at="2026-01-01T00:00:05+00:00",
        )
        titles = {finding["title"] for finding in result["findings"]}
        self.assertIn("Possible SYN scanning behavior", titles)
        self.assertIn("Repeated destination-port attempts", titles)
        for finding in result["findings"]:
            self.assertIn(finding["severity"], {"Informational", "Low", "Medium", "High"})
            self.assertTrue(finding["confidence"])


class PacketCaptureServiceTests(unittest.TestCase):
    INTERFACE = {
        "id": "iface-test",
        "name": "Wi-Fi",
        "description": "Authorized adapter",
        "address": "192.0.2.10",
        "capture_name": "\\Device\\NPF_{12345678-1234-1234-1234-123456789ABC}",
    }

    def test_duration_and_packet_limit_validation(self):
        environment = {"available": True}
        with patch.object(packet_inspector, "get_capture_environment", return_value=environment), patch.object(
            packet_inspector, "_interface_records", return_value=[self.INTERFACE]
        ):
            for value in (MIN_CAPTURE_DURATION - 1, MAX_CAPTURE_DURATION + 1):
                with self.subTest(duration=value):
                    with self.assertRaises(PacketInspectionError):
                        validate_capture_request(interface="iface-test", duration=value, packet_limit=10, authorization_confirmed=True)
            for value in (MIN_PACKET_LIMIT - 1, MAX_PACKET_LIMIT + 1):
                with self.subTest(packet_limit=value):
                    with self.assertRaises(PacketInspectionError):
                        validate_capture_request(interface="iface-test", duration=5, packet_limit=value, authorization_confirmed=True)

    def test_authorization_and_interface_validation(self):
        with self.assertRaises(PacketInspectionError) as missing_auth:
            validate_capture_request(interface="iface-test", duration=5, packet_limit=10, authorization_confirmed=False)
        self.assertEqual(missing_auth.exception.code, "authorization_required")
        with patch.object(packet_inspector, "get_capture_environment", return_value={"available": True}), patch.object(
            packet_inspector, "_interface_records", return_value=[self.INTERFACE]
        ):
            with self.assertRaises(PacketInspectionError) as invalid_interface:
                validate_capture_request(interface="not-allowlisted", duration=5, packet_limit=10, authorization_confirmed=True)
        self.assertEqual(invalid_interface.exception.code, "invalid_interface")

    def test_mocked_capture_is_bounded_and_returns_metadata_only(self):
        packet = IP(src="192.0.2.1", dst="198.51.100.1") / TCP(sport=40000, dport=443, flags="S") / Raw(
            b"secret payload must never leave the callback"
        )

        def fake_sniff(**kwargs):
            self.assertFalse(kwargs["store"])
            self.assertEqual(kwargs["count"], 10)
            self.assertEqual(kwargs["timeout"], 5)
            kwargs["prn"](packet)

        with patch.object(packet_inspector, "validate_capture_request", return_value=(self.INTERFACE, 5, 10)), patch.object(
            packet_inspector, "sniff", side_effect=fake_sniff
        ):
            result = capture_packets(interface="iface-test", duration=5, packet_limit=10, authorization_confirmed=True)
        self.assertEqual(len(result["packets"]), 1)
        self.assertEqual(result["packets"][0]["transport_protocol"], "TCP")
        self.assertNotIn("secret payload", repr(result))
        self.assertFalse(result["storage"]["pcap"])
        self.assertFalse(packet_inspector.capture_in_progress())

    def test_capture_errors_release_lock_and_are_user_facing(self):
        with patch.object(packet_inspector, "validate_capture_request", return_value=(self.INTERFACE, 5, 10)), patch.object(
            packet_inspector, "sniff", side_effect=PermissionError("Access is denied")
        ):
            with self.assertRaises(PacketInspectionError) as error:
                capture_packets(interface="iface-test", duration=5, packet_limit=10, authorization_confirmed=True)
        self.assertEqual(error.exception.code, "permission_denied")
        self.assertFalse(packet_inspector.capture_in_progress())

    def test_capture_lock_rejects_duplicate_capture(self):
        packet_inspector._capture_lock.acquire()
        try:
            with patch.object(packet_inspector, "validate_capture_request", return_value=(self.INTERFACE, 5, 10)):
                with self.assertRaises(PacketInspectionError) as error:
                    capture_packets(interface="iface-test", duration=5, packet_limit=10, authorization_confirmed=True)
            self.assertEqual(error.exception.code, "capture_in_progress")
        finally:
            packet_inspector._capture_lock.release()

    def test_missing_scapy_and_npcap_are_clear(self):
        with patch.object(packet_inspector, "SCAPY_AVAILABLE", False):
            environment = packet_inspector.get_capture_environment()
        self.assertEqual(environment["code"], "scapy_missing")
        with patch.object(packet_inspector, "SCAPY_AVAILABLE", True), patch.object(
            packet_inspector, "_detect_windows_capture_driver", return_value=(False, "Npcap is unavailable.")
        ):
            environment = packet_inspector.get_capture_environment()
        self.assertEqual(environment["code"], "npcap_missing")


class DPIResultStoreTests(unittest.TestCase):
    def test_uuid_storage_is_bounded_and_oldest_is_removed(self):
        store = DPIResultStore(max_entries=3)
        ids = [store.add({"index": index}) for index in range(4)]
        self.assertEqual(len(store), 3)
        self.assertIsNone(store.get(ids[0]))
        self.assertEqual(store.get(ids[-1])["index"], 3)
        self.assertTrue(all(len(item) == 36 for item in store.ids()))


class WebsiteDomainValidationTests(unittest.TestCase):
    def test_valid_domain_and_url_normalization(self):
        cases = {
            "Example.COM.": "example.com",
            "www.example.com": "www.example.com",
            "https://Example.com/path?value=1#part": "example.com",
            "https://www.Example.com:443/page": "www.example.com",
            "example.com:8443/path": "example.com",
        }
        for submitted, expected in cases.items():
            with self.subTest(submitted=submitted):
                self.assertEqual(normalize_domain(submitted), expected)

    def test_idna_domain_normalization(self):
        self.assertEqual(normalize_domain("https://b\u00fccher.example/catalog"), "xn--bcher-kva.example")

    def test_rejects_unsafe_or_non_domain_values(self):
        invalid = (
            "",
            "127.0.0.1",
            "::1",
            "localhost",
            "test.localhost",
            "*.example.com",
            "intranet",
            "bad..example.com",
            "-bad.example.com",
            "bad_.example.com",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "example.com\nevil.example",
            "example.com evil.example",
            "127.0.0.1 example.com",
            "example.com;whoami",
            "ftp://example.com",
            "https://user:password@example.com",
        )
        for submitted in invalid:
            with self.subTest(submitted=submitted):
                with self.assertRaises(DomainValidationError):
                    normalize_domain(submitted)

    def test_root_and_www_expansion_does_not_expand_arbitrary_subdomains(self):
        self.assertEqual(affected_domains_for("example.com", True), ["example.com", "www.example.com"])
        self.assertEqual(affected_domains_for("www.example.com", True), ["example.com", "www.example.com"])
        self.assertEqual(affected_domains_for("example.co.uk", True), ["example.co.uk", "www.example.co.uk"])
        self.assertEqual(affected_domains_for("shop.example.com", True), ["shop.example.com"])
        self.assertEqual(affected_domains_for("www.shop.example.com", True), ["www.shop.example.com"])
        self.assertEqual(affected_domains_for("example.com", False), ["example.com"])


class WebsiteBlockerServiceTests(unittest.TestCase):
    ORIGINAL_HOSTS = (
        b"# Windows hosts fixture\r\n"
        b"127.0.0.1 localhost\r\n"
        b"10.10.10.10 existing.lab.example\r\n"
    )

    def setUp(self):
        workspace_tmp = Path(__file__).resolve().parents[1] / "tmp"
        workspace_tmp.mkdir(exist_ok=True)
        self.temporary_directory = tempfile.TemporaryDirectory(dir=workspace_tmp)
        self.root = Path(self.temporary_directory.name)
        self.hosts_path = self.root / "hosts"
        self.hosts_path.write_bytes(self.ORIGINAL_HOSTS)
        self.backup_directory = self.root / "backups"
        self.audit_path = self.root / "website_blocking_audit.jsonl"
        self.blocker = WebsiteBlocker(
            hosts_path=self.hosts_path,
            backup_directory=self.backup_directory,
            audit_path=self.audit_path,
        )

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_blocks_new_domain_and_creates_managed_markers(self):
        result = self.blocker.block_domain("https://Example.com/path", include_www=False, authorization_confirmed=True)
        self.assertTrue(result["success"])
        self.assertTrue(result["changed"])
        content = self.hosts_path.read_bytes()
        self.assertTrue(content.startswith(self.ORIGINAL_HOSTS))
        self.assertIn(MANAGED_SECTION_START.encode(), content)
        self.assertIn(b"127.0.0.1 example.com", content)
        self.assertIn(MANAGED_SECTION_END.encode(), content)
        self.assertEqual(self.blocker.get_managed_domains(), ["example.com"])

    def test_blocks_root_and_www_without_duplicates(self):
        first = self.blocker.block_domain("www.example.com", include_www=True, authorization_confirmed=True)
        second = self.blocker.block_domain("example.com", include_www=True, authorization_confirmed=True)
        self.assertTrue(first["success"])
        self.assertEqual(first["affected_domains"], ["example.com", "www.example.com"])
        self.assertTrue(second["success"])
        self.assertFalse(second["changed"])
        self.assertEqual(second["error_code"], "already_blocked")
        content = self.hosts_path.read_text(encoding="utf-8")
        self.assertEqual(content.count("127.0.0.1 example.com"), 1)
        self.assertEqual(content.count("127.0.0.1 www.example.com"), 1)

    def test_unblocks_present_and_missing_domains(self):
        self.blocker.block_domain("example.com", include_www=False, authorization_confirmed=True)
        removed = self.blocker.unblock_domain("example.com", include_www=False, authorization_confirmed=True)
        missing = self.blocker.unblock_domain("example.com", include_www=False, authorization_confirmed=True)
        self.assertTrue(removed["success"])
        self.assertTrue(removed["changed"])
        self.assertEqual(self.blocker.get_managed_domains(), [])
        self.assertTrue(missing["success"])
        self.assertFalse(missing["changed"])
        self.assertEqual(missing["error_code"], "domain_not_blocked")

    def test_preserves_content_outside_existing_managed_section_exactly(self):
        prefix = b"# prefix\r\n10.0.0.1 keep.before.example\r\n"
        section = (
            f"{MANAGED_SECTION_START}\r\n"
            "127.0.0.1 old.example\r\n"
            f"{MANAGED_SECTION_END}\r\n"
        ).encode()
        suffix = b"10.0.0.2 keep.after.example\r\n# suffix\r\n"
        self.hosts_path.write_bytes(prefix + section + suffix)
        result = self.blocker.block_domain("new.example", include_www=False, authorization_confirmed=True)
        self.assertTrue(result["success"])
        updated = self.hosts_path.read_bytes()
        self.assertTrue(updated.startswith(prefix))
        self.assertTrue(updated.endswith(suffix))
        self.assertIn(b"127.0.0.1 new.example", updated)
        self.assertIn(b"127.0.0.1 old.example", updated)

    def test_preserves_crlf_and_deduplicates_managed_entries(self):
        self.hosts_path.write_bytes(
            self.ORIGINAL_HOSTS
            + (
                f"{MANAGED_SECTION_START}\r\n"
                "127.0.0.1 z.example\r\n"
                "127.0.0.1 a.example\r\n"
                "127.0.0.1 z.example\r\n"
                f"{MANAGED_SECTION_END}\r\n"
            ).encode()
        )
        result = self.blocker.block_domain("m.example", include_www=False, authorization_confirmed=True)
        self.assertTrue(result["success"])
        content = self.hosts_path.read_bytes()
        self.assertNotIn(b"\n", content.replace(b"\r\n", b""))
        text = content.decode()
        self.assertEqual(text.count("127.0.0.1 z.example"), 1)
        self.assertLess(text.index("127.0.0.1 a.example"), text.index("127.0.0.1 m.example"))
        self.assertLess(text.index("127.0.0.1 m.example"), text.index("127.0.0.1 z.example"))

    def test_backup_is_created_once_from_original_content(self):
        self.blocker.block_domain("example.com", include_www=False, authorization_confirmed=True)
        backups = list(self.backup_directory.glob("hosts-backup-*.txt"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), self.ORIGINAL_HOSTS)
        self.blocker.block_domain("second.example", include_www=False, authorization_confirmed=True)
        self.assertEqual(len(list(self.backup_directory.glob("hosts-backup-*.txt"))), 1)

    def test_backup_failure_prevents_modification(self):
        original = self.hosts_path.read_bytes()
        failure = BlocklistError(
            "backup_failed",
            "The hosts-file backup could not be created, so no modification was attempted.",
            503,
        )
        with patch.object(self.blocker.manager, "create_backup_if_required", side_effect=failure):
            result = self.blocker.block_domain("example.com", include_www=False, authorization_confirmed=True)
        self.assertFalse(result["success"])
        self.assertEqual(result["error_code"], "backup_failed")
        self.assertEqual(self.hosts_path.read_bytes(), original)

    def test_atomic_write_failure_restores_original(self):
        original = self.hosts_path.read_bytes()

        def corrupt_then_fail(_content):
            self.hosts_path.write_bytes(b"corrupted")
            raise OSError("simulated replacement failure")

        with patch.object(self.blocker.manager, "_atomic_write", side_effect=corrupt_then_fail):
            result = self.blocker.block_domain("example.com", include_www=False, authorization_confirmed=True)
        self.assertFalse(result["success"])
        self.assertEqual(result["error_code"], "atomic_write_failed")
        self.assertEqual(self.hosts_path.read_bytes(), original)

    def test_permission_denied_is_friendly_and_preserves_file(self):
        original = self.hosts_path.read_bytes()
        denied = BlocklistError(
            "administrator_required",
            "Administrator privileges are required to modify the Windows hosts file.",
            403,
        )
        with patch.object(self.blocker.manager, "_assert_modifiable", side_effect=denied):
            result = self.blocker.block_domain("example.com", include_www=False, authorization_confirmed=True)
        self.assertFalse(result["success"])
        self.assertEqual(result["error_code"], "administrator_required")
        self.assertNotIn(str(self.hosts_path), result["message"])
        self.assertEqual(self.hosts_path.read_bytes(), original)

    def test_unavailable_hosts_and_malformed_markers_fail_closed(self):
        self.hosts_path.unlink()
        unavailable = self.blocker.block_domain("example.com", include_www=False, authorization_confirmed=True)
        self.assertFalse(unavailable["success"])
        self.assertEqual(unavailable["error_code"], "hosts_file_unavailable")

        malformed = self.ORIGINAL_HOSTS + f"{MANAGED_SECTION_START}\r\n127.0.0.1 example.com\r\n".encode()
        self.hosts_path.write_bytes(malformed)
        invalid_section = self.blocker.block_domain("second.example", include_www=False, authorization_confirmed=True)
        self.assertFalse(invalid_section["success"])
        self.assertEqual(invalid_section["error_code"], "managed_section_invalid")
        self.assertEqual(self.hosts_path.read_bytes(), malformed)

    def test_authorization_is_required_before_modification(self):
        original = self.hosts_path.read_bytes()
        result = self.blocker.block_domain("example.com", include_www=False, authorization_confirmed=False)
        self.assertFalse(result["success"])
        self.assertEqual(result["error_code"], "authorization_required")
        self.assertEqual(self.hosts_path.read_bytes(), original)

    def test_audit_logging_contains_only_approved_fields(self):
        result = self.blocker.block_domain("example.com", include_www=False, authorization_confirmed=True)
        self.assertTrue(result["success"])
        record = json.loads(self.audit_path.read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(
            set(record),
            {
                "event_id", "action", "normalized_domain", "affected_domains", "timestamp",
                "success", "authorization_confirmed", "error_code",
            },
        )
        self.assertEqual(record["action"], "block")
        self.assertNotIn("hosts", repr(record).lower())
        self.assertNotIn(str(self.hosts_path), repr(record))

    def test_audit_failure_is_a_non_fatal_warning(self):
        with patch.object(self.blocker.audit, "record", side_effect=OSError("audit unavailable")):
            result = self.blocker.block_domain("example.com", include_www=False, authorization_confirmed=True)
        self.assertTrue(result["success"])
        self.assertTrue(result["changed"])
        self.assertTrue(result["warnings"])
        self.assertIn("example.com", self.blocker.get_managed_domains())


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

    def test_generates_metadata_only_dpi_pdf_without_payload_or_credentials(self):
        capture_id = "87654321-4321-8765-4321-876543218765"
        assessment = {
            "assessed_at": "2026-01-01T00:00:00+00:00",
            "authorization_confirmed": True,
            "capture": {
                "selected_interface": "Wi-Fi",
                "requested_duration_seconds": 15,
                "actual_duration_seconds": 4.2,
                "packet_limit": 200,
            },
            "summary": {
                "total_packets": 2,
                "ipv4_packet_count": 2,
                "ipv6_packet_count": 0,
                "tcp_packet_count": 1,
                "udp_packet_count": 1,
                "icmp_packet_count": 0,
                "dns_packet_count": 1,
                "other_packet_count": 0,
                "total_bytes": 180,
                "average_packet_size": 90,
                "unique_source_ip_count": 1,
                "unique_destination_ip_count": 1,
                "top_source_ips": [{"value": "192.0.2.1", "count": 2}],
                "top_destination_ips": [{"value": "198.51.100.1", "count": 2}],
                "top_destination_ports": [{"port": 443, "count": 1, "service_estimate": "HTTPS/TLS (estimated)"}],
                "protocol_distribution": [{"protocol": "TCP", "count": 1, "percentage": 50.0}],
                "tcp_flag_distribution": [{"value": "S", "count": 1}],
                "dns_queries_observed": [{"value": "example.edu", "count": 1}],
                "encryption_estimate": {
                    "likely_encrypted": 1,
                    "not_identified_as_encrypted": 1,
                    "likely_encrypted_percentage": 50.0,
                    "basis": "Port estimate only.",
                },
            },
            "findings": [
                {
                    "title": "Informational observation",
                    "severity": "Informational",
                    "evidence": "A bounded metadata observation was completed.",
                    "recommendation": "Review expected traffic.",
                    "confidence": "Possible only; not a confirmed attack.",
                }
            ],
            "recommendations": ["Review expected traffic."],
            "limitations": ["Payloads were not stored or displayed."],
            "payload": "Authorization: Bearer should-not-appear",
            "credentials": "NeverStoreMe1!",
        }
        result = generate_dpi_report(
            assessment=assessment,
            authorization_confirmed=True,
            reports_directory=self.reports_directory,
            capture_id=capture_id,
        )
        report_path = Path(result["path"])
        self.assertEqual(report_path, dpi_report_path_for_capture_id(capture_id, self.reports_directory))
        report_bytes = report_path.read_bytes()
        self.assertTrue(report_bytes.startswith(b"%PDF"))
        self.assertNotIn(b"NeverStoreMe1!", report_bytes)
        self.assertNotIn(b"Authorization: Bearer", report_bytes)


if __name__ == "__main__":
    unittest.main()
