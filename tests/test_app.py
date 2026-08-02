from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import create_app
from services.packet_inspector import PacketInspectionError
from services.report_generator import dpi_report_path_for_capture_id, report_path_for_scan_id


SAMPLE_RECON = {
    "target": "localhost",
    "success": True,
    "addresses": [{"address": "127.0.0.1", "version": "IPv4", "reverse_dns": "localhost"}],
    "whois": {
        "available": False,
        "message": "WHOIS data is not available for a local hostname.",
        "registrar": "Unavailable or redacted",
        "creation_date": "Unavailable or redacted",
        "expiration_date": "Unavailable or redacted",
        "organization": "Unavailable or redacted",
        "country": "Unavailable or redacted",
        "name_servers": "Unavailable or redacted",
        "status": "Unavailable or redacted",
    },
    "errors": [],
}
SAMPLE_PORTS = {
    "target": "localhost",
    "success": True,
    "host_state": "up",
    "ports": [],
    "message": "The scan completed and no open TCP ports were reported in the 1-1024 range.",
    "setup_required": False,
}
SAMPLE_HEADERS = {
    "target": "localhost",
    "success": True,
    "url": "http://localhost",
    "status_code": 200,
    "message": "Security headers were analyzed successfully.",
    "headers": [
        {
            "name": "Content-Security-Policy",
            "status": "Missing",
            "value": "Not supplied",
            "required": True,
            "severity": "High",
            "recommendation": "Define a restrictive policy.",
        }
    ],
    "recommendations": [
        {"header": "Content-Security-Policy", "severity": "High", "text": "Define a restrictive policy."}
    ],
}


class FlaskApplicationTests(unittest.TestCase):
    def setUp(self):
        workspace_tmp = Path(__file__).resolve().parents[1] / "tmp"
        workspace_tmp.mkdir(exist_ok=True)
        self.temporary_directory = tempfile.TemporaryDirectory(dir=workspace_tmp)
        self.app = create_app(
            {
                "TESTING": True,
                "REPORTS_DIRECTORY": self.temporary_directory.name,
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_home_and_security_response_headers(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Cybersential", response.data)
        self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")

    def test_assessment_requires_authorization(self):
        response = self.client.post("/scan", data={"target": "localhost"})
        self.assertEqual(response.status_code, 403)
        self.assertIn(b"explicit permission", response.data)

    def test_assessment_rejects_invalid_target(self):
        response = self.client.post("/scan", data={"target": "bad target", "authorized": "yes"})
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"must not contain spaces", response.data)

    def test_password_strengths_and_no_password_echo(self):
        cases = (("abc123", b"Weak"), ("Example1", b"Medium"), ("LongExample1!", b"Strong"))
        for password, expected in cases:
            with self.subTest(expected=expected):
                response = self.client.post("/password-analysis", data={"password": password})
                self.assertEqual(response.status_code, 200)
                self.assertIn(expected, response.data)
                self.assertNotIn(password.encode(), response.data)

    @patch("app.generate_assessment_report")
    @patch("app.analyze_security_headers", return_value=SAMPLE_HEADERS)
    @patch("app.scan_tcp_ports", return_value=SAMPLE_PORTS)
    @patch("app.perform_reconnaissance", return_value=SAMPLE_RECON)
    def test_authorized_assessment_orchestrates_services_and_never_passes_password(
        self, recon_mock, port_mock, header_mock, report_mock
    ):
        response = self.client.post(
            "/scan",
            data={"target": "http://127.0.0.1:5000/path", "authorized": "yes", "password": "NeverStoreMe1!"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Assessment complete", response.data)
        self.assertIn(b"no open TCP ports", response.data)
        self.assertIn(b"http://127.0.0.1:5000/path", response.data)
        self.assertIn(b"Scan host", response.data)
        self.assertNotIn(b"NeverStoreMe1!", response.data)
        recon_mock.assert_called_once_with("127.0.0.1")
        port_mock.assert_called_once_with("127.0.0.1")
        header_mock.assert_called_once_with("http://127.0.0.1:5000/path", fallback_to_http=False)
        self.assertNotIn("password", report_mock.call_args.kwargs)
        self.assertTrue(report_mock.call_args.kwargs["authorization_confirmed"])
        self.assertEqual(report_mock.call_args.kwargs["target"], "http://127.0.0.1:5000/path")
        self.assertEqual(report_mock.call_args.kwargs["scan_host"], "127.0.0.1")

    def test_download_accepts_only_existing_uuid_report(self):
        scan_id = "12345678-1234-5678-1234-567812345678"
        report_path = report_path_for_scan_id(scan_id, self.temporary_directory.name)
        report_path.write_bytes(b"%PDF-1.4 test")

        response = self.client.get(f"/reports/{scan_id}/download")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/pdf")
        self.assertIn("attachment", response.headers["Content-Disposition"])
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        response.close()

        self.assertEqual(self.client.get("/reports/not-a-uuid/download").status_code, 404)
        self.assertEqual(self.client.get(f"/reports/{scan_id[:-1]}9/download").status_code, 404)

    def test_dpi_page_exposes_authorized_bounded_capture_controls(self):
        environment = {
            "available": True,
            "code": "ready",
            "message": "Ready",
            "interfaces": [{"id": "iface-test", "name": "Wi-Fi", "description": "", "address": "192.0.2.10"}],
            "privilege_notice": "Administrator permission may be required.",
        }
        with patch("app.get_capture_environment", return_value=environment):
            response = self.client.get("/dpi")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Deep Packet Inspection", response.data)
        self.assertIn(b"explicit authorization", response.data)
        self.assertIn(b"Npcap", response.data)
        self.assertIn(b"raw payloads", response.data)

    def test_dpi_capture_requires_authorization_before_service_call(self):
        with patch("app.capture_packets") as capture_mock:
            response = self.client.post("/dpi/capture", data={"interface": "iface-test", "duration": "15", "packet_limit": "200"})
        self.assertEqual(response.status_code, 403)
        self.assertIn(b"explicit permission", response.data)
        capture_mock.assert_not_called()

    def test_dpi_capture_surfaces_safe_service_errors(self):
        error = PacketInspectionError("npcap_missing", "Npcap is unavailable; install it manually.", 503)
        environment = {"available": False, "code": "npcap_missing", "message": error.message, "interfaces": [], "privilege_notice": "No driver"}
        with patch("app.capture_packets", side_effect=error), patch("app.get_capture_environment", return_value=environment):
            response = self.client.post("/dpi/capture", data={"interface": "iface-test", "duration": "15", "packet_limit": "200", "authorized": "yes"})
        self.assertEqual(response.status_code, 503)
        self.assertIn(b"Npcap is unavailable", response.data)
        self.assertNotIn(b"Traceback", response.data)

    def test_dpi_result_is_uuid_backed_and_contains_no_raw_packet_object(self):
        capture_id = "12345678-1234-5678-1234-567812345678"
        capture = {
            "interface_name": "Wi-Fi",
            "requested_duration_seconds": 15,
            "capture_duration_seconds": 1.0,
            "packet_limit": 200,
            "started_at": "2026-01-01T00:00:00+00:00",
            "completed_at": "2026-01-01T00:00:01+00:00",
            "packets": [object()],
        }
        with patch("app.uuid.uuid4", return_value=capture_id), patch("app.capture_packets", return_value=capture), patch(
            "app.generate_dpi_report", return_value={"path": "ignored"}
        ):
            response = self.client.post(
                "/dpi/capture",
                data={"interface": "iface-test", "duration": "15", "packet_limit": "200", "authorized": "yes"},
                follow_redirects=False,
            )
        self.assertEqual(response.status_code, 303)
        self.assertIn(f"/dpi/result/{capture_id}".encode(), response.data)
        result = self.client.get(f"/dpi/result/{capture_id}")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.headers["Cache-Control"], "no-store")
        self.assertNotIn(b"object at", result.data)

    def test_dpi_result_and_report_download_reject_unknown_ids(self):
        self.assertEqual(self.client.get("/dpi/result/not-a-uuid").status_code, 404)
        self.assertEqual(self.client.get("/dpi/reports/not-a-uuid/download").status_code, 404)
        capture_id = "12345678-1234-5678-1234-567812345678"
        report_path = dpi_report_path_for_capture_id(capture_id, self.temporary_directory.name)
        report_path.write_bytes(b"%PDF-1.4 test")
        self.assertEqual(self.client.get(f"/dpi/reports/{capture_id}/download").status_code, 404)


if __name__ == "__main__":
    unittest.main()
