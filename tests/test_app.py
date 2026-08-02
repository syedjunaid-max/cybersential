from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import create_app
from services.report_generator import report_path_for_scan_id


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


if __name__ == "__main__":
    unittest.main()
