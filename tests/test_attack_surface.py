"""Tests for the Attack Surface Mapping workflow (new target-based pipeline)."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import create_app


class AttackSurfaceWorkflowTests(unittest.TestCase):
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

    # ── Form page ──────────────────────────────────────────────────────────────

    def test_form_page_contains_fields(self):
        """GET /attack-surface renders target input and authorization checkbox."""
        response = self.client.get("/attack-surface")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Target URL/Hostname", response.data)
        self.assertIn(b"authorized", response.data)

    # ── Authorization guard ────────────────────────────────────────────────────

    def test_analyze_missing_authorization_returns_403(self):
        """POST without authorization checkbox returns 403."""
        response = self.client.post(
            "/attack-surface/analyze", data={"target": "example.com"}
        )
        self.assertEqual(response.status_code, 403)

    def test_analyze_empty_target_returns_400(self):
        """POST with authorization but no target returns 400."""
        response = self.client.post(
            "/attack-surface/analyze", data={"authorized": "on", "target": ""}
        )
        self.assertEqual(response.status_code, 400)

    # ── Full pipeline & PDF report ─────────────────────────────────────────────

    def test_full_assessment_flow_generates_pdf_and_allows_download(self):
        """POST a valid authorized target: expect redirect to result page that shows
        the normalized target URL, exposure summary, download button, and allows PDF download."""
        response = self.client.post(
            "/attack-surface/analyze",
            data={"target": "example.com", "authorized": "on"},
            follow_redirects=False,
        )
        # Should redirect (303) to the result page
        self.assertEqual(response.status_code, 303)
        location = response.headers.get("Location", "")
        self.assertTrue(
            location.startswith("/attack-surface/result/"),
            msg=f"Expected redirect to /attack-surface/result/..., got: {location}",
        )

        scan_id = location.split("/")[-1]

        # Follow the redirect
        result_resp = self.client.get(location)
        self.assertEqual(result_resp.status_code, 200)

        # Page must contain the title and the target hostname
        self.assertIn(b"AUTHORIZED ATTACK SURFACE MAPPING", result_resp.data)
        self.assertIn(b"example.com", result_resp.data)

        # Exposure summary section must be present
        self.assertIn(b"Exposure Summary", result_resp.data)

        # Download PDF button must be present
        self.assertIn(b"Download PDF report", result_resp.data)
        self.assertIn(f"/attack-surface/reports/{scan_id}/download".encode(), result_resp.data)

        # Download the PDF report
        download_resp = self.client.get(f"/attack-surface/reports/{scan_id}/download")
        self.assertEqual(download_resp.status_code, 200)
        self.assertEqual(download_resp.mimetype, "application/pdf")
        self.assertTrue(download_resp.data.startswith(b"%PDF"))
        self.assertIn("attachment", download_resp.headers.get("Content-Disposition", ""))
        self.assertIn(
            f"Cybersential_ASM_Report_{scan_id}.pdf",
            download_resp.headers.get("Content-Disposition", ""),
        )
        download_resp.close()

    def test_unknown_scan_id_returns_404(self):
        """GET /attack-surface/result/<unknown-id> returns 404."""
        response = self.client.get(
            "/attack-surface/result/00000000-0000-0000-0000-000000000000"
        )
        self.assertEqual(response.status_code, 404)

    def test_download_unknown_scan_id_returns_404(self):
        """GET /attack-surface/reports/<unknown-id>/download returns 404."""
        response = self.client.get(
            "/attack-surface/reports/00000000-0000-0000-0000-000000000000/download"
        )
        self.assertEqual(response.status_code, 404)

    def test_download_invalid_uuid_returns_404(self):
        """GET /attack-surface/reports/<invalid-id>/download returns 404."""
        response = self.client.get("/attack-surface/reports/not-a-uuid/download")
        self.assertEqual(response.status_code, 404)

    def test_pdf_generation_error_handled_gracefully(self):
        """When PDF generation fails, analysis completes and surfaces the error gracefully."""
        with patch("app.generate_asm_report", side_effect=RuntimeError("PDF engine error")):
            response = self.client.post(
                "/attack-surface/analyze",
                data={"target": "example.com", "authorized": "on"},
                follow_redirects=True,
            )
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"The assessment completed, but the PDF report could not be generated.", response.data)


if __name__ == "__main__":
    unittest.main()
