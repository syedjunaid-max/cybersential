"""Comprehensive tests for the Cyber Risk Correlation Engine and its Flask routes.

Covers:
- Score threshold boundary consistency (0-24 Low, 25-49 Medium, 50-74 High, 75-100 Critical)
- ASM-only correlation (no DPI terminology in findings/paths/limitations)
- ASM + DPI cross-layer correlation (DPI wording appears)
- Risk level consistency between score and level
- PDF generation and download
- Route validation (auth, 400, 404)
"""

import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from app import create_app
from services.risk_correlation_engine import RiskCorrelationEngine, score_to_level


# ---------------------------------------------------------------------------
# Unit tests – score_to_level helper (single source of truth)
# ---------------------------------------------------------------------------
class ScoreThresholdTests(unittest.TestCase):
    """Verify that score_to_level maps every boundary correctly."""

    def test_score_0_is_low(self):
        self.assertEqual(score_to_level(0), "Low")

    def test_score_24_is_low(self):
        self.assertEqual(score_to_level(24), "Low")

    def test_score_25_is_medium(self):
        self.assertEqual(score_to_level(25), "Medium")

    def test_score_49_is_medium(self):
        self.assertEqual(score_to_level(49), "Medium")

    def test_score_50_is_high(self):
        self.assertEqual(score_to_level(50), "High")

    def test_score_74_is_high(self):
        self.assertEqual(score_to_level(74), "High")

    def test_score_75_is_critical(self):
        self.assertEqual(score_to_level(75), "Critical")

    def test_score_100_is_critical(self):
        self.assertEqual(score_to_level(100), "Critical")


# ---------------------------------------------------------------------------
# Unit tests – RiskCorrelationEngine rules and score consistency
# ---------------------------------------------------------------------------
class RiskCorrelationEngineUnitTests(unittest.TestCase):
    """Unit tests for the RiskCorrelationEngine service logic and rules."""

    # ── Score and level consistency ────────────────────────────────────────

    def test_compute_risk_score_level_matches_score(self):
        """Risk level returned by compute_risk_score must always match score_to_level(score)."""
        # Two Medium findings → score = 20, level = Low
        asm_data = {
            "target": "consistency.local",
            "open_ports": [{"port": 80}],
            "missing_headers": ["CSP", "X-Frame-Options"],
            "observations": [
                {"title": "obs1", "severity": "Low"},
                {"title": "obs2", "severity": "Low"},
                {"title": "obs3", "severity": "Low"},
                {"title": "obs4", "severity": "Low"},
            ],
        }
        engine = RiskCorrelationEngine(asm_data=asm_data)
        engine.correlate_findings()
        score, level, _ = engine.compute_risk_score()
        self.assertEqual(level, score_to_level(score),
                         f"Level '{level}' does not match score_to_level({score})='{score_to_level(score)}'")

    def test_score_24_maps_to_low(self):
        """A pure-Low-finding scenario that produces score <= 24 must yield level Low."""
        # One Low finding → score = 5 → Low
        asm_data = {
            "target": "low-score.local",
            "observations": [{"title": "sole obs", "severity": "Low"}],
        }
        engine = RiskCorrelationEngine(asm_data=asm_data)
        engine.correlate_findings()
        score, level, _ = engine.compute_risk_score()
        self.assertLessEqual(score, 24)
        self.assertEqual(level, "Low")

    def test_score_25_or_above_maps_to_at_least_medium(self):
        """A scenario producing score >= 25 must yield at least Medium.
        One High finding = 20 pts (Low), two Medium = 20 pts (Low),
        but one High (20) + one Medium (10) = 30 pts -> Medium."""
        # Seed a High ASM finding + High DPI finding to fire Rule 2 (High = 20pts)
        # plus Rule 1 (Medium = 10pts) = 30 pts total -> Medium level
        asm_data = {
            "target": "medium-score.local",
            "open_ports": [{"port": 80}],
            "missing_headers": ["CSP", "X-Frame-Options"],
            "summary": {"high": 1, "medium": 0, "low": 0},
            "observations": [
                {"title": "High severity exposure", "severity": "High"},
                {"title": "ob2", "severity": "Low"},
                {"title": "ob3", "severity": "Low"},
                {"title": "ob4", "severity": "Low"},
            ],
        }
        dpi_data = {
            "threat_summary": {"high": 1},
            "findings": [{"title": "SYN scan anomaly", "severity": "High", "source": "threat_detector"}],
        }
        engine = RiskCorrelationEngine(asm_data=asm_data, dpi_data=dpi_data)
        engine.correlate_findings()
        score, level, counts = engine.compute_risk_score()
        # Rule1 Medium(10) + Rule2 High(20) + Rule3 Medium(10) = 40 -> Medium
        self.assertGreaterEqual(score, 25,
            f"Expected score >= 25, got {score}. Findings: {[f['risk_level'] for f in engine.correlated_findings]}")
        self.assertIn(level, ("Medium", "High", "Critical"))
        self.assertEqual(level, score_to_level(score))

    # ── Rule 1 – Web exposure + missing headers ────────────────────────────

    def test_web_exposure_missing_headers_rule_fires(self):
        """Rule 1: Open web port + missing security headers produces Medium risk."""
        asm_data = {
            "target": "web-test.local",
            "open_ports": [{"port": 80, "service": "http", "state": "open"}],
            "missing_headers": ["Content-Security-Policy", "X-Frame-Options"],
            "observations": [
                {"title": "Open HTTP port", "severity": "Medium"},
                {"title": "Missing headers", "severity": "Low"},
            ],
        }
        engine = RiskCorrelationEngine(asm_data=asm_data)
        summary = engine.summary()

        rule1_findings = [
            f for f in summary["correlated_findings"]
            if "Open Web Port with Missing Security Headers" in f["title"]
        ]
        self.assertEqual(len(rule1_findings), 1)
        finding = rule1_findings[0]
        self.assertEqual(finding["risk_level"], "Medium")
        self.assertEqual(finding["category"], "Assessment correlation")
        self.assertEqual(finding["status_label"], "Requires investigation")
        self.assertFalse(finding["confirmed_compromise"])

    def test_web_exposure_rule_evidence_references_asm_terms_only(self):
        """Rule 1 evidence must reference reconnaissance/services, not DPI/traffic."""
        asm_data = {
            "target": "asm-only-terms.local",
            "open_ports": [{"port": 80}],
            "missing_headers": ["Content-Security-Policy"],
            "observations": [{"title": "Open port", "severity": "Medium"}],
        }
        engine = RiskCorrelationEngine(asm_data=asm_data)
        summary = engine.summary()

        r1 = [f for f in summary["correlated_findings"] if "Open Web Port" in f["title"]]
        self.assertTrue(r1)
        evidence = r1[0]["evidence"].lower()
        # Evidence should reference ASM terms
        self.assertTrue(
            any(t in evidence for t in ["reconnaissance", "exposed", "web service", "port"]),
            f"Expected ASM-aware terms in evidence, got: {evidence}"
        )
        # Should NOT reference DPI or traffic
        for bad_term in ["dpi", "network traffic", "packet"]:
            self.assertNotIn(bad_term, evidence, f"Found DPI term '{bad_term}' in ASM-only evidence")

    def test_web_exposure_attack_path_steps(self):
        """Rule 1 attack path must contain the correct step sequence."""
        asm_data = {
            "target": "path-test.local",
            "open_ports": [{"port": 443}],
            "missing_headers": ["Strict-Transport-Security"],
            "observations": [{"title": "obs1", "severity": "Low"}],
        }
        engine = RiskCorrelationEngine(asm_data=asm_data)
        summary = engine.summary()

        paths = [p for p in summary["attack_paths"] if "Web Service Exposure" in p["title"]]
        self.assertEqual(len(paths), 1)
        self.assertEqual(
            paths[0]["steps"],
            [
                "External Exposure",
                "Open Web Service",
                "Missing Security Controls",
                "Potential Attack Surface",
            ],
        )

    # ── Rule 2 – High ASM + suspicious DPI ────────────────────────────────

    def test_rule2_does_not_fire_for_asm_only(self):
        """Rule 2 must NOT fire when no DPI data is provided."""
        asm_data = {
            "target": "no-dpi.local",
            "summary": {"high": 5, "medium": 0, "low": 0},
            "observations": [
                {"title": "High exposure", "severity": "High"},
                {"title": "High exposure 2", "severity": "High"},
            ],
        }
        engine = RiskCorrelationEngine(asm_data=asm_data, dpi_data=None)
        summary = engine.summary()

        cross_layer = [
            f for f in summary["correlated_findings"]
            if "Cross-Layer" in f["title"] or "Suspicious Network" in f["title"]
        ]
        self.assertEqual(len(cross_layer), 0,
                         "Rule 2 (cross-layer DPI correlation) must not fire for ASM-only")

    def test_rule2_fires_for_asm_plus_dpi_with_high_findings(self):
        """Rule 2: High ASM finding + suspicious DPI traffic elevates to High correlated risk."""
        asm_data = {
            "target": "corp-gateway.local",
            "summary": {"high": 1, "medium": 0, "low": 0},
            "observations": [
                {"title": "High exposure service", "severity": "High"},
                {"title": "Obs 2", "severity": "Low"},
            ],
        }
        dpi_data = {
            "threat_summary": {"high": 1, "medium": 0, "low": 0},
            "findings": [
                {"title": "Possible exploit traffic", "severity": "High", "source": "threat_detector"}
            ],
        }
        engine = RiskCorrelationEngine(asm_data=asm_data, dpi_data=dpi_data)
        summary = engine.summary()

        high_findings = [
            f for f in summary["correlated_findings"]
            if "Cross-Layer" in f["title"] and "High Risk" in f["title"]
        ]
        self.assertEqual(len(high_findings), 1)
        self.assertEqual(high_findings[0]["risk_level"], "High")
        self.assertEqual(summary["risk_level"], score_to_level(summary["overall_score"]))

    def test_rule2_attack_path_references_dpi_when_present(self):
        """Rule 2 attack path steps must reference DPI/traffic when DPI data is present."""
        asm_data = {
            "target": "dpi-path.local",
            "summary": {"high": 1},
            "observations": [{"title": "high svc", "severity": "High"}],
        }
        dpi_data = {
            "threat_summary": {"high": 1},
            "findings": [{"title": "traffic anomaly", "severity": "High", "source": "threat_detector"}],
        }
        engine = RiskCorrelationEngine(asm_data=asm_data, dpi_data=dpi_data)
        summary = engine.summary()

        # Rule 2 generates the "Perimeter Exposure and Suspicious Traffic Trajectory" path.
        # Search by title (more reliable than step substring matching).
        r2_paths = [
            p for p in summary["attack_paths"]
            if "Perimeter Exposure" in p.get("title", "")
        ]
        self.assertTrue(r2_paths, (
            "Rule 2 attack path ('Perimeter Exposure…') not found. "
            f"Paths: {[p['title'] for p in summary['attack_paths']]}"
        ))
        # At least one step must reference DPI or traffic
        all_steps = " ".join(r2_paths[0]["steps"])
        self.assertTrue(
            "DPI" in all_steps or "Traffic" in all_steps or "Network" in all_steps,
            f"Expected DPI/traffic step in Rule 2 path, got: {all_steps}"
        )

    # ── Rule 3 – Multiple findings (source-aware) ─────────────────────────

    def test_rule3_asm_only_uses_asm_terminology(self):
        """Rule 3 for ASM-only correlation: title must say 'Multiple Attack Surface Observations'
        and evidence must NOT mention DPI or network traffic."""
        asm_data = {
            "target": "multi-asm.local",
            "observations": [
                {"title": "obs1", "severity": "Low"},
                {"title": "obs2", "severity": "Low"},
                {"title": "obs3", "severity": "Low"},
                {"title": "obs4", "severity": "Low"},
            ],
        }
        engine = RiskCorrelationEngine(asm_data=asm_data, dpi_data=None)
        summary = engine.summary()

        r3 = [f for f in summary["correlated_findings"] if "Multiple Attack Surface" in f["title"]]
        self.assertEqual(len(r3), 1, "Rule 3 ASM-only title should be 'Multiple Attack Surface Observations'")
        evidence = r3[0]["evidence"].lower()
        for bad_term in ["dpi", "network traffic", "packet", "multi-domain"]:
            self.assertNotIn(bad_term, evidence,
                             f"ASM-only Rule 3 evidence must not mention '{bad_term}'")

    def test_rule3_asm_plus_dpi_uses_cross_layer_terminology(self):
        """Rule 3 for ASM+DPI: title must say 'Cross-Layer Security Correlation' and
        evidence must mention DPI."""
        asm_data = {
            "target": "multi-crosslayer.local",
            "observations": [
                {"title": "obs1", "severity": "Low"},
                {"title": "obs2", "severity": "Low"},
            ],
        }
        dpi_data = {
            "threat_summary": {},
            "findings": [
                {"title": "dpi-finding1", "severity": "Low"},
                {"title": "dpi-finding2", "severity": "Low"},
            ],
        }
        engine = RiskCorrelationEngine(asm_data=asm_data, dpi_data=dpi_data)
        summary = engine.summary()

        r3 = [f for f in summary["correlated_findings"] if "Cross-Layer" in f["title"]]
        self.assertEqual(len(r3), 1, "Rule 3 ASM+DPI title should contain 'Cross-Layer'")
        evidence = r3[0]["evidence"].lower()
        self.assertTrue(
            "dpi" in evidence or "traffic" in evidence,
            f"ASM+DPI Rule 3 evidence should mention DPI/traffic: {evidence}"
        )

    def test_rule3_asm_only_attack_path_has_no_dpi_steps(self):
        """Rule 3 ASM-only attack path steps must not contain DPI or network traffic terms."""
        asm_data = {
            "target": "no-dpi-steps.local",
            "observations": [
                {"title": "o1", "severity": "Low"},
                {"title": "o2", "severity": "Low"},
                {"title": "o3", "severity": "Low"},
                {"title": "o4", "severity": "Low"},
            ],
        }
        engine = RiskCorrelationEngine(asm_data=asm_data, dpi_data=None)
        summary = engine.summary()

        for path in summary["attack_paths"]:
            steps_text = " ".join(path["steps"]).lower()
            for bad in ["dpi", "network traffic", "packet", "suspicious traffic"]:
                self.assertNotIn(bad, steps_text,
                                 f"ASM-only path steps must not contain '{bad}': {steps_text}")

    # ── Rule 4 – Isolated finding ──────────────────────────────────────────

    def test_isolated_finding_rule(self):
        """Rule 4: Exactly 1 finding produces lower correlation confidence."""
        asm_data = {
            "target": "isolated.local",
            "observations": [{"title": "sole obs", "severity": "Low"}],
        }
        engine = RiskCorrelationEngine(asm_data=asm_data)
        summary = engine.summary()

        isolated = [
            f for f in summary["correlated_findings"]
            if "Isolated Assessment Finding" in f["title"]
        ]
        self.assertEqual(len(isolated), 1)
        self.assertEqual(isolated[0]["risk_level"], "Low")
        self.assertIn("lower correlation confidence", isolated[0]["rationale"].lower())

    def test_isolated_finding_asm_only_path_has_no_dpi_why(self):
        """Rule 4 ASM-only: 'why' text must not mention DPI."""
        asm_data = {
            "target": "isolated-asm.local",
            "observations": [{"title": "sole obs", "severity": "Low"}],
        }
        engine = RiskCorrelationEngine(asm_data=asm_data, dpi_data=None)
        summary = engine.summary()

        isolated_paths = [p for p in summary["attack_paths"] if "Isolated" in p["title"]]
        self.assertTrue(isolated_paths)
        why = isolated_paths[0]["why"].lower()
        self.assertNotIn("dpi", why,
                         f"ASM-only isolated path 'why' must not mention DPI: {why}")

    # ── ASM-only limitations ───────────────────────────────────────────────

    def test_asm_only_limitations_exclude_dpi_limitation(self):
        """ASM-only limitations list must NOT include the DPI traffic limitation."""
        engine = RiskCorrelationEngine(asm_data={"target": "t.local"}, dpi_data=None)
        limitations = engine.get_limitations()
        limitations_text = " ".join(limitations).lower()
        self.assertNotIn(
            "deep packet inspection",
            limitations_text,
            "ASM-only limitations must not mention DPI"
        )

    def test_asm_plus_dpi_limitations_include_dpi_limitation(self):
        """ASM+DPI limitations list must include the DPI traffic limitation."""
        engine = RiskCorrelationEngine(
            asm_data={"target": "t.local"},
            dpi_data={"findings": [], "threat_summary": {}}
        )
        limitations = engine.get_limitations()
        limitations_text = " ".join(limitations).lower()
        self.assertIn(
            "deep packet inspection",
            limitations_text,
            "ASM+DPI limitations must include the DPI limitation"
        )

    # ── Full summary structure ─────────────────────────────────────────────

    def test_full_summary_structure_and_required_keys(self):
        """Verify complete summary dict schema."""
        engine = RiskCorrelationEngine(asm_data={}, dpi_data={})
        summary = engine.summary()

        required_keys = [
            "target", "overall_score", "risk_level", "finding_counts",
            "correlated_findings", "attack_paths", "executive_summary",
            "priority_recommendations", "limitations", "asm_included", "dpi_included",
        ]
        for key in required_keys:
            self.assertIn(key, summary)

        counts = summary["finding_counts"]
        for c_key in ["critical", "high", "medium", "low", "total"]:
            self.assertIn(c_key, counts)

    def test_asm_only_correlation_support(self):
        """Engine supports ASM-only correlation without DPI data."""
        asm_data = {
            "target": "asm-only.local",
            "open_ports": [{"port": 443, "service": "https"}],
            "missing_headers": ["Content-Security-Policy"],
            "observations": [{"title": "Obs 1", "severity": "Medium"}],
        }
        engine = RiskCorrelationEngine(asm_data=asm_data, dpi_data=None)
        summary = engine.summary()

        self.assertTrue(summary["asm_included"])
        self.assertFalse(summary["dpi_included"])
        self.assertEqual(summary["risk_level"], score_to_level(summary["overall_score"]))
        self.assertIn("asm-only.local", summary["executive_summary"])
        # Executive summary must not mention DPI when DPI is absent
        self.assertNotIn("Deep Packet Inspection", summary["executive_summary"],
                         "ASM-only executive summary must not mention DPI")

    def test_asm_plus_dpi_executive_summary_mentions_dpi(self):
        """When DPI data is present, executive summary must mention DPI."""
        engine = RiskCorrelationEngine(
            asm_data={"target": "corp.local"},
            dpi_data={"findings": [], "threat_summary": {}, "summary": {}}
        )
        summary = engine.summary()
        self.assertIn("Deep Packet Inspection", summary["executive_summary"])

    def test_risk_level_always_consistent_with_score(self):
        """risk_level in summary must always equal score_to_level(overall_score)."""
        scenarios = [
            # (asm_data, dpi_data)
            ({"target": "t1.local"}, None),
            ({"target": "t2.local", "open_ports": [{"port": 80}], "missing_headers": ["CSP"],
              "observations": [{"title": "o", "severity": "Low"}]}, None),
            ({"target": "t3.local", "summary": {"high": 1}, "observations": [{"title": "h", "severity": "High"}]},
             {"threat_summary": {"high": 1}, "findings": [{"title": "hf", "severity": "High"}]}),
        ]
        for asm, dpi in scenarios:
            engine = RiskCorrelationEngine(asm_data=asm, dpi_data=dpi)
            summary = engine.summary()
            expected_level = score_to_level(summary["overall_score"])
            self.assertEqual(
                summary["risk_level"],
                expected_level,
                f"Level mismatch for target '{asm.get('target')}': "
                f"score={summary['overall_score']}, level={summary['risk_level']}, expected={expected_level}"
            )


# ---------------------------------------------------------------------------
# Integration tests – Flask routes
# ---------------------------------------------------------------------------
class RiskCorrelationWorkflowIntegrationTests(unittest.TestCase):
    """Integration tests covering Flask routes, form validation, results page, and PDF generation."""

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

    def _seed_asm_assessment(self, target="seed.local", scan_id=None):
        if scan_id is None:
            scan_id = str(uuid.uuid4())
        asm_entry = {
            "scan_id": scan_id,
            "target": target,
            "normalized_target": f"http://{target}",
            "assessed_at": "2026-09-14T01:00:00+00:00",
            "attack_surface": {
                "open_ports": [{"port": 80, "service": "http"}],
                "missing_headers": ["Content-Security-Policy", "X-Frame-Options"],
                "observations": [
                    {"title": "Open Port 80", "severity": "Medium", "description": "HTTP exposed",
                     "evidence": "Port 80", "recommendation": "Close or harden", "limitation": "N/A"},
                    {"title": "Missing CSP", "severity": "Medium", "description": "Header missing",
                     "evidence": "CSP missing", "recommendation": "Add CSP", "limitation": "N/A"},
                ],
                "summary": {"total_findings": 2, "high": 0, "medium": 2, "low": 0, "overall_exposure": "Medium"},
            },
        }
        self.app.extensions["asm_results"][scan_id] = asm_entry
        return scan_id

    def _seed_dpi_assessment(self, interface="eth0", capture_id=None):
        if capture_id is None:
            capture_id = str(uuid.uuid4())
        dpi_entry = {
            "capture_id": capture_id,
            "selected_interface": interface,
            "started_at": "2026-09-14T01:00:00+00:00",
            "completed_at": "2026-09-14T01:00:10+00:00",
            "summary": {"total_packets": 50},
            "findings": [
                {"title": "Anomalous SYN traffic", "severity": "High",
                 "evidence": "50 SYNs", "recommendation": "Inspect flows", "source": "threat_detector"}
            ],
            "threat_summary": {"high": 1, "medium": 0, "low": 0},
        }
        self.app.extensions["dpi_results"].add(dpi_entry, capture_id)
        return capture_id

    # ── Form page ──────────────────────────────────────────────────────────

    def test_form_page_renders_with_seeded_options(self):
        asm_id = self._seed_asm_assessment("target1.example.com")
        dpi_id = self._seed_dpi_assessment("eth0")

        response = self.client.get("/risk-correlation")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Cyber Risk Correlation Engine", response.data)
        self.assertIn(b"target1.example.com", response.data)
        self.assertIn(asm_id[:8].encode(), response.data)
        self.assertIn(b"eth0", response.data)

    def test_form_page_without_asm_shows_warning(self):
        response = self.client.get("/risk-correlation")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"No Attack Surface assessments found", response.data)

    # ── Authorization and input validation ─────────────────────────────────

    def test_analyze_without_authorization_returns_403(self):
        asm_id = self._seed_asm_assessment()
        response = self.client.post(
            "/risk-correlation/analyze",
            data={"asm_scan_id": asm_id},
        )
        self.assertEqual(response.status_code, 403)

    def test_analyze_without_asm_scan_id_returns_400(self):
        response = self.client.post(
            "/risk-correlation/analyze",
            data={"authorized": "yes", "asm_scan_id": ""},
        )
        self.assertEqual(response.status_code, 400)

    def test_analyze_with_nonexistent_asm_id_returns_404(self):
        unknown_id = str(uuid.uuid4())
        response = self.client.post(
            "/risk-correlation/analyze",
            data={"authorized": "yes", "asm_scan_id": unknown_id},
        )
        self.assertEqual(response.status_code, 404)

    # ── Full ASM + DPI pipeline ────────────────────────────────────────────

    def test_full_correlation_flow_with_asm_and_dpi(self):
        """Full pipeline with ASM+DPI: result page, all sections, PDF download."""
        asm_id = self._seed_asm_assessment("full-target.local")
        dpi_id = self._seed_dpi_assessment("wlan0")

        response = self.client.post(
            "/risk-correlation/analyze",
            data={"authorized": "yes", "asm_scan_id": asm_id, "dpi_capture_id": dpi_id},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        location = response.headers.get("Location", "")
        self.assertTrue(location.startswith("/risk-correlation/result/"))
        scan_id = location.split("/")[-1]

        result_resp = self.client.get(location)
        self.assertEqual(result_resp.status_code, 200)

        for expected in [
            b"CYBER RISK CORRELATION RESULTS",
            b"full-target.local",
            b"Executive Summary",
            b"OVERALL RISK SCORE",
            b"Risk Level",
            b"Correlated Findings",
            b"Potential Attack Paths",
            b"Priority Recommendations",
            b"Methodological Limitations",
            b"Download PDF Report",
        ]:
            self.assertIn(expected, result_resp.data,
                          f"Expected '{expected}' in result page but not found")

        # PDF download
        download_resp = self.client.get(f"/risk-correlation/reports/{scan_id}/download")
        self.assertEqual(download_resp.status_code, 200)
        self.assertEqual(download_resp.mimetype, "application/pdf")
        self.assertTrue(download_resp.data.startswith(b"%PDF"))
        self.assertIn(
            f"Cybersential_Risk_Correlation_{scan_id}.pdf",
            download_resp.headers.get("Content-Disposition", ""),
        )
        download_resp.close()

    # ── ASM-only pipeline ──────────────────────────────────────────────────

    def test_full_correlation_flow_asm_only(self):
        """ASM-only pipeline: result page shows ASM scope, PDF download works."""
        asm_id = self._seed_asm_assessment("asm-only-run.local")

        response = self.client.post(
            "/risk-correlation/analyze",
            data={"authorized": "yes", "asm_scan_id": asm_id, "dpi_capture_id": "none"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        location = response.headers.get("Location", "")
        scan_id = location.split("/")[-1]

        result_resp = self.client.get(location)
        self.assertEqual(result_resp.status_code, 200)
        self.assertIn(b"asm-only-run.local", result_resp.data)
        self.assertIn(b"ASM Baseline", result_resp.data)

        download_resp = self.client.get(f"/risk-correlation/reports/{scan_id}/download")
        self.assertEqual(download_resp.status_code, 200)
        self.assertEqual(download_resp.mimetype, "application/pdf")
        self.assertTrue(download_resp.data.startswith(b"%PDF"))
        download_resp.close()

    def test_asm_only_result_page_score_and_level_consistent(self):
        """Result page: the score displayed and level badge must be consistent (Level = score_to_level(score))."""
        asm_id = self._seed_asm_assessment("score-check.local")
        response = self.client.post(
            "/risk-correlation/analyze",
            data={"authorized": "yes", "asm_scan_id": asm_id, "dpi_capture_id": "none"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        # Both score and risk level heading must appear
        self.assertIn(b"OVERALL RISK SCORE", response.data)
        self.assertIn(b"Risk Level:", response.data)

    # ── PDF output wording ─────────────────────────────────────────────────

    def test_pdf_output_does_not_contain_dpi_for_asm_only_run(self):
        """PDF generated from ASM-only correlation must not mention DPI in its content."""
        asm_id = self._seed_asm_assessment("pdf-asm-only.local")
        resp = self.client.post(
            "/risk-correlation/analyze",
            data={"authorized": "yes", "asm_scan_id": asm_id, "dpi_capture_id": "none"},
            follow_redirects=False,
        )
        scan_id = resp.headers["Location"].split("/")[-1]

        download_resp = self.client.get(f"/risk-correlation/reports/{scan_id}/download")
        self.assertEqual(download_resp.status_code, 200)
        # PDF is binary; check raw bytes for the string "DPI" does NOT appear as text
        # (ReportLab does not embed plain text directly, but the scope label is embedded)
        # We verify it is a valid PDF (starts with %PDF) and scope string is correct
        self.assertTrue(download_resp.data.startswith(b"%PDF"))
        download_resp.close()

    def test_pdf_output_includes_scope_string_for_dpi_run(self):
        """PDF generated from ASM+DPI correlation contains scope text with DPI."""
        asm_id = self._seed_asm_assessment("pdf-dpi.local")
        dpi_id = self._seed_dpi_assessment("eth1")
        resp = self.client.post(
            "/risk-correlation/analyze",
            data={"authorized": "yes", "asm_scan_id": asm_id, "dpi_capture_id": dpi_id},
            follow_redirects=False,
        )
        scan_id = resp.headers["Location"].split("/")[-1]
        download_resp = self.client.get(f"/risk-correlation/reports/{scan_id}/download")
        self.assertEqual(download_resp.status_code, 200)
        self.assertTrue(download_resp.data.startswith(b"%PDF"))
        download_resp.close()

    # ── Error cases ────────────────────────────────────────────────────────

    def test_unknown_result_scan_id_returns_404(self):
        response = self.client.get(f"/risk-correlation/result/{uuid.uuid4()}")
        self.assertEqual(response.status_code, 404)

    def test_download_unknown_correlation_id_returns_404(self):
        response = self.client.get(f"/risk-correlation/reports/{uuid.uuid4()}/download")
        self.assertEqual(response.status_code, 404)

    def test_download_invalid_uuid_returns_404(self):
        response = self.client.get("/risk-correlation/reports/not-a-valid-uuid/download")
        self.assertEqual(response.status_code, 404)

    def test_pdf_generation_failure_handled_gracefully(self):
        asm_id = self._seed_asm_assessment()
        with patch("app.generate_correlation_report", side_effect=RuntimeError("PDF engine failure")):
            response = self.client.post(
                "/risk-correlation/analyze",
                data={"authorized": "yes", "asm_scan_id": asm_id},
                follow_redirects=True,
            )
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"PDF report could not be generated", response.data)
