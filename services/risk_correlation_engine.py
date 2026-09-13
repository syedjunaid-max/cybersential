"""Cyber Risk Correlation Engine

Aggregates findings from Attack Surface Mapping (ASM), DPI traffic analysis, and Threat Detection
into a unified risk score, finding counts, correlated findings, potential attack paths,
priority recommendations, and executive summary.

Risk Score Thresholds (consistent across engine, UI, PDF):
  0-24   => Low
  25-49  => Medium
  50-74  => High
  75-100 => Critical
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple


# ---------------------------------------------------------------------------
# Score-to-level mapping – single source of truth used by engine, tests, UI.
# ---------------------------------------------------------------------------
SCORE_THRESHOLDS: List[Tuple[int, str]] = [
    # (minimum score inclusive, level)
    (75, "Critical"),
    (50, "High"),
    (25, "Medium"),
    (0, "Low"),
]


def score_to_level(score: int) -> str:
    """Return the risk level string for a given 0-100 score.

    Thresholds:
        75-100 -> Critical
        50-74  -> High
        25-49  -> Medium
         0-24  -> Low
    """
    for threshold, level in SCORE_THRESHOLDS:
        if score >= threshold:
            return level
    return "Low"


class RiskCorrelationEngine:
    """Core engine for correlating security assessment data."""

    def __init__(
        self,
        asm_data: Dict[str, Any] | None = None,
        dpi_data: Dict[str, Any] | None = None,
        threat_data: Dict[str, Any] | None = None,
    ) -> None:
        self.raw_asm = asm_data or {}
        self.raw_dpi = dpi_data or {}
        self.raw_threat = threat_data or {}

        # Normalise ASM data whether full assessment or attack_surface dictionary
        if "attack_surface" in self.raw_asm and isinstance(self.raw_asm["attack_surface"], dict):
            self.asm_surface = self.raw_asm["attack_surface"]
        else:
            self.asm_surface = self.raw_asm

        self.target = (
            self.raw_asm.get("normalized_target")
            or self.raw_asm.get("target")
            or self.asm_surface.get("target")
            or "Assessed System"
        )

        # Track whether DPI data was actually supplied by the caller.
        # An empty dict {} counts as "no DPI" – only a non-empty dict means DPI present.
        self._dpi_present: bool = bool(self.raw_dpi)

        # Normalise DPI and Threat data
        self.dpi_findings = self.raw_dpi.get("findings", [])
        self.dpi_summary = self.raw_dpi.get("summary", {})

        # Threat data might be embedded in raw_dpi or passed explicitly
        if self.raw_threat:
            self.threat_summary = self.raw_threat.get("threat_summary", {})
            self.threat_findings = self.raw_threat.get("findings", [])
        elif "threat_summary" in self.raw_dpi:
            self.threat_summary = self.raw_dpi.get("threat_summary", {})
            self.threat_findings = [
                f for f in self.dpi_findings
                if f.get("source") == "threat_detector" or "threat" in str(f.get("title", "")).lower()
            ]
        else:
            self.threat_summary = {}
            self.threat_findings = []

        self.correlated_findings: List[Dict[str, Any]] = []
        self.attack_paths: List[Dict[str, Any]] = []

    # ---------------------------------------------------------------------
    # Helper utilities
    # ---------------------------------------------------------------------
    @staticmethod
    def _make_finding(
        title: str,
        risk_level: str,
        evidence: str,
        rationale: str,
        recommendation: str,
        category: str = "Assessment correlation",
        status_label: str = "Requires investigation",
    ) -> Dict[str, Any]:
        return {
            "title": title,
            "risk_level": risk_level,
            "category": category,
            "evidence": evidence,
            "rationale": rationale,
            "recommendation": recommendation,
            "status_label": status_label,
            "confirmed_compromise": False,
        }

    @staticmethod
    def _make_attack_path(
        title: str,
        risk_level: str,
        steps: List[str],
        evidence: str,
        why: str,
        recommendation: str,
    ) -> Dict[str, Any]:
        return {
            "title": title,
            "risk_level": risk_level,
            "steps": steps,
            "evidence": evidence,
            "why": why,
            "recommendation": recommendation,
            "type_label": "Potential attack path",
        }

    # ---------------------------------------------------------------------
    # Correlation rules
    # ---------------------------------------------------------------------
    def _rule_web_exposure_missing_headers(self) -> None:
        """Rule 1 – Open web port + missing security headers = increased web exposure.

        Source-aware: references only reconnaissance, exposed services, and web security
        analysis regardless of whether DPI data is present.
        """
        open_ports = (
            self.asm_surface.get("open_ports")
            or self.raw_asm.get("port_scan", {}).get("open_ports")
            or []
        )
        missing_headers = (
            self.asm_surface.get("missing_headers")
            or self.raw_asm.get("header_analysis", {}).get("missing_headers")
            or []
        )
        if not open_ports or not missing_headers:
            return

        web_ports = {80, 443, 8080, 8443, 8000, 8888, 5000}
        detected_web_ports = [p.get("port") for p in open_ports if p.get("port") in web_ports]

        if not detected_web_ports:
            return

        ports_str = ", ".join(str(p) for p in detected_web_ports)
        headers_str = ", ".join(missing_headers[:5])
        if len(missing_headers) > 5:
            headers_str += f" (+{len(missing_headers) - 5} more)"

        title = "Open Web Port with Missing Security Headers"
        evidence = (
            f"Reconnaissance identified exposed web service port(s) {ports_str}; "
            f"web security header analysis found missing: {headers_str}."
        )
        rationale = (
            "An externally exposed web service identified during attack surface reconnaissance "
            "lacks fundamental defensive HTTP headers identified in web security analysis. "
            "This increases the exploitable attack surface. Requires investigation."
        )
        recommendation = (
            "Implement critical defense headers (Content-Security-Policy, Strict-Transport-Security, "
            "X-Frame-Options, X-Content-Type-Options) to harden the exposed service."
        )
        self.correlated_findings.append(
            self._make_finding(title, "Medium", evidence, rationale, recommendation)
        )

        # Attack path – source-aware: references only ASM observations
        self.attack_paths.append(
            self._make_attack_path(
                title="Web Service Exposure and Header Deficiency Path",
                risk_level="Medium",
                steps=[
                    "External Exposure",
                    "Open Web Service",
                    "Missing Security Controls",
                    "Potential Attack Surface",
                ],
                evidence=evidence,
                why=(
                    "Attack surface reconnaissance reveals an active web service, while "
                    "web security header analysis shows absent browser-enforced security boundaries."
                ),
                recommendation=recommendation,
            )
        )

    def _rule_high_asm_and_suspicious_dpi(self) -> None:
        """Rule 2 – High ASM finding + suspicious DPI traffic = correlated high risk.

        Source-aware: only fires when DPI data is actually present.
        Concurrent high-severity observations across layers suggest elevated risk.
        """
        # This rule requires DPI data to exist; skip entirely for ASM-only correlation.
        if not self._dpi_present:
            return

        asm_summary = (
            self.asm_surface.get("summary")
            or self.raw_asm.get("summary")
            or {}
        )
        asm_high = asm_summary.get("high", 0)
        if not asm_high:
            asm_obs = self.asm_surface.get("observations") or self.raw_asm.get("observations") or []
            asm_high = sum(1 for o in asm_obs if str(o.get("severity", "")).lower() in ("high", "critical"))

        dpi_high = self.threat_summary.get("high", 0)
        if not dpi_high:
            dpi_high = sum(1 for f in self.dpi_findings if str(f.get("severity", "")).lower() in ("high", "critical"))

        if asm_high > 0 and dpi_high > 0:
            title = "Cross-Layer Security Correlation: High Risk Surface and Suspicious Traffic"
            evidence = (
                f"Attack surface high-severity findings: {asm_high} | "
                f"DPI traffic threat high-severity indicators: {dpi_high}."
            )
            rationale = (
                "Concurrent high-severity indicators across external perimeter mapping and DPI network traffic "
                "inspection suggest that exposed attack surface vectors may be actively probed or targeted. "
                "Requires investigation."
            )
            recommendation = (
                "Prioritize remediation of identified high-severity perimeter exposures and review DPI network "
                "flow logs for the flagged endpoints immediately."
            )
            self.correlated_findings.append(
                self._make_finding(title, "High", evidence, rationale, recommendation)
            )

            # Attack path – includes DPI/traffic steps because DPI data is confirmed present
            self.attack_paths.append(
                self._make_attack_path(
                    title="Perimeter Exposure and Suspicious Traffic Trajectory",
                    risk_level="High",
                    steps=[
                        "External Attack Surface",
                        "High Severity Service Exposure",
                        "Suspicious Network Traffic (DPI)",
                        "Elevated Exploitation Risk",
                    ],
                    evidence=evidence,
                    why=(
                        "High-severity vulnerabilities identified during attack surface mapping align "
                        "with anomalous packet traffic patterns observed in DPI deep packet inspection."
                    ),
                    recommendation=recommendation,
                )
            )

    def _rule_multiple_related_findings(self) -> None:
        """Rule 3 – Multiple related findings = increase confidence.

        Source-aware: wording adapts to whether DPI is present.
        When only ASM is selected, uses 'Multiple Attack Surface Observations'.
        When ASM + DPI present, uses 'Cross-Layer Security Correlation'.
        """
        asm_obs = self.asm_surface.get("observations") or self.raw_asm.get("observations") or []
        total_findings = len(asm_obs) + len(self.dpi_findings) + len(self.threat_findings)

        if total_findings <= 3:
            return

        if self._dpi_present:
            # Cross-layer: include DPI terminology
            title = "Cross-Layer Security Correlation: Multiple Findings Across Domains"
            evidence = (
                f"Total of {total_findings} distinct security observations recorded across "
                f"attack surface mapping and DPI traffic analysis."
            )
            rationale = (
                "A cluster of multiple findings across reconnaissance, exposed services, web security analysis, "
                "and DPI network traffic increases cross-layer correlation confidence that systemic "
                "configuration or exposure issues exist. Requires investigation."
            )
            recommendation = (
                "Perform a comprehensive security review addressing systemic exposure across perimeter services, "
                "host configuration baselines, and observed network traffic patterns."
            )
            path_title = "Cross-Layer Defense Gaps"
            path_steps = [
                "Broad Attack Surface",
                "Multiple Correlated Observations",
                "Network Traffic Anomalies",
                "Expanded Threat Footprint",
            ]
            path_why = (
                "Multiple independent observations across attack surface and DPI traffic corroborate "
                "increased overall exposure."
            )
        else:
            # ASM-only: no DPI terminology
            title = "Multiple Attack Surface Observations"
            evidence = (
                f"Total of {total_findings} distinct attack surface observations recorded across "
                f"reconnaissance, exposed services, and web security analysis."
            )
            rationale = (
                "A cluster of multiple attack surface findings across reconnaissance, exposed services, "
                "and web security analysis increases assessment confidence that systemic configuration "
                "or exposure issues exist. Requires investigation."
            )
            recommendation = (
                "Perform a comprehensive security review addressing systemic exposure across perimeter services, "
                "host configuration baselines, and web security header posture."
            )
            path_title = "Multiple Attack Surface Exposure Gaps"
            path_steps = [
                "Broad Attack Surface",
                "Multiple ASM Observations",
                "Compounded Service Misconfigurations",
                "Expanded Exposure Footprint",
            ]
            path_why = (
                "Multiple independent attack surface observations across reconnaissance and service analysis "
                "corroborate increased overall exposure."
            )

        self.correlated_findings.append(
            self._make_finding(title, "Medium", evidence, rationale, recommendation)
        )

        if not any(p["title"] == path_title for p in self.attack_paths):
            self.attack_paths.append(
                self._make_attack_path(
                    title=path_title,
                    risk_level="Medium",
                    steps=path_steps,
                    evidence=evidence,
                    why=path_why,
                    recommendation=recommendation,
                )
            )

    def _rule_isolated_finding(self) -> None:
        """Rule 4 – Isolated finding = lower confidence.

        Source-aware: when ASM-only, does not mention DPI or network indicators.
        """
        asm_obs = self.asm_surface.get("observations") or self.raw_asm.get("observations") or []
        total_findings = len(asm_obs) + len(self.dpi_findings) + len(self.threat_findings)

        if total_findings != 1:
            return

        title = "Isolated Assessment Finding with Lower Correlation Confidence"
        evidence = "Exactly one observation was recorded across all integrated assessment modules."
        rationale = (
            "The lack of corroborating evidence across other assessment layers results in "
            "lower correlation confidence and suggests this single observation may be a transient "
            "condition, an isolated configuration detail, or a potential false positive. Requires investigation."
        )
        recommendation = (
            "Validate this isolated finding via targeted follow-up testing or manual verification before "
            "initiating complex remediation."
        )
        self.correlated_findings.append(
            self._make_finding(title, "Low", evidence, rationale, recommendation)
        )

        # Source-aware attack path text
        if self._dpi_present:
            path_why = (
                "No corroborating DPI traffic or network indicators accompanied this single observation."
            )
        else:
            path_why = (
                "No corroborating reconnaissance, service, or web security indicators accompanied "
                "this single observation."
            )

        self.attack_paths.append(
            self._make_attack_path(
                title="Isolated Observation Trajectory",
                risk_level="Low",
                steps=[
                    "Isolated Surface Indicator",
                    "Uncorroborated Anomaly",
                    "Limited Exploration Surface",
                ],
                evidence=evidence,
                why=path_why,
                recommendation=recommendation,
            )
        )

    # ---------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------
    def correlate_findings(self) -> List[Dict[str, Any]]:
        """Apply all correlation rules and return the list of correlated findings."""
        self.correlated_findings.clear()
        self.attack_paths.clear()

        self._rule_web_exposure_missing_headers()
        self._rule_high_asm_and_suspicious_dpi()
        self._rule_multiple_related_findings()
        self._rule_isolated_finding()

        return self.correlated_findings

    def compute_risk_score(self) -> Tuple[int, str, Dict[str, int]]:
        """Derive a 0-100 risk score, risk level, and finding counts breakdown.

        Score calculation (per finding):
            Critical: 30 pts  |  High: 20 pts  |  Medium: 10 pts  |  Low: 5 pts
            Clamped to 0-100.

        Risk level determined solely from score (consistent thresholds):
            75-100 => Critical
            50-74  => High
            25-49  => Medium
             0-24  => Low
        """
        critical_count = sum(
            1 for f in self.correlated_findings if f.get("risk_level", "").lower() == "critical"
        )
        high_count = sum(
            1 for f in self.correlated_findings if f.get("risk_level", "").lower() == "high"
        )
        medium_count = sum(
            1 for f in self.correlated_findings if f.get("risk_level", "").lower() == "medium"
        )
        low_count = sum(
            1 for f in self.correlated_findings if f.get("risk_level", "").lower() == "low"
        )
        total_count = critical_count + high_count + medium_count + low_count

        # Score calculation (0 to 100)
        score = critical_count * 30 + high_count * 20 + medium_count * 10 + low_count * 5
        score = max(0, min(100, score))

        # Risk level derived exclusively from score — single source of truth
        level = score_to_level(score)

        counts = {
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "total": total_count,
        }

        return score, level, counts

    def generate_attack_paths(self) -> List[Dict[str, Any]]:
        """Return generated attack paths."""
        return self.attack_paths

    def generate_executive_summary(
        self, score: int, level: str, counts: Dict[str, int]
    ) -> str:
        """Generate a concise, professional executive summary.

        Source-aware: only mentions DPI if DPI data was provided.
        """
        scope_desc = "Attack Surface Mapping"
        if self._dpi_present:
            scope_desc += " and Deep Packet Inspection (DPI) traffic analysis"

        return (
            f"An authorized cyber risk correlation was executed against '{self.target}' covering {scope_desc}. "
            f"The assessment produced an Overall Risk Score of {score}/100 with an aggregate Risk Level of '{level}'. "
            f"A total of {counts['total']} correlated findings were identified ({counts['critical']} Critical, "
            f"{counts['high']} High, {counts['medium']} Medium, {counts['low']} Low), yielding {len(self.attack_paths)} "
            f"potential attack paths requiring investigation. Note: All findings reflect assessment correlations and "
            f"do not claim exploitation or confirmed system compromise."
        )

    def generate_priority_recommendations(self) -> List[str]:
        """Aggregate and prioritize actionable recommendations."""
        recs: List[str] = []
        for finding in self.correlated_findings:
            rec = finding.get("recommendation")
            if rec and rec not in recs:
                recs.append(rec)
        for path in self.attack_paths:
            rec = path.get("recommendation")
            if rec and rec not in recs:
                recs.append(rec)

        if not recs:
            recs.append(
                "Maintain continuous monitoring and schedule regular authorized perimeter assessments."
            )
        return recs

    def get_limitations(self) -> List[str]:
        """Return transparent educational and methodological limitations.

        Source-aware: DPI limitation only included when DPI data was provided.
        """
        limitations = [
            "Assessment correlation only: Findings reflect correlated security observations across modules and do not confirm vulnerability exploitation or active compromise.",
            "Potential attack paths represent theoretical attacker pathways based on discovered exposures rather than verified exploits.",
            "Point-in-time observation: Findings reflect host and network states at the time of assessment and may vary with dynamic configurations.",
            "Authorized educational use only: Security assessments must only be conducted on systems with explicit written authorization.",
        ]
        if self._dpi_present:
            limitations.insert(
                3,
                "Deep Packet Inspection traffic analysis is bounded and metadata-only; encrypted payloads were neither decrypted nor inspected.",
            )
        return limitations

    def summary(self) -> Dict[str, Any]:
        """Return the complete correlation summary used by UI and PDF reports."""
        correlated = self.correlate_findings()
        score, level, counts = self.compute_risk_score()
        paths = self.generate_attack_paths()
        exec_summary = self.generate_executive_summary(score, level, counts)
        priority_recs = self.generate_priority_recommendations()
        limitations = self.get_limitations()

        return {
            "target": self.target,
            "overall_score": score,
            "risk_level": level,
            "finding_counts": counts,
            "correlated_findings": correlated,
            "attack_paths": paths,
            "executive_summary": exec_summary,
            "priority_recommendations": priority_recs,
            "limitations": limitations,
            "asm_included": bool(self.raw_asm),
            "dpi_included": self._dpi_present,
        }
