"""Threat detection engine for Cybersential.

This module provides a `detect_threats` function that analyses the traffic
assessment dictionary (produced by `services.traffic_analyzer.analyze_traffic`)
and generates rule‑based findings as described in
`cybersential_threat_detection_engine.md`.

The implementation is intentionally lightweight and operates only on the
metadata summary that is already available – no raw packet payloads are used.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _make_finding(
    finding_id: str,
    threat_type: str,
    risk_level: str,
    source: str | None,
    destination: str | None,
    detection_reason: str,
    evidence_summary: str,
    recommendation: str,
    confidence: str,
) -> Dict[str, Any]:
    """Create a finding dictionary matching the specification.

    The keys correspond to the fields listed in the markdown file:
    ``finding_id``, ``threat_type``, ``risk_level``, ``source``,
    ``destination``, ``detection_reason``, ``evidence_summary``,
    ``recommendation`` and ``confidence``.
    """
    return {
        "id": finding_id,
        "threat_type": threat_type,
        "risk_level": risk_level,
        "source": source,
        "destination": destination,
        "detection_reason": detection_reason,
        "evidence_summary": evidence_summary,
        "recommendation": recommendation,
        "confidence": confidence,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_threats(assessment: Dict[str, Any]) -> Dict[str, Any]:
    """Detect threat patterns based on the traffic ``assessment``.

    The function returns a dictionary with two top‑level keys:

    * ``findings`` – a list of finding dictionaries.
    * ``summary`` – a statistics dictionary containing the total number of
      findings, a count per risk level and an overall risk assessment.

    The logic follows the capabilities described in
    ``cybersential_threat_detection_engine.md`` and is deliberately simple –
    it operates on the already‑summarised metadata to respect the privacy
    constraints of the project.
    """
    findings: List[Dict[str, Any]] = []
    summary: Dict[str, Any] = {
        "total_findings": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "overall_risk": "Low",
    }

    # Helper to register a finding and update the summary counters.
    def _add(finding: Dict[str, Any]) -> None:
        findings.append(finding)
        summary["total_findings"] += 1
        level = finding["risk_level"].lower()
        if level in ("low", "medium", "high"):
            summary[level] += 1
        # Re‑evaluate overall risk – the highest severity present wins.
        if level == "high":
            summary["overall_risk"] = "High"
        elif level == "medium" and summary["overall_risk"] != "High":
            summary["overall_risk"] = "Medium"
        elif summary["overall_risk"] not in ("High", "Medium"):
            summary["overall_risk"] = "Low"

    # -------------------------------------------------------------------
    # 1. Possible Port Scanning (SYN‑without‑ACK pattern)
    # -------------------------------------------------------------------
    tcp_flags = assessment.get("summary", {}).get("tcp_flag_distribution", [])
    syn_without_ack = 0
    ack = 0
    for entry in tcp_flags:
        flag = entry.get("value", "")
        count = entry.get("count", 0)
        if "S" in flag and "A" not in flag:
            syn_without_ack += count
        if "A" in flag:
            ack += count
    if syn_without_ack >= 20 and ack * 3 < syn_without_ack:
        fid = f"THR-{uuid.uuid4().hex[:8].upper()}"
        _add(
            _make_finding(
                finding_id=fid,
                threat_type="Possible Port Scan",
                risk_level="Medium" if syn_without_ack < 40 else "High",
                source=None,
                destination=None,
                detection_reason=f"Observed {syn_without_ack} SYN packets without ACKs (ACK count: {ack}).",
                evidence_summary="SYN‑without‑ACK pattern suggests a scan.",
                recommendation="Confirm the source activity and compare with authorized scanning tools.",
                confidence="Tentative – short captures may miss ACKs.",
            )
        )

    # -------------------------------------------------------------------
    # 2. Repeated Connection Attempts (many distinct destination ports)
    # -------------------------------------------------------------------
    top_ports = assessment.get("summary", {}).get("top_destination_ports", [])
    distinct_port_count = len(top_ports)
    if distinct_port_count >= 15:
        fid = f"THR-{uuid.uuid4().hex[:8].upper()}"
        _add(
            _make_finding(
                finding_id=fid,
                threat_type="Repeated Connection Attempts",
                risk_level="Medium",
                source=None,
                destination=None,
                detection_reason=f"Observed traffic to {distinct_port_count} distinct destination ports.",
                evidence_summary="Multiple ports accessed may indicate probing or brute‑force.",
                recommendation="Verify whether the activity matches legitimate services or scanning tools.",
                confidence="Moderate – without source attribution it is heuristic.",
            )
        )

    # -------------------------------------------------------------------
    # 3. Unusual Traffic Volume
    # -------------------------------------------------------------------
    total_packets = assessment.get("summary", {}).get("total_packets", 0)
    if total_packets >= 5000:
        fid = f"THR-{uuid.uuid4().hex[:8].upper()}"
        _add(
            _make_finding(
                finding_id=fid,
                threat_type="Unusual Traffic Volume",
                risk_level="High",
                source=None,
                destination=None,
                detection_reason=f"Captured {total_packets} packets during the session.",
                evidence_summary="High packet count relative to typical bounded captures.",
                recommendation="Correlate with expected workload and verify no runaway processes.",
                confidence="High – volume outlier is clear.",
            )
        )

    # -------------------------------------------------------------------
    # 4. Suspicious TCP Flags (e.g., many RST flags)
    # -------------------------------------------------------------------
    rst_count = 0
    for entry in tcp_flags:
        if "R" in entry.get("value", ""):
            rst_count += entry.get("count", 0)
    if rst_count >= 30:
        fid = f"THR-{uuid.uuid4().hex[:8].upper()}"
        _add(
            _make_finding(
                finding_id=fid,
                threat_type="Suspicious TCP Flags",
                risk_level="Medium",
                source=None,
                destination=None,
                detection_reason=f"Observed {rst_count} packets with the RST flag set.",
                evidence_summary="Frequent resets can indicate scanning or connection issues.",
                recommendation="Check source behavior and ensure no denial‑of‑service patterns.",
                confidence="Tentative – could be normal resets in some services.",
            )
        )

    # -------------------------------------------------------------------
    # 5. Possible Brute‑Force Pattern (many DNS queries + high packet count)
    # -------------------------------------------------------------------
    dns_queries = sum(item.get("count", 0) for item in assessment.get("summary", {}).get("dns_queries_observed", []))
    if dns_queries >= 100 and total_packets >= 2000:
        fid = f"THR-{uuid.uuid4().hex[:8].upper()}"
        _add(
            _make_finding(
                finding_id=fid,
                threat_type="Possible Brute‑Force Pattern",
                risk_level="Medium",
                source=None,
                destination=None,
                detection_reason=f"High DNS query volume ({dns_queries}) together with {total_packets} packets.",
                evidence_summary="Could indicate automated credential‑guessing over the network.",
                recommendation="Enforce rate limits and review authentication logs.",
                confidence="Low – correlation does not prove brute‑force.",
            )
        )

    # Ensure the summary always contains the required keys even when no findings.
    if not findings:
        summary.update({"total_findings": 0, "low": 0, "medium": 0, "high": 0, "overall_risk": "Low"})

    return {"findings": findings, "summary": summary}
