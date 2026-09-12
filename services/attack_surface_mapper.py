'''Attack surface mapping service.

Generates observations about a target based on assessment module results:
reconnaissance, port scanning, and security header analysis.
Each observation follows the required finding schema:
- title
- severity
- description
- evidence
- recommendation
- limitation
'''

from __future__ import annotations

from typing import Any, Dict, List


# Helper to create a finding dict consistent with threat detector expectations.
def _make_observation(
    title: str,
    severity: str,
    description: str,
    evidence: str,
    recommendation: str,
    limitation: str = "Observation based on assessment metadata; not a confirmed vulnerability.",
) -> Dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "limitation": limitation,
    }


def map_attack_surface(assessment: Dict[str, Any]) -> Dict[str, Any]:
    """Map the attack surface from a combined assessment result.

    Consumes the output of:
      - ``reconnaissance.perform_reconnaissance``  → ``assessment["recon"]``
      - ``port_scanner.scan_tcp_ports``            → ``assessment["port_scan"]``
      - ``header_analyzer.analyze_security_headers`` → ``assessment["header_analysis"]``

    Returns a dictionary with two top-level keys:
        * ``observations`` – list of finding dicts (title/severity/description/evidence/recommendation/limitation).
        * ``summary``      – counts per severity and an overall exposure level.

    Open ports and DNS/recon findings are also surfaced at the top level for
    direct template rendering:
        * ``open_ports``         – list of port dicts from port_scan
        * ``dns_addresses``      – list of address dicts from reconnaissance
        * ``whois``              – WHOIS summary dict from reconnaissance
        * ``https_supported``    – bool, True when header analysis reached HTTPS
        * ``missing_headers``    – list of missing header names
        * ``header_findings``    – full header findings list from header_analyzer
    """
    observations: List[Dict[str, Any]] = []
    low = medium = high = 0

    # ── 1. Recon / DNS ────────────────────────────────────────────────────────
    recon = assessment.get("recon") or {}
    dns_addresses = recon.get("addresses", [])
    whois_data = recon.get("whois", {})

    if dns_addresses:
        addr_summary = ", ".join(
            f"{a['address']} ({a['version']})" for a in dns_addresses
        )
        observations.append(
            _make_observation(
                title="DNS Resolution Succeeded",
                severity="Low",
                description=f"The target resolved to {len(dns_addresses)} address(es).",
                evidence=f"Resolved addresses: {addr_summary}.",
                recommendation="Verify only intended IP addresses are published in DNS.",
            )
        )
        low += 1
    else:
        recon_errors = "; ".join(recon.get("errors", [])) or "Unknown DNS failure."
        observations.append(
            _make_observation(
                title="DNS Resolution Failed",
                severity="Medium",
                description="The target could not be resolved via DNS.",
                evidence=recon_errors,
                recommendation="Confirm the target hostname is correct and publicly reachable.",
            )
        )
        medium += 1

    # ── 2. Port scan ──────────────────────────────────────────────────────────
    port_scan = assessment.get("port_scan") or {}
    open_ports = port_scan.get("ports", [])
    port_scan_success = port_scan.get("success", False)
    port_scan_setup_required = port_scan.get("setup_required", False)

    if port_scan_setup_required:
        observations.append(
            _make_observation(
                title="Port Scan Unavailable",
                severity="Medium",
                description="Nmap is not installed; TCP port scan could not be performed.",
                evidence=port_scan.get("message", ""),
                recommendation="Install Nmap to enable active port scanning.",
            )
        )
        medium += 1
    elif not port_scan_success:
        observations.append(
            _make_observation(
                title="Port Scan Failed",
                severity="Medium",
                description="The TCP port scan did not complete successfully.",
                evidence=port_scan.get("message", ""),
                recommendation="Verify the target is reachable and Nmap is configured correctly.",
            )
        )
        medium += 1
    elif open_ports:
        port_list = ", ".join(
            f"{p['port']}/{p['protocol']} ({p.get('service', 'unknown')})"
            for p in open_ports
        )
        severity = "High" if len(open_ports) > 10 else "Medium"
        observations.append(
            _make_observation(
                title=f"{len(open_ports)} Open TCP Port(s) Found",
                severity=severity,
                description=f"The scan found {len(open_ports)} open TCP port(s) in range 1–1024.",
                evidence=f"Open ports: {port_list}.",
                recommendation="Restrict any ports that are not required for the target's service.",
            )
        )
        if severity == "High":
            high += 1
        else:
            medium += 1
    else:
        observations.append(
            _make_observation(
                title="No Open Ports Found in Range 1–1024",
                severity="Low",
                description="The TCP port scan reported no open ports in the standard range.",
                evidence=port_scan.get("message", "Scan completed with no open ports."),
                recommendation="Confirm this is expected for the target's profile.",
            )
        )
        low += 1

    # ── 3. Security headers ───────────────────────────────────────────────────
    header_analysis = assessment.get("header_analysis") or {}
    header_success = header_analysis.get("success", False)
    header_findings = header_analysis.get("headers", [])

    https_supported = False
    missing_headers: List[str] = []

    if not header_success:
        observations.append(
            _make_observation(
                title="Web Header Analysis Failed",
                severity="Medium",
                description="The header analyzer could not reach the target URL.",
                evidence=header_analysis.get("message", ""),
                recommendation="Confirm the target exposes an HTTP/HTTPS service.",
            )
        )
        medium += 1
    else:
        # Determine HTTPS support from the URL that responded
        final_url = header_analysis.get("url", "") or header_analysis.get("target", "")
        https_supported = final_url.lower().startswith("https://")

        if not https_supported:
            observations.append(
                _make_observation(
                    title="HTTPS Not Supported",
                    severity="High",
                    description="The target did not respond on HTTPS; traffic may be unencrypted.",
                    evidence=f"Final responding URL: {final_url or 'unknown'}.",
                    recommendation="Enable HTTPS and redirect all HTTP traffic to HTTPS.",
                )
            )
            high += 1
        else:
            observations.append(
                _make_observation(
                    title="HTTPS Supported",
                    severity="Low",
                    description="The target responded over HTTPS.",
                    evidence=f"Final URL: {final_url}.",
                    recommendation="Ensure TLS is configured with strong ciphers and a valid certificate.",
                )
            )
            low += 1

        # Missing security headers
        missing_headers = [
            f["name"] for f in header_findings if f.get("status") == "Missing"
        ]
        required_missing = [
            f["name"] for f in header_findings
            if f.get("status") == "Missing" and f.get("required")
        ]
        if required_missing:
            observations.append(
                _make_observation(
                    title="Required Security Headers Missing",
                    severity="High",
                    description="Critical HTTP security headers are absent from the response.",
                    evidence=f"Missing required headers: {', '.join(required_missing)}.",
                    recommendation="Add the listed headers to improve the security posture of the web service.",
                )
            )
            high += 1
        optional_missing = [h for h in missing_headers if h not in required_missing]
        if optional_missing:
            observations.append(
                _make_observation(
                    title="Optional Security Headers Missing",
                    severity="Low",
                    description="Some recommended HTTP security headers are not present.",
                    evidence=f"Missing optional headers: {', '.join(optional_missing)}.",
                    recommendation="Consider adding these headers to further harden the web service.",
                )
            )
            low += 1

    # ── 4. Overall exposure ───────────────────────────────────────────────────
    if high:
        overall = "High"
    elif medium:
        overall = "Medium"
    else:
        overall = "Low"

    summary_counts = {
        "total_findings": len(observations),
        "low": low,
        "medium": medium,
        "high": high,
        "overall_exposure": overall,
    }
    return {
        "observations": observations,
        "summary": summary_counts,
        # Convenience keys for template rendering
        "open_ports": open_ports,
        "dns_addresses": dns_addresses,
        "whois": whois_data,
        "https_supported": https_supported,
        "missing_headers": missing_headers,
        "header_findings": header_findings,
    }
