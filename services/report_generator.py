"""Professional A4 PDF generation for completed authorized assessments."""

from __future__ import annotations

import os
import unicodedata
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import LongTable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


PROJECT_NAME = "Cybersential"
REPORT_PREFIX = "cybersential_"
DPI_REPORT_PREFIX = "cybersential_dpi_"
NAVY = colors.HexColor("#0F172A")
SLATE = colors.HexColor("#334155")
LIGHT_SLATE = colors.HexColor("#E2E8F0")
PALE = colors.HexColor("#F8FAFC")
GREEN = colors.HexColor("#15803D")
AMBER = colors.HexColor("#B45309")
RED = colors.HexColor("#B91C1C")


def _plain_text(value: Any) -> str:
    if value is None:
        return "Unavailable"
    if isinstance(value, (list, tuple, set)):
        return ", ".join(_plain_text(item) for item in value)
    normalized = unicodedata.normalize("NFKD", str(value))
    return normalized.encode("ascii", "replace").decode("ascii")


def _paragraph(value: Any, style: ParagraphStyle) -> Paragraph:
    safe_text = escape(_plain_text(value)).replace("\n", "<br/>")
    return Paragraph(safe_text, style)


def _table(data: list[list[Any]], widths: list[float], *, repeat_rows: int = 1) -> LongTable:
    result = LongTable(data, colWidths=widths, repeatRows=repeat_rows, hAlign="LEFT")
    result.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.35, LIGHT_SLATE),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return result


def _draw_page(canvas: Any, document: SimpleDocTemplate) -> None:
    canvas.saveState()
    width, height = A4
    canvas.setFillColor(NAVY)
    canvas.rect(0, height - 18 * mm, width, 18 * mm, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 12)
    canvas.drawString(18 * mm, height - 11.5 * mm, PROJECT_NAME)
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(width - 18 * mm, height - 11.5 * mm, "Authorized Vulnerability Assessment")
    canvas.setStrokeColor(LIGHT_SLATE)
    canvas.line(18 * mm, 14 * mm, width - 18 * mm, 14 * mm)
    canvas.setFillColor(SLATE)
    canvas.drawString(18 * mm, 9 * mm, "Educational and authorized use only")
    canvas.drawRightString(width - 18 * mm, 9 * mm, f"Page {document.page}")
    canvas.restoreState()


def _canonical_scan_id(scan_id: str | uuid.UUID) -> str:
    try:
        parsed = scan_id if isinstance(scan_id, uuid.UUID) else uuid.UUID(str(scan_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("Invalid scan ID.") from exc
    canonical = str(parsed)
    if not isinstance(scan_id, uuid.UUID) and str(scan_id).lower() != canonical:
        raise ValueError("Invalid scan ID.")
    return canonical


def report_path_for_scan_id(scan_id: str | uuid.UUID, reports_directory: str | Path) -> Path:
    """Derive a report path only from a canonical UUID."""
    directory = Path(reports_directory).resolve()
    return directory / f"{REPORT_PREFIX}{_canonical_scan_id(scan_id)}.pdf"


def dpi_report_path_for_capture_id(capture_id: str | uuid.UUID, reports_directory: str | Path) -> Path:
    """Derive a DPI report path only from a canonical UUID."""
    directory = Path(reports_directory).resolve()
    return directory / f"{DPI_REPORT_PREFIX}{_canonical_scan_id(capture_id)}.pdf"


def _build_styles() -> dict[str, ParagraphStyle]:
    sheet = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ReportTitle", parent=sheet["Title"], fontName="Helvetica-Bold", fontSize=23,
            leading=28, textColor=NAVY, spaceAfter=5 * mm,
        ),
        "heading": ParagraphStyle(
            "SectionHeading", parent=sheet["Heading2"], fontName="Helvetica-Bold", fontSize=14,
            leading=17, textColor=NAVY, spaceBefore=5 * mm, spaceAfter=2.5 * mm,
        ),
        "body": ParagraphStyle(
            "BodySmall", parent=sheet["BodyText"], fontName="Helvetica", fontSize=8.5,
            leading=11, textColor=SLATE,
        ),
        "cell": ParagraphStyle(
            "TableText", parent=sheet["BodyText"], fontName="Helvetica", fontSize=7.4,
            leading=9.3, textColor=NAVY,
        ),
        "header": ParagraphStyle(
            "TableHeader", parent=sheet["BodyText"], fontName="Helvetica-Bold", fontSize=7.4,
            leading=9.3, textColor=colors.white,
        ),
        "disclaimer": ParagraphStyle(
            "Disclaimer", parent=sheet["BodyText"], fontName="Helvetica-Oblique", fontSize=8.5,
            leading=12, textColor=SLATE, alignment=TA_CENTER,
        ),
    }


def generate_assessment_report(
    *,
    target: str,
    scan_host: str | None = None,
    authorization_confirmed: bool,
    reconnaissance: dict[str, Any],
    port_scan: dict[str, Any],
    header_analysis: dict[str, Any],
    reports_directory: str | Path,
    scan_id: str | uuid.UUID | None = None,
    assessment_datetime: datetime | None = None,
) -> dict[str, str]:
    """Generate one UUID-named report. Password data is intentionally not accepted."""
    if not authorization_confirmed:
        raise ValueError("A report can only be generated for an authorized assessment.")

    canonical_scan_id = _canonical_scan_id(scan_id or uuid.uuid4())
    assessed_at = assessment_datetime or datetime.now().astimezone()
    output_path = report_path_for_scan_id(canonical_scan_id, reports_directory)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_suffix(".tmp")

    style = _build_styles()
    body, cell, header = style["body"], style["cell"], style["header"]
    story: list[Any] = [Spacer(1, 5 * mm)]
    story.extend(
        [
            Paragraph("Vulnerability Assessment Report", style["title"]),
            Paragraph("A bounded reconnaissance, TCP port, and HTTP security-header review.", body),
            Spacer(1, 5 * mm),
        ]
    )

    metadata = [
        [_paragraph("Project", header), _paragraph(PROJECT_NAME, header)],
        [_paragraph("Scan ID", cell), _paragraph(canonical_scan_id, cell)],
        [_paragraph("Web URL", cell), _paragraph(target, cell)],
        [_paragraph("Scan host", cell), _paragraph(scan_host or reconnaissance.get("target") or "Unavailable", cell)],
        [_paragraph("Assessment date and time", cell), _paragraph(assessed_at.isoformat(), cell)],
        [_paragraph("Authorization", cell), _paragraph("Confirmed by the user", cell)],
    ]
    metadata_table = Table(metadata, colWidths=[50 * mm, 120 * mm], hAlign="LEFT")
    metadata_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("BACKGROUND", (0, 1), (0, -1), PALE),
                ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.35, LIGHT_SLATE),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(metadata_table)

    story.append(Paragraph("1. Reconnaissance", style["heading"]))
    addresses = reconnaissance.get("addresses") or []
    if addresses:
        address_rows = [[_paragraph("Address", header), _paragraph("Version", header), _paragraph("Reverse DNS", header)]]
        address_rows.extend(
            [_paragraph(item.get("address"), cell), _paragraph(item.get("version"), cell), _paragraph(item.get("reverse_dns"), cell)]
            for item in addresses
        )
        story.append(_table(address_rows, [55 * mm, 25 * mm, 90 * mm]))
    else:
        story.append(_paragraph("No IP addresses were resolved.", body))

    whois_data = reconnaissance.get("whois") or {}
    whois_rows = [[_paragraph("WHOIS field", header), _paragraph("Value", header)]]
    for key, label in (
        ("registrar", "Registrar"), ("creation_date", "Creation date"),
        ("expiration_date", "Expiration date"), ("organization", "Organization"),
        ("country", "Country"), ("name_servers", "Name servers"), ("status", "Status"),
    ):
        whois_rows.append([_paragraph(label, cell), _paragraph(whois_data.get(key), cell)])
    story.extend([Spacer(1, 3 * mm), _table(whois_rows, [45 * mm, 125 * mm])])
    if whois_data.get("message"):
        story.append(_paragraph(whois_data["message"], body))
    for error in reconnaissance.get("errors") or []:
        story.append(_paragraph(f"Reconnaissance note: {error}", body))

    story.append(Paragraph("2. TCP Port Scan (1-1024)", style["heading"]))
    story.append(_paragraph(port_scan.get("message", "No scan status was supplied."), body))
    ports = port_scan.get("ports") or []
    if ports:
        port_rows = [[
            _paragraph("Port", header), _paragraph("Protocol", header), _paragraph("State", header),
            _paragraph("Service", header), _paragraph("Product / version", header),
        ]]
        port_rows.extend(
            [
                _paragraph(item.get("port"), cell), _paragraph(item.get("protocol"), cell),
                _paragraph(item.get("state"), cell), _paragraph(item.get("service"), cell),
                _paragraph(item.get("product_version"), cell),
            ]
            for item in ports
        )
        story.extend([Spacer(1, 2 * mm), _table(port_rows, [18 * mm, 23 * mm, 23 * mm, 38 * mm, 68 * mm])])

    story.extend([PageBreak(), Spacer(1, 3 * mm), Paragraph("3. HTTP Security Headers", style["heading"])])
    story.append(_paragraph(header_analysis.get("message", "No header status was supplied."), body))
    if header_analysis.get("url"):
        story.append(_paragraph(f"Analyzed URL: {header_analysis['url']}", body))
    headers = header_analysis.get("headers") or []
    if headers:
        header_rows = [[
            _paragraph("Header", header), _paragraph("Status", header),
            _paragraph("Severity", header), _paragraph("Observed value", header),
        ]]
        header_rows.extend(
            [
                _paragraph(item.get("name"), cell), _paragraph(item.get("status"), cell),
                _paragraph(item.get("severity"), cell), _paragraph(item.get("value"), cell),
            ]
            for item in headers
        )
        story.extend([Spacer(1, 2 * mm), _table(header_rows, [48 * mm, 24 * mm, 24 * mm, 74 * mm])])

    story.append(Paragraph("4. Findings and Recommendations", style["heading"]))
    recommendation_rows = [[
        _paragraph("Severity", header), _paragraph("Finding", header), _paragraph("Recommendation", header),
    ]]
    recommendation_rows.extend(
        [
            _paragraph(item.get("severity"), cell),
            _paragraph(f"Missing {item.get('header')}", cell),
            _paragraph(item.get("text"), cell),
        ]
        for item in (header_analysis.get("recommendations") or [])
    )
    if not header_analysis.get("success"):
        recommendation_rows.append(
            [
                _paragraph("Medium", cell),
                _paragraph("HTTP security-header assessment was incomplete", cell),
                _paragraph("Verify HTTP/HTTPS reachability and rerun the authorized assessment.", cell),
            ]
        )
    if not port_scan.get("success"):
        recommendation_rows.append(
            [
                _paragraph("Medium", cell),
                _paragraph("TCP port assessment was incomplete", cell),
                _paragraph("Install Nmap if required, verify reachability, and rerun the authorized assessment.", cell),
            ]
        )
    if ports:
        recommendation_rows.append(
            [
                _paragraph("Low", cell),
                _paragraph("Open TCP services were identified", cell),
                _paragraph("Confirm that each exposed service is necessary, patched, and access-restricted.", cell),
            ]
        )
    if len(recommendation_rows) == 1:
        recommendation_rows.append(
            [
                _paragraph("Info", cell),
                _paragraph("No configured header omissions or open ports were reported", cell),
                _paragraph("Continue routine review and validate application-specific controls separately.", cell),
            ]
        )
    story.append(_table(recommendation_rows, [25 * mm, 55 * mm, 90 * mm]))

    story.append(Paragraph("Educational and Authorized-Use Disclaimer", style["heading"]))
    story.append(
        Paragraph(
            "This report documents a limited educational assessment. It must only be used for systems owned "
            "by the assessor or covered by explicit permission. Results are point-in-time observations, not "
            "proof that a system is secure. No exploitation, credential attack, brute force, evasion, or "
            "destructive testing was performed.",
            style["disclaimer"],
        )
    )

    document = SimpleDocTemplate(
        str(temporary_path), pagesize=A4, rightMargin=20 * mm, leftMargin=20 * mm,
        topMargin=24 * mm, bottomMargin=19 * mm,
        title=f"{PROJECT_NAME} Vulnerability Assessment {canonical_scan_id}", author=PROJECT_NAME,
        subject="Authorized educational vulnerability assessment",
    )
    try:
        document.build(story, onFirstPage=_draw_page, onLaterPages=_draw_page)
        os.replace(temporary_path, output_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()

    return {
        "scan_id": canonical_scan_id,
        "filename": output_path.name,
        "path": str(output_path),
        "generated_at": assessed_at.isoformat(),
    }


def _draw_dpi_page(canvas: Any, document: SimpleDocTemplate) -> None:
    canvas.saveState()
    width, height = A4
    canvas.setFillColor(NAVY)
    canvas.rect(0, height - 18 * mm, width, 18 * mm, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 12)
    canvas.drawString(18 * mm, height - 11.5 * mm, PROJECT_NAME)
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(width - 18 * mm, height - 11.5 * mm, "Authorized Metadata-Only Traffic Analysis")
    canvas.setStrokeColor(LIGHT_SLATE)
    canvas.line(18 * mm, 14 * mm, width - 18 * mm, 14 * mm)
    canvas.setFillColor(SLATE)
    canvas.drawString(18 * mm, 9 * mm, "Passive, bounded, educational use only")
    canvas.drawRightString(width - 18 * mm, 9 * mm, f"Page {document.page}")
    canvas.restoreState()


def generate_dpi_report(
    *,
    assessment: dict[str, Any],
    authorization_confirmed: bool,
    reports_directory: str | Path,
    capture_id: str | uuid.UUID,
) -> dict[str, str]:
    """Generate a metadata-only DPI PDF from explicitly approved assessment fields."""
    if not authorization_confirmed or not assessment.get("authorization_confirmed"):
        raise ValueError("A DPI report can only be generated for an authorized capture.")

    canonical_capture_id = _canonical_scan_id(capture_id)
    output_path = dpi_report_path_for_capture_id(canonical_capture_id, reports_directory)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_suffix(".tmp")

    style = _build_styles()
    body, cell, header = style["body"], style["cell"], style["header"]
    capture = assessment.get("capture") or {}
    summary = assessment.get("summary") or {}
    story: list[Any] = [
        Spacer(1, 5 * mm),
        Paragraph("Deep Packet Inspection and Network Traffic Analysis", style["title"]),
        Paragraph(
            "A passive, bounded, metadata-only observation. No packet payload, credential, cookie, token, "
            "authorization header, form content, decryption material, or complete packet dump is included.",
            body,
        ),
        Spacer(1, 5 * mm),
    ]

    metadata = [
        [_paragraph("Assessment", header), _paragraph(PROJECT_NAME, header)],
        [_paragraph("Capture ID", cell), _paragraph(canonical_capture_id, cell)],
        [_paragraph("Assessment date and time", cell), _paragraph(assessment.get("assessed_at"), cell)],
        [_paragraph("Authorization", cell), _paragraph("Confirmed by the user", cell)],
        [_paragraph("Selected interface", cell), _paragraph(capture.get("selected_interface"), cell)],
        [_paragraph("Requested duration", cell), _paragraph(f"{capture.get('requested_duration_seconds', 0)} seconds", cell)],
        [_paragraph("Observed duration", cell), _paragraph(f"{capture.get('actual_duration_seconds', 0)} seconds", cell)],
        [_paragraph("Packet limit", cell), _paragraph(capture.get("packet_limit"), cell)],
        [_paragraph("Packets observed", cell), _paragraph(summary.get("total_packets", 0), cell)],
        [_paragraph("Storage", cell), _paragraph("PCAP disabled; raw payload storage disabled", cell)],
    ]
    metadata_table = Table(metadata, colWidths=[50 * mm, 120 * mm], hAlign="LEFT")
    metadata_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("BACKGROUND", (0, 1), (0, -1), PALE),
                ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.35, LIGHT_SLATE),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(metadata_table)

    story.append(Paragraph("1. Capture Overview", style["heading"]))
    overview_rows = [[_paragraph("Metric", header), _paragraph("Observed value", header)]]
    for key, label in (
        ("ipv4_packet_count", "IPv4 packets"),
        ("ipv6_packet_count", "IPv6 packets"),
        ("tcp_packet_count", "TCP packets"),
        ("udp_packet_count", "UDP packets"),
        ("icmp_packet_count", "ICMP packets"),
        ("dns_packet_count", "DNS queries"),
        ("other_packet_count", "Other packets"),
        ("total_bytes", "Total bytes observed"),
        ("average_packet_size", "Average packet size (bytes)"),
        ("unique_source_ip_count", "Unique source IPs"),
        ("unique_destination_ip_count", "Unique destination IPs"),
    ):
        overview_rows.append([_paragraph(label, cell), _paragraph(summary.get(key, 0), cell)])
    story.append(_table(overview_rows, [85 * mm, 85 * mm]))

    story.append(Paragraph("2. Protocol and Encryption Estimates", style["heading"]))
    protocol_rows = [[_paragraph("Protocol", header), _paragraph("Packets", header), _paragraph("Share", header)]]
    for item in summary.get("protocol_distribution") or []:
        protocol_rows.append(
            [
                _paragraph(item.get("protocol"), cell),
                _paragraph(item.get("count"), cell),
                _paragraph(f"{item.get('percentage', 0)}%", cell),
            ]
        )
    if len(protocol_rows) == 1:
        protocol_rows.append([_paragraph("No traffic observed", cell), _paragraph("0", cell), _paragraph("0%", cell)])
    story.append(_table(protocol_rows, [80 * mm, 45 * mm, 45 * mm]))
    encryption = summary.get("encryption_estimate") or {}
    story.extend(
        [
            Spacer(1, 2 * mm),
            _paragraph(
                f"Likely encrypted: {encryption.get('likely_encrypted', 0)}; not identified as encrypted: "
                f"{encryption.get('not_identified_as_encrypted', 0)}; estimated encrypted share: "
                f"{encryption.get('likely_encrypted_percentage', 0)}%.",
                body,
            ),
            _paragraph(encryption.get("basis", "Encryption classification was not available."), body),
        ]
    )

    # Let the encryption note share the next available space with the endpoint
    # tables; forcing a page break here can leave an otherwise empty page when
    # the overview table happens to end near the page boundary.
    story.extend([Spacer(1, 3 * mm), Paragraph("3. Traffic Endpoints", style["heading"])])
    endpoint_rows = [[_paragraph("Direction", header), _paragraph("IP address", header), _paragraph("Packets", header)]]
    for direction, items in (
        ("Source", summary.get("top_source_ips") or []),
        ("Destination", summary.get("top_destination_ips") or []),
    ):
        endpoint_rows.extend(
            [_paragraph(direction, cell), _paragraph(item.get("value"), cell), _paragraph(item.get("count"), cell)]
            for item in items
        )
    if len(endpoint_rows) == 1:
        endpoint_rows.append([_paragraph("None", cell), _paragraph("No IP endpoints observed", cell), _paragraph("0", cell)])
    story.append(_table(endpoint_rows, [35 * mm, 95 * mm, 40 * mm]))

    story.append(Paragraph("4. Destination Ports and TCP Flags", style["heading"]))
    port_rows = [[
        _paragraph("Destination port", header),
        _paragraph("Packets", header),
        _paragraph("Service estimate", header),
    ]]
    for item in summary.get("top_destination_ports") or []:
        port_rows.append(
            [
                _paragraph(item.get("port"), cell),
                _paragraph(item.get("count"), cell),
                _paragraph(item.get("service_estimate"), cell),
            ]
        )
    if len(port_rows) == 1:
        port_rows.append([_paragraph("None", cell), _paragraph("0", cell), _paragraph("No transport ports observed", cell)])
    story.append(_table(port_rows, [40 * mm, 30 * mm, 100 * mm]))
    story.append(_paragraph("Service estimates are based only on standard port mappings and are not definitive software identification.", body))

    flag_rows = [[_paragraph("TCP flags", header), _paragraph("Packets", header)]]
    for item in summary.get("tcp_flag_distribution") or []:
        flag_rows.append([_paragraph(item.get("value"), cell), _paragraph(item.get("count"), cell)])
    if len(flag_rows) > 1:
        story.extend([Spacer(1, 2 * mm), _table(flag_rows, [85 * mm, 85 * mm])])

    story.append(Paragraph("5. DNS Observations", style["heading"]))
    dns_rows = [[_paragraph("Query name", header), _paragraph("Count", header)]]
    for item in summary.get("dns_queries_observed") or []:
        dns_rows.append([_paragraph(item.get("value"), cell), _paragraph(item.get("count"), cell)])
    if len(dns_rows) == 1:
        dns_rows.append([_paragraph("No DNS queries observed", cell), _paragraph("0", cell)])
    story.append(_table(dns_rows, [140 * mm, 30 * mm]))

    story.extend([PageBreak(), Spacer(1, 3 * mm), Paragraph("6. Rule-Based Findings", style["heading"])])
    finding_rows = [[
        _paragraph("Severity / finding", header),
        _paragraph("Evidence", header),
        _paragraph("Recommendation and limitation", header),
    ]]
    for finding in assessment.get("findings") or []:
        finding_rows.append(
            [
                _paragraph(f"{finding.get('severity')}: {finding.get('title')}", cell),
                _paragraph(finding.get("evidence"), cell),
                _paragraph(f"{finding.get('recommendation')} Limitation: {finding.get('confidence')}", cell),
            ]
        )
    if len(finding_rows) == 1:
        finding_rows.append(
            [
                _paragraph("Informational: No configured threshold reached", cell),
                _paragraph("The bounded observation did not meet the configured rule thresholds.", cell),
                _paragraph("Continue authorized monitoring as appropriate; absence of a finding does not prove security.", cell),
            ]
        )
    story.append(_table(finding_rows, [45 * mm, 58 * mm, 67 * mm]))

    story.append(Paragraph("7. Recommendations", style["heading"]))
    for recommendation in assessment.get("recommendations") or []:
        story.append(_paragraph(f"- {recommendation}", body))

    story.append(Paragraph("8. Technical Limitations", style["heading"]))
    for limitation in assessment.get("limitations") or []:
        story.append(_paragraph(f"- {limitation}", body))

    story.append(Paragraph("Educational and Authorized-Use Disclaimer", style["heading"]))
    story.append(
        Paragraph(
            "This passive assessment is permitted only on systems and networks owned by the user or covered "
            "by explicit authorization. Shared, college, workplace, public Wi-Fi, and third-party traffic must "
            "not be captured without permission. Encrypted content remained encrypted. Findings are tentative, "
            "may produce false positives, and represent only a short point-in-time observation. No injection, "
            "spoofing, modification, replay, exploitation, decryption, credential interception, ARP poisoning, "
            "MITM activity, evasion, or destructive action was performed.",
            style["disclaimer"],
        )
    )

    document = SimpleDocTemplate(
        str(temporary_path),
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=24 * mm,
        bottomMargin=19 * mm,
        title=f"{PROJECT_NAME} Metadata-Only Traffic Analysis {canonical_capture_id}",
        author=PROJECT_NAME,
        subject="Authorized passive metadata-only network traffic analysis",
    )
    try:
        document.build(story, onFirstPage=_draw_dpi_page, onLaterPages=_draw_dpi_page)
        os.replace(temporary_path, output_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()

    return {
        "capture_id": canonical_capture_id,
        "filename": output_path.name,
        "path": str(output_path),
        "generated_at": str(assessment.get("assessed_at") or datetime.now().astimezone().isoformat()),
    }
