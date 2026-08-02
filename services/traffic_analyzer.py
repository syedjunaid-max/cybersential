"""Structured traffic summaries and transparent metadata-only detection rules."""

from __future__ import annotations

import copy
import threading
import uuid
from collections import Counter, OrderedDict, defaultdict
from datetime import datetime, timezone
from typing import Any


TOP_LIST_LIMIT = 10
MAX_DPI_RESULTS = 10
MAX_STORED_ASSESSMENTS = MAX_DPI_RESULTS

SERVICE_ESTIMATES = {
    20: "FTP data",
    21: "FTP control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP server",
    68: "DHCP client",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS/TLS",
    445: "SMB",
    465: "SMTP over TLS",
    587: "SMTP submission",
    636: "LDAPS",
    853: "DNS over TLS",
    993: "IMAPS",
    995: "POP3S",
    1433: "Microsoft SQL Server",
    3306: "MySQL",
    3389: "Remote Desktop",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "Alternate HTTP",
    8443: "Alternate HTTPS",
}

COMMON_DESTINATION_PORTS = set(SERVICE_ESTIMATES)

LIMITATIONS = [
    "Only packet headers and approved metadata were analyzed; packet payloads were not stored or displayed.",
    "HTTPS and other encrypted payloads remain encrypted and were not decrypted or intercepted.",
    "Encrypted-traffic labels are estimates based on observed protocol layers and commonly encrypted ports.",
    "Service names inferred from destination ports are estimates, not definitive software identification.",
    "Rule-based findings may produce false positives and never confirm that an attack occurred.",
    "This short, point-in-time capture may not represent normal long-term network behavior.",
]


def _top(counter: Counter[Any], *, limit: int = TOP_LIST_LIMIT) -> list[dict[str, Any]]:
    return [{"value": value, "count": count} for value, count in counter.most_common(limit)]


def _port_rows(counter: Counter[int]) -> list[dict[str, Any]]:
    rows = []
    for port, count in counter.most_common(TOP_LIST_LIMIT):
        estimate = SERVICE_ESTIMATES.get(port, "Unmapped / uncommon")
        rows.append({"port": port, "count": count, "service_estimate": f"{estimate} (estimated)"})
    return rows


def _nonnegative_integer(value: Any) -> int:
    """Read numeric metadata defensively; malformed synthetic frames are ignored."""
    if isinstance(value, bool):
        return 0
    try:
        return max(0, int(value))
    except (TypeError, ValueError, OverflowError):
        return 0


def _finding(
    title: str,
    severity: str,
    evidence: str,
    recommendation: str,
    confidence: str,
) -> dict[str, str]:
    return {
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "recommendation": recommendation,
        "confidence": confidence,
    }


def _tcp_flag_sets(packets: list[dict[str, Any]]) -> tuple[dict[str, Counter[str]], dict[str, int]]:
    per_source: dict[str, Counter[str]] = defaultdict(Counter)
    totals = {"syn_without_ack": 0, "ack": 0}
    for packet in packets:
        if packet.get("transport_protocol") != "TCP":
            continue
        flags = str(packet.get("tcp_flags") or "")
        source = str(packet.get("source_ip") or "Unknown")
        is_syn_without_ack = "S" in flags and "A" not in flags
        has_ack = "A" in flags
        if is_syn_without_ack:
            per_source[source]["syn_without_ack"] += 1
            totals["syn_without_ack"] += 1
        if has_ack:
            per_source[source]["ack"] += 1
            totals["ack"] += 1
    return per_source, totals


def detect_anomalies(packets: list[dict[str, Any]], summary: dict[str, Any]) -> list[dict[str, str]]:
    """Apply educational rules; every result is explicitly tentative."""
    findings: list[dict[str, str]] = []
    total_packets = _nonnegative_integer(summary.get("total_packets"))

    tcp_by_source, _ = _tcp_flag_sets(packets)
    syn_candidates = [
        (source, counts["syn_without_ack"], counts["ack"])
        for source, counts in tcp_by_source.items()
        if counts["syn_without_ack"] >= 10 and counts["ack"] * 3 < counts["syn_without_ack"]
    ]
    if syn_candidates:
        source, syn_count, ack_count = max(syn_candidates, key=lambda item: item[1])
        findings.append(
            _finding(
                "Possible SYN scanning behavior",
                "Medium" if syn_count >= 20 else "Low",
                f"Source {source} produced {syn_count} SYN-without-ACK packets and {ack_count} ACK-bearing packets.",
                "Confirm whether an authorized scanner or connection burst was active and compare with host logs.",
                "Possible only: a short capture cannot distinguish scanning from retries, loss, or incomplete bidirectional visibility.",
            )
        )

    destination_ports_by_source: dict[str, set[int]] = defaultdict(set)
    for packet in packets:
        source = packet.get("source_ip")
        port = packet.get("destination_port")
        if source and isinstance(port, int) and port > 0:
            destination_ports_by_source[str(source)].add(port)
    repeated_candidates = [
        (source, ports) for source, ports in destination_ports_by_source.items() if len(ports) >= 10
    ]
    if repeated_candidates:
        source, ports = max(repeated_candidates, key=lambda item: len(item[1]))
        sample = ", ".join(str(port) for port in sorted(ports)[:10])
        findings.append(
            _finding(
                "Repeated destination-port attempts",
                "Medium" if len(ports) >= 25 else "Low",
                f"Source {source} contacted {len(ports)} distinct destination ports; sample: {sample}.",
                "Verify the source process and whether broad port access was expected in this authorized lab window.",
                "Possible only: legitimate discovery tools, application behavior, and return traffic can create this pattern.",
            )
        )

    dns_count = _nonnegative_integer(summary.get("dns_packet_count"))
    if dns_count >= 25 or (dns_count >= 15 and total_packets and dns_count / total_packets >= 0.5):
        findings.append(
            _finding(
                "Excessive DNS activity",
                "Medium" if dns_count >= 60 else "Low",
                f"Observed {dns_count} DNS queries among {total_packets} captured packets.",
                "Compare the query rate and requesting hosts with expected application and resolver behavior.",
                "Threshold-based observation only; software updates, browsing, and local resolvers may generate bursts.",
            )
        )

    long_queries = sorted(
        {
            str(packet["dns_query_name"])
            for packet in packets
            if packet.get("dns_query_name") and len(str(packet["dns_query_name"])) > 80
        },
        key=len,
        reverse=True,
    )
    if long_queries:
        longest = long_queries[0]
        findings.append(
            _finding(
                "Unusually long DNS query names",
                "Low" if len(longest) > 150 else "Informational",
                f"Observed {len(long_queries)} unique query name(s) longer than 80 characters; longest was {len(longest)} characters.",
                "Review the responsible application and domain context without assuming malicious tunneling.",
                "Length alone does not confirm DNS tunneling; content was not reconstructed or inspected beyond the query name.",
            )
        )

    large_icmp = [
        packet
        for packet in packets
        if packet.get("transport_protocol") == "ICMP" and _nonnegative_integer(packet.get("packet_length")) > 1000
    ]
    if large_icmp:
        largest = max(_nonnegative_integer(packet.get("packet_length")) for packet in large_icmp)
        findings.append(
            _finding(
                "Large ICMP packets",
                "Low",
                f"Observed {len(large_icmp)} ICMP packet(s) larger than 1000 bytes; largest was {largest} bytes.",
                "Confirm whether diagnostics or lab traffic explain the size and review endpoint logs if unexpected.",
                "Packet size is a weak signal and does not establish misuse.",
            )
        )

    destination_port_counts = Counter(
        int(packet["destination_port"])
        for packet in packets
        if isinstance(packet.get("destination_port"), int) and int(packet["destination_port"]) > 0
    )
    uncommon_ports = [(port, count) for port, count in destination_port_counts.most_common() if port not in COMMON_DESTINATION_PORTS]
    if uncommon_ports:
        examples = ", ".join(f"{port} ({count})" for port, count in uncommon_ports[:10])
        findings.append(
            _finding(
                "Uncommon destination ports observed",
                "Informational",
                f"Observed destination ports outside the configured common-service list: {examples}.",
                "Validate the ports against the applications expected in the authorized environment.",
                "Port numbers are contextual and do not identify software or malicious behavior definitively.",
            )
        )

    top_destinations = summary.get("top_destination_ips") or []
    if total_packets >= 10 and top_destinations:
        top = top_destinations[0]
        percentage = top["count"] / total_packets * 100
        if percentage >= 70:
            findings.append(
                _finding(
                    "High connection concentration",
                    "Low" if percentage >= 90 and total_packets >= 20 else "Informational",
                    f"{top['value']} received {top['count']} of {total_packets} packets ({percentage:.1f}%).",
                    "Confirm whether a server, gateway, DNS resolver, or test target was expected to dominate this capture.",
                    "Concentration is often normal in short captures and is not evidence of an attack by itself.",
                )
            )

    return findings


def analyze_traffic(
    packets: list[dict[str, Any]],
    *,
    selected_interface: str = "Unknown interface",
    capture_duration_seconds: float = 0.0,
    requested_duration_seconds: int = 0,
    packet_limit: int = 0,
    authorization_confirmed: bool = False,
    started_at: str = "",
    completed_at: str = "",
) -> dict[str, Any]:
    """Create a serializable assessment from approved packet metadata dictionaries."""
    safe_packets = [packet for packet in (packets or []) if isinstance(packet, dict)]
    total_packets = len(safe_packets)
    ip_versions = Counter(packet.get("ip_version") for packet in safe_packets)
    protocols = Counter(str(packet.get("transport_protocol") or "Other") for packet in safe_packets)
    source_ips = Counter(str(packet["source_ip"]) for packet in safe_packets if packet.get("source_ip"))
    destination_ips = Counter(str(packet["destination_ip"]) for packet in safe_packets if packet.get("destination_ip"))
    destination_ports = Counter(
        int(packet["destination_port"])
        for packet in safe_packets
        if isinstance(packet.get("destination_port"), int) and int(packet["destination_port"]) > 0
    )
    tcp_flags = Counter(
        str(packet["tcp_flags"])
        for packet in safe_packets
        if packet.get("transport_protocol") == "TCP" and packet.get("tcp_flags")
    )
    dns_queries = Counter(str(packet["dns_query_name"]) for packet in safe_packets if packet.get("dns_query_name"))
    total_bytes = sum(_nonnegative_integer(packet.get("packet_length")) for packet in safe_packets)
    encrypted_count = sum(bool(packet.get("encrypted_estimate")) for packet in safe_packets)
    other_count = sum(protocol not in {"TCP", "UDP", "ICMP"} for protocol in protocols.elements())

    protocol_distribution = [
        {"protocol": protocol, "count": count, "percentage": round(count / total_packets * 100, 1) if total_packets else 0.0}
        for protocol, count in sorted(protocols.items(), key=lambda item: (-item[1], item[0]))
    ]
    summary: dict[str, Any] = {
        "total_packets": total_packets,
        "capture_duration_seconds": round(max(0.0, float(capture_duration_seconds)), 3),
        "selected_interface": str(selected_interface)[:120],
        "ipv4_packet_count": ip_versions[4],
        "ipv6_packet_count": ip_versions[6],
        "tcp_packet_count": protocols["TCP"],
        "udp_packet_count": protocols["UDP"],
        "icmp_packet_count": protocols["ICMP"],
        "dns_packet_count": sum(
            1 for packet in safe_packets if bool(packet.get("dns_packet") or packet.get("dns_query_name"))
        ),
        "other_packet_count": other_count,
        "total_bytes": total_bytes,
        "total_bytes_observed": total_bytes,
        "average_packet_size": round(total_bytes / total_packets, 1) if total_packets else 0.0,
        "average_packet_size_bytes": round(total_bytes / total_packets, 1) if total_packets else 0.0,
        "unique_source_ip_count": len(source_ips),
        "unique_destination_ip_count": len(destination_ips),
        "top_source_ips": _top(source_ips),
        "top_destination_ips": _top(destination_ips),
        "top_destination_ports": _port_rows(destination_ports),
        "protocol_distribution": protocol_distribution,
        "tcp_flag_distribution": _top(tcp_flags),
        "dns_queries_observed": _top(dns_queries),
        "encryption_estimate": {
            "likely_encrypted": encrypted_count,
            "not_identified_as_encrypted": total_packets - encrypted_count,
            "likely_encrypted_percentage": round(encrypted_count / total_packets * 100, 1) if total_packets else 0.0,
            "basis": "Observed TLS layers or commonly encrypted source/destination ports; this is an estimate.",
        },
    }
    findings = detect_anomalies(safe_packets, summary)
    return {
        "capture_id": None,
        "assessment_type": "Deep Packet Inspection and Network Traffic Analysis",
        "assessed_at": completed_at or datetime.now(timezone.utc).isoformat(),
        "authorization_confirmed": bool(authorization_confirmed),
        "capture": {
            "selected_interface": str(selected_interface)[:120],
            "requested_duration_seconds": int(requested_duration_seconds),
            "actual_duration_seconds": summary["capture_duration_seconds"],
            "packet_limit": int(packet_limit),
            "started_at": started_at,
            "completed_at": completed_at,
            "pcap_storage_enabled": False,
            "raw_payload_storage_enabled": False,
            "message": (
                "No traffic was observed during this bounded capture."
                if total_packets == 0
                else f"Analyzed metadata for {total_packets} packet(s)."
            ),
        },
        "summary": summary,
        "findings": findings,
        "recommendations": [finding["recommendation"] for finding in findings]
        or ["No configured anomaly threshold was reached; continue authorized monitoring with appropriate network-owner approval."],
        "limitations": list(LIMITATIONS),
        "report_available": False,
        "report_error": None,
    }


def _canonical_uuid(value: str | uuid.UUID) -> str:
    try:
        parsed = value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("Invalid capture ID.") from exc
    canonical = str(parsed)
    if not isinstance(value, uuid.UUID) and str(value).lower() != canonical:
        raise ValueError("Invalid capture ID.")
    return canonical


class DPIResultStore:
    """Thread-safe, process-local, oldest-first bounded assessment storage."""

    def __init__(self, max_entries: int = MAX_DPI_RESULTS) -> None:
        if not 1 <= int(max_entries) <= MAX_DPI_RESULTS:
            raise ValueError(f"DPI result storage must contain between 1 and {MAX_DPI_RESULTS} entries.")
        self.max_entries = int(max_entries)
        self._items: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._lock = threading.Lock()

    def add(self, assessment: dict[str, Any], capture_id: str | uuid.UUID | None = None) -> str:
        canonical_id = _canonical_uuid(capture_id or uuid.uuid4())
        stored = copy.deepcopy(assessment)
        stored["capture_id"] = canonical_id
        with self._lock:
            self._items[canonical_id] = stored
            self._items.move_to_end(canonical_id)
            while len(self._items) > self.max_entries:
                self._items.popitem(last=False)
        return canonical_id

    def get(self, capture_id: str | uuid.UUID) -> dict[str, Any] | None:
        try:
            canonical_id = _canonical_uuid(capture_id)
        except ValueError:
            return None
        with self._lock:
            result = self._items.get(canonical_id)
            return copy.deepcopy(result) if result is not None else None

    def update(self, capture_id: str | uuid.UUID, **values: Any) -> bool:
        try:
            canonical_id = _canonical_uuid(capture_id)
        except ValueError:
            return False
        with self._lock:
            if canonical_id not in self._items:
                return False
            self._items[canonical_id].update(copy.deepcopy(values))
            return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    def ids(self) -> list[str]:
        with self._lock:
            return list(self._items)


# Descriptive alias for integrations that call the aggregation step a
# "summary" rather than an "analysis". It intentionally points to the same
# metadata-only implementation.
summarize_traffic = analyze_traffic
