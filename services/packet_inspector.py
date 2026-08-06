"""Passive, bounded packet capture with metadata-only Scapy processing."""

from __future__ import annotations

import hashlib
import platform
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any

try:
    from scapy.all import DNS, DNSQR, ICMP, IP, IPv6, TCP, UDP, conf, sniff
    from scapy.error import Scapy_Exception
except ImportError:  # pragma: no cover - exercised through patched dependency tests
    DNS = DNSQR = ICMP = IP = IPv6 = TCP = UDP = conf = sniff = None

    class Scapy_Exception(Exception):
        """Fallback type used only when Scapy is not installed."""


DEFAULT_CAPTURE_DURATION = 15
MIN_CAPTURE_DURATION = 5
MAX_CAPTURE_DURATION = 30
DEFAULT_PACKET_LIMIT = 200
MIN_PACKET_LIMIT = 10
MAX_PACKET_LIMIT = 500
# Short aliases make the safety limits convenient for callers while keeping
# the more descriptive names used by the Flask UI and tests.
DEFAULT_DURATION = DEFAULT_CAPTURE_DURATION
MIN_DURATION = MIN_CAPTURE_DURATION
MAX_DURATION = MAX_CAPTURE_DURATION
DEFAULT_PACKET_COUNT = DEFAULT_PACKET_LIMIT
MIN_PACKETS = MIN_PACKET_LIMIT
MAX_PACKETS = MAX_PACKET_LIMIT
SCAPY_AVAILABLE = sniff is not None

ENCRYPTED_PORTS = {
    22,    # SSH
    443,   # HTTPS / TLS
    465,   # SMTP over TLS
    636,   # LDAPS
    853,   # DNS over TLS
    989,   # FTPS data
    990,   # FTPS control
    993,   # IMAPS
    995,   # POP3S
    3389,  # RDP commonly uses encryption
    8443,  # Common alternate HTTPS
}

_capture_lock = threading.Lock()
_GUID_PATTERN = re.compile(r"(?:\\Device\\NPF_)?\{[0-9A-F-]{36}\}", re.IGNORECASE)


class PacketInspectionError(Exception):
    """A safe, user-facing packet-capture failure."""

    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def _interface_token(capture_name: str) -> str:
    digest = hashlib.sha256(capture_name.encode("utf-8", errors="replace")).hexdigest()[:20]
    return f"iface-{digest}"


def _friendly_interface_name(interface: Any, fallback: str) -> str:
    candidates = (
        getattr(interface, "name", None),
        getattr(interface, "description", None),
        fallback,
    )
    for candidate in candidates:
        text = str(candidate or "").strip()
        if text and not _GUID_PATTERN.search(text) and "\\Device\\NPF_" not in text:
            return text[:120]
    return "Local network interface"


def _detect_windows_capture_driver() -> tuple[bool, str]:
    """Return whether an Npcap-compatible capture library is available."""
    if platform.system() != "Windows":
        return True, "The operating system does not require Npcap."
    try:
        from scapy.libs.winpcapy import pcap_lib_version

        raw_version = pcap_lib_version()
        version = raw_version.decode("ascii", errors="replace") if isinstance(raw_version, bytes) else str(raw_version)
    except Exception:
        return False, "Npcap is unavailable. Install Npcap from npcap.com, then restart the application."
    if "npcap" not in version.lower():
        return False, "Npcap was not detected. Install a current Npcap release, then restart the application."
    return True, version[:160]


def _interface_records() -> list[dict[str, str]]:
    """Return internal interface records; capture identifiers never leave this module."""
    if not SCAPY_AVAILABLE or conf is None:
        return []

    try:
        interfaces = list(conf.ifaces.values())
    except Exception as exc:
        raise PacketInspectionError(
            "no_interfaces",
            "Capture interfaces could not be enumerated. Check Npcap and local capture permissions.",
            503,
        ) from exc

    records: list[dict[str, str]] = []
    seen_tokens: set[str] = set()
    for interface in interfaces:
        capture_name = str(
            getattr(interface, "network_name", None)
            or getattr(interface, "name", None)
            or ""
        ).strip()
        if not capture_name:
            continue
        token = _interface_token(capture_name)
        if token in seen_tokens:
            continue
        seen_tokens.add(token)
        name = _friendly_interface_name(interface, capture_name)
        description = str(getattr(interface, "description", None) or "").strip()
        if description == name or _GUID_PATTERN.search(description) or "\\Device\\NPF_" in description:
            description = ""
        address = str(getattr(interface, "ip", None) or "").strip()
        records.append(
            {
                "id": token,
                "name": name,
                "description": description[:160],
                "address": address[:64],
                "capture_name": capture_name,
            }
        )
    records.sort(key=lambda item: (not bool(item["address"]), item["name"].lower(), item["id"]))
    return records


def get_capture_environment() -> dict[str, Any]:
    """Return safe setup status and interface information for the UI."""
    if not SCAPY_AVAILABLE:
        return {
            "available": False,
            "code": "scapy_missing",
            "message": "Scapy is not installed. Run: python -m pip install -r requirements.txt",
            "interfaces": [],
            "privilege_notice": "Administrator or packet-capture permission may be required.",
        }

    driver_available, driver_message = _detect_windows_capture_driver()
    if not driver_available:
        return {
            "available": False,
            "code": "npcap_missing",
            "message": driver_message,
            "interfaces": [],
            "privilege_notice": "Do not attempt to install a capture driver from this application.",
        }

    try:
        records = _interface_records()
    except PacketInspectionError as exc:
        return {
            "available": False,
            "code": exc.code,
            "message": exc.message,
            "interfaces": [],
            "privilege_notice": "Administrator or packet-capture permission may be required.",
        }
    if not records:
        return {
            "available": False,
            "code": "no_interfaces",
            "message": "No packet-capture interfaces are available. Check Npcap and local adapter status.",
            "interfaces": [],
            "privilege_notice": "Administrator or packet-capture permission may be required.",
        }

    safe_interfaces = [
        {key: record[key] for key in ("id", "name", "description", "address")}
        for record in records
    ]
    return {
        "available": True,
        "code": "ready",
        "message": "Passive metadata capture is available.",
        "interfaces": safe_interfaces,
        "driver": driver_message if platform.system() == "Windows" else "System packet-capture support",
        "privilege_notice": "Administrator permission may be required by the selected interface or Npcap configuration.",
    }


def get_capture_interfaces() -> list[dict[str, str]]:
    """Return interface aliases and friendly labels without adapter GUIDs or MAC addresses."""
    return list(get_capture_environment()["interfaces"])


def _parse_bounded_integer(value: Any, *, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise PacketInspectionError("invalid_capture_limits", f"{name} must be a whole number.")
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise PacketInspectionError("invalid_capture_limits", f"{name} must be a whole number.") from exc
    if parsed < minimum or parsed > maximum:
        raise PacketInspectionError(
            "invalid_capture_limits",
            f"{name} must be between {minimum} and {maximum}.",
        )
    return parsed


def validate_capture_request(
    *,
    interface: str,
    duration: Any,
    packet_limit: Any,
    authorization_confirmed: bool = False,
) -> tuple[dict[str, str], int, int]:
    """Validate authorization, bounded limits, and the server-generated interface alias."""
    if not authorization_confirmed:
        raise PacketInspectionError(
            "authorization_required",
            "Confirm that you own the system and network or have explicit permission to capture this traffic.",
            403,
        )
    if not SCAPY_AVAILABLE or sniff is None:
        raise PacketInspectionError(
            "scapy_missing",
            "Scapy is not installed. Run: python -m pip install -r requirements.txt",
            503,
        )

    parsed_duration = _parse_bounded_integer(
        duration,
        name="Capture duration",
        minimum=MIN_CAPTURE_DURATION,
        maximum=MAX_CAPTURE_DURATION,
    )
    parsed_limit = _parse_bounded_integer(
        packet_limit,
        name="Packet limit",
        minimum=MIN_PACKET_LIMIT,
        maximum=MAX_PACKET_LIMIT,
    )

    environment = get_capture_environment()
    if not environment["available"]:
        raise PacketInspectionError(environment["code"], environment["message"], 503)

    selected = next((item for item in _interface_records() if item["id"] == str(interface)), None)
    if selected is None:
        raise PacketInspectionError(
            "invalid_interface",
            "Select a network interface from the current server-generated list.",
        )
    return selected, parsed_duration, parsed_limit


def _safe_timestamp(packet: Any) -> str:
    try:
        timestamp = float(packet.time)
    except (AttributeError, TypeError, ValueError, OverflowError):
        timestamp = time.time()
    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return datetime.now(timezone.utc).isoformat()


def _safe_packet_length(packet: Any) -> int:
    try:
        return max(0, min(int(len(packet)), 16 * 1024 * 1024))
    except (TypeError, ValueError, OverflowError):
        return 0


def _safe_integer(value: Any, *, minimum: int | None = None, maximum: int | None = None) -> int | None:
    """Convert a Scapy scalar to a bounded integer without allowing malformed packets to escape."""
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if minimum is not None and parsed < minimum:
        return None
    if maximum is not None and parsed > maximum:
        return None
    return parsed


def _has_layer(packet: Any, layer: Any) -> bool:
    if layer is None:
        return False
    try:
        return bool(packet.haslayer(layer))
    except Exception:
        return False


def _layer(packet: Any, layer: Any) -> Any | None:
    if not _has_layer(packet, layer):
        return None
    try:
        return packet[layer]
    except Exception:
        return None


def _icmpv6_type(packet: Any) -> int | None:
    try:
        current = packet
        while current is not None:
            layer_name = current.__class__.__name__
            if layer_name.startswith("ICMPv6"):
                value = getattr(current, "type", None)
                return _safe_integer(value, minimum=0, maximum=255)
            next_layer = getattr(current, "payload", None)
            if next_layer is None or next_layer is current or next_layer.__class__.__name__ == "NoPayload":
                break
            current = next_layer
    except Exception:
        return None
    return None


def _dns_query_name(packet: Any) -> str | None:
    try:
        dns_layer = _layer(packet, DNS)
        query_response = _safe_integer(getattr(dns_layer, "qr", 1), minimum=0, maximum=1) if dns_layer is not None else None
        if dns_layer is None or query_response != 0:
            return None
        query_layer = _layer(packet, DNSQR)
        if query_layer is None:
            return None
        raw_name = getattr(query_layer, "qname", None)
        if isinstance(raw_name, bytes):
            name = raw_name.decode("ascii", errors="replace")
        else:
            name = str(raw_name or "")
        name = "".join(character if character.isprintable() else "?" for character in name).rstrip(".")
        return name[:253] or None
    except Exception:
        return None


def _contains_tls_layer(packet: Any) -> bool:
    try:
        return bool(packet.haslayer("TLS") or packet.haslayer("SSLv2"))
    except Exception:
        return False


def extract_packet_metadata(packet: Any) -> dict[str, Any]:
    """Extract only approved header metadata; raw payload content is never accessed."""
    metadata: dict[str, Any] = {
        "timestamp": _safe_timestamp(packet),
        "ip_version": None,
        "source_ip": None,
        "destination_ip": None,
        "transport_protocol": "Other",
        "source_port": None,
        "destination_port": None,
        "packet_length": _safe_packet_length(packet),
        "tcp_flags": None,
        "icmp_type": None,
        "dns_query_name": None,
        "dns_packet": False,
        "encrypted_estimate": False,
    }

    ip_layer = _layer(packet, IP)
    if ip_layer is not None:
        metadata.update(
            ip_version=4,
            source_ip=str(getattr(ip_layer, "src", "") or "")[:64] or None,
            destination_ip=str(getattr(ip_layer, "dst", "") or "")[:64] or None,
        )
    else:
        ipv6_layer = _layer(packet, IPv6)
        if ipv6_layer is not None:
            metadata.update(
                ip_version=6,
                source_ip=str(getattr(ipv6_layer, "src", "") or "")[:64] or None,
                destination_ip=str(getattr(ipv6_layer, "dst", "") or "")[:64] or None,
            )

    tcp_layer = _layer(packet, TCP)
    udp_layer = _layer(packet, UDP)
    icmp_layer = _layer(packet, ICMP)
    if tcp_layer is not None:
        metadata["transport_protocol"] = "TCP"
        metadata["source_port"] = _safe_integer(getattr(tcp_layer, "sport", None), minimum=1, maximum=65535)
        metadata["destination_port"] = _safe_integer(getattr(tcp_layer, "dport", None), minimum=1, maximum=65535)
        flags = str(getattr(tcp_layer, "flags", "") or "")
        metadata["tcp_flags"] = flags[:16] or None
    elif udp_layer is not None:
        metadata["transport_protocol"] = "UDP"
        metadata["source_port"] = _safe_integer(getattr(udp_layer, "sport", None), minimum=1, maximum=65535)
        metadata["destination_port"] = _safe_integer(getattr(udp_layer, "dport", None), minimum=1, maximum=65535)
    elif icmp_layer is not None:
        metadata["transport_protocol"] = "ICMP"
        value = getattr(icmp_layer, "type", None)
        metadata["icmp_type"] = _safe_integer(value, minimum=0, maximum=255)
    else:
        icmpv6_type = _icmpv6_type(packet)
        if icmpv6_type is not None:
            metadata["transport_protocol"] = "ICMP"
            metadata["icmp_type"] = icmpv6_type

    metadata["dns_packet"] = _has_layer(packet, DNS)
    metadata["dns_query_name"] = _dns_query_name(packet)
    ports = {metadata["source_port"], metadata["destination_port"]}
    metadata["encrypted_estimate"] = bool(ports & ENCRYPTED_PORTS) or _contains_tls_layer(packet)
    return metadata


def _capture_error(exc: BaseException) -> PacketInspectionError:
    message = str(exc).lower()
    if isinstance(exc, (PermissionError,)) or any(
        marker in message for marker in ("permission denied", "access is denied", "operation not permitted", "winerror 10013")
    ):
        return PacketInspectionError(
            "permission_denied",
            "Packet capture permission was denied. Run with appropriate administrator/capture privileges and verify Npcap access.",
            403,
        )
    if any(marker in message for marker in ("npcap", "winpcap", "libpcap", "pcap is not available")):
        return PacketInspectionError(
            "npcap_missing",
            "Npcap or the system packet-capture driver is unavailable. Install Npcap manually and restart the application.",
            503,
        )
    if isinstance(exc, TimeoutError) or "timed out" in message or "timeout" in message:
        return PacketInspectionError(
            "capture_timeout",
            "The capture stopped because the packet-capture operation timed out.",
            504,
        )
    if "no such device" in message or "interface" in message:
        return PacketInspectionError(
            "invalid_interface",
            "The selected interface became unavailable. Refresh the interface list and try again.",
        )
    return PacketInspectionError(
        "capture_failed",
        "Packet capture could not be completed safely. Check the adapter, Npcap, and capture permissions.",
        503,
    )


def capture_packets(
    *,
    interface: str,
    duration: Any = DEFAULT_CAPTURE_DURATION,
    packet_limit: Any = DEFAULT_PACKET_LIMIT,
    authorization_confirmed: bool = False,
) -> dict[str, Any]:
    """Capture bounded traffic and return ordinary dictionaries containing metadata only."""
    selected, parsed_duration, parsed_limit = validate_capture_request(
        interface=interface,
        duration=duration,
        packet_limit=packet_limit,
        authorization_confirmed=authorization_confirmed,
    )
    if not _capture_lock.acquire(blocking=False):
        raise PacketInspectionError(
            "capture_in_progress",
            "A packet capture is already running in this Flask process. Wait for it to finish and try again.",
            409,
        )

    captured_metadata: list[dict[str, Any]] = []
    started_at = datetime.now(timezone.utc)
    started_clock = time.monotonic()

    def process_packet(packet: Any) -> None:
        if len(captured_metadata) < parsed_limit:
            try:
                metadata = extract_packet_metadata(packet)
            except Exception:
                # A malformed frame must not terminate the bounded capture or
                # expose an internal Scapy exception to the Flask response.
                return
            captured_metadata.append(metadata)

    try:
        sniff(
            iface=selected["capture_name"],
            prn=process_packet,
            store=False,
            timeout=parsed_duration,
            count=parsed_limit,
        )
    except (PermissionError, OSError, Scapy_Exception, RuntimeError, TimeoutError) as exc:
        raise _capture_error(exc) from exc
    except Exception as exc:
        raise _capture_error(exc) from exc
    finally:
        elapsed = max(0.0, time.monotonic() - started_clock)
        _capture_lock.release()

    return {
        "success": True,
        "interface_id": selected["id"],
        "interface_name": selected["name"],
        "requested_duration_seconds": parsed_duration,
        "capture_duration_seconds": round(min(elapsed, float(parsed_duration) + 1.0), 3),
        "packet_limit": parsed_limit,
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "packets": captured_metadata,
        "message": (
            "No traffic was observed during this bounded capture."
            if not captured_metadata
            else f"Captured metadata for {len(captured_metadata)} packet(s)."
        ),
        "storage": {"pcap": False, "raw_payload": False},
    }


def capture_in_progress() -> bool:
    """Return process-local capture state without modifying it."""
    acquired = _capture_lock.acquire(blocking=False)
    if acquired:
        _capture_lock.release()
        return False
    return True
