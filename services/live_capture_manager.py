import threading
import time
from collections import deque
from typing import Deque, Dict, List, Optional
from datetime import datetime

try:
    from scapy.all import AsyncSniffer, conf, sniff
    from scapy.error import Scapy_Exception
except ImportError:  # pragma: no cover
    AsyncSniffer = None
    sniff = None
    conf = None
    class Scapy_Exception(Exception):
        pass

from .packet_inspector import extract_packet_metadata, PacketInspectionError, _capture_error

class LiveCaptureManager:
    """Singleton manager for a background live packet capture.

    Captures metadata-only packets from a selected interface using Scapy's AsyncSniffer.
    Stores a bounded deque of recent packet metadata (default 200 events) and aggregates simple stats.
    Thread‑safe via internal lock.
    """

    _instance = None
    _instance_lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, max_events: int = 200):
        # Init only once
        if getattr(self, "_initialized", False):
            return
        self._initialized = True
        self.max_events = max_events
        self._lock = threading.Lock()
        self._sniffer: Optional[AsyncSniffer] = None
        self._running = False
        self._events: Deque[Dict] = deque(maxlen=self.max_events)
        self._stats: Dict[str, int] = {
            "total_packets": 0,
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "other": 0,
            "total_bytes": 0,
        }
        self._interface_id: Optional[str] = None
        self._interface_name: Optional[str] = None
        self._error: Optional[Dict] = None
        self._session_metadata: Deque[Dict] = deque(maxlen=1000)
        self._started_at: Optional[datetime] = None
        self._completed_at: Optional[datetime] = None

    def _packet_callback(self, packet):
        try:
            meta = extract_packet_metadata(packet)
        except Exception:
            # ignore malformed packets
            return
        with self._lock:
            self._events.append(meta)
            self._session_metadata.append(meta)
            self._stats["total_packets"] += 1
            proto = meta.get("transport_protocol", "Other")
            if proto == "TCP":
                self._stats["tcp"] += 1
            elif proto == "UDP":
                self._stats["udp"] += 1
            elif proto == "ICMP":
                self._stats["icmp"] += 1
            else:
                self._stats["other"] += 1
            length = meta.get("packet_length") or 0
            self._stats["total_bytes"] += length

    def start(self, interface_name: str) -> None:
        """Start live capture on the given interface.
        Raises PacketInspectionError on failure or if a capture is already active.
        """
        with self._lock:
            if self._running:
                raise PacketInspectionError("capture_in_progress", "A live capture is already running.", 409)
            if AsyncSniffer is None:
                raise PacketInspectionError("scapy_missing", "Scapy is not available.", 503)
            # Resolve interface token via packet_inspector helper
            from .packet_inspector import _interface_records
            record = next((r for r in _interface_records() if r["id"] == interface_name), None)
            if not record:
                raise PacketInspectionError("invalid_interface", "Selected interface not found.", 400)
            iface = record["capture_name"]
            self._sniffer = AsyncSniffer(iface=iface, prn=self._packet_callback, store=False)
            try:
                self._sniffer.start()
            except Exception as exc:
                raise _capture_error(exc) from exc
            self._running = True
            self._interface_id = interface_name
            self._interface_name = record["name"]
            self._error = None
            self._started_at = datetime.now()
            self._completed_at = None
            self._session_metadata.clear()
            self._stats = {"total_packets": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0, "total_bytes": 0}

    def stop(self) -> None:
        """Stop the live capture, if running."""
        with self._lock:
            if not self._running:
                return
            try:
                self._sniffer.stop()
            except Exception as exc:
                self._error = {"code": "stop_failed", "message": str(exc)}
            finally:
                self._sniffer = None
                self._running = False
                self._completed_at = datetime.now()

    def status(self) -> Dict:
        with self._lock:
            return {
                "running": self._running,
                "interface_id": self._interface_id,
                "error": self._error,
            }

    def recent_events(self, limit: int = 20) -> List[Dict]:
        with self._lock:
            return list(self._events)[-limit:]

    def stats(self) -> Dict:
        with self._lock:
            return dict(self._stats)

    def finalized_session(self) -> Dict:
        """Return a copy of the completed capture session metadata."""
        with self._lock:
            return {
                "interface_id": self._interface_id,
                "interface_name": self._interface_name or self._interface_id,
                "started_at": self._started_at.isoformat() if self._started_at else None,
                "completed_at": self._completed_at.isoformat() if self._completed_at else None,
                "packet_metadata": list(self._session_metadata),
                "stats": dict(self._stats),
            }


