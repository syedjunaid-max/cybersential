"""Bounded TCP port scanning through python-nmap."""

from __future__ import annotations

import inspect
import ipaddress
import subprocess
from typing import Any

from services.reconnaissance import TargetValidationError, normalize_target

try:
    import nmap
except ImportError:  # pragma: no cover - exercised on incomplete installations
    nmap = None


PORT_RANGE = "1-1024"
NMAP_ARGUMENTS = "-sT -Pn --host-timeout 60s --open"
PROCESS_TIMEOUT_SECONDS = 75


def _error_result(target: str, message: str, *, setup_required: bool = False) -> dict[str, Any]:
    return {
        "target": target,
        "success": False,
        "host_state": "unknown",
        "ports": [],
        "message": message,
        "setup_required": setup_required,
    }


def scan_tcp_ports(raw_target: str) -> dict[str, Any]:
    """Scan TCP ports 1-1024 using a normal connect scan and safe arguments."""
    try:
        target = normalize_target(raw_target)
    except TargetValidationError as exc:
        return _error_result("", str(exc))

    if nmap is None:
        return _error_result(
            target,
            "python-nmap is not installed. Run: pip install python-nmap",
            setup_required=True,
        )

    try:
        scanner = nmap.PortScanner()
    except Exception as exc:
        port_scanner_error = getattr(nmap, "PortScannerError", ())
        if port_scanner_error and isinstance(exc, port_scanner_error):
            return _error_result(
                target,
                "Nmap was not found. Install the Nmap executable and ensure it is on PATH.",
                setup_required=True,
            )
        return _error_result(target, "The Nmap scanner could not be initialized.")

    try:
        scan_arguments = NMAP_ARGUMENTS
        try:
            if ipaddress.ip_address(target).version == 6:
                scan_arguments = f"{scan_arguments} -6"
        except ValueError:
            pass
        scan_kwargs: dict[str, Any] = {
            "hosts": target,
            "ports": PORT_RANGE,
            "arguments": scan_arguments,
        }
        if "timeout" in inspect.signature(scanner.scan).parameters:
            scan_kwargs["timeout"] = PROCESS_TIMEOUT_SECONDS
        scanner.scan(**scan_kwargs)
    except (subprocess.TimeoutExpired, TimeoutError):
        return _error_result(target, "The Nmap scan timed out after 60 seconds.")
    except Exception as exc:
        port_scanner_error = getattr(nmap, "PortScannerError", ())
        if port_scanner_error and isinstance(exc, port_scanner_error):
            message = str(exc).lower()
            if "not found" in message or "nmap program" in message:
                return _error_result(
                    target,
                    "Nmap was not found. Install the Nmap executable and ensure it is on PATH.",
                    setup_required=True,
                )
            if "timeout" in message or "timed out" in message:
                return _error_result(target, "The Nmap scan timed out after 60 seconds.")
            return _error_result(target, "Nmap could not scan the target. Verify that it is reachable.")
        return _error_result(target, "The port scan failed safely. Verify the target and try again.")

    hosts = scanner.all_hosts()
    if not hosts:
        return _error_result(
            target,
            "Nmap returned no host results. The target may be invalid or unreachable.",
        )

    results: list[dict[str, Any]] = []
    host_states: list[str] = []
    for host in hosts:
        try:
            host_states.append(scanner[host].state())
        except (KeyError, AttributeError):
            host_states.append("unknown")
        try:
            protocols = scanner[host].all_protocols()
        except (KeyError, AttributeError):
            protocols = []
        for protocol in protocols:
            if protocol.lower() != "tcp":
                continue
            for port in sorted(scanner[host][protocol].keys()):
                port_data = scanner[host][protocol][port]
                product_parts = [
                    str(port_data.get(key, "")).strip()
                    for key in ("product", "version", "extrainfo")
                    if str(port_data.get(key, "")).strip()
                ]
                results.append(
                    {
                        "port": int(port),
                        "protocol": "tcp",
                        "state": str(port_data.get("state", "unknown")),
                        "service": str(port_data.get("name", "unknown") or "unknown"),
                        "product_version": " ".join(product_parts) or "Not detected",
                    }
                )

    host_state = ", ".join(dict.fromkeys(host_states)) or "unknown"
    message = (
        f"Found {len(results)} reported open TCP port(s) in the 1-1024 range."
        if results
        else "The scan completed and no open TCP ports were reported in the 1-1024 range."
    )
    return {
        "target": target,
        "success": True,
        "host_state": host_state,
        "ports": results,
        "message": message,
        "setup_required": False,
    }
