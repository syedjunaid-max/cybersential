"""Target validation and passive domain reconnaissance services."""

from __future__ import annotations

import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

try:
    import whois
except ImportError:  # pragma: no cover - exercised on incomplete installations
    whois = None


DNS_TIMEOUT_SECONDS = 10
REVERSE_DNS_TIMEOUT_SECONDS = 3
WHOIS_TIMEOUT_SECONDS = 15
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


class TargetValidationError(ValueError):
    """Raised when the submitted value is not one valid assessment target."""


@dataclass(frozen=True)
class NormalizedAssessmentTarget:
    """The distinct network host and HTTP URL derived from one submitted target."""

    scan_host: str
    web_url: str
    fallback_to_http: bool


def _run_with_timeout(function: Callable[..., Any], timeout: int, *args: Any) -> Any:
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(function, *args)
    try:
        return future.result(timeout=timeout)
    except FutureTimeoutError as exc:
        future.cancel()
        raise TimeoutError from exc
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def _validate_submitted_value(raw_target: str) -> str:
    if not isinstance(raw_target, str) or not raw_target.strip():
        raise TargetValidationError("Enter one domain name or IP address.")

    value = raw_target.strip()
    if len(value) > 2048:
        raise TargetValidationError("The target is too long.")
    if any(character.isspace() or ord(character) < 32 for character in value):
        raise TargetValidationError("The target must not contain spaces or control characters.")
    return value


def _normalize_host(host: str) -> str:
    host = host.rstrip(".").lower()
    if not host or "%" in host:
        raise TargetValidationError("The target does not contain a valid host.")

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if re.fullmatch(r"[0-9.]+", host):
            raise TargetValidationError("Enter a valid IPv4 address.")
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise TargetValidationError("The domain name cannot be normalized.") from exc

        if len(ascii_host) > 253:
            raise TargetValidationError("The domain name is too long.")
        labels = ascii_host.split(".")
        if any(not _HOST_LABEL.fullmatch(label) for label in labels):
            raise TargetValidationError("Enter a valid domain name or IP address.")
        return ascii_host.lower()

    if address.is_unspecified or address.is_multicast:
        raise TargetValidationError("Unspecified and multicast addresses are not valid targets.")
    return address.compressed


def _validate_url_suffix(path: str, query: str) -> None:
    """Reject ambiguous or control-character URL suffixes before requests sees them."""
    suffix = f"{path}?{query}" if query else path
    if "\\" in suffix:
        raise TargetValidationError("Backslashes are not allowed in the target URL.")
    for match in re.finditer(r"%([0-9a-fA-F]{2})", suffix):
        if int(match.group(1), 16) < 32 or int(match.group(1), 16) == 127:
            raise TargetValidationError("Encoded control characters are not allowed in the target URL.")
    if re.search(r"%(?![0-9a-fA-F]{2})", suffix):
        raise TargetValidationError("The target URL contains invalid percent encoding.")


def normalize_assessment_target(raw_target: str) -> NormalizedAssessmentTarget:
    """Return a canonical scan host and a complete HTTP(S) URL."""
    value = _validate_submitted_value(raw_target)
    explicit_scheme = "://" in value

    try:
        if explicit_scheme:
            parsed = urlsplit(value)
        else:
            authority = re.split(r"[/?#]", value, maxsplit=1)[0]
            unwrapped = authority[1:-1] if authority.startswith("[") and authority.endswith("]") else authority
            try:
                direct_address = ipaddress.ip_address(unwrapped)
            except ValueError:
                parsed = urlsplit(f"//{value}")
            else:
                formatted_address = f"[{direct_address.compressed}]" if direct_address.version == 6 else direct_address.compressed
                parsed = urlsplit(f"//{formatted_address}{value[len(authority):]}")
    except ValueError as exc:
        raise TargetValidationError("The target contains invalid formatting.") from exc

    if explicit_scheme:
        if parsed.scheme.lower() not in {"http", "https"}:
            raise TargetValidationError("Only HTTP or HTTPS URLs can be normalized.")
    elif parsed.scheme:
        raise TargetValidationError("Only HTTP or HTTPS URLs can be normalized.")

    if parsed.username or parsed.password:
        raise TargetValidationError("Credentials are not allowed in a target.")
    authority = parsed.netloc.rsplit("@", maxsplit=1)[-1]
    if authority.endswith(":"):
        raise TargetValidationError("The target contains an invalid port.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise TargetValidationError("The target contains an invalid port.") from exc
    if port == 0:
        raise TargetValidationError("The target contains an invalid port.")

    scan_host = _normalize_host(parsed.hostname or "")
    _validate_url_suffix(parsed.path, parsed.query)

    try:
        address = ipaddress.ip_address(scan_host)
        url_host = f"[{scan_host}]" if address.version == 6 else scan_host
    except ValueError:
        url_host = scan_host
    netloc = f"{url_host}:{port}" if port is not None else url_host
    scheme = parsed.scheme.lower() if explicit_scheme else "https"
    web_url = urlunsplit((scheme, netloc, parsed.path, parsed.query, ""))
    return NormalizedAssessmentTarget(
        scan_host=scan_host,
        web_url=web_url,
        fallback_to_http=not explicit_scheme,
    )


def normalize_target(raw_target: str) -> str:
    """Return only the canonical hostname/IP for DNS, WHOIS, and TCP scanning."""
    return normalize_assessment_target(raw_target).scan_host


def _format_whois_value(value: Any) -> str:
    if value is None:
        return "Unavailable or redacted"
    if isinstance(value, (list, tuple, set)):
        formatted = []
        for item in value:
            item_text = _format_whois_value(item)
            if item_text not in formatted and item_text != "Unavailable or redacted":
                formatted.append(item_text)
        return ", ".join(formatted) if formatted else "Unavailable or redacted"
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    text = str(value).strip()
    return text if text else "Unavailable or redacted"


def _whois_field(record: Any, field_name: str) -> Any:
    if hasattr(record, "get"):
        return record.get(field_name)
    return getattr(record, field_name, None)


def _reverse_dns(address: str) -> str:
    try:
        result = _run_with_timeout(
            socket.gethostbyaddr,
            REVERSE_DNS_TIMEOUT_SECONDS,
            address,
        )
        return result[0]
    except (OSError, TimeoutError):
        return "Unavailable"


def _resolve_addresses(target: str) -> list[dict[str, str]]:
    records = _run_with_timeout(
        socket.getaddrinfo,
        DNS_TIMEOUT_SECONDS,
        target,
        None,
        socket.AF_UNSPEC,
        socket.SOCK_STREAM,
    )
    addresses: list[dict[str, str]] = []
    seen: set[str] = set()
    for family, _, _, _, socket_address in records:
        address = socket_address[0]
        if address in seen or family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        seen.add(address)
        addresses.append(
            {
                "address": address,
                "version": "IPv4" if family == socket.AF_INET else "IPv6",
                "reverse_dns": _reverse_dns(address),
            }
        )
    return addresses


def _lookup_whois(target: str) -> dict[str, Any]:
    empty_fields = {
        "registrar": "Unavailable or redacted",
        "creation_date": "Unavailable or redacted",
        "expiration_date": "Unavailable or redacted",
        "organization": "Unavailable or redacted",
        "country": "Unavailable or redacted",
        "name_servers": "Unavailable or redacted",
        "status": "Unavailable or redacted",
    }

    try:
        ipaddress.ip_address(target)
        return {
            "available": False,
            "message": "WHOIS domain data does not apply to an IP address.",
            **empty_fields,
        }
    except ValueError:
        pass

    if target == "localhost" or "." not in target:
        return {
            "available": False,
            "message": "WHOIS data is not available for a local hostname.",
            **empty_fields,
        }
    if whois is None:
        return {
            "available": False,
            "message": "python-whois is not installed. Run: pip install python-whois",
            **empty_fields,
        }

    try:
        record = _run_with_timeout(whois.whois, WHOIS_TIMEOUT_SECONDS, target)
    except TimeoutError:
        return {
            "available": False,
            "message": "The WHOIS lookup timed out.",
            **empty_fields,
        }
    except Exception:
        return {
            "available": False,
            "message": "WHOIS data was unavailable or redacted for this domain.",
            **empty_fields,
        }

    return {
        "available": True,
        "message": "WHOIS lookup completed.",
        "registrar": _format_whois_value(_whois_field(record, "registrar")),
        "creation_date": _format_whois_value(_whois_field(record, "creation_date")),
        "expiration_date": _format_whois_value(_whois_field(record, "expiration_date")),
        "organization": _format_whois_value(_whois_field(record, "org")),
        "country": _format_whois_value(_whois_field(record, "country")),
        "name_servers": _format_whois_value(_whois_field(record, "name_servers")),
        "status": _format_whois_value(_whois_field(record, "status")),
    }


def perform_reconnaissance(raw_target: str) -> dict[str, Any]:
    """Resolve addresses, reverse DNS, and WHOIS without leaking raw exceptions."""
    target = normalize_target(raw_target)
    errors: list[str] = []
    try:
        addresses = _resolve_addresses(target)
        if not addresses:
            errors.append("No IPv4 or IPv6 addresses were returned for the target.")
    except TimeoutError:
        addresses = []
        errors.append("DNS resolution timed out.")
    except socket.gaierror:
        addresses = []
        errors.append("The target could not be resolved by DNS.")
    except OSError:
        addresses = []
        errors.append("DNS resolution failed.")

    whois_result = _lookup_whois(target)
    return {
        "target": target,
        "addresses": addresses,
        "whois": whois_result,
        "errors": errors,
        "success": bool(addresses) or bool(whois_result.get("available")),
    }
