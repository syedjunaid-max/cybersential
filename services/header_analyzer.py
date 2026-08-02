"""HTTP response security-header analysis with bounded redirects."""

from __future__ import annotations

import ipaddress
import socket
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

from services.reconnaissance import TargetValidationError, normalize_assessment_target, normalize_target


REQUEST_TIMEOUT = (5, 10)
MAX_REDIRECTS = 5
REDIRECT_CODES = {301, 302, 303, 307, 308}

HEADER_RULES = {
    "Content-Security-Policy": {
        "required": True,
        "severity": "High",
        "recommendation": "Define a restrictive Content-Security-Policy to limit trusted content sources.",
    },
    "X-Frame-Options": {
        "required": True,
        "severity": "Medium",
        "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN to reduce clickjacking risk.",
    },
    "X-XSS-Protection": {
        "required": True,
        "severity": "Low",
        "recommendation": "Add X-XSS-Protection for legacy clients; use CSP as the primary modern control.",
    },
    "Strict-Transport-Security": {
        "required": False,
        "severity": "Medium",
        "recommendation": "On HTTPS sites, enable Strict-Transport-Security after confirming all traffic supports HTTPS.",
    },
    "X-Content-Type-Options": {
        "required": False,
        "severity": "Low",
        "recommendation": "Set X-Content-Type-Options to nosniff.",
    },
    "Referrer-Policy": {
        "required": False,
        "severity": "Low",
        "recommendation": "Set a Referrer-Policy such as strict-origin-when-cross-origin.",
    },
    "Permissions-Policy": {
        "required": False,
        "severity": "Low",
        "recommendation": "Use Permissions-Policy to disable browser capabilities the application does not need.",
    },
}


class UnsafeRedirectError(requests.RequestException):
    """Raised when a redirect leaves the permitted HTTP(S) URL shape."""


def _blocked_redirect_host(hostname: str) -> bool:
    metadata_addresses = {"169.254.169.254", "100.100.100.200"}
    try:
        addresses = [ipaddress.ip_address(hostname)]
    except ValueError:
        try:
            records = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            addresses = list({ipaddress.ip_address(record[4][0]) for record in records})
        except OSError:
            return False
    return any(
        str(address) in metadata_addresses
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        for address in addresses
    )


def _validate_redirect_url(
    url: str,
    allowed_hostname: str | None = None,
    allowed_ports: set[int] | None = None,
) -> None:
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise UnsafeRedirectError("The site redirected to an unsupported URL.")
    if parsed.username or parsed.password:
        raise UnsafeRedirectError("The site redirected to a URL containing credentials.")
    try:
        effective_port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        if effective_port not in (allowed_ports or {80, 443}):
            raise UnsafeRedirectError("The site redirected to a non-standard network port.")
    except ValueError as exc:
        raise UnsafeRedirectError("The site returned an invalid redirect port.") from exc
    try:
        normalized_hostname = normalize_target(parsed.hostname)
    except TargetValidationError as exc:
        raise UnsafeRedirectError("The site redirected to an invalid hostname.") from exc
    if allowed_hostname and normalized_hostname != allowed_hostname:
        raise UnsafeRedirectError("The site redirected to a different host, so the request was stopped.")
    if _blocked_redirect_host(parsed.hostname):
        raise UnsafeRedirectError("The site redirected to a blocked link-local address.")


def _request_with_safe_redirects(session: requests.Session, initial_url: str) -> requests.Response:
    current_url = initial_url
    initial = urlsplit(initial_url)
    allowed_hostname = normalize_target(initial.hostname or "")
    initial_port = initial.port or (443 if initial.scheme.lower() == "https" else 80)
    allowed_ports = {80, 443, initial_port}
    for redirect_count in range(MAX_REDIRECTS + 1):
        _validate_redirect_url(current_url, allowed_hostname, allowed_ports)
        response = session.get(
            current_url,
            allow_redirects=False,
            timeout=REQUEST_TIMEOUT,
            stream=True,
        )
        if response.status_code not in REDIRECT_CODES or not response.headers.get("Location"):
            return response
        if redirect_count == MAX_REDIRECTS:
            response.close()
            raise requests.TooManyRedirects("The site exceeded the redirect limit.")
        next_url = urljoin(current_url, response.headers["Location"])
        response.close()
        current_url = next_url
    raise requests.TooManyRedirects("The site exceeded the redirect limit.")


def _not_checked_result(target: str, message: str) -> dict[str, Any]:
    return {
        "target": target,
        "success": False,
        "url": "",
        "status_code": None,
        "headers": [],
        "recommendations": [],
        "message": message,
    }


def analyze_security_headers(raw_target: str, *, fallback_to_http: bool | None = None) -> dict[str, Any]:
    """Analyze an explicit URL, or try HTTPS then HTTP for a host-only target."""
    try:
        normalized_target = normalize_assessment_target(raw_target)
    except TargetValidationError as exc:
        return _not_checked_result("", str(exc))

    target = normalized_target.web_url

    session = requests.Session()
    session.headers.update({"User-Agent": "Cybersential-Authorized-Assessment/1.0"})
    response: requests.Response | None = None
    connection_errors: list[str] = []
    initial = urlsplit(target)
    candidate_urls = [target]
    should_fallback = normalized_target.fallback_to_http if fallback_to_http is None else fallback_to_http
    if should_fallback and initial.scheme.lower() == "https":
        candidate_urls.append(urlunsplit(("http", initial.netloc, initial.path, initial.query, "")))

    for url in candidate_urls:
        scheme = urlsplit(url).scheme
        try:
            response = _request_with_safe_redirects(session, url)
            break
        except requests.exceptions.SSLError:
            connection_errors.append(f"{scheme.upper()} TLS negotiation failed")
        except requests.exceptions.Timeout:
            connection_errors.append(f"{scheme.upper()} request timed out")
        except requests.exceptions.ConnectionError:
            connection_errors.append(f"{scheme.upper()} connection failed")
        except requests.TooManyRedirects:
            session.close()
            return _not_checked_result(target, "The website exceeded the safe redirect limit.")
        except UnsafeRedirectError as exc:
            session.close()
            return _not_checked_result(target, str(exc))
        except requests.RequestException:
            connection_errors.append(f"{scheme.upper()} request failed")

    if response is None:
        session.close()
        detail = "; ".join(connection_errors)
        return _not_checked_result(
            target,
            f"The website could not be reached at the requested URL. {detail}".strip(),
        )

    findings: list[dict[str, Any]] = []
    recommendations: list[dict[str, str]] = []
    for header_name, rule in HEADER_RULES.items():
        value = response.headers.get(header_name)
        missing = not bool(value and value.strip())
        finding = {
            "name": header_name,
            "status": "Missing" if missing else "Present",
            "value": value.strip() if value else "Not supplied",
            "required": rule["required"],
            "severity": rule["severity"] if missing else "Info",
            "recommendation": rule["recommendation"] if missing else "No action required.",
        }
        findings.append(finding)
        if missing:
            recommendations.append(
                {
                    "header": header_name,
                    "severity": rule["severity"],
                    "text": rule["recommendation"],
                }
            )

    result = {
        "target": target,
        "success": True,
        "url": response.url,
        "status_code": response.status_code,
        "headers": findings,
        "recommendations": recommendations,
        "message": "Security headers were analyzed successfully.",
    }
    response.close()
    session.close()
    return result
