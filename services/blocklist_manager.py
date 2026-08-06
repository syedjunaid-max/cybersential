"""Safe domain normalization and Cybersential-owned hosts-section updates."""

from __future__ import annotations

import errno
import ipaddress
import os
import re
import stat
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit


WINDOWS_HOSTS_PATH = Path(r"C:\Windows\System32\drivers\etc\hosts")
MANAGED_SECTION_START = "# CYBERSENTIAL BLOCKLIST START"
MANAGED_SECTION_END = "# CYBERSENTIAL BLOCKLIST END"
LOOPBACK_ADDRESS = "127.0.0.1"

_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_DISALLOWED_RAW_CHARACTERS = set("|;<>`^$(){}\x00\r\n")
_LOOPBACK_NAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "loopback",
}
_COMMON_COUNTRY_SECOND_LEVELS = {"ac", "co", "com", "edu", "gov", "net", "org"}


class DomainValidationError(ValueError):
    """Raised when one submitted value is not a safe public-style domain."""


class BlocklistError(Exception):
    """A safe hosts-management failure suitable for a browser response."""

    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def normalize_domain(raw_value: Any) -> str:
    """Normalize one URL/domain to strict lowercase IDNA without resolving it."""
    if not isinstance(raw_value, str):
        raise DomainValidationError("Enter one valid domain name.")
    value = raw_value.strip()
    if not value:
        raise DomainValidationError("Enter one domain name to manage.")
    if len(value) > 2048:
        raise DomainValidationError("The submitted domain or URL is too long.")
    if any(character.isspace() for character in value):
        raise DomainValidationError("Enter one domain only; whitespace and multiple values are not allowed.")
    if any(character in _DISALLOWED_RAW_CHARACTERS for character in value):
        raise DomainValidationError("The submitted value contains unsupported command or control characters.")
    if "\\" in value:
        raise DomainValidationError("File paths and backslash characters are not accepted.")
    if "*" in value:
        raise DomainValidationError("Wildcard domains are not supported.")

    candidate = value if "://" in value or value.startswith("//") else f"//{value}"
    try:
        parsed = urlsplit(candidate)
    except ValueError as exc:
        raise DomainValidationError("Enter a valid domain name or HTTP(S) URL.") from exc

    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        raise DomainValidationError("Only domain names and HTTP(S) URLs are accepted.")
    if parsed.username or parsed.password:
        raise DomainValidationError("URLs containing credentials are not accepted.")
    try:
        explicit_port = parsed.port
    except ValueError as exc:
        raise DomainValidationError("The URL contains an invalid port.") from exc
    if explicit_port is not None and not 1 <= explicit_port <= 65535:
        raise DomainValidationError("The URL contains an invalid port.")

    hostname = (parsed.hostname or "").rstrip(".").lower()
    if not hostname:
        raise DomainValidationError("Enter a valid domain name.")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise DomainValidationError("IP addresses cannot be added to the website blocklist.")

    if hostname in _LOOPBACK_NAMES or hostname.endswith(".localhost"):
        raise DomainValidationError("Localhost and loopback hostnames cannot be managed here.")
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise DomainValidationError("The internationalized domain name is not valid.") from exc

    if len(ascii_hostname) > 253:
        raise DomainValidationError("The normalized domain name is too long.")
    labels = ascii_hostname.split(".")
    if len(labels) < 2:
        raise DomainValidationError("Single-label hostnames are not supported.")
    if any(not label or len(label) > 63 or not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise DomainValidationError("The domain name is malformed.")
    if labels[-1].isdigit():
        raise DomainValidationError("The domain suffix cannot contain only digits.")
    return ascii_hostname


def affected_domains_for(normalized_domain: str, include_www: bool = True) -> list[str]:
    """Return exact managed names without expanding arbitrary subdomains."""
    domain = normalize_domain(normalized_domain)
    if not include_www:
        return [domain]
    # Without a network-fetched public-suffix list, expand unambiguous two-label
    # names plus common country-code forms such as example.co.uk. Other
    # multi-label inputs are conservatively treated as exact subdomains.
    def is_conventional_root(candidate: str) -> bool:
        labels = candidate.split(".")
        return len(labels) == 2 or (
            len(labels) == 3
            and len(labels[-1]) == 2
            and labels[-2] in _COMMON_COUNTRY_SECOND_LEVELS
        )

    if domain.startswith("www."):
        root = domain[4:]
        return sorted({root, domain}) if is_conventional_root(root) else [domain]
    if is_conventional_root(domain):
        return sorted({domain, f"www.{domain}"})
    return [domain]


def _safe_os_error(exc: BaseException) -> BlocklistError:
    permission_codes = {errno.EACCES, errno.EPERM}
    if isinstance(exc, PermissionError) or getattr(exc, "errno", None) in permission_codes or getattr(exc, "winerror", None) == 5:
        return BlocklistError(
            "administrator_required",
            "Administrator privileges are required to modify the Windows hosts file.",
            403,
        )
    return BlocklistError(
        "hosts_file_unavailable",
        "The Windows hosts file is unavailable. Confirm that it exists and is accessible.",
        503,
    )


class BlocklistManager:
    """Own only the marked section of one trusted, server-configured hosts file."""

    def __init__(self, hosts_path: str | Path, backup_directory: str | Path) -> None:
        self.hosts_path = Path(hosts_path)
        self.backup_directory = Path(backup_directory)
        self._lock = threading.RLock()

    def _read_original(self) -> bytes:
        if not self.hosts_path.is_file():
            raise BlocklistError(
                "hosts_file_unavailable",
                "The Windows hosts file is unavailable. Confirm that it exists and is accessible.",
                503,
            )
        try:
            return self.hosts_path.read_bytes()
        except OSError as exc:
            raise _safe_os_error(exc) from exc

    @staticmethod
    def _decode(content: bytes) -> str:
        return content.decode("utf-8", errors="surrogateescape")

    @staticmethod
    def _encode(content: str) -> bytes:
        return content.encode("utf-8", errors="surrogateescape")

    @staticmethod
    def _line_ending(text: str) -> str:
        for index, character in enumerate(text):
            if character == "\n":
                return "\r\n" if index > 0 and text[index - 1] == "\r" else "\n"
            if character == "\r":
                return "\r"
        return "\r\n"

    @staticmethod
    def _section_bounds(text: str) -> tuple[int, int, list[str]] | None:
        lines = text.splitlines(keepends=True)
        starts: list[tuple[int, int]] = []
        ends: list[tuple[int, int]] = []
        offset = 0
        for line in lines:
            line_end = offset + len(line)
            content = line.rstrip("\r\n")
            if content == MANAGED_SECTION_START:
                starts.append((offset, line_end))
            elif content == MANAGED_SECTION_END:
                ends.append((offset, line_end))
            offset = line_end

        if not starts and not ends:
            return None
        if len(starts) != 1 or len(ends) != 1 or starts[0][0] >= ends[0][0]:
            raise BlocklistError(
                "managed_section_invalid",
                "The Cybersential blocklist markers are incomplete or duplicated; no changes were made.",
                409,
            )

        managed_lines = []
        inside = False
        for line in lines:
            content = line.rstrip("\r\n")
            if content == MANAGED_SECTION_START:
                inside = True
                continue
            if content == MANAGED_SECTION_END:
                inside = False
                break
            if inside:
                managed_lines.append(content)
        return starts[0][0], ends[0][1], managed_lines

    @staticmethod
    def _domains_from_lines(lines: Iterable[str]) -> list[str]:
        domains: set[str] = set()
        for line in lines:
            parts = line.strip().split()
            if len(parts) != 2 or parts[0] != LOOPBACK_ADDRESS:
                continue
            candidate = parts[1].lower().rstrip(".")
            try:
                normalized = normalize_domain(candidate)
            except DomainValidationError:
                continue
            if candidate == normalized:
                domains.add(normalized)
        return sorted(domains)

    def get_managed_domains(self) -> list[str]:
        with self._lock:
            text = self._decode(self._read_original())
            bounds = self._section_bounds(text)
            return [] if bounds is None else self._domains_from_lines(bounds[2])

    def is_domain_blocked(self, domain: str) -> bool:
        return normalize_domain(domain) in set(self.get_managed_domains())

    def permission_status(self) -> dict[str, Any]:
        if not self.hosts_path.is_file():
            return {
                "available": False,
                "writable": False,
                "error_code": "hosts_file_unavailable",
                "message": "The Windows hosts file is unavailable.",
            }
        writable = os.access(self.hosts_path, os.W_OK) and os.access(self.hosts_path.parent, os.W_OK)
        return {
            "available": True,
            "writable": bool(writable),
            "error_code": None if writable else "administrator_required",
            "message": (
                "The hosts file is available for authorized local management."
                if writable
                else "Administrator privileges are required to modify the Windows hosts file."
            ),
        }

    def _assert_modifiable(self) -> None:
        status = self.permission_status()
        if not status["available"]:
            raise BlocklistError("hosts_file_unavailable", status["message"], 503)
        if not status["writable"]:
            raise BlocklistError("administrator_required", status["message"], 403)

    def backup_status(self) -> dict[str, Any]:
        try:
            candidates = sorted(self.backup_directory.glob("hosts-backup-*.txt"))
        except OSError:
            candidates = []
        return {
            "exists": bool(candidates),
            "message": (
                "A pre-modification hosts backup is available."
                if candidates
                else "A backup will be created before the first successful modification."
            ),
        }

    def create_backup_if_required(self, original_content: bytes | None = None) -> dict[str, Any]:
        """Create one fixed-location backup before the first attempted update."""
        with self._lock:
            existing = self.backup_status()
            if existing["exists"]:
                return {**existing, "created": False}
            content = original_content if original_content is not None else self._read_original()
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            backup_path = self.backup_directory / f"hosts-backup-{timestamp}.txt"
            try:
                self.backup_directory.mkdir(parents=True, exist_ok=True)
                with backup_path.open("xb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
            except OSError as exc:
                try:
                    if backup_path.exists():
                        backup_path.unlink()
                except OSError:
                    pass
                raise BlocklistError(
                    "backup_failed",
                    "The hosts-file backup could not be created, so no modification was attempted.",
                    503,
                ) from exc
            return {
                "exists": True,
                "created": True,
                "message": "A pre-modification hosts backup was created successfully.",
            }

    def _replace_bytes(self, content: bytes) -> None:
        descriptor: int | None = None
        temporary_name: str | None = None
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".cybersential-hosts-",
                suffix=".tmp",
                dir=str(self.hosts_path.parent),
            )
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = None
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                mode = stat.S_IMODE(self.hosts_path.stat().st_mode)
                os.chmod(temporary_name, mode)
            except OSError:
                pass
            os.replace(temporary_name, self.hosts_path)
            temporary_name = None
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary_name is not None:
                try:
                    Path(temporary_name).unlink()
                except OSError:
                    pass

    def _atomic_write(self, content: bytes) -> None:
        self._replace_bytes(content)

    def _restore_original(self, original_content: bytes) -> None:
        self._replace_bytes(original_content)

    def _updated_content(self, original_content: bytes, domains: Iterable[str]) -> bytes:
        text = self._decode(original_content)
        newline = self._line_ending(text)
        normalized_domains = sorted({normalize_domain(domain) for domain in domains})
        managed_section = newline.join(
            [
                MANAGED_SECTION_START,
                *(f"{LOOPBACK_ADDRESS} {domain}" for domain in normalized_domains),
                MANAGED_SECTION_END,
            ]
        ) + newline
        bounds = self._section_bounds(text)
        if bounds is None:
            separator = "" if not text or text.endswith(("\n", "\r")) else newline
            updated = f"{text}{separator}{managed_section}"
        else:
            start, end, _managed_lines = bounds
            updated = f"{text[:start]}{managed_section}{text[end:]}"
        return self._encode(updated)

    def update_managed_section(self, domains: Iterable[str]) -> dict[str, Any]:
        """Write sorted managed domains atomically while preserving outside bytes."""
        with self._lock:
            normalized_domains = sorted({normalize_domain(domain) for domain in domains})
            original = self._read_original()
            updated = self._updated_content(original, normalized_domains)
            if updated == original:
                return {
                    "changed": False,
                    "managed_domains": self.get_managed_domains(),
                    "backup": self.backup_status(),
                }
            self._assert_modifiable()
            backup = self.create_backup_if_required(original)
            try:
                self._atomic_write(updated)
                if self._read_original() != updated:
                    raise OSError("Atomic hosts-file verification failed.")
            except Exception as exc:
                restoration_verified = False
                try:
                    current = self.hosts_path.read_bytes() if self.hosts_path.is_file() else None
                    if current != original:
                        self._restore_original(original)
                    restoration_verified = self.hosts_path.read_bytes() == original
                except OSError:
                    restoration_verified = False
                mapped = _safe_os_error(exc)
                if mapped.code == "hosts_file_unavailable":
                    mapped = BlocklistError(
                        "atomic_write_failed",
                        (
                            "The hosts-file update could not be completed atomically; the original content was retained."
                            if restoration_verified
                            else "The hosts-file update failed and automatic restoration could not be verified. Use the Cybersential backup before making further changes."
                        ),
                        503,
                    )
                raise mapped from exc
            return {
                "changed": True,
                "managed_domains": normalized_domains,
                "backup": backup,
            }
