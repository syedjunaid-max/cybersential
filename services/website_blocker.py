"""Authorized local-only website blocking orchestration."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from services.blocking_audit import AUDIT_WARNING, BlockingAuditLog, utc_timestamp
from services.blocklist_manager import (
    WINDOWS_HOSTS_PATH,
    BlocklistError,
    BlocklistManager,
    DomainValidationError,
    affected_domains_for,
    normalize_domain,
)


BASE_DIRECTORY = Path(__file__).resolve().parents[1]
DEFAULT_BACKUP_DIRECTORY = BASE_DIRECTORY / "data" / "backups"
DEFAULT_AUDIT_PATH = BASE_DIRECTORY / "data" / "website_blocking_audit.jsonl"
DNS_CACHE_INSTRUCTION = "Open an Administrator terminal and run: ipconfig /flushdns"


class WebsiteBlocker:
    """Coordinate validation, managed hosts updates, backups, and audit events."""

    def __init__(
        self,
        *,
        hosts_path: str | Path = WINDOWS_HOSTS_PATH,
        backup_directory: str | Path = DEFAULT_BACKUP_DIRECTORY,
        audit_path: str | Path = DEFAULT_AUDIT_PATH,
    ) -> None:
        self.manager = BlocklistManager(hosts_path, backup_directory)
        self.audit = BlockingAuditLog(audit_path)
        self._operation_lock = threading.Lock()

    @staticmethod
    def _result(
        *,
        success: bool,
        action: str,
        normalized_domain: str = "",
        affected_domains: list[str] | None = None,
        message: str,
        error_code: str | None = None,
        authorization_confirmed: bool,
        changed: bool = False,
        status_code: int = 200,
        backup: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "success": bool(success),
            "normalized_domain": normalized_domain,
            "affected_domains": list(affected_domains or []),
            "action": action,
            "message": message,
            "timestamp": utc_timestamp(),
            "error_code": error_code,
            "authorization_confirmed": bool(authorization_confirmed),
            "changed": bool(changed),
            "status_code": int(status_code),
            "backup": backup or {},
            "warnings": [],
            "dns_cache_instruction": DNS_CACHE_INSTRUCTION if changed else "",
        }

    def _audit_result(self, result: dict[str, Any]) -> dict[str, Any]:
        try:
            warning = self.audit.record(
                action=result["action"],
                normalized_domain=result["normalized_domain"],
                affected_domains=result["affected_domains"],
                timestamp=result["timestamp"],
                success=result["success"],
                authorization_confirmed=result["authorization_confirmed"],
                error_code=result["error_code"],
            )
        except Exception:
            warning = AUDIT_WARNING
        if warning:
            result["warnings"].append(warning)
        return result

    def _authorization_failure(self, action: str) -> dict[str, Any]:
        return self._audit_result(
            self._result(
                success=False,
                action=action,
                message="Confirm that you own or explicitly administer this Windows computer before modifying its local blocklist.",
                error_code="authorization_required",
                authorization_confirmed=False,
                status_code=403,
            )
        )

    def _validation_failure(self, action: str, authorization_confirmed: bool, exc: DomainValidationError) -> dict[str, Any]:
        return self._audit_result(
            self._result(
                success=False,
                action=action,
                message=str(exc),
                error_code="invalid_domain",
                authorization_confirmed=authorization_confirmed,
                status_code=400,
            )
        )

    def _management_failure(
        self,
        *,
        action: str,
        normalized_domain: str,
        affected_domains: list[str],
        authorization_confirmed: bool,
        exc: BlocklistError,
    ) -> dict[str, Any]:
        return self._audit_result(
            self._result(
                success=False,
                action=action,
                normalized_domain=normalized_domain,
                affected_domains=affected_domains,
                message=exc.message,
                error_code=exc.code,
                authorization_confirmed=authorization_confirmed,
                status_code=exc.status_code,
            )
        )

    def get_managed_domains(self) -> list[str]:
        return self.manager.get_managed_domains()

    def is_domain_blocked(self, domain: str) -> bool:
        return self.manager.is_domain_blocked(domain)

    def create_backup_if_required(self) -> dict[str, Any]:
        return self.manager.create_backup_if_required()

    def update_managed_section(self, domains: list[str]) -> dict[str, Any]:
        return self.manager.update_managed_section(domains)

    def block_domain(
        self,
        domain: str,
        include_www: bool = True,
        authorization_confirmed: bool = False,
    ) -> dict[str, Any]:
        if not authorization_confirmed:
            return self._authorization_failure("block")
        try:
            normalized = normalize_domain(domain)
            affected = affected_domains_for(normalized, include_www)
        except DomainValidationError as exc:
            return self._validation_failure("block", True, exc)
        try:
            with self._operation_lock:
                current = set(self.manager.get_managed_domains())
                if set(affected).issubset(current):
                    return self._audit_result(
                        self._result(
                            success=True,
                            action="block",
                            normalized_domain=normalized,
                            affected_domains=affected,
                            message="The requested domain entries are already blocked by Cybersential.",
                            error_code="already_blocked",
                            authorization_confirmed=True,
                        )
                    )
                update = self.manager.update_managed_section(sorted(current.union(affected)))
        except BlocklistError as exc:
            return self._management_failure(
                action="block",
                normalized_domain=normalized,
                affected_domains=affected,
                authorization_confirmed=True,
                exc=exc,
            )
        return self._audit_result(
            self._result(
                success=True,
                action="block",
                normalized_domain=normalized,
                affected_domains=affected,
                message="Domain blocked successfully on this Windows computer.",
                authorization_confirmed=True,
                changed=bool(update["changed"]),
                backup=update["backup"],
            )
        )

    def unblock_domain(
        self,
        domain: str,
        include_www: bool = True,
        authorization_confirmed: bool = False,
    ) -> dict[str, Any]:
        if not authorization_confirmed:
            return self._authorization_failure("unblock")
        try:
            normalized = normalize_domain(domain)
            affected = affected_domains_for(normalized, include_www)
        except DomainValidationError as exc:
            return self._validation_failure("unblock", True, exc)
        try:
            with self._operation_lock:
                current = set(self.manager.get_managed_domains())
                removable = current.intersection(affected)
                if not removable:
                    return self._audit_result(
                        self._result(
                            success=True,
                            action="unblock",
                            normalized_domain=normalized,
                            affected_domains=affected,
                            message="The requested domain was not blocked by Cybersential.",
                            error_code="domain_not_blocked",
                            authorization_confirmed=True,
                        )
                    )
                update = self.manager.update_managed_section(sorted(current.difference(removable)))
        except BlocklistError as exc:
            return self._management_failure(
                action="unblock",
                normalized_domain=normalized,
                affected_domains=affected,
                authorization_confirmed=True,
                exc=exc,
            )
        return self._audit_result(
            self._result(
                success=True,
                action="unblock",
                normalized_domain=normalized,
                affected_domains=sorted(removable),
                message="Domain unblocked successfully on this Windows computer.",
                authorization_confirmed=True,
                changed=bool(update["changed"]),
                backup=update["backup"],
            )
        )

    def get_status(self) -> dict[str, Any]:
        permission = self.manager.permission_status()
        error_code = permission.get("error_code")
        try:
            domains = self.manager.get_managed_domains() if permission["available"] else []
        except BlocklistError as exc:
            domains = []
            error_code = exc.code
            permission = {
                "available": False,
                "writable": False,
                "error_code": exc.code,
                "message": exc.message,
            }
        return {
            "available": bool(permission["available"]),
            "writable": bool(permission["writable"]),
            "error_code": error_code,
            "message": permission["message"],
            "managed_domains": domains,
            "managed_domain_count": len(domains),
            "backup": self.manager.backup_status(),
            "audit": self.audit.summary(),
            "temporary_blocking_enabled": False,
        }

    def cleanup_expired(self, authorization_confirmed: bool = False) -> dict[str, Any]:
        if not authorization_confirmed:
            return self._result(
                success=False,
                action="cleanup",
                message="Authorization confirmation is required for cleanup actions.",
                error_code="authorization_required",
                authorization_confirmed=False,
                status_code=403,
            )
        return self._result(
            success=True,
            action="cleanup",
            message="Temporary blocking is not enabled; there are no expiry records to clean up.",
            error_code="temporary_blocking_not_enabled",
            authorization_confirmed=True,
        )


_default_blocker = WebsiteBlocker()


def get_managed_domains() -> list[str]:
    return _default_blocker.get_managed_domains()


def block_domain(domain: str, include_www: bool = True, authorization_confirmed: bool = False) -> dict[str, Any]:
    return _default_blocker.block_domain(domain, include_www, authorization_confirmed)


def unblock_domain(domain: str, include_www: bool = True, authorization_confirmed: bool = False) -> dict[str, Any]:
    return _default_blocker.unblock_domain(domain, include_www, authorization_confirmed)


def is_domain_blocked(domain: str) -> bool:
    return _default_blocker.is_domain_blocked(domain)


def create_backup_if_required() -> dict[str, Any]:
    return _default_blocker.create_backup_if_required()


def update_managed_section(domains: list[str]) -> dict[str, Any]:
    return _default_blocker.update_managed_section(domains)
