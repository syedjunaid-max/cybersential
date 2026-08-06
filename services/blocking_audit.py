"""Structured, privacy-limited audit logging for local website blocking."""

from __future__ import annotations

import json
import os
import threading
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


AUDIT_WARNING = "The website action completed, but the audit log could not be updated."
ALLOWED_ACTIONS = {"block", "unblock"}


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


class BlockingAuditLog:
    """Append and read only the small set of fields approved for the UI."""

    def __init__(self, audit_path: str | Path) -> None:
        self.audit_path = Path(audit_path)
        self._lock = threading.Lock()

    def record(
        self,
        *,
        action: str,
        normalized_domain: str,
        affected_domains: list[str],
        success: bool,
        authorization_confirmed: bool,
        error_code: str | None = None,
        timestamp: str | None = None,
    ) -> str | None:
        """Append one JSONL event. Logging failure is returned as a warning."""
        safe_action = action if action in ALLOWED_ACTIONS else "block"
        record = {
            "event_id": str(uuid.uuid4()),
            "action": safe_action,
            "normalized_domain": str(normalized_domain or "")[:253],
            "affected_domains": [str(domain)[:253] for domain in affected_domains[:2]],
            "timestamp": timestamp or utc_timestamp(),
            "success": bool(success),
            "authorization_confirmed": bool(authorization_confirmed),
            "error_code": str(error_code)[:80] if error_code else None,
        }
        encoded = json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n"
        try:
            with self._lock:
                self.audit_path.parent.mkdir(parents=True, exist_ok=True)
                with self.audit_path.open("a", encoding="utf-8", newline="\n") as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
        except (OSError, ValueError):
            return AUDIT_WARNING
        return None

    def recent(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return bounded, validated audit records without exposing the log path."""
        bounded_limit = max(1, min(int(limit), 25))
        if not self.audit_path.is_file():
            return []
        records: deque[dict[str, Any]] = deque(maxlen=bounded_limit)
        try:
            with self._lock:
                with self.audit_path.open("r", encoding="utf-8", errors="replace") as stream:
                    for line in stream:
                        try:
                            item = json.loads(line)
                        except (json.JSONDecodeError, TypeError):
                            continue
                        if not isinstance(item, dict) or item.get("action") not in ALLOWED_ACTIONS:
                            continue
                        records.append(
                            {
                                "event_id": str(item.get("event_id") or "")[:36],
                                "action": item["action"],
                                "normalized_domain": str(item.get("normalized_domain") or "")[:253],
                                "affected_domains": [
                                    str(domain)[:253]
                                    for domain in (item.get("affected_domains") or [])[:2]
                                ],
                                "timestamp": str(item.get("timestamp") or "")[:64],
                                "success": bool(item.get("success")),
                                "authorization_confirmed": bool(item.get("authorization_confirmed")),
                                "error_code": str(item.get("error_code") or "")[:80] or None,
                            }
                        )
        except (OSError, ValueError):
            return []
        return list(reversed(records))

    def summary(self) -> dict[str, Any]:
        recent = self.recent(10)
        return {
            "recent_events": recent,
            "recent_event_count": len(recent),
            "recent_success_count": sum(bool(item["success"]) for item in recent),
        }
