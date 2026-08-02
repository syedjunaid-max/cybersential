"""Rule-based password analysis that never stores the submitted value."""

from __future__ import annotations

import re
from typing import Any


def analyze_password(password: str) -> dict[str, Any]:
    """Classify a password using length and four character-class checks."""
    candidate = password if isinstance(password, str) else ""
    checks = {
        "At least 8 characters": len(candidate) >= 8,
        "At least 12 characters": len(candidate) >= 12,
        "Contains an uppercase letter": bool(re.search(r"[A-Z]", candidate)),
        "Contains a lowercase letter": bool(re.search(r"[a-z]", candidate)),
        "Contains a number": bool(re.search(r"[0-9]", candidate)),
        "Contains a special character": bool(re.search(r"[^A-Za-z0-9]", candidate)),
    }
    character_class_checks = [
        checks["Contains an uppercase letter"],
        checks["Contains a lowercase letter"],
        checks["Contains a number"],
        checks["Contains a special character"],
    ]
    class_count = sum(character_class_checks)

    if len(candidate) >= 12 and class_count == 4:
        strength = "Strong"
    elif len(candidate) >= 8 and class_count >= 3:
        strength = "Medium"
    else:
        strength = "Weak"

    passed_checks = [name for name, passed in checks.items() if passed]
    failed_checks = [name for name, passed in checks.items() if not passed]
    recommendations: list[str] = []
    if len(candidate) < 12:
        recommendations.append("Use at least 12 characters for a Strong rating.")
    if not checks["Contains an uppercase letter"]:
        recommendations.append("Add at least one uppercase letter.")
    if not checks["Contains a lowercase letter"]:
        recommendations.append("Add at least one lowercase letter.")
    if not checks["Contains a number"]:
        recommendations.append("Add at least one number.")
    if not checks["Contains a special character"]:
        recommendations.append("Add at least one special character.")
    if not recommendations:
        recommendations.append("The password meets all configured strength rules.")

    # Deliberately return only derived properties, never the password itself.
    return {
        "strength": strength,
        "length": len(candidate),
        "character_classes": class_count,
        "passed_checks": passed_checks,
        "failed_checks": failed_checks,
        "recommendations": recommendations,
    }
