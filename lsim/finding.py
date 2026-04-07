"""
Finding dataclass and state determination logic.
All scanner, auditor, and responder modules exchange Finding objects.
"""

from dataclasses import dataclass, field
from typing import Optional

from lsim.config import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_ORDER,
)


@dataclass
class Finding:
    category: str           # "File Integrity" | "Process" | "User" | "Network" | "Firewall" | "Permissions" | "Packages"
    severity: str           # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str              # Short description
    detail: str             # Full detail / evidence
    recommendation: str     # What the user should do
    pid: Optional[int] = None           # For process findings
    username: Optional[str] = None      # For user findings
    filepath: Optional[str] = None      # For file findings
    auto_remediate: bool = False        # Whether the responder should act

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "recommendation": self.recommendation,
            "pid": self.pid,
            "username": self.username,
            "filepath": self.filepath,
            "auto_remediate": self.auto_remediate,
        }


def determine_state(findings: list) -> str:
    """
    Map a list of Finding objects to the overall system state.

    LOCKDOWN  — any CRITICAL or HIGH finding
    AT_RISK   — at least one MEDIUM finding, no CRITICAL/HIGH
    SECURE    — only LOW or INFO findings (or no findings at all)
    """
    has_medium = False
    for f in findings:
        if f.severity in (SEVERITY_CRITICAL, SEVERITY_HIGH):
            return "LOCKDOWN"
        if f.severity == SEVERITY_MEDIUM:
            has_medium = True
    return "AT_RISK" if has_medium else "SECURE"


def sort_findings(findings: list) -> list:
    """Return findings sorted by severity (CRITICAL first)."""
    return sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else len(SEVERITY_ORDER),
    )
