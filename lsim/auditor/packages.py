"""
Packages auditor - checks for pending security updates and stale apt cache.
Tries python-apt first, falls back to running apt list --upgradable.
"""

import os
import subprocess
import time

from lsim.config import SEVERITY_HIGH, SEVERITY_INFO, SEVERITY_LOW
from lsim.finding import Finding

_APT_CACHE_FILE = "/var/cache/apt/pkgcache.bin"
_STALE_DAYS = 7


class PackagesAuditor:
    def audit(self) -> list:
        findings = []
        findings += self._check_cache_age()
        findings += self._check_upgradable()
        return findings

    def _check_cache_age(self) -> list:
        if not os.path.isfile(_APT_CACHE_FILE):
            return []
        try:
            age_days = (time.time() - os.path.getmtime(_APT_CACHE_FILE)) / 86400
            if age_days > _STALE_DAYS:
                return [Finding(
                    category="Packages",
                    severity=SEVERITY_INFO,
                    title=f"Package cache is stale ({int(age_days)} days old)",
                    detail=f"apt cache last updated {int(age_days)} days ago. You may be missing security updates.",
                    recommendation="Run: sudo apt update",
                )]
        except OSError:
            pass
        return []

    def _check_upgradable(self) -> list:
        # Try python-apt first since it doesn't need a TTY
        try:
            return self._check_upgradable_python_apt()
        except ImportError:
            pass
        return self._check_upgradable_subprocess()

    def _check_upgradable_python_apt(self) -> list:
        import apt  # type: ignore
        cache = apt.Cache()
        cache.open()

        security_pkgs = []
        other_pkgs = []

        for pkg in cache:
            if pkg.is_upgradable:
                candidate = pkg.candidate
                if candidate is None:
                    continue
                is_security = any(
                    "security" in (origin.label or "").lower()
                    or "security" in (origin.origin or "").lower()
                    for origin in candidate.origins
                )
                if is_security:
                    security_pkgs.append(pkg.name)
                else:
                    other_pkgs.append(pkg.name)

        findings = []
        if security_pkgs:
            findings.append(Finding(
                category="Packages",
                severity=SEVERITY_HIGH,
                title=f"{len(security_pkgs)} security update(s) pending",
                detail=(
                    "Packages with security updates:\n  "
                    + "\n  ".join(security_pkgs[:20])
                    + (f"\n  ... and {len(security_pkgs) - 20} more" if len(security_pkgs) > 20 else "")
                ),
                recommendation="Apply security updates: sudo apt-get upgrade",
            ))
        if other_pkgs:
            findings.append(Finding(
                category="Packages",
                severity=SEVERITY_LOW,
                title=f"{len(other_pkgs)} non-security update(s) available",
                detail=(
                    f"{len(other_pkgs)} packages can be upgraded:\n  "
                    + "\n  ".join(other_pkgs[:10])
                    + (f"\n  ... and {len(other_pkgs) - 10} more" if len(other_pkgs) > 10 else "")
                ),
                recommendation="Run: sudo apt-get upgrade",
            ))
        return findings

    def _check_upgradable_subprocess(self) -> list:
        try:
            result = subprocess.run(
                ["apt", "list", "--upgradable"],
                capture_output=True, text=True, timeout=30,
                env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
            )
            output = result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

        security_pkgs = []
        other_pkgs = []

        for line in output.splitlines():
            if "/" not in line or line.startswith("Listing"):
                continue
            pkg_name = line.split("/")[0]
            if "security" in line.lower():
                security_pkgs.append(pkg_name)
            else:
                other_pkgs.append(pkg_name)

        findings = []
        if security_pkgs:
            findings.append(Finding(
                category="Packages",
                severity=SEVERITY_HIGH,
                title=f"{len(security_pkgs)} security update(s) pending",
                detail=(
                    "Security updates available:\n  "
                    + "\n  ".join(security_pkgs[:20])
                    + (f"\n  ... and {len(security_pkgs) - 20} more" if len(security_pkgs) > 20 else "")
                ),
                recommendation="Apply now: sudo apt-get upgrade",
            ))
        if other_pkgs:
            findings.append(Finding(
                category="Packages",
                severity=SEVERITY_LOW,
                title=f"{len(other_pkgs)} non-security update(s) available",
                detail=(
                    f"{len(other_pkgs)} packages can be upgraded:\n  "
                    + "\n  ".join(other_pkgs[:10])
                    + (f"\n  ... and {len(other_pkgs) - 10} more" if len(other_pkgs) > 10 else "")
                ),
                recommendation="Run: sudo apt-get upgrade",
            ))
        return findings
