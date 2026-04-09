"""
Permissions auditor - finds dangerous file permission settings.
Checks for unexpected SUID binaries, world-writable files in critical dirs,
and files not owned by any existing user/group.
"""

import grp
import os
import pwd
import subprocess

from lsim.config import (
    KNOWN_SETUID_BINARIES,
    SEVERITY_CRITICAL,
    SEVERITY_MEDIUM,
)
from lsim.finding import Finding

# Directories where world-writable files are a big problem
_CRITICAL_DIRS = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin"]


def _run(cmd: list, timeout: int = 60) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return ""


class PermissionsAuditor:
    def audit(self) -> list:
        findings = []
        findings += self._find_unexpected_suid()
        findings += self._find_world_writable_critical()
        findings += self._find_unowned_files()
        return findings

    def _find_unexpected_suid(self) -> list:
        """Find SUID binaries that aren't in our known-good list."""
        output = _run([
            "find", "/", "-xdev", "-perm", "-4000", "-type", "f",
            "-not", "-path", "/proc/*",
            "-not", "-path", "/sys/*",
        ], timeout=120)

        known = set(KNOWN_SETUID_BINARIES)
        findings = []
        for line in output.splitlines():
            path = line.strip()
            if not path:
                continue
            if path not in known:
                findings.append(Finding(
                    category="Permissions",
                    severity=SEVERITY_CRITICAL,
                    title=f"Unexpected SUID binary: {path}",
                    detail=(
                        f"{path} has the SUID bit set but isn't in the known-safe list.\n"
                        "SUID binaries run as the file owner (usually root) regardless of who executes them."
                    ),
                    recommendation=(
                        f"Verify {path} is supposed to be there. "
                        f"If not, remove the SUID bit: sudo chmod u-s {path}"
                    ),
                    filepath=path,
                    auto_remediate=False,
                ))
        return findings

    def _find_world_writable_critical(self) -> list:
        """Find files in critical directories that are writable by anyone."""
        existing = [d for d in _CRITICAL_DIRS if os.path.isdir(d)]
        if not existing:
            return []

        output = _run(["find"] + existing + ["-perm", "-o+w", "-type", "f"], timeout=30)

        findings = []
        for line in output.splitlines():
            path = line.strip()
            if not path:
                continue
            findings.append(Finding(
                category="Permissions",
                severity=SEVERITY_CRITICAL,
                title=f"World-writable file in critical directory: {path}",
                detail=(
                    f"{path} is writable by any user. "
                    "An attacker could modify this file to compromise the system."
                ),
                recommendation=f"Fix permissions: sudo chmod o-w {path}",
                filepath=path,
                auto_remediate=False,
            ))
        return findings

    def _find_unowned_files(self) -> list:
        """Find files whose UID or GID doesn't match any existing user/group."""
        valid_uids = {e.pw_uid for e in pwd.getpwall()}
        try:
            valid_gids = {e.gr_gid for e in grp.getgrall()}
        except Exception:
            valid_gids = set()

        output = _run([
            "find", "/", "-xdev",
            "-not", "-path", "/proc/*",
            "-not", "-path", "/sys/*",
            "-not", "-path", "/run/*",
        ], timeout=120)

        findings = []
        for line in output.splitlines():
            path = line.strip()
            if not path:
                continue
            try:
                st = os.lstat(path)
                if st.st_uid not in valid_uids or st.st_gid not in valid_gids:
                    findings.append(Finding(
                        category="Permissions",
                        severity=SEVERITY_MEDIUM,
                        title=f"Unowned file: {path}",
                        detail=(
                            f"{path} has uid={st.st_uid} gid={st.st_gid} "
                            "which don't match any user or group in the system. "
                            "Possibly leftover from a deleted account."
                        ),
                        recommendation=(
                            f"Assign ownership: sudo chown root:root {path} "
                            "or remove if not needed."
                        ),
                        filepath=path,
                        auto_remediate=False,
                    ))
            except (OSError, PermissionError):
                continue

        return findings
