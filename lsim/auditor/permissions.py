"""
Permissions Auditor — finds dangerous file/directory permissions.
"""

import grp
import os
import pwd
import stat
import subprocess

from lsim.config import (
    KNOWN_SETUID_BINARIES,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
)
from lsim.finding import Finding

_CRITICAL_DIRS_FOR_WORLD_WRITABLE = [
    "/etc",
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
]


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
        findings += self._check_tmp_sticky()
        findings += self._find_unowned_files()
        return findings

    # ------------------------------------------------------------------
    # Find SUID binaries not in the known-good list
    # ------------------------------------------------------------------
    def _find_unexpected_suid(self) -> list:
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
                        f"SUID binary found at {path} which is not in the known-safe list.\n"
                        "SUID binaries run with the file owner's privileges (usually root) "
                        "regardless of who executes them."
                    ),
                    recommendation=(
                        f"Verify {path} legitimacy. If unexpected, remove SUID bit: "
                        f"sudo chmod u-s {path}"
                    ),
                    filepath=path,
                    auto_remediate=False,
                ))
        return findings

    # ------------------------------------------------------------------
    # World-writable files in critical directories
    # ------------------------------------------------------------------
    def _find_world_writable_critical(self) -> list:
        dirs_args = _CRITICAL_DIRS_FOR_WORLD_WRITABLE[:]
        existing_dirs = [d for d in dirs_args if os.path.isdir(d)]
        if not existing_dirs:
            return []

        output = _run(
            ["find"] + existing_dirs + ["-perm", "-o+w", "-type", "f"],
            timeout=30,
        )

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
                    f"{path} is writable by any user on the system. "
                    "An attacker could modify this file to compromise system integrity."
                ),
                recommendation=f"Fix permissions: sudo chmod o-w {path}",
                filepath=path,
                auto_remediate=False,
            ))
        return findings

    # ------------------------------------------------------------------
    # /tmp sticky bit
    # ------------------------------------------------------------------
    def _check_tmp_sticky(self) -> list:
        try:
            mode = os.stat("/tmp").st_mode
        except OSError:
            return []

        if not (mode & stat.S_ISVTX):
            return [Finding(
                category="Permissions",
                severity=SEVERITY_HIGH,
                title="/tmp directory is missing the sticky bit",
                detail=(
                    "/tmp should have the sticky bit set (permissions 1777) so that only "
                    "file owners can delete their own files. Without it, any user can delete "
                    f"other users' temp files. Current permissions: {oct(stat.S_IMODE(mode))}"
                ),
                recommendation="Fix: sudo chmod 1777 /tmp",
                filepath="/tmp",
                auto_remediate=False,
            )]
        return []

    # ------------------------------------------------------------------
    # Unowned files (uid/gid not in passwd/group databases)
    # ------------------------------------------------------------------
    def _find_unowned_files(self) -> list:
        # Build set of valid UIDs and GIDs
        valid_uids = {entry.pw_uid for entry in pwd.getpwall()}
        try:
            valid_gids = {entry.gr_gid for entry in grp.getgrall()}
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
                            "which do not correspond to any existing user/group. "
                            "This may be a leftover from a deleted account."
                        ),
                        recommendation=(
                            f"Assign ownership: sudo chown root:root {path} "
                            "or remove if the file is not needed."
                        ),
                        filepath=path,
                        auto_remediate=False,
                    ))
            except (OSError, PermissionError):
                continue

        return findings
