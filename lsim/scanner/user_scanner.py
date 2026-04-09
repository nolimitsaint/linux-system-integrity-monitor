"""
User scanner - looks for suspicious or misconfigured user accounts.
Checks /etc/passwd, /etc/shadow, and sudoers files.
"""

import os
import pwd
import re

from lsim.config import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
)
from lsim.finding import Finding

SHADOW_FILE = "/etc/shadow"
SUDOERS_FILE = "/etc/sudoers"
SUDOERS_DIR = "/etc/sudoers.d/"

# Shadow hash values that mean "no real password"
# * and ! mean the account is locked (ok for system accounts, bad for real users)
# empty string means anyone can log in with no password
_LOCKED_MARKERS = ("!", "!!", "*")
_NOLOGIN_SHELLS = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/dev/null"}


class UserScanner:
    def scan(self) -> list:
        findings = []
        findings += self._check_uid_zero_accounts()
        findings += self._check_empty_passwords()
        findings += self._check_sudo_entries()
        return findings

    def _check_uid_zero_accounts(self) -> list:
        """Flag any non-root account with UID 0 (root-equivalent)."""
        findings = []
        try:
            for entry in pwd.getpwall():
                if entry.pw_uid == 0 and entry.pw_name != "root":
                    findings.append(Finding(
                        category="User",
                        severity=SEVERITY_CRITICAL,
                        title=f"Unauthorized root-equivalent account: {entry.pw_name}",
                        detail=(
                            f"User '{entry.pw_name}' has UID 0 (same as root). "
                            "This account has full root privileges.\n"
                            f"  Shell: {entry.pw_shell}  Home: {entry.pw_dir}"
                        ),
                        recommendation=(
                            f"Investigate '{entry.pw_name}'. If unauthorized, "
                            "lock it: sudo passwd --lock {entry.pw_name}"
                        ),
                        username=entry.pw_name,
                        auto_remediate=True,
                    ))
        except Exception:
            pass
        return findings

    def _check_empty_passwords(self) -> list:
        """Flag interactive user accounts with no password hash set."""
        findings = []
        if not os.path.isfile(SHADOW_FILE):
            return findings

        passwd_map = {}
        try:
            for entry in pwd.getpwall():
                passwd_map[entry.pw_name] = entry
        except Exception:
            pass

        try:
            with open(SHADOW_FILE) as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if len(parts) < 2:
                        continue
                    username, pw_hash = parts[0], parts[1]

                    is_empty = (pw_hash == "")
                    is_locked = pw_hash in _LOCKED_MARKERS

                    if not is_empty and not is_locked:
                        continue

                    # Skip system accounts that are supposed to be locked
                    if is_locked and not is_empty:
                        entry = passwd_map.get(username)
                        if entry is not None:
                            if entry.pw_uid < 1000:
                                continue
                            if entry.pw_shell in _NOLOGIN_SHELLS:
                                continue

                    findings.append(Finding(
                        category="User",
                        severity=SEVERITY_HIGH,
                        title=f"Account with no valid password: {username}",
                        detail=(
                            f"User '{username}' has no password set "
                            f"(shadow hash: '{pw_hash}'). "
                            "This account can be logged into without a password."
                        ),
                        recommendation=(
                            f"Set a password or lock the account: "
                            f"sudo passwd --lock {username}"
                        ),
                        username=username,
                        auto_remediate=False,
                    ))
        except PermissionError:
            pass
        return findings

    def _check_sudo_entries(self) -> list:
        """Flag sudoers entries that grant passwordless root access."""
        findings = []
        sudoers_files = []
        if os.path.isfile(SUDOERS_FILE):
            sudoers_files.append(SUDOERS_FILE)
        if os.path.isdir(SUDOERS_DIR):
            for name in os.listdir(SUDOERS_DIR):
                path = os.path.join(SUDOERS_DIR, name)
                if os.path.isfile(path):
                    sudoers_files.append(path)

        nopasswd_pattern = re.compile(r"NOPASSWD\s*:\s*ALL", re.IGNORECASE)

        for path in sudoers_files:
            try:
                with open(path) as fh:
                    for lineno, line in enumerate(fh, 1):
                        stripped = line.strip()
                        if stripped.startswith("#") or not stripped:
                            continue
                        if nopasswd_pattern.search(stripped):
                            subject = stripped.split()[0] if stripped.split() else "unknown"
                            findings.append(Finding(
                                category="User",
                                severity=SEVERITY_HIGH,
                                title=f"NOPASSWD sudo access: {subject}",
                                detail=(
                                    f"Passwordless sudo (NOPASSWD:ALL) found in {path}:{lineno}.\n"
                                    f"  Rule: {stripped}"
                                ),
                                recommendation=(
                                    "Remove NOPASSWD:ALL or restrict to specific commands. "
                                    f"Edit with: sudo visudo -f {path}"
                                ),
                                username=subject if not subject.startswith("%") else None,
                                auto_remediate=False,
                            ))
            except PermissionError:
                pass
        return findings
