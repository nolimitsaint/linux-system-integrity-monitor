"""
User Scanner — detects compromised, unauthorized, or suspicious user accounts.
"""

import os
import pwd
import re
from datetime import datetime, timezone

from lsim.config import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
)
from lsim.finding import Finding

SHADOW_FILE = "/etc/shadow"
SUDOERS_FILE = "/etc/sudoers"
SUDOERS_DIR = "/etc/sudoers.d/"
AUTH_LOG = "/var/log/auth.log"

# Shadow fields: name:hash:lastchg:min:max:warn:inactive:expire:reserved
#
# * means "password login disabled" — intentional for system service accounts
# ! means "account locked" — also intentional for service accounts
# !! means "never had a password set" — normal for service accounts
#
# These are only a problem on accounts that real users are supposed to log
# into (UID >= 1000 with a real login shell). A truly empty hash ("") on any
# account IS a vulnerability — it means password auth succeeds with no input.
_SHADOW_EMPTY_HASH = ("", "!", "!!", "*")
_NOLOGIN_SHELLS = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/dev/null"}


class UserScanner:
    def scan(self) -> list:
        findings = []
        findings += self._check_uid_zero_accounts()
        findings += self._check_empty_passwords()
        findings += self._check_sudo_entries()
        findings += self._check_auth_log()
        return findings

    # ------------------------------------------------------------------
    # Check for UID-0 accounts that are not root
    # ------------------------------------------------------------------
    def _check_uid_zero_accounts(self) -> list:
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
                            f"Investigate account '{entry.pw_name}'. If unauthorized, "
                            "lock it immediately with: sudo passwd --lock {entry.pw_name}"
                        ),
                        username=entry.pw_name,
                        auto_remediate=True,
                    ))
        except Exception:
            pass
        return findings

    # ------------------------------------------------------------------
    # Check for accounts with empty or missing password hashes
    # ------------------------------------------------------------------
    def _check_empty_passwords(self) -> list:
        findings = []
        if not os.path.isfile(SHADOW_FILE):
            return findings

        # Build a map of username → passwd entry so we can filter system accounts
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

                    # A truly empty hash ("") is always a vulnerability —
                    # password auth will succeed with no input for any account.
                    is_truly_empty = (pw_hash == "")

                    # *, !, !! mean "login disabled" — only a problem on
                    # interactive user accounts (UID >= 1000 with a real shell).
                    is_locked_marker = pw_hash in ("!", "!!", "*")

                    if not is_truly_empty and not is_locked_marker:
                        continue  # has a real password hash, nothing to flag

                    if is_locked_marker and not is_truly_empty:
                        # Skip system service accounts — they're supposed to be locked
                        entry = passwd_map.get(username)
                        if entry is not None:
                            if entry.pw_uid < 1000:
                                continue  # system account, locked by design
                            if entry.pw_shell in _NOLOGIN_SHELLS:
                                continue  # no login shell, locked by design

                    findings.append(Finding(
                        category="User",
                        severity=SEVERITY_HIGH,
                        title=f"Account with no valid password: {username}",
                        detail=(
                            f"User '{username}' has no password set "
                            f"(shadow hash field: '{pw_hash}'). "
                            "This interactive account can be logged into without a password."
                        ),
                        recommendation=(
                            f"Set a strong password for '{username}' or lock the account: "
                            f"sudo passwd --lock {username}"
                        ),
                        username=username,
                        auto_remediate=False,
                    ))
        except PermissionError:
            pass
        return findings

    # ------------------------------------------------------------------
    # Check sudoers for NOPASSWD:ALL entries
    # ------------------------------------------------------------------
    def _check_sudo_entries(self) -> list:
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
                            # Extract username/group heuristically
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
                                    "Remove NOPASSWD:ALL from sudoers or restrict to specific commands. "
                                    f"Edit with: sudo visudo -f {path}"
                                ),
                                username=subject if not subject.startswith("%") else None,
                                auto_remediate=False,
                            ))
            except PermissionError:
                pass
        return findings

    # ------------------------------------------------------------------
    # Parse auth.log for suspicious login events
    # ------------------------------------------------------------------
    def _check_auth_log(self) -> list:
        findings = []
        if not os.path.isfile(AUTH_LOG):
            return findings

        failed_logins: dict = {}   # username -> count
        root_ssh_logins = []

        try:
            with open(AUTH_LOG) as fh:
                for line in fh:
                    # Failed password attempts
                    m = re.search(r"Failed password for (?:invalid user )?(\S+) from (\S+)", line)
                    if m:
                        user = m.group(1)
                        failed_logins[user] = failed_logins.get(user, 0) + 1

                    # Successful root login via SSH
                    if "Accepted" in line and "for root" in line and "ssh" in line.lower():
                        root_ssh_logins.append(line.strip())
        except PermissionError:
            return findings

        # Flag users with >10 failed login attempts
        for user, count in failed_logins.items():
            if count > 10:
                findings.append(Finding(
                    category="User",
                    severity=SEVERITY_MEDIUM,
                    title=f"Repeated failed logins for user: {user} ({count} attempts)",
                    detail=(
                        f"User '{user}' had {count} failed login attempts recorded in {AUTH_LOG}. "
                        "This may indicate a brute-force attack."
                    ),
                    recommendation=(
                        f"Review login attempts for '{user}'. Consider installing fail2ban "
                        "and enforcing SSH key-only authentication."
                    ),
                    username=user,
                    auto_remediate=False,
                ))

        # Flag root SSH logins
        for log_line in root_ssh_logins[:5]:  # cap at 5 to avoid finding flood
            findings.append(Finding(
                category="User",
                severity=SEVERITY_HIGH,
                title="Successful root login via SSH detected",
                detail=(
                    f"Root logged in via SSH:\n  {log_line}\n"
                    "Direct root SSH login is a security risk."
                ),
                recommendation=(
                    "Disable root SSH login: set 'PermitRootLogin no' in /etc/ssh/sshd_config "
                    "and reload sshd."
                ),
                username="root",
                auto_remediate=False,
            ))

        return findings
