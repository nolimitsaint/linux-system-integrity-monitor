"""
Tests for lsim/scanner/user_scanner.py

All tests mock pwd, shadow file, and auth.log reads.
"""

import unittest
from unittest.mock import MagicMock, mock_open, patch

from lsim.config import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM
from lsim.scanner.user_scanner import UserScanner


def _make_passwd_entry(name, uid=1000, gid=1000, home="/home/user", shell="/bin/bash"):
    entry = MagicMock()
    entry.pw_name = name
    entry.pw_uid = uid
    entry.pw_gid = gid
    entry.pw_dir = home
    entry.pw_shell = shell
    return entry


class TestUidZeroAccounts(unittest.TestCase):
    def test_detects_uid_zero_non_root(self):
        entries = [
            _make_passwd_entry("root", uid=0),
            _make_passwd_entry("backdoor", uid=0),
        ]
        with patch("lsim.scanner.user_scanner.pwd.getpwall", return_value=entries):
            scanner = UserScanner()
            findings = scanner._check_uid_zero_accounts()

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, SEVERITY_CRITICAL)
        self.assertEqual(findings[0].username, "backdoor")

    def test_no_finding_for_only_root(self):
        entries = [_make_passwd_entry("root", uid=0)]
        with patch("lsim.scanner.user_scanner.pwd.getpwall", return_value=entries):
            scanner = UserScanner()
            findings = scanner._check_uid_zero_accounts()
        self.assertEqual(findings, [])

    def test_no_finding_for_normal_users(self):
        entries = [
            _make_passwd_entry("root", uid=0),
            _make_passwd_entry("alice", uid=1001),
            _make_passwd_entry("bob", uid=1002),
        ]
        with patch("lsim.scanner.user_scanner.pwd.getpwall", return_value=entries):
            scanner = UserScanner()
            findings = scanner._check_uid_zero_accounts()
        self.assertEqual(findings, [])


class TestEmptyPasswords(unittest.TestCase):
    def test_detects_empty_password_hash(self):
        # A truly empty hash ("") is always flagged regardless of UID
        shadow_content = (
            "root:$6$abc:19000:0:99999:7:::\n"
            "nopassuser::19000:0:99999:7:::\n"  # empty hash — always a vulnerability
            "alice:$6$xyz:19000:0:99999:7:::\n"
        )
        # nopassuser has UID 1001 (interactive user) and a real shell
        mock_passwd = [
            _make_passwd_entry("root", uid=0, shell="/bin/bash"),
            _make_passwd_entry("nopassuser", uid=1001, shell="/bin/bash"),
            _make_passwd_entry("alice", uid=1002, shell="/bin/bash"),
        ]
        with patch("lsim.scanner.user_scanner.os.path.isfile", return_value=True), \
             patch("lsim.scanner.user_scanner.pwd.getpwall", return_value=mock_passwd), \
             patch("builtins.open", mock_open(read_data=shadow_content)):
            scanner = UserScanner()
            findings = scanner._check_empty_passwords()

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, SEVERITY_HIGH)
        self.assertEqual(findings[0].username, "nopassuser")

    def test_detects_exclamation_mark_on_interactive_user(self):
        # '!' on a real user account (UID >= 1000, real shell) is flagged
        shadow_content = "realuser:!:19000:0:99999:7:::\n"
        mock_passwd = [_make_passwd_entry("realuser", uid=1001, shell="/bin/bash")]
        with patch("lsim.scanner.user_scanner.os.path.isfile", return_value=True), \
             patch("lsim.scanner.user_scanner.pwd.getpwall", return_value=mock_passwd), \
             patch("builtins.open", mock_open(read_data=shadow_content)):
            scanner = UserScanner()
            findings = scanner._check_empty_passwords()

        self.assertEqual(len(findings), 1)

    def test_ignores_exclamation_mark_on_system_account(self):
        # '!' on a system service account (UID < 1000) is normal — do NOT flag
        shadow_content = "messagebus:!:19000:0:99999:7:::\n"
        mock_passwd = [_make_passwd_entry("messagebus", uid=106, shell="/usr/sbin/nologin")]
        with patch("lsim.scanner.user_scanner.os.path.isfile", return_value=True), \
             patch("lsim.scanner.user_scanner.pwd.getpwall", return_value=mock_passwd), \
             patch("builtins.open", mock_open(read_data=shadow_content)):
            scanner = UserScanner()
            findings = scanner._check_empty_passwords()

        self.assertEqual(findings, [])

    def test_ignores_star_on_system_account(self):
        # '*' (login disabled) on system accounts like daemon, www-data — do NOT flag
        shadow_content = (
            "daemon:*:19000:0:99999:7:::\n"
            "www-data:*:19000:0:99999:7:::\n"
        )
        mock_passwd = [
            _make_passwd_entry("daemon", uid=1, shell="/usr/sbin/nologin"),
            _make_passwd_entry("www-data", uid=33, shell="/usr/sbin/nologin"),
        ]
        with patch("lsim.scanner.user_scanner.os.path.isfile", return_value=True), \
             patch("lsim.scanner.user_scanner.pwd.getpwall", return_value=mock_passwd), \
             patch("builtins.open", mock_open(read_data=shadow_content)):
            scanner = UserScanner()
            findings = scanner._check_empty_passwords()

        self.assertEqual(findings, [])

    def test_no_findings_for_hashed_passwords(self):
        shadow_content = (
            "root:$6$salt$hash:19000:0:99999:7:::\n"
            "alice:$6$salt2$hash2:19000:0:99999:7:::\n"
        )
        mock_passwd = [
            _make_passwd_entry("root", uid=0),
            _make_passwd_entry("alice", uid=1001),
        ]
        with patch("lsim.scanner.user_scanner.os.path.isfile", return_value=True), \
             patch("lsim.scanner.user_scanner.pwd.getpwall", return_value=mock_passwd), \
             patch("builtins.open", mock_open(read_data=shadow_content)):
            scanner = UserScanner()
            findings = scanner._check_empty_passwords()
        self.assertEqual(findings, [])

    def test_no_findings_when_shadow_missing(self):
        with patch("lsim.scanner.user_scanner.os.path.isfile", return_value=False):
            scanner = UserScanner()
            findings = scanner._check_empty_passwords()
        self.assertEqual(findings, [])


class TestSudoEntries(unittest.TestCase):
    def test_detects_nopasswd_all(self):
        sudoers_content = "alice ALL=(ALL) NOPASSWD:ALL\n"
        with patch("lsim.scanner.user_scanner.os.path.isfile", return_value=True), \
             patch("lsim.scanner.user_scanner.os.path.isdir", return_value=False), \
             patch("builtins.open", mock_open(read_data=sudoers_content)):
            scanner = UserScanner()
            findings = scanner._check_sudo_entries()

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, SEVERITY_HIGH)
        self.assertIn("NOPASSWD", findings[0].title)

    def test_ignores_commented_nopasswd(self):
        sudoers_content = "# alice ALL=(ALL) NOPASSWD:ALL\n"
        with patch("lsim.scanner.user_scanner.os.path.isfile", return_value=True), \
             patch("lsim.scanner.user_scanner.os.path.isdir", return_value=False), \
             patch("builtins.open", mock_open(read_data=sudoers_content)):
            scanner = UserScanner()
            findings = scanner._check_sudo_entries()
        self.assertEqual(findings, [])


class TestAuthLog(unittest.TestCase):
    def test_detects_repeated_failed_logins(self):
        # Generate 11 failed login attempts for 'attacker'
        log_lines = "\n".join(
            [f"Apr  1 12:00:{i:02d} host sshd[123]: Failed password for attacker from 1.2.3.4 port 22 ssh2"
             for i in range(11)]
        ) + "\n"

        with patch("lsim.scanner.user_scanner.os.path.isfile", return_value=True), \
             patch("builtins.open", mock_open(read_data=log_lines)):
            scanner = UserScanner()
            findings = scanner._check_auth_log()

        failed_findings = [f for f in findings if "failed" in f.title.lower()]
        self.assertTrue(len(failed_findings) >= 1)
        self.assertEqual(failed_findings[0].severity, SEVERITY_MEDIUM)

    def test_no_finding_for_few_failures(self):
        log_lines = (
            "Apr  1 12:00:01 host sshd[123]: Failed password for alice from 1.2.3.4 port 22 ssh2\n"
        )
        with patch("lsim.scanner.user_scanner.os.path.isfile", return_value=True), \
             patch("builtins.open", mock_open(read_data=log_lines)):
            scanner = UserScanner()
            findings = scanner._check_auth_log()

        failed_findings = [f for f in findings if "failed" in f.title.lower()]
        self.assertEqual(failed_findings, [])

    def test_detects_root_ssh_login(self):
        log_lines = (
            "Apr  1 12:00:01 host sshd[123]: Accepted publickey for root from 5.6.7.8 port 22 ssh2\n"
        )
        with patch("lsim.scanner.user_scanner.os.path.isfile", return_value=True), \
             patch("builtins.open", mock_open(read_data=log_lines)):
            scanner = UserScanner()
            findings = scanner._check_auth_log()

        root_findings = [f for f in findings if "root" in f.title.lower()]
        self.assertTrue(len(root_findings) >= 1)
        self.assertEqual(root_findings[0].severity, SEVERITY_HIGH)


if __name__ == "__main__":
    unittest.main()
