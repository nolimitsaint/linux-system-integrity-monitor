"""
Tests for lsim/auditor/ modules.

All subprocess calls are mocked — no live system commands.
"""

import subprocess
import unittest
from unittest.mock import MagicMock, patch

from lsim.auditor.firewall import FirewallAuditor
from lsim.auditor.permissions import PermissionsAuditor
from lsim.config import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM


def _mock_run(stdout="", stderr="", returncode=0):
    """Return a mock CompletedProcess result."""
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


class TestFirewallAuditor(unittest.TestCase):
    def test_detects_ufw_inactive(self):
        with patch("lsim.auditor.firewall.subprocess.run",
                   return_value=_mock_run(stdout="Status: inactive\n")):
            auditor = FirewallAuditor()
            findings = auditor._check_ufw_status()

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, SEVERITY_HIGH)
        self.assertIn("inactive", findings[0].title.lower())

    def test_no_finding_when_ufw_active(self):
        with patch("lsim.auditor.firewall.subprocess.run",
                   return_value=_mock_run(stdout="Status: active\nTo                         Action      From\n")):
            auditor = FirewallAuditor()
            findings = auditor._check_ufw_status()
        self.assertEqual(findings, [])

    def test_detects_iptables_accept_input_policy(self):
        iptables_output = (
            "Chain INPUT (policy ACCEPT 123 packets, 456 bytes)\n"
            "Chain FORWARD (policy DROP 0 packets, 0 bytes)\n"
            "Chain OUTPUT (policy ACCEPT 789 packets, 0 bytes)\n"
        )
        with patch("lsim.auditor.firewall.subprocess.run",
                   return_value=_mock_run(stdout=iptables_output)):
            auditor = FirewallAuditor()
            findings = auditor._check_iptables_defaults()

        input_findings = [f for f in findings if "INPUT" in f.title]
        self.assertEqual(len(input_findings), 1)
        self.assertEqual(input_findings[0].severity, SEVERITY_HIGH)

    def test_no_finding_when_iptables_drop_input(self):
        iptables_output = (
            "Chain INPUT (policy DROP 0 packets, 0 bytes)\n"
            "Chain FORWARD (policy DROP 0 packets, 0 bytes)\n"
            "Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)\n"
        )
        with patch("lsim.auditor.firewall.subprocess.run",
                   return_value=_mock_run(stdout=iptables_output)):
            auditor = FirewallAuditor()
            findings = auditor._check_iptables_defaults()
        self.assertEqual(findings, [])

    def test_detects_ssh_without_rate_limiting(self):
        ufw_output = (
            "Status: active\n"
            "22/tcp                     ALLOW IN    Anywhere\n"
            "22/tcp (v6)                ALLOW IN    Anywhere (v6)\n"
        )
        with patch("lsim.auditor.firewall.subprocess.run",
                   return_value=_mock_run(stdout=ufw_output)):
            auditor = FirewallAuditor()
            findings = auditor._check_ssh_exposure()

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, SEVERITY_MEDIUM)
        self.assertIn("22", findings[0].title)


class TestPermissionsAuditor(unittest.TestCase):
    def test_detects_unknown_suid_binary(self):
        find_output = "/usr/bin/sudo\n/usr/local/bin/mystery_suid\n"
        with patch("lsim.auditor.permissions.subprocess.run",
                   return_value=_mock_run(stdout=find_output)):
            auditor = PermissionsAuditor()
            findings = auditor._find_unexpected_suid()

        # /usr/bin/sudo is known; /usr/local/bin/mystery_suid is not
        unknown = [f for f in findings if "mystery_suid" in f.title]
        self.assertEqual(len(unknown), 1)
        self.assertEqual(unknown[0].severity, SEVERITY_CRITICAL)

    def test_no_finding_for_known_suid_only(self):
        find_output = "/usr/bin/sudo\n/usr/bin/su\n/usr/bin/passwd\n"
        with patch("lsim.auditor.permissions.subprocess.run",
                   return_value=_mock_run(stdout=find_output)):
            auditor = PermissionsAuditor()
            findings = auditor._find_unexpected_suid()
        self.assertEqual(findings, [])

    def test_detects_world_writable_critical_file(self):
        find_output = "/etc/passwd\n"
        with patch("lsim.auditor.permissions.os.path.isdir", return_value=True), \
             patch("lsim.auditor.permissions.subprocess.run",
                   return_value=_mock_run(stdout=find_output)):
            auditor = PermissionsAuditor()
            findings = auditor._find_world_writable_critical()

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, SEVERITY_CRITICAL)
        self.assertIn("/etc/passwd", findings[0].title)

if __name__ == "__main__":
    unittest.main()
