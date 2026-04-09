"""
Firewall auditor - checks UFW and iptables configuration.
"""

import subprocess

from lsim.config import LOCKDOWN_CHAIN, SEVERITY_HIGH, SEVERITY_MEDIUM
from lsim.finding import Finding


def _run(cmd: list, timeout: int = 10) -> str:
    """Run a shell command and return stdout+stderr, or empty string on failure."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout + result.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return ""


class FirewallAuditor:
    def audit(self) -> list:
        findings = []
        findings += self._check_ufw_status()
        findings += self._check_iptables_defaults()
        findings += self._check_ssh_exposure()
        findings += self._check_stale_lockdown_chain()
        return findings

    def _check_ufw_status(self) -> list:
        output = _run(["ufw", "status", "verbose"])
        if not output:
            return []
        if "inactive" in output.lower():
            return [Finding(
                category="Firewall",
                severity=SEVERITY_HIGH,
                title="UFW firewall is inactive",
                detail="UFW is not running. No packet filtering rules are in effect.",
                recommendation="Enable UFW: sudo ufw enable && sudo ufw default deny incoming",
            )]
        return []

    def _check_iptables_defaults(self) -> list:
        output = _run(["iptables", "-L", "-n", "-v"])
        if not output:
            return []

        findings = []
        for line in output.splitlines():
            if line.startswith("Chain INPUT") and "policy ACCEPT" in line:
                findings.append(Finding(
                    category="Firewall",
                    severity=SEVERITY_HIGH,
                    title="iptables INPUT chain default policy is ACCEPT",
                    detail=(
                        "The default INPUT policy is ACCEPT, so all inbound traffic "
                        "is allowed unless a rule explicitly drops it.\n"
                        f"  {line.strip()}"
                    ),
                    recommendation=(
                        "Set a restrictive default: sudo iptables -P INPUT DROP && "
                        "sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"
                    ),
                ))
            if line.startswith("Chain FORWARD") and "policy ACCEPT" in line:
                findings.append(Finding(
                    category="Firewall",
                    severity=SEVERITY_HIGH,
                    title="iptables FORWARD chain default policy is ACCEPT",
                    detail=(
                        "The FORWARD chain is set to ACCEPT, which could expose "
                        "internal hosts if this machine is used as a router.\n"
                        f"  {line.strip()}"
                    ),
                    recommendation="Set: sudo iptables -P FORWARD DROP",
                ))
        return findings

    def _check_ssh_exposure(self) -> list:
        output = _run(["ufw", "status", "verbose"])
        if not output or "inactive" in output.lower():
            return []

        ssh_open = False
        rate_limited = False
        for line in output.splitlines():
            lower = line.lower()
            if "22" in line and ("allow" in lower or "anywhere" in lower):
                ssh_open = True
            if "22" in line and "limit" in lower:
                rate_limited = True

        if ssh_open and not rate_limited:
            return [Finding(
                category="Firewall",
                severity=SEVERITY_MEDIUM,
                title="SSH (port 22) is exposed without rate limiting",
                detail=(
                    "Port 22 is open to everyone with no rate limit, "
                    "making it an easy target for brute-force attacks."
                ),
                recommendation=(
                    "Enable rate limiting: sudo ufw limit ssh\n"
                    "Also consider disabling password auth: set 'PasswordAuthentication no' in sshd_config"
                ),
            )]
        return []

    def _check_stale_lockdown_chain(self) -> list:
        output = _run(["iptables", "-L", "-n"])
        if not output:
            return []

        chain_exists = LOCKDOWN_CHAIN in output

        # Check if INPUT actually references the chain
        referenced = False
        for line in output.splitlines():
            if LOCKDOWN_CHAIN in line and not line.strip().startswith(LOCKDOWN_CHAIN):
                referenced = True
                break

        if chain_exists and not referenced:
            return [Finding(
                category="Firewall",
                severity=SEVERITY_MEDIUM,
                title=f"Stale LSIM lockdown chain detected ({LOCKDOWN_CHAIN})",
                detail=(
                    f"The iptables chain '{LOCKDOWN_CHAIN}' exists but isn't referenced "
                    "by INPUT. Probably a leftover from a failed or interrupted lockdown."
                ),
                recommendation=(
                    f"Clean it up: sudo iptables -F {LOCKDOWN_CHAIN} && "
                    f"sudo iptables -X {LOCKDOWN_CHAIN}"
                ),
            )]
        return []
