"""
Firewall Auditor — checks UFW / iptables configuration.
"""

import subprocess

from lsim.config import LOCKDOWN_CHAIN, SEVERITY_HIGH, SEVERITY_MEDIUM
from lsim.finding import Finding


def _run(cmd: list, timeout: int = 10) -> str:
    """Run a command and return combined stdout+stderr. Returns empty string on error."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
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

    # ------------------------------------------------------------------
    # UFW status
    # ------------------------------------------------------------------
    def _check_ufw_status(self) -> list:
        output = _run(["ufw", "status", "verbose"])
        if not output:
            return []

        if "inactive" in output.lower() or "Status: inactive" in output:
            return [Finding(
                category="Firewall",
                severity=SEVERITY_HIGH,
                title="UFW firewall is inactive",
                detail=(
                    "The Uncomplicated Firewall (UFW) is currently inactive. "
                    "No packet filtering rules are in effect."
                ),
                recommendation="Enable UFW: sudo ufw enable && sudo ufw default deny incoming",
            )]
        return []

    # ------------------------------------------------------------------
    # iptables default policies
    # ------------------------------------------------------------------
    def _check_iptables_defaults(self) -> list:
        output = _run(["iptables", "-L", "-n", "-v"])
        if not output:
            return []

        findings = []
        for line in output.splitlines():
            # Lines like: "Chain INPUT (policy ACCEPT 1234 packets, ...)"
            if line.startswith("Chain INPUT") and "policy ACCEPT" in line:
                findings.append(Finding(
                    category="Firewall",
                    severity=SEVERITY_HIGH,
                    title="iptables INPUT chain default policy is ACCEPT",
                    detail=(
                        "The iptables INPUT chain default policy is ACCEPT, meaning all "
                        "inbound traffic is allowed unless explicitly dropped by a rule.\n"
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
                        "The iptables FORWARD chain allows forwarding by default, "
                        "which may expose internal network hosts.\n"
                        f"  {line.strip()}"
                    ),
                    recommendation="Set: sudo iptables -P FORWARD DROP",
                ))
        return findings

    # ------------------------------------------------------------------
    # SSH exposure check
    # ------------------------------------------------------------------
    def _check_ssh_exposure(self) -> list:
        output = _run(["ufw", "status", "verbose"])
        if not output or "inactive" in output.lower():
            return []

        # Check if port 22 is allowed from anywhere with no rate limiting
        lines = output.splitlines()
        ssh_anywhere = False
        ssh_rate_limited = False
        for line in lines:
            lower = line.lower()
            if "22" in line and ("allow" in lower or "anywhere" in lower):
                ssh_anywhere = True
            if "22" in line and "limit" in lower:
                ssh_rate_limited = True

        if ssh_anywhere and not ssh_rate_limited:
            return [Finding(
                category="Firewall",
                severity=SEVERITY_MEDIUM,
                title="SSH (port 22) is exposed to the world without rate limiting",
                detail=(
                    "Port 22 (SSH) is open to all inbound connections without rate limiting. "
                    "This leaves the service vulnerable to brute-force attacks."
                ),
                recommendation=(
                    "Enable SSH rate limiting: sudo ufw limit ssh\n"
                    "Also consider key-only auth: set 'PasswordAuthentication no' in sshd_config"
                ),
            )]
        return []

    # ------------------------------------------------------------------
    # Stale LSIM_LOCKDOWN chain (lockdown partially applied)
    # ------------------------------------------------------------------
    def _check_stale_lockdown_chain(self) -> list:
        output = _run(["iptables", "-L", "-n"])
        if not output:
            return []

        chain_exists = LOCKDOWN_CHAIN in output

        # Check if it's referenced from INPUT
        referenced = False
        for line in output.splitlines():
            if LOCKDOWN_CHAIN in line and line.strip().startswith(LOCKDOWN_CHAIN) is False:
                referenced = True
                break

        if chain_exists and not referenced:
            return [Finding(
                category="Firewall",
                severity=SEVERITY_MEDIUM,
                title=f"Stale LSIM lockdown chain detected ({LOCKDOWN_CHAIN})",
                detail=(
                    f"The iptables chain '{LOCKDOWN_CHAIN}' exists but is not referenced "
                    "from INPUT/OUTPUT/FORWARD. This may be a leftover from a failed lockdown."
                ),
                recommendation=(
                    f"Clean up: sudo iptables -F {LOCKDOWN_CHAIN} && "
                    f"sudo iptables -X {LOCKDOWN_CHAIN}\n"
                    "Or re-run lockdown: sudo python3 lsim.py --lockdown"
                ),
            )]
        return []
