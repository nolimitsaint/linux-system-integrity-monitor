"""
Network scanner - checks active network connections for anything suspicious.
"""

from collections import Counter

from lsim.config import (
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SUSPICIOUS_PORTS,
)
from lsim.finding import Finding

# Ports that are expected to listen on all interfaces for normal services
_WELL_KNOWN_PORTS = {22, 80, 443, 25, 587, 465, 143, 993, 110, 995, 53, 123}


class NetworkScanner:
    def scan(self) -> list:
        try:
            import psutil
        except ImportError:
            return [Finding(
                category="Network",
                severity="INFO",
                title="psutil not installed",
                detail="Network scanner requires psutil. Run: sudo pip3 install psutil",
                recommendation="Run: sudo bash setup.sh",
            )]

        try:
            connections = psutil.net_connections(kind="all")
        except psutil.AccessDenied:
            return [Finding(
                category="Network",
                severity="INFO",
                title="Cannot read network connections (permission denied)",
                detail="Run LSIM as root to inspect all network connections.",
                recommendation="Run: sudo python3 lsim.py --scan",
            )]

        findings = []
        findings += self._check_suspicious_ports(connections, psutil)
        findings += self._check_unexpected_listeners(connections)
        findings += self._check_connection_floods(connections)
        return findings

    def _check_suspicious_ports(self, connections, psutil) -> list:
        """Flag connections to/from ports known to be used by attack tools."""
        findings = []
        seen = set()
        for conn in connections:
            lport = conn.laddr.port if conn.laddr and hasattr(conn.laddr, "port") else None
            rport = conn.raddr.port if conn.raddr and hasattr(conn.raddr, "port") else None
            for port in (lport, rport):
                if port in SUSPICIOUS_PORTS and (conn.pid, port) not in seen:
                    seen.add((conn.pid, port))
                    name = "unknown"
                    exe = "unknown"
                    try:
                        if conn.pid:
                            import psutil as _psutil
                            p = _psutil.Process(conn.pid)
                            name = p.name()
                            exe = p.exe()
                    except Exception:
                        pass
                    findings.append(Finding(
                        category="Network",
                        severity=SEVERITY_HIGH,
                        title=f"Connection on suspicious port {port}: {SUSPICIOUS_PORTS[port]}",
                        detail=(
                            f"Port {port} ({SUSPICIOUS_PORTS[port]}) is active.\n"
                            f"  PID: {conn.pid}  Process: {name}  Executable: {exe}\n"
                            f"  Local: {conn.laddr}  Remote: {conn.raddr}  Status: {conn.status}"
                        ),
                        recommendation=(
                            f"Investigate port {port}. Commonly associated with {SUSPICIOUS_PORTS[port]}."
                        ),
                        pid=conn.pid,
                        auto_remediate=False,
                    ))
        return findings

    def _check_unexpected_listeners(self, connections) -> list:
        """Flag services listening on 0.0.0.0 that aren't in the well-known port list."""
        findings = []
        for conn in connections:
            if conn.status != "LISTEN":
                continue
            laddr = conn.laddr
            if not laddr:
                continue
            if laddr.ip not in ("0.0.0.0", "::"):
                continue
            port = laddr.port
            if port in _WELL_KNOWN_PORTS:
                continue
            if port in SUSPICIOUS_PORTS:
                continue  # already reported above
            findings.append(Finding(
                category="Network",
                severity=SEVERITY_MEDIUM,
                title=f"Unexpected service listening on 0.0.0.0:{port}",
                detail=(
                    f"Port {port} is listening on all interfaces. "
                    f"PID: {conn.pid}. This service is publicly reachable."
                ),
                recommendation=(
                    f"Verify port {port} should be publicly accessible. "
                    "If not, restrict it: sudo ufw deny {port}"
                ),
                pid=conn.pid,
                auto_remediate=False,
            ))
        return findings

    def _check_connection_floods(self, connections) -> list:
        """Flag a single remote IP with more than 20 established connections."""
        findings = []
        counts: Counter = Counter()
        for conn in connections:
            if conn.status == "ESTABLISHED" and conn.raddr and hasattr(conn.raddr, "ip"):
                counts[conn.raddr.ip] += 1

        for ip, count in counts.items():
            if count > 20:
                findings.append(Finding(
                    category="Network",
                    severity=SEVERITY_MEDIUM,
                    title=f"Connection flood from {ip} ({count} connections)",
                    detail=(
                        f"{ip} has {count} established connections to this host. "
                        "Could be a DoS attempt, port scan, or data exfiltration."
                    ),
                    recommendation=(
                        f"Review connections from {ip}. "
                        f"Block if needed: sudo ufw deny from {ip}"
                    ),
                    auto_remediate=False,
                ))
        return findings
