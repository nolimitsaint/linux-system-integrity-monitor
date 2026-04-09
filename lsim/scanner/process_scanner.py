"""
Process scanner - checks running processes for anything suspicious.
Uses psutil to read process info from /proc.
"""

import socket

from lsim.config import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SUSPICIOUS_PORTS,
    SUSPICIOUS_PROC_NAMES,
    SUSPICIOUS_PROC_PATHS,
)
from lsim.finding import Finding


class ProcessScanner:
    def scan(self) -> list:
        try:
            import psutil
        except ImportError:
            return [Finding(
                category="Process",
                severity="INFO",
                title="psutil not installed",
                detail="Process scanner requires psutil. Run: sudo pip3 install psutil",
                recommendation="Run: sudo bash setup.sh",
            )]

        findings = []
        findings += self._check_suspicious_names(psutil)
        findings += self._check_suspicious_paths(psutil)
        findings += self._check_priv_escalation(psutil)
        findings += self._check_unusual_listeners(psutil)
        findings += self._check_cpu_hog(psutil)
        return findings

    def _check_suspicious_names(self, psutil) -> list:
        """Flag processes whose name matches a known hacking/malware tool."""
        findings = []
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                info = proc.info
                name = (info.get("name") or "").lower()
                if name in SUSPICIOUS_PROC_NAMES:
                    findings.append(Finding(
                        category="Process",
                        severity=SEVERITY_HIGH,
                        title=f"Suspicious process name: {info['name']}",
                        detail=(
                            f"PID {info['pid']} has a suspicious process name '{info['name']}'.\n"
                            f"  Executable: {info.get('exe') or 'unknown'}\n"
                            f"  Command: {' '.join(info.get('cmdline') or [])}"
                        ),
                        recommendation=f"Investigate PID {info['pid']} and terminate if unauthorized.",
                        pid=info["pid"],
                        auto_remediate=False,
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return findings

    def _check_suspicious_paths(self, psutil) -> list:
        """Flag processes running from world-writable directories like /tmp."""
        findings = []
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                exe = proc.info.get("exe") or ""
                for sus_path in SUSPICIOUS_PROC_PATHS:
                    if exe.startswith(sus_path):
                        findings.append(Finding(
                            category="Process",
                            severity=SEVERITY_CRITICAL,
                            title=f"Process running from suspicious path: {exe}",
                            detail=(
                                f"PID {proc.info['pid']} ({proc.info['name']}) is executing "
                                f"from {exe}, which is a world-writable directory."
                            ),
                            recommendation=(
                                f"Terminate PID {proc.info['pid']} and check how the binary "
                                f"ended up in {sus_path}."
                            ),
                            pid=proc.info["pid"],
                            auto_remediate=True,
                        ))
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return findings

    def _check_priv_escalation(self, psutil) -> list:
        """Flag processes where effective UID is 0 but real UID is not (SUID abuse)."""
        findings = []
        for proc in psutil.process_iter(["pid", "name", "exe", "uids"]):
            try:
                uids = proc.info.get("uids")
                if uids is None:
                    continue
                real_uid, effective_uid = uids.real, uids.effective
                if effective_uid == 0 and real_uid != 0:
                    findings.append(Finding(
                        category="Process",
                        severity=SEVERITY_CRITICAL,
                        title=f"Privilege escalation detected: PID {proc.info['pid']}",
                        detail=(
                            f"PID {proc.info['pid']} ({proc.info['name']}) has effective UID 0 "
                            f"but real UID {real_uid}. This could mean SUID abuse or privilege escalation.\n"
                            f"  Executable: {proc.info.get('exe') or 'unknown'}"
                        ),
                        recommendation=f"Verify PID {proc.info['pid']} is a known SUID binary.",
                        pid=proc.info["pid"],
                        auto_remediate=False,
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return findings

    def _check_unusual_listeners(self, psutil) -> list:
        """Flag processes listening on ports associated with attack tools."""
        findings = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status != "LISTEN":
                    continue
                port = conn.laddr.port if conn.laddr else None
                if port in SUSPICIOUS_PORTS:
                    pid = conn.pid
                    name = "unknown"
                    exe = "unknown"
                    try:
                        if pid:
                            p = psutil.Process(pid)
                            name = p.name()
                            exe = p.exe()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    findings.append(Finding(
                        category="Process",
                        severity=SEVERITY_HIGH,
                        title=f"Process listening on suspicious port {port}",
                        detail=(
                            f"Port {port} ({SUSPICIOUS_PORTS[port]}) is open.\n"
                            f"  PID: {pid}  Process: {name}  Executable: {exe}"
                        ),
                        recommendation=f"Investigate port {port} and kill the process if unauthorized.",
                        pid=pid,
                        auto_remediate=False,
                    ))
        except (psutil.AccessDenied, PermissionError):
            pass
        return findings

    def _check_cpu_hog(self, psutil) -> list:
        """Flag non-system processes using >90% CPU with no terminal (possible miner)."""
        findings = []
        for proc in psutil.process_iter(["pid", "name", "exe", "terminal"]):
            try:
                if proc.info.get("terminal") is not None:
                    continue
                uids = proc.uids()
                if uids.real == 0:
                    continue
                cpu = proc.cpu_percent(interval=None)
                if cpu > 90.0:
                    findings.append(Finding(
                        category="Process",
                        severity=SEVERITY_MEDIUM,
                        title=f"High CPU usage by non-system process: PID {proc.info['pid']}",
                        detail=(
                            f"PID {proc.info['pid']} ({proc.info['name']}) is using {cpu:.1f}% CPU "
                            "with no controlling terminal. Could be a cryptominer.\n"
                            f"  Executable: {proc.info.get('exe') or 'unknown'}"
                        ),
                        recommendation=f"Investigate PID {proc.info['pid']} for unauthorized CPU usage.",
                        pid=proc.info["pid"],
                        auto_remediate=False,
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return findings
