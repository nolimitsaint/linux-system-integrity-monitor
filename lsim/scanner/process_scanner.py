"""
Process Scanner — detects malicious or suspicious running processes.
Uses psutil for all process inspection.
"""

import os
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
        findings += self._check_hidden_procs(psutil)
        findings += self._check_priv_escalation(psutil)
        findings += self._check_unusual_listeners(psutil)
        findings += self._check_ld_preload(psutil)
        findings += self._check_deleted_exec(psutil)
        findings += self._check_cpu_hog(psutil)
        return findings

    # ------------------------------------------------------------------
    # Heuristic: suspicious process name
    # ------------------------------------------------------------------
    def _check_suspicious_names(self, psutil) -> list:
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
                            f"PID {info['pid']} has a known-suspicious process name '{info['name']}'.\n"
                            f"  Executable: {info.get('exe') or 'unknown'}\n"
                            f"  Command: {' '.join(info.get('cmdline') or [])}"
                        ),
                        recommendation=f"Investigate PID {info['pid']} ({info['name']}) and terminate if unauthorized.",
                        pid=info["pid"],
                        auto_remediate=False,
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return findings

    # ------------------------------------------------------------------
    # Heuristic: process running from suspicious path
    # ------------------------------------------------------------------
    def _check_suspicious_paths(self, psutil) -> list:
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
                                f"from {exe}, which is a world-writable or temp directory."
                            ),
                            recommendation=(
                                f"Terminate PID {proc.info['pid']} immediately and investigate "
                                f"how the binary ended up in {sus_path}."
                            ),
                            pid=proc.info["pid"],
                            auto_remediate=True,
                        ))
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return findings

    # ------------------------------------------------------------------
    # Heuristic: hidden processes (in /proc but absent from psutil.pids())
    # ------------------------------------------------------------------
    def _check_hidden_procs(self, psutil) -> list:
        findings = []
        try:
            known_pids = set(psutil.pids())
            proc_pids = set()
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    proc_pids.add(int(entry))

            hidden = proc_pids - known_pids
            for pid in hidden:
                findings.append(Finding(
                    category="Process",
                    severity=SEVERITY_CRITICAL,
                    title=f"Hidden process detected: PID {pid}",
                    detail=(
                        f"PID {pid} exists in /proc but is not visible via normal process APIs. "
                        "This may indicate a rootkit or kernel-level process hiding."
                    ),
                    recommendation="Investigate with 'ls -la /proc/{pid}'. Consider booting into recovery mode.",
                    pid=pid,
                    auto_remediate=False,
                ))
        except PermissionError:
            pass
        return findings

    # ------------------------------------------------------------------
    # Heuristic: privilege escalation (euid=0 but ruid != 0)
    # ------------------------------------------------------------------
    def _check_priv_escalation(self, psutil) -> list:
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
                            f"but real UID {real_uid}. This indicates SUID execution or privilege escalation.\n"
                            f"  Executable: {proc.info.get('exe') or 'unknown'}"
                        ),
                        recommendation=f"Verify that PID {proc.info['pid']} is a known SUID binary.",
                        pid=proc.info["pid"],
                        auto_remediate=False,
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return findings

    # ------------------------------------------------------------------
    # Heuristic: unusual listener on suspicious port
    # ------------------------------------------------------------------
    def _check_unusual_listeners(self, psutil) -> list:
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
                            f"Port {port} ({SUSPICIOUS_PORTS[port]}) is open and being listened on.\n"
                            f"  PID: {pid}  Process: {name}  Executable: {exe}"
                        ),
                        recommendation=f"Investigate why port {port} is open and kill the process if unauthorized.",
                        pid=pid,
                        auto_remediate=False,
                    ))
        except (psutil.AccessDenied, PermissionError):
            pass
        return findings

    # ------------------------------------------------------------------
    # Heuristic: LD_PRELOAD injection
    # ------------------------------------------------------------------
    def _check_ld_preload(self, psutil) -> list:
        findings = []
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                env = proc.environ()
                if "LD_PRELOAD" in env:
                    findings.append(Finding(
                        category="Process",
                        severity=SEVERITY_HIGH,
                        title=f"LD_PRELOAD detected in process environment: PID {proc.info['pid']}",
                        detail=(
                            f"PID {proc.info['pid']} ({proc.info['name']}) has LD_PRELOAD set:\n"
                            f"  LD_PRELOAD={env['LD_PRELOAD']}\n"
                            f"  Executable: {proc.info.get('exe') or 'unknown'}"
                        ),
                        recommendation="LD_PRELOAD can be used to hijack library calls. Investigate this process.",
                        pid=proc.info["pid"],
                        auto_remediate=False,
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return findings

    # ------------------------------------------------------------------
    # Heuristic: deleted executable (process running from deleted binary)
    # ------------------------------------------------------------------
    def _check_deleted_exec(self, psutil) -> list:
        findings = []
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                exe_link = f"/proc/{proc.info['pid']}/exe"
                if not os.path.lexists(exe_link):
                    continue
                try:
                    target = os.readlink(exe_link)
                except OSError:
                    continue
                if "(deleted)" in target:
                    findings.append(Finding(
                        category="Process",
                        severity=SEVERITY_HIGH,
                        title=f"Process running from deleted executable: PID {proc.info['pid']}",
                        detail=(
                            f"PID {proc.info['pid']} ({proc.info['name']}) is running from a "
                            f"deleted binary: {target}\n"
                            "This is a common technique used by malware to hide on disk."
                        ),
                        recommendation=f"Investigate and terminate PID {proc.info['pid']}.",
                        pid=proc.info["pid"],
                        auto_remediate=True,
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return findings

    # ------------------------------------------------------------------
    # Heuristic: CPU hog (potential cryptominer) — sampled, run last
    # ------------------------------------------------------------------
    def _check_cpu_hog(self, psutil) -> list:
        findings = []
        for proc in psutil.process_iter(["pid", "name", "exe", "terminal"]):
            try:
                # Skip kernel threads and system processes (uid 0 with known paths)
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
                            f"PID {proc.info['pid']} ({proc.info['name']}) is consuming {cpu:.1f}% CPU "
                            "with no controlling terminal. This may indicate a cryptominer.\n"
                            f"  Executable: {proc.info.get('exe') or 'unknown'}"
                        ),
                        recommendation=f"Investigate PID {proc.info['pid']} for unauthorized CPU usage.",
                        pid=proc.info["pid"],
                        auto_remediate=False,
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return findings
