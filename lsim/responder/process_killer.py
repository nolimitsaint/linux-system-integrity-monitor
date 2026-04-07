"""
Process Killer — terminates confirmed malicious processes.

Safety invariants (never bypass):
  - Never kill PID < 100
  - Never kill PID 1 (init/systemd)
  - Never kill os.getpid() (self)
  - Log intended action BEFORE sending signal
"""

import logging
import os
import signal
import time

logger = logging.getLogger("lsim")

_SAFE_KILL_MIN_PID = 100
_SIGTERM_WAIT_SECONDS = 3


class ProcessKiller:
    def __init__(self):
        self._self_pid = os.getpid()

    def kill_process(self, pid: int, reason: str) -> bool:
        """
        Gracefully terminate PID (SIGTERM), wait 3 seconds, then SIGKILL if needed.
        Returns True if the process was successfully killed.
        """
        if not self._is_safe_to_kill(pid):
            logger.warning("ProcessKiller: refused to kill PID %d (%s) — safety check failed", pid, reason)
            return False

        try:
            import psutil
        except ImportError:
            logger.error("ProcessKiller: psutil not available")
            return False

        logger.info("ProcessKiller: sending SIGTERM to PID %d — reason: %s", pid, reason)

        try:
            proc = psutil.Process(pid)
        except psutil.NoSuchProcess:
            logger.info("ProcessKiller: PID %d no longer exists", pid)
            return True  # Already gone — counts as success

        try:
            proc.send_signal(signal.SIGTERM)
            time.sleep(_SIGTERM_WAIT_SECONDS)

            if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
                logger.info("ProcessKiller: PID %d still alive, sending SIGKILL", pid)
                proc.send_signal(signal.SIGKILL)
                time.sleep(0.5)

            if not proc.is_running() or proc.status() == psutil.STATUS_ZOMBIE:
                logger.info("ProcessKiller: PID %d successfully killed", pid)
                return True
            else:
                logger.warning("ProcessKiller: PID %d could not be killed", pid)
                return False

        except psutil.NoSuchProcess:
            logger.info("ProcessKiller: PID %d exited during kill attempt", pid)
            return True
        except psutil.AccessDenied:
            logger.error("ProcessKiller: access denied killing PID %d", pid)
            return False
        except Exception as exc:
            logger.error("ProcessKiller: unexpected error killing PID %d: %s", pid, exc)
            return False

    def kill_processes(self, pids: list, reason: str) -> dict:
        """Kill multiple PIDs. Returns {pid: success_bool}."""
        return {pid: self.kill_process(pid, reason) for pid in pids}

    def _is_safe_to_kill(self, pid: int) -> bool:
        if pid < _SAFE_KILL_MIN_PID:
            return False
        if pid == 1:
            return False
        if pid == self._self_pid:
            return False
        return True
