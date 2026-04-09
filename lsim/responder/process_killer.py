# Kills a process cleanly: SIGTERM first, then SIGKILL if it's still alive.
# Won't touch PID 1, PIDs below 100, or our own process.

import logging
import os
import signal
import time

logger = logging.getLogger("lsim")

_MIN_PID = 100
_SIGTERM_WAIT = 3


class ProcessKiller:
    def __init__(self):
        self._self_pid = os.getpid()

    def kill_process(self, pid: int, reason: str) -> bool:
        """Send SIGTERM, wait 3 seconds, then SIGKILL if needed. Returns True if killed."""
        if not self._safe_to_kill(pid):
            logger.warning("Refused to kill PID %d (%s) — failed safety check", pid, reason)
            return False

        try:
            import psutil
        except ImportError:
            logger.error("psutil not available, can't kill process")
            return False

        logger.info("Sending SIGTERM to PID %d — %s", pid, reason)

        try:
            proc = psutil.Process(pid)
        except psutil.NoSuchProcess:
            logger.info("PID %d already gone", pid)
            return True

        try:
            proc.send_signal(signal.SIGTERM)
            time.sleep(_SIGTERM_WAIT)

            if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
                logger.info("PID %d still alive, sending SIGKILL", pid)
                proc.send_signal(signal.SIGKILL)
                time.sleep(0.5)

            if not proc.is_running() or proc.status() == psutil.STATUS_ZOMBIE:
                logger.info("PID %d killed successfully", pid)
                return True
            else:
                logger.warning("PID %d could not be killed", pid)
                return False

        except psutil.NoSuchProcess:
            logger.info("PID %d exited during kill attempt", pid)
            return True
        except psutil.AccessDenied:
            logger.error("Access denied killing PID %d", pid)
            return False
        except Exception as exc:
            logger.error("Unexpected error killing PID %d: %s", pid, exc)
            return False

    def kill_processes(self, pids: list, reason: str) -> dict:
        """Kill a list of PIDs. Returns {pid: True/False}."""
        return {pid: self.kill_process(pid, reason) for pid in pids}

    def _safe_to_kill(self, pid: int) -> bool:
        if pid < _MIN_PID:
            return False
        if pid == 1:
            return False
        if pid == self._self_pid:
            return False
        return True
