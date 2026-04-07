"""
LSIM Structured Logger.

Two outputs:
  1. Human-readable: /var/log/lsim/lsim.log (RotatingFileHandler)
  2. Machine-readable: /var/log/lsim/lsim_events.jsonl (JSON Lines)
"""

import json
import logging
import logging.handlers
import os
import socket
from datetime import datetime, timezone

from lsim.config import LOG_DIR, LOG_FILE, LOG_FILE_JSONL

_logger_configured = False


def get_logger() -> logging.Logger:
    """Return the configured 'lsim' logger, initializing it on first call."""
    global _logger_configured
    log = logging.getLogger("lsim")

    if _logger_configured:
        return log

    log.setLevel(logging.DEBUG)

    os.makedirs(LOG_DIR, exist_ok=True)

    # Human-readable rotating log
    try:
        fh = logging.handlers.RotatingFileHandler(
            LOG_FILE,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            fmt="[%(asctime)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        ))
        log.addHandler(fh)
    except (PermissionError, OSError):
        # Running without write access to log dir (e.g. in tests)
        pass

    _logger_configured = True
    return log


def _jsonl_append(record: dict):
    """Append a JSON-Lines record to the machine log."""
    os.makedirs(LOG_DIR, exist_ok=True)
    try:
        with open(LOG_FILE_JSONL, "a") as fh:
            fh.write(json.dumps(record) + "\n")
    except (PermissionError, OSError):
        pass


class LSIMLogger:
    def __init__(self):
        self._log = get_logger()
        self._hostname = socket.gethostname()

    def log_scan_result(self, state: str, findings: list, actions_taken: list):
        """Write a full scan result to both log files."""
        ts = datetime.now(timezone.utc).isoformat()
        summary = (
            f"Scan complete — state={state}  findings={len(findings)}  "
            f"actions={len(actions_taken)}"
        )
        self._log.info(summary)

        record = {
            "timestamp": ts,
            "event_type": "scan_result",
            "state": state,
            "hostname": self._hostname,
            "findings": [f.to_dict() for f in findings],
            "actions_taken": actions_taken,
        }
        _jsonl_append(record)

    def log_action(self, action: str, target: str, reason: str, success: bool):
        """Log a specific automated response action."""
        ts = datetime.now(timezone.utc).isoformat()
        status = "SUCCESS" if success else "FAILED"
        self._log.info("Action %s: %s on '%s' — %s", status, action, target, reason)

        record = {
            "timestamp": ts,
            "event_type": "action",
            "action": action,
            "target": target,
            "reason": reason,
            "success": success,
            "hostname": self._hostname,
        }
        _jsonl_append(record)

    def log_lockdown(self, activated: bool, reason: str):
        """Log lockdown activation or deactivation."""
        ts = datetime.now(timezone.utc).isoformat()
        verb = "ACTIVATED" if activated else "DEACTIVATED"
        self._log.warning("Lockdown %s: %s", verb, reason)

        record = {
            "timestamp": ts,
            "event_type": "lockdown",
            "activated": activated,
            "reason": reason,
            "hostname": self._hostname,
        }
        _jsonl_append(record)
