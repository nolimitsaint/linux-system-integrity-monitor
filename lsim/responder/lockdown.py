# Network lockdown using iptables.
# Creates a custom chain that blocks all new connections while keeping
# existing SSH sessions alive (using the ESTABLISHED/RELATED match).

import json
import logging
import os
import subprocess
from datetime import datetime, timezone

from lsim.config import LOCKDOWN_CHAIN, LOCKDOWN_STATE_FILE

logger = logging.getLogger("lsim")


def _ipt(args: list, ignore_errors: bool = False) -> bool:
    """Run an iptables command. Returns True on success."""
    cmd = ["iptables"] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode != 0 and not ignore_errors:
            logger.error("iptables %s failed: %s", " ".join(args), result.stderr.strip())
            return False
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.error("iptables command error: %s", exc)
        return False


class LockdownManager:
    def activate_lockdown(self, admin_user: str = "root", reason: str = "Threat detected") -> bool:
        """Block all new network connections via iptables."""
        if self.is_locked_down():
            logger.info("Already in lockdown, skipping")
            return True

        logger.info("Activating lockdown — %s", reason)

        # Create the chain (ignore error if it already exists)
        _ipt(["-N", LOCKDOWN_CHAIN], ignore_errors=True)
        _ipt(["-F", LOCKDOWN_CHAIN], ignore_errors=True)

        # Allow existing connections first so we don't lose our SSH session
        ok = _ipt(["-A", LOCKDOWN_CHAIN, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        if not ok:
            return False

        # Drop everything else
        ok = _ipt(["-A", LOCKDOWN_CHAIN, "-j", "DROP"])
        if not ok:
            return False

        # Hook the chain into INPUT at position 1 so it runs before other rules
        ok = _ipt(["-I", "INPUT", "1", "-j", LOCKDOWN_CHAIN])
        if not ok:
            return False

        self._write_state(reason)
        logger.info("Lockdown activated")
        return True

    def deactivate_lockdown(self) -> bool:
        """Remove the lockdown chain and restore normal network access."""
        if not self.is_locked_down():
            logger.warning("No lockdown state file found")

        logger.info("Deactivating lockdown")

        _ipt(["-D", "INPUT", "-j", LOCKDOWN_CHAIN], ignore_errors=True)
        _ipt(["-F", LOCKDOWN_CHAIN], ignore_errors=True)
        _ipt(["-X", LOCKDOWN_CHAIN], ignore_errors=True)

        try:
            if os.path.isfile(LOCKDOWN_STATE_FILE):
                os.remove(LOCKDOWN_STATE_FILE)
        except OSError as exc:
            logger.error("Could not remove state file: %s", exc)
            return False

        logger.info("Lockdown deactivated")
        return True

    def is_locked_down(self) -> bool:
        return os.path.isfile(LOCKDOWN_STATE_FILE)

    def get_lockdown_info(self) -> dict:
        if not self.is_locked_down():
            return {}
        try:
            with open(LOCKDOWN_STATE_FILE) as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            return {}

    def _write_state(self, reason: str, findings_count: int = 0):
        state = {
            "locked_at": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "findings_count": findings_count,
        }
        os.makedirs(os.path.dirname(LOCKDOWN_STATE_FILE), exist_ok=True)
        with open(LOCKDOWN_STATE_FILE, "w") as fh:
            json.dump(state, fh, indent=2)
