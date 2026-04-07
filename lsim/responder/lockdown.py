"""
Lockdown Manager — full network lockdown via iptables.

Lockdown sequence (order is critical — preserve established connections first):
  1. Create LSIM_LOCKDOWN chain (idempotent)
  2. Allow ESTABLISHED/RELATED (keeps admin SSH alive)
  3. Drop everything else in the chain
  4. Jump into the chain from INPUT
  5. Write state file

Unlock:
  1. Remove INPUT jump
  2. Flush chain
  3. Delete chain
  4. Remove state file
"""

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
        """
        Apply iptables rules to block all network traffic except established
        connections (to preserve the admin SSH session).
        """
        if self.is_locked_down():
            logger.info("LockdownManager: already in lockdown — skipping activation")
            return True

        logger.info("LockdownManager: activating lockdown — reason: %s", reason)

        # Step 1: Create chain (idempotent — ignore "already exists")
        _ipt(["-N", LOCKDOWN_CHAIN], ignore_errors=True)

        # Step 2: Flush the chain in case it has stale rules
        _ipt(["-F", LOCKDOWN_CHAIN], ignore_errors=True)

        # Step 3: Allow established/related (CRITICAL — do this first to preserve SSH)
        ok = _ipt([
            "-A", LOCKDOWN_CHAIN,
            "-m", "state",
            "--state", "ESTABLISHED,RELATED",
            "-j", "ACCEPT",
        ])
        if not ok:
            return False

        # Step 4: Drop everything else entering the chain
        ok = _ipt(["-A", LOCKDOWN_CHAIN, "-j", "DROP"])
        if not ok:
            return False

        # Step 5: Insert the chain into INPUT at position 1
        ok = _ipt(["-I", "INPUT", "1", "-j", LOCKDOWN_CHAIN])
        if not ok:
            return False

        # Step 6: Write the state file
        self._write_state(reason)
        logger.info("LockdownManager: lockdown activated successfully")
        return True

    def deactivate_lockdown(self) -> bool:
        """Remove LSIM_LOCKDOWN chain and restore normal network operation."""
        if not self.is_locked_down():
            logger.warning("LockdownManager: no lockdown state file found — nothing to deactivate")

        logger.info("LockdownManager: deactivating lockdown")

        # Remove the jump from INPUT (may not exist if state file is stale)
        _ipt(["-D", "INPUT", "-j", LOCKDOWN_CHAIN], ignore_errors=True)

        # Flush and delete the chain
        _ipt(["-F", LOCKDOWN_CHAIN], ignore_errors=True)
        _ipt(["-X", LOCKDOWN_CHAIN], ignore_errors=True)

        # Remove state file
        try:
            if os.path.isfile(LOCKDOWN_STATE_FILE):
                os.remove(LOCKDOWN_STATE_FILE)
        except OSError as exc:
            logger.error("LockdownManager: could not remove state file: %s", exc)
            return False

        logger.info("LockdownManager: lockdown deactivated")
        return True

    def is_locked_down(self) -> bool:
        """Return True if a lockdown state file exists."""
        return os.path.isfile(LOCKDOWN_STATE_FILE)

    def get_lockdown_info(self) -> dict:
        """Return the lockdown state dict, or empty dict if not locked down."""
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
        parent = os.path.dirname(LOCKDOWN_STATE_FILE)
        os.makedirs(parent, exist_ok=True)
        with open(LOCKDOWN_STATE_FILE, "w") as fh:
            json.dump(state, fh, indent=2)
