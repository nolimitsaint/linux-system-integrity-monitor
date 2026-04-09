# Locks compromised user accounts by locking the password and expiring the account.
# Never touches root or the user who ran sudo.

import logging
import os
import pwd
import subprocess

from lsim.config import ADMIN_USER

logger = logging.getLogger("lsim")


class UserDisabler:
    def __init__(self):
        # Build a set of accounts we'll never disable
        self._protected = {"root", ADMIN_USER}
        sudo_user = os.environ.get("SUDO_USER", "")
        if sudo_user:
            self._protected.add(sudo_user)

    def disable_user(self, username: str, reason: str) -> bool:
        """Lock the account and expire it immediately. Returns True on success."""
        if not self._safe_to_disable(username):
            logger.warning("Refused to disable '%s' — protected account", username)
            return False

        if not self._user_exists(username):
            logger.warning("User '%s' does not exist", username)
            return False

        logger.info("Disabling user '%s' — %s", username, reason)

        success = True

        # Lock the password so they can't log in
        try:
            result = subprocess.run(
                ["passwd", "--lock", username],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                logger.error("passwd --lock failed for '%s': %s", username, result.stderr.strip())
                success = False
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            logger.error("passwd command error for '%s': %s", username, exc)
            success = False

        # Set expiry date to Jan 2 1970 (basically immediately expired)
        try:
            result = subprocess.run(
                ["usermod", "--expiredate", "1", username],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                logger.error("usermod --expiredate failed for '%s': %s", username, result.stderr.strip())
                success = False
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            logger.error("usermod command error for '%s': %s", username, exc)
            success = False

        return success

    def kill_user_sessions(self, username: str) -> bool:
        """Kill all processes owned by the user."""
        if not self._safe_to_disable(username):
            logger.warning("Refused to kill sessions for '%s' — protected account", username)
            return False

        logger.info("Killing all sessions for '%s'", username)
        try:
            result = subprocess.run(
                ["pkill", "-KILL", "-u", username],
                capture_output=True, text=True, timeout=10,
            )
            # pkill exits 1 if no processes found, that's fine
            if result.returncode in (0, 1):
                return True
            logger.error("pkill failed for '%s': %s", username, result.stderr.strip())
            return False
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            logger.error("pkill error for '%s': %s", username, exc)
            return False

    def _safe_to_disable(self, username: str) -> bool:
        return username not in self._protected

    def _user_exists(self, username: str) -> bool:
        try:
            pwd.getpwnam(username)
            return True
        except KeyError:
            return False
