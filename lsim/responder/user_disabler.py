"""
User Disabler — locks compromised user accounts.

Safety invariants (never bypass):
  - Never disable 'root'
  - Never disable the invoking user (SUDO_USER)
  - Verify the username exists before acting
  - Log intended action BEFORE calling subprocess
"""

import logging
import os
import pwd
import subprocess

from lsim.config import ADMIN_USER

logger = logging.getLogger("lsim")


class UserDisabler:
    def __init__(self):
        # The user who invoked sudo — never disable them
        self._protected_users = {"root", ADMIN_USER}
        sudo_user = os.environ.get("SUDO_USER", "")
        if sudo_user:
            self._protected_users.add(sudo_user)

    def disable_user(self, username: str, reason: str) -> bool:
        """
        Lock the account with passwd --lock and expire it immediately.
        Returns True on success.
        """
        if not self._is_safe_to_disable(username):
            logger.warning("UserDisabler: refused to disable '%s' — protected account", username)
            return False

        if not self._user_exists(username):
            logger.warning("UserDisabler: user '%s' does not exist", username)
            return False

        logger.info("UserDisabler: disabling user '%s' — reason: %s", username, reason)

        success = True

        # Lock the password
        try:
            result = subprocess.run(
                ["passwd", "--lock", username],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                logger.error("UserDisabler: passwd --lock failed for '%s': %s", username, result.stderr.strip())
                success = False
            else:
                logger.info("UserDisabler: password locked for '%s'", username)
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            logger.error("UserDisabler: passwd command error for '%s': %s", username, exc)
            success = False

        # Expire the account immediately (epoch day 1 = Jan 2, 1970)
        try:
            result = subprocess.run(
                ["usermod", "--expiredate", "1", username],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                logger.error("UserDisabler: usermod --expiredate failed for '%s': %s", username, result.stderr.strip())
                success = False
            else:
                logger.info("UserDisabler: account expiry set for '%s'", username)
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            logger.error("UserDisabler: usermod command error for '%s': %s", username, exc)
            success = False

        return success

    def kill_user_sessions(self, username: str) -> bool:
        """Kill all processes owned by the user."""
        if not self._is_safe_to_disable(username):
            logger.warning("UserDisabler: refused to kill sessions for '%s' — protected account", username)
            return False

        logger.info("UserDisabler: killing all sessions for user '%s'", username)
        try:
            result = subprocess.run(
                ["pkill", "-KILL", "-u", username],
                capture_output=True,
                text=True,
                timeout=10,
            )
            # pkill returns 1 if no processes were found — that's fine
            if result.returncode in (0, 1):
                logger.info("UserDisabler: sessions for '%s' terminated", username)
                return True
            logger.error("UserDisabler: pkill failed for '%s': %s", username, result.stderr.strip())
            return False
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            logger.error("UserDisabler: pkill error for '%s': %s", username, exc)
            return False

    def _is_safe_to_disable(self, username: str) -> bool:
        return username not in self._protected_users

    def _user_exists(self, username: str) -> bool:
        try:
            pwd.getpwnam(username)
            return True
        except KeyError:
            return False
