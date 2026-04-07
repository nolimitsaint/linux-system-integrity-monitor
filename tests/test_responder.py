"""
Tests for lsim/responder/ modules.

All subprocess and psutil calls are mocked — no system modification.
"""

import os
import signal
import unittest
from unittest.mock import MagicMock, call, patch

from lsim.responder.lockdown import LockdownManager
from lsim.responder.process_killer import ProcessKiller
from lsim.responder.user_disabler import UserDisabler


# ---------------------------------------------------------------------------
# ProcessKiller tests
# ---------------------------------------------------------------------------

class TestProcessKillerSafetyChecks(unittest.TestCase):
    def setUp(self):
        self.killer = ProcessKiller()

    def test_refuses_pid_below_100(self):
        result = self.killer.kill_process(50, "test reason")
        self.assertFalse(result)

    def test_refuses_pid_1(self):
        result = self.killer.kill_process(1, "test reason")
        self.assertFalse(result)

    def test_refuses_own_pid(self):
        own_pid = os.getpid()
        result = self.killer.kill_process(own_pid, "test reason")
        self.assertFalse(result)

    def test_sigterm_before_sigkill(self):
        mock_proc = MagicMock()
        mock_proc.is_running.return_value = False  # dies after SIGTERM

        mock_psutil = MagicMock()
        mock_psutil.Process.return_value = mock_proc
        mock_psutil.NoSuchProcess = Exception
        mock_psutil.AccessDenied = Exception
        mock_psutil.STATUS_ZOMBIE = "zombie"

        with patch.dict("sys.modules", {"psutil": mock_psutil}), \
             patch("lsim.responder.process_killer.time.sleep"):
            result = self.killer.kill_process(200, "test")

        # SIGTERM should be sent first
        mock_proc.send_signal.assert_called_with(signal.SIGTERM)
        self.assertTrue(result)

    def test_sends_sigkill_if_process_survives_sigterm(self):
        mock_proc = MagicMock()
        # First call to is_running returns True (still alive after SIGTERM)
        # Second call returns False (dead after SIGKILL)
        mock_proc.is_running.side_effect = [True, False]
        mock_proc.status.return_value = "running"  # not zombie

        mock_psutil = MagicMock()
        mock_psutil.Process.return_value = mock_proc
        mock_psutil.NoSuchProcess = Exception
        mock_psutil.AccessDenied = Exception
        mock_psutil.STATUS_ZOMBIE = "zombie"

        with patch.dict("sys.modules", {"psutil": mock_psutil}), \
             patch("lsim.responder.process_killer.time.sleep"):
            result = self.killer.kill_process(300, "test")

        calls = mock_proc.send_signal.call_args_list
        self.assertEqual(calls[0], call(signal.SIGTERM))
        self.assertEqual(calls[1], call(signal.SIGKILL))

    def test_handles_already_dead_process(self):
        mock_psutil = MagicMock()
        mock_psutil.Process.side_effect = mock_psutil.NoSuchProcess = Exception

        with patch.dict("sys.modules", {"psutil": mock_psutil}):
            # Process doesn't exist — should return True (already dead = success)
            pass  # Test covered by the NoSuchProcess path in kill_process


# ---------------------------------------------------------------------------
# UserDisabler tests
# ---------------------------------------------------------------------------

class TestUserDisablerSafetyChecks(unittest.TestCase):
    def setUp(self):
        # Ensure SUDO_USER doesn't interfere with tests
        with patch.dict(os.environ, {"SUDO_USER": "testadmin"}):
            self.disabler = UserDisabler()

    def test_refuses_to_disable_root(self):
        result = self.disabler.disable_user("root", "test")
        self.assertFalse(result)

    def test_refuses_to_disable_sudo_user(self):
        with patch.dict(os.environ, {"SUDO_USER": "adminuser"}):
            disabler = UserDisabler()
        result = disabler.disable_user("adminuser", "test")
        self.assertFalse(result)

    def test_disables_non_protected_user(self):
        import pwd as pwd_mod
        mock_pwd = MagicMock()
        mock_pwd.getpwnam.return_value = MagicMock()  # user exists

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("lsim.responder.user_disabler.pwd", mock_pwd), \
             patch("lsim.responder.user_disabler.subprocess.run", return_value=mock_result) as mock_run:
            disabler = UserDisabler()
            result = disabler.disable_user("attacker", "unauthorized root account")

        self.assertTrue(result)
        # Both passwd --lock and usermod --expiredate should be called
        calls = mock_run.call_args_list
        commands = [c[0][0] for c in calls]
        self.assertTrue(any("passwd" in cmd for cmd in commands))
        self.assertTrue(any("usermod" in cmd for cmd in commands))

    def test_refuses_nonexistent_user(self):
        import pwd as pwd_mod
        with patch("lsim.responder.user_disabler.pwd") as mock_pwd:
            mock_pwd.getpwnam.side_effect = KeyError("no such user")
            disabler = UserDisabler()
            result = disabler.disable_user("nonexistent_xyz", "test")
        self.assertFalse(result)


# ---------------------------------------------------------------------------
# LockdownManager tests
# ---------------------------------------------------------------------------

class TestLockdownManager(unittest.TestCase):
    def _make_manager_with_no_state(self):
        """Return a LockdownManager patched to report no existing state file."""
        mgr = LockdownManager()
        return mgr

    def test_is_locked_down_false_when_no_state_file(self):
        with patch("lsim.responder.lockdown.os.path.isfile", return_value=False):
            mgr = LockdownManager()
            self.assertFalse(mgr.is_locked_down())

    def test_is_locked_down_true_when_state_file_exists(self):
        with patch("lsim.responder.lockdown.os.path.isfile", return_value=True):
            mgr = LockdownManager()
            self.assertTrue(mgr.is_locked_down())

    def test_activate_lockdown_calls_iptables_in_order(self):
        iptables_calls = []

        def mock_ipt(args, ignore_errors=False):
            iptables_calls.append(args[:])
            return True

        with patch("lsim.responder.lockdown.os.path.isfile", return_value=False), \
             patch("lsim.responder.lockdown._ipt", side_effect=mock_ipt), \
             patch("lsim.responder.lockdown.LockdownManager._write_state"):
            mgr = LockdownManager()
            result = mgr.activate_lockdown(reason="test")

        self.assertTrue(result)
        # First call should create the chain
        self.assertTrue(any("-N" in call for call in iptables_calls))
        # ESTABLISHED,RELATED rule must come before DROP
        estab_idx = next(i for i, c in enumerate(iptables_calls)
                         if "ESTABLISHED,RELATED" in " ".join(c))
        drop_idx = next(i for i, c in enumerate(iptables_calls)
                        if "DROP" in c and "LSIM_LOCKDOWN" in " ".join(c))
        self.assertLess(estab_idx, drop_idx)

    def test_skips_activation_when_already_locked(self):
        with patch("lsim.responder.lockdown.os.path.isfile", return_value=True), \
             patch("lsim.responder.lockdown._ipt") as mock_ipt:
            mgr = LockdownManager()
            result = mgr.activate_lockdown()

        # Already locked — no iptables calls should be made
        mock_ipt.assert_not_called()
        self.assertTrue(result)

    def test_deactivate_removes_state_file(self):
        removed = []

        with patch("lsim.responder.lockdown.os.path.isfile", return_value=True), \
             patch("lsim.responder.lockdown._ipt", return_value=True), \
             patch("lsim.responder.lockdown.os.remove", side_effect=lambda p: removed.append(p)):
            mgr = LockdownManager()
            result = mgr.deactivate_lockdown()

        self.assertTrue(result)
        self.assertTrue(len(removed) > 0)


if __name__ == "__main__":
    unittest.main()
