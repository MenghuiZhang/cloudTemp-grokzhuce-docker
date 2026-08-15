import unittest
import signal
from unittest.mock import Mock, call, patch

import solver_manager


class SolverManagerStartupTests(unittest.TestCase):
    def test_missing_camoufox_binary_is_reported(self):
        solver_manager._DEPS_CACHE = {"ts": 0.0, "data": None}
        with patch(
            "camoufox.pkgman.installed_verstr",
            side_effect=RuntimeError("official/stable is not installed"),
        ):
            result = solver_manager.check_dependencies(force=True)

        self.assertFalse(result["ok"])
        self.assertFalse(result["camoufox_browser"])
        self.assertIn("camoufox-browser", result["missing"])

    def test_wait_http_returns_immediately_when_new_process_exits(self):
        process = Mock()
        process.poll.return_value = 1
        with patch.object(solver_manager, "check_http") as check_http:
            ready = solver_manager._wait_http(
                "http://127.0.0.1:5072",
                timeout=120.0,
                process=process,
            )

        self.assertFalse(ready)
        check_http.assert_not_called()

    def test_managed_process_group_requires_matching_state(self):
        with patch.object(solver_manager, "sys") as fake_sys, patch.object(
            solver_manager, "_read_state", return_value={"pid": 123, "pgid": 123}
        ):
            fake_sys.platform = "linux"
            self.assertEqual(solver_manager._managed_process_group(123), 123)
            self.assertIsNone(solver_manager._managed_process_group(124))

    def test_stop_terminates_managed_process_group(self):
        with patch.object(solver_manager, "_read_pid", return_value=123), patch.object(
            solver_manager, "_managed_process_group", return_value=123
        ), patch.object(
            solver_manager, "is_pid_running", return_value=False
        ), patch.object(
            solver_manager, "_process_group_running", side_effect=[True, False, False]
        ), patch.object(solver_manager.os, "killpg") as killpg, patch.object(
            solver_manager, "_clear_process_state"
        ), patch.object(
            solver_manager, "status", return_value={"ready": False}
        ):
            result = solver_manager.stop()

        self.assertTrue(result["ok"])
        killpg.assert_called_once_with(123, signal.SIGTERM)

    def test_stop_force_kills_group_after_grace_period(self):
        with patch.object(solver_manager, "_read_pid", return_value=123), patch.object(
            solver_manager, "_managed_process_group", return_value=123
        ), patch.object(
            solver_manager, "is_pid_running", return_value=False
        ), patch.object(
            solver_manager, "_process_group_running", side_effect=[True, True]
        ), patch.object(
            solver_manager.time, "monotonic", side_effect=[0.0, 6.0]
        ), patch.object(solver_manager.os, "killpg") as killpg, patch.object(
            solver_manager, "_clear_process_state"
        ), patch.object(
            solver_manager, "status", return_value={"ready": False}
        ):
            result = solver_manager.stop()

        self.assertTrue(result["ok"])
        self.assertEqual(
            killpg.call_args_list,
            [
                call(123, signal.SIGTERM),
                call(123, signal.SIGKILL),
            ],
        )


if __name__ == "__main__":
    unittest.main()
