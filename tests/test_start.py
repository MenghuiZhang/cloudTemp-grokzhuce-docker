import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import start


class StartLocalSolverTests(unittest.TestCase):
    def test_starts_solver_and_marks_new_process_as_owned(self):
        fake = SimpleNamespace(
            status=Mock(return_value={"process_running": False, "ready": False}),
            ensure_ready=Mock(
                return_value={
                    "ok": True,
                    "ready": True,
                    "started": True,
                    "pid": 123,
                    "message": "Solver 已就绪",
                }
            ),
            stop=Mock(),
        )

        with patch.dict(sys.modules, {"solver_manager": fake}):
            ok, owned = start.start_local_solver(timeout=9.0)

        self.assertTrue(ok)
        self.assertTrue(owned)
        fake.ensure_ready.assert_called_once_with(timeout=9.0)
        fake.stop.assert_not_called()

    def test_does_not_claim_an_existing_solver(self):
        fake = SimpleNamespace(
            status=Mock(return_value={"process_running": True, "ready": False}),
            ensure_ready=Mock(
                return_value={
                    "ok": True,
                    "ready": True,
                    "started": True,
                    "pid": 456,
                    "message": "进程已存在，HTTP 已就绪",
                }
            ),
            stop=Mock(),
        )

        with patch.dict(sys.modules, {"solver_manager": fake}):
            ok, owned = start.start_local_solver()

        self.assertTrue(ok)
        self.assertFalse(owned)

    def test_failed_new_solver_is_stopped(self):
        fake = SimpleNamespace(
            status=Mock(return_value={"process_running": False, "ready": False}),
            ensure_ready=Mock(
                return_value={
                    "ok": False,
                    "ready": False,
                    "started": True,
                    "pid": 789,
                    "message": "等待 HTTP 超时",
                }
            ),
            stop=Mock(return_value={"ok": True}),
        )

        with patch.dict(sys.modules, {"solver_manager": fake}):
            ok, owned = start.start_local_solver()

        self.assertFalse(ok)
        self.assertFalse(owned)
        fake.stop.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
