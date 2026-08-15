import os
import unittest
from unittest.mock import patch

import app


class _FakeTimer:
    instances = []

    def __init__(self, interval, function):
        self.interval = interval
        self.function = function
        self.cancelled = False
        self.started = False
        self.daemon = False
        self.name = ""
        type(self).instances.append(self)

    def start(self):
        self.started = True

    def cancel(self):
        self.cancelled = True


class AppResourceLifecycleTests(unittest.TestCase):
    def setUp(self):
        app._cancel_solver_idle_shutdown()
        _FakeTimer.instances.clear()

    def tearDown(self):
        app._cancel_solver_idle_shutdown()
        app._stop_proxy_pool_health_checks()

    def test_idle_timer_stops_solver_after_configured_delay(self):
        stopped = {"ok": True, "message": "stopped"}
        with patch.dict(os.environ, {"SOLVER_IDLE_SHUTDOWN_SECONDS": "60", "YESCAPTCHA_KEY": ""}), patch.object(
            app.threading, "Timer", _FakeTimer
        ), patch.object(app.engine, "is_running", return_value=False), patch.object(
            app.solver_manager, "stop", return_value=stopped
        ) as stop_solver:
            app._schedule_solver_idle_shutdown()
            timer = _FakeTimer.instances[-1]
            self.assertEqual(timer.interval, 60)
            self.assertTrue(timer.started)
            timer.function()

        stop_solver.assert_called_once_with()

    def test_new_task_cancels_stale_idle_callback(self):
        with patch.dict(os.environ, {"SOLVER_IDLE_SHUTDOWN_SECONDS": "60", "YESCAPTCHA_KEY": ""}), patch.object(
            app.threading, "Timer", _FakeTimer
        ), patch.object(app.engine, "is_running", return_value=False), patch.object(
            app.solver_manager, "stop"
        ) as stop_solver:
            app._schedule_solver_idle_shutdown()
            timer = _FakeTimer.instances[-1]
            app._cancel_solver_idle_shutdown()
            timer.function()

        self.assertTrue(timer.cancelled)
        stop_solver.assert_not_called()


if __name__ == "__main__":
    unittest.main()
