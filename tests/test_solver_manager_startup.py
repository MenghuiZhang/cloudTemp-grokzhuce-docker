import unittest
from unittest.mock import Mock, patch

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


if __name__ == "__main__":
    unittest.main()
