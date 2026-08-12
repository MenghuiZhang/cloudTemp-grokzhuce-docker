import unittest
from unittest.mock import patch

from grok import RegisterEngine


class RiskToggleTests(unittest.TestCase):
    def test_same_session_snapshots_disabled_risk_check(self):
        engine = RegisterEngine(log_fn=lambda *_args: None)
        with patch.object(engine, "_run_workers", return_value=None):
            result = engine.start(
                workers=1,
                target=1,
                blocking=True,
                mode="same_session",
                risk_check_enabled=False,
            )

        self.assertTrue(result["ok"])
        self.assertFalse(engine.risk_check_enabled)
        self.assertFalse(result["risk_check_enabled"])

    def test_same_session_defaults_to_enabled_risk_check(self):
        engine = RegisterEngine(log_fn=lambda *_args: None)
        with patch.object(engine, "_run_workers", return_value=None):
            result = engine.start(
                workers=1,
                target=1,
                blocking=True,
                mode="same_session",
            )

        self.assertTrue(engine.risk_check_enabled)
        self.assertTrue(result["risk_check_enabled"])

    def test_protocol_is_always_unchecked(self):
        engine = RegisterEngine(log_fn=lambda *_args: None)
        with patch.object(engine, "_run_workers", return_value=None):
            result = engine.start(
                workers=1,
                target=1,
                blocking=True,
                mode="protocol",
                risk_check_enabled=True,
            )

        self.assertFalse(engine.risk_check_enabled)
        self.assertFalse(result["risk_check_enabled"])


if __name__ == "__main__":
    unittest.main()
