"""Regression tests for Web same-session direct/proxy selection."""
import os
import unittest
from unittest.mock import patch

from g.same_session_register import resolve_session_proxy
from grok import _ss_local_proxy_spec


class SameSessionProxyTests(unittest.TestCase):
    def test_web_proxy_empty_means_direct(self):
        with patch.dict(
            os.environ,
            {
                "GROK_PROXY": "",
                "GROK_SAME_SESSION_PROXY": "",
                "STANDALONE_LOCAL_PROXY": "127.0.0.1:7897",
                "LOCAL_PROXY": "127.0.0.1:7897",
            },
            clear=True,
        ):
            self.assertEqual(_ss_local_proxy_spec(), "")

    def test_web_proxy_uses_configured_value(self):
        with patch.dict(
            os.environ,
            {"GROK_PROXY": "127.0.0.1:7890"},
            clear=True,
        ):
            self.assertEqual(_ss_local_proxy_spec(), "127.0.0.1:7890")

    def test_explicit_empty_proxy_ignores_system_proxy(self):
        with patch.dict(
            os.environ,
            {"HTTPS_PROXY": "http://127.0.0.1:9999"},
            clear=True,
        ):
            self.assertIsNone(resolve_session_proxy(""))

    def test_none_proxy_can_inherit_environment_for_other_callers(self):
        with patch.dict(
            os.environ,
            {"HTTPS_PROXY": "http://127.0.0.1:9999"},
            clear=True,
        ):
            resolved = resolve_session_proxy(None)

        self.assertIsNotNone(resolved)
        self.assertEqual(resolved["server"], "http://127.0.0.1:9999")


if __name__ == "__main__":
    unittest.main()
