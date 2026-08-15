"""Regression tests for Web same-session direct/proxy selection."""
import os
import importlib
import unittest
from unittest.mock import patch

from g.same_session_register import resolve_session_proxy
from grok import _ss_local_proxy_spec

same_session = importlib.import_module("g.same_session_register")


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

    def test_legacy_global_proxy_is_ignored(self):
        with patch.dict(
            os.environ,
            {"GROK_PROXY": "127.0.0.1:7890"},
            clear=True,
        ):
            self.assertEqual(_ss_local_proxy_spec(), "")

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

    def test_page_start_failure_closes_camoufox_manager(self):
        class Context:
            def new_page(self):
                raise RuntimeError("new_page failed")

        class Browser:
            def new_context(self, **_kwargs):
                return Context()

        class Manager:
            def __init__(self):
                self.exit_calls = []

            def __enter__(self):
                return Browser()

            def __exit__(self, *args):
                self.exit_calls.append(args)

        manager = Manager()
        device_fp = {
            "screen": {"width": 1280, "height": 720},
            "viewport": {"width": 1100, "height": 650},
            "webgl_vendor": "vendor",
            "webgl_renderer": "renderer",
        }
        with patch.dict(
            os.environ,
            {"GROK_SAME_SESSION_BROWSER_POOL": "0"},
            clear=False,
        ), patch("camoufox.sync_api.Camoufox", return_value=manager), patch.object(
            same_session, "device_fp_camoufox_kwargs", return_value={}
        ), patch.object(same_session, "_clear_thread_event_loop"):
            with self.assertRaisesRegex(RuntimeError, "new_page failed"):
                same_session._acquire_camoufox_pooled(
                    fp_os_val="windows",
                    locale="en-US",
                    humanize_val=False,
                    vp={"width": 1100, "height": 650},
                    pw_proxy=None,
                    timezone_id="UTC",
                    log_fn=lambda *_args: None,
                    device_fp=device_fp,
                )

        self.assertEqual(len(manager.exit_calls), 1)
        self.assertIs(manager.exit_calls[0][0], RuntimeError)


if __name__ == "__main__":
    unittest.main()
