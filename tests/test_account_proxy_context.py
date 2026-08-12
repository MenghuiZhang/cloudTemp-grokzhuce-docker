import os
import unittest
from unittest.mock import patch

import grok
from g.antibot_service import _proxy_kwargs as antibot_proxy_kwargs
from g.import_services import _proxy_kwargs as import_proxy_kwargs
from g.nsfw_service import NsfwSettingsService
from g.user_agreement_service import UserAgreementService


class AccountProxyContextTests(unittest.TestCase):
    def test_protocol_retry_stops_at_signup_boundary(self):
        self.assertTrue(
            grok._protocol_safe_to_retry_with_new_proxy("proxy timeout while loading page")
        )
        self.assertFalse(
            grok._protocol_safe_to_retry_with_new_proxy("提交注册异常: proxy timeout")
        )

    def test_explicit_account_proxy_beats_environment(self):
        with patch.dict(os.environ, {"GROK_PROXY": "http://wrong.test:9000"}, clear=False):
            expected = "http://user:pass@right.test:8000"
            self.assertEqual(
                grok._proxy_kw(expected)["proxies"]["https"], expected
            )
            self.assertEqual(
                antibot_proxy_kwargs(proxy_spec=expected)["proxies"]["https"],
                expected,
            )

    def test_explicit_empty_account_proxy_is_direct(self):
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://wrong.test:9000"}, clear=False):
            self.assertEqual(
                grok._proxy_kw("")["proxies"], {"http": "", "https": ""}
            )
            self.assertEqual(
                antibot_proxy_kwargs(proxy_spec="")["proxies"],
                {"http": "", "https": ""},
            )

    def test_xai_post_processing_receives_same_proxy(self):
        response = type(
            "Response",
            (),
            {"content": b"ok", "headers": {}, "status_code": 200},
        )()
        proxy = "http://user:pass@right.test:8000"
        with patch("g.user_agreement_service.requests.post", return_value=response) as post:
            UserAgreementService().accept_tos_version(
                "sso", "rw", "chrome120", proxy_spec=proxy
            )
            self.assertEqual(post.call_args.kwargs["proxies"]["https"], proxy)
        with patch("g.nsfw_service.requests.post", return_value=response) as post:
            NsfwSettingsService().enable_nsfw(
                "sso", "rw", "chrome120", proxy_spec=proxy
            )
            self.assertEqual(post.call_args.kwargs["proxies"]["https"], proxy)

    def test_import_targets_are_forced_direct(self):
        cfg = {
            "proxy_mode": "custom",
            "proxy_url": "http://must-not-be-used.test:9000",
            "tls_verify": True,
        }
        self.assertEqual(
            import_proxy_kwargs(cfg, "http://register.test:8000")["proxies"],
            {"http": "", "https": ""},
        )


if __name__ == "__main__":
    unittest.main()
