import os
import unittest
from unittest.mock import Mock, patch

from g.email_service import EmailService, PROVIDER_REGISTRY


class FakeResponse:
    def __init__(self, status=200, data=None):
        self.status_code = status
        self._data = data or {}
        self.text = ""
        self.headers = {"content-type": "application/json"}

    def json(self):
        return self._data


class EmailProviderRegistryTests(unittest.TestCase):
    def test_registry_contains_all_four_providers(self):
        self.assertEqual(set(PROVIDER_REGISTRY), {"outlook", "freemail", "yyds", "cloudflare_temp"})

    def test_yyds_create_fetch_and_delete(self):
        session = Mock()
        session.post.return_value = FakeResponse(201, {"data": {"id": "acc-1", "address": "box@yyds.example", "token": "temp-token"}})
        session.get.return_value = FakeResponse(200, {"data": {"verificationCode": "ABC-123"}})
        session.delete.return_value = FakeResponse(204)
        env = {
            "EMAIL_PROVIDER": "yyds",
            "EMAIL_YYDS_BASE_URL": "https://maliapi.215.im/v1",
            "EMAIL_YYDS_API_KEY": "AC-test",
            "EMAIL_YYDS_PLATFORM_CODE": "grok",
        }
        with patch.dict(os.environ, env, clear=False), patch("g.email_service.load_dotenv"), patch.object(EmailService, "_build_session", return_value=session):
            service = EmailService()
            token, address = service.create_email()
            code = service.fetch_verification_code(address, max_attempts=1)
            deleted = service.delete_email(address)
        self.assertEqual((token, address), ("temp-token", "box@yyds.example"))
        self.assertEqual(code, "ABC-123")
        self.assertTrue(deleted)
        self.assertEqual(session.post.call_args.kwargs["headers"]["X-API-Key"], "AC-test")

    def test_cloudflare_domains_rotate_in_configured_order(self):
        EmailService._cf_domain_cursor = 0
        EmailService._cf_domain_health.clear()
        session = Mock()
        session.post.side_effect = [
            FakeResponse(200, {"address": "one@a.example", "jwt": "j1"}),
            FakeResponse(200, {"address": "two@b.example", "jwt": "j2"}),
        ]
        env = {
            "EMAIL_PROVIDER": "cloudflare_temp",
            "EMAIL_CF_TEMP_BASE_URL": "https://mail.example",
            "EMAIL_CF_TEMP_DOMAINS_JSON": '["a.example","b.example"]',
            "EMAIL_CF_TEMP_AUTO_DOMAIN": "0",
        }
        with patch.dict(os.environ, env, clear=False), patch("g.email_service.load_dotenv"), patch.object(EmailService, "_build_session", return_value=session):
            EmailService().create_email()
            EmailService().create_email()
        domains = [call.kwargs["json"]["domain"] for call in session.post.call_args_list]
        self.assertEqual(domains, ["a.example", "b.example"])

    def test_cloudflare_failure_tries_next_domain_once(self):
        EmailService._cf_domain_cursor = 0
        EmailService._cf_domain_health.clear()
        session = Mock()
        session.post.side_effect = [
            FakeResponse(503),
            FakeResponse(200, {"address": "two@b.example", "jwt": "j2"}),
        ]
        env = {
            "EMAIL_PROVIDER": "cloudflare_temp",
            "EMAIL_CF_TEMP_BASE_URL": "https://mail.example",
            "EMAIL_CF_TEMP_DOMAINS_JSON": '["a.example","b.example"]',
            "EMAIL_CF_TEMP_AUTO_DOMAIN": "0",
        }
        with patch.dict(os.environ, env, clear=False), patch("g.email_service.load_dotenv"), patch.object(EmailService, "_build_session", return_value=session):
            _token, address = EmailService().create_email()
        self.assertEqual(address, "two@b.example")
        self.assertEqual([c.kwargs["json"]["domain"] for c in session.post.call_args_list], ["a.example", "b.example"])


if __name__ == "__main__":
    unittest.main()
