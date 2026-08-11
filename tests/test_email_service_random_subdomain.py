"""Tests for cloudflare_temp_email random-subdomain discovery."""
import unittest
from unittest.mock import Mock, patch

from g.email_service import EmailService


class FakeResponse:
    status_code = 200

    def json(self):
        return {
            "domains": ["example.com"],
            "defaultDomains": ["example.com"],
            "randomSubdomainDomains": ["example.com", "mail.example.net"],
            "randomSubdomainLength": 10,
        }


class RandomSubdomainDomainTests(unittest.TestCase):
    def test_fetch_domains_exposes_random_subdomain_metadata(self):
        session = Mock()
        session.get.return_value = FakeResponse()

        with (
            patch("g.email_service.load_dotenv"),
            patch.object(
                EmailService,
                "_build_session",
                return_value=session,
            ),
        ):
            result = EmailService.fetch_mail_domains(
                worker_domain="mail.example.workers.dev",
                token="site-password",
            )

        self.assertTrue(result["ok"])
        self.assertEqual(
            result["random_subdomain_domains"],
            ["example.com", "mail.example.net"],
        )
        self.assertEqual(
            result["settings"]["randomSubdomainLength"],
            10,
        )
        self.assertIn("mail.example.net", result["domains"])


if __name__ == "__main__":
    unittest.main()
