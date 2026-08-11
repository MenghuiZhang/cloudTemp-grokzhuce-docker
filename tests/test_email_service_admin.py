import os
import unittest
from unittest.mock import Mock, patch

from g.email_service import EmailService


class FakeResponse:
    def __init__(self, status_code=200, data=None, text=""):
        self.status_code = status_code
        self._data = data or {}
        self.text = text

    def json(self):
        return self._data


class EmailServiceAdminTests(unittest.TestCase):
    def make_service(
        self,
        admin_key="admin-password",
        random_subdomain=False,
    ):
        session = Mock()
        session.post.return_value = FakeResponse(
            data={"address": "test@example.com", "jwt": "address-jwt"}
        )
        env = {
            "EMAIL_TYPE": "freemail",
            "WORKER_DOMAIN": "mail.example.workers.dev",
            "FREEMAIL_TOKEN": "site-password",
            "FREEMAIL_ADMIN_KEY": admin_key,
            "FREEMAIL_DOMAIN": "example.com",
            "FREEMAIL_RANDOM_SUBDOMAIN": (
                "1" if random_subdomain else "0"
            ),
            "FREEMAIL_API_STYLE": "cf_temp",
        }
        with (
            patch.dict(os.environ, env, clear=False),
            patch("g.email_service.load_dotenv"),
            patch.object(EmailService, "_build_session", return_value=session),
        ):
            service = EmailService()
        return service, session

    def test_admin_key_uses_admin_endpoint_and_both_password_headers(self):
        service, session = self.make_service()

        jwt, email = service.create_email()

        self.assertEqual((jwt, email), ("address-jwt", "test@example.com"))
        call = session.post.call_args
        self.assertEqual(
            call.args[0],
            "https://mail.example.workers.dev/admin/new_address",
        )
        self.assertEqual(call.kwargs["headers"]["x-admin-auth"], "admin-password")
        self.assertEqual(call.kwargs["headers"]["x-custom-auth"], "site-password")
        self.assertEqual(call.kwargs["json"]["domain"], "example.com")

    def test_without_admin_key_keeps_public_endpoint(self):
        service, session = self.make_service(admin_key="")

        service.create_email()

        call = session.post.call_args
        self.assertEqual(
            call.args[0],
            "https://mail.example.workers.dev/api/new_address",
        )
        self.assertNotIn("x-admin-auth", call.kwargs["headers"])

    def test_random_subdomain_uses_native_create_flag(self):
        service, session = self.make_service(random_subdomain=True)

        service.create_email()

        payload = session.post.call_args.kwargs["json"]
        self.assertEqual(payload["domain"], "example.com")
        self.assertIs(payload["enableRandomSubdomain"], True)


if __name__ == "__main__":
    unittest.main()
