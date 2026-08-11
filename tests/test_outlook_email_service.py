"""Unit tests for Outlook / Hotmail alias email support in EmailService"""
import os
import unittest
from unittest.mock import MagicMock, patch

from g.email_service import EmailService


class OutlookEmailServiceTests(unittest.TestCase):
    def setUp(self):
        self.dotenv_patcher = patch("g.email_service.load_dotenv")
        self.dotenv_patcher.start()
        self.env_patcher = patch.dict(
            os.environ,
            {
                "EMAIL_TYPE": "outlook-hotmail",
                "OUTLOOK_ACCOUNTS": "user1@outlook.com:pass123\nuser2@hotmail.com----pass456",
                "OUTLOOK_ALIAS_LIMIT": "2",
                "WORKER_DOMAIN": "",
                "FREEMAIL_TOKEN": "",
            },
            clear=False,
        )
        self.env_patcher.start()
        EmailService._shared_outlook_usage.clear()
        EmailService._shared_outlook_map.clear()

    def tearDown(self):
        EmailService._shared_outlook_usage.clear()
        EmailService._shared_outlook_map.clear()
        self.env_patcher.stop()
        self.dotenv_patcher.stop()

    def test_parse_accounts(self):
        service = EmailService()
        accounts = service._outlook_accounts
        self.assertEqual(len(accounts), 2)
        self.assertEqual(accounts[0]["email"], "user1@outlook.com")
        self.assertEqual(accounts[0]["password"], "pass123")
        self.assertEqual(accounts[0]["refresh_token"], "")
        self.assertEqual(accounts[0]["client_id"], "")
        self.assertEqual(accounts[1]["email"], "user2@hotmail.com")
        self.assertEqual(accounts[1]["password"], "pass456")

    def test_parse_escaped_multiline_and_oauth_fields(self):
        with patch.dict(
            os.environ,
            {
                "OUTLOOK_ACCOUNTS": (
                    "one@outlook.com:app-pass\\n"
                    "two@outlook.com----backup-pass"
                    "----refresh-token----client-id"
                )
            },
        ):
            service = EmailService()

        self.assertEqual(len(service._outlook_accounts), 2)
        oauth_account = service._outlook_accounts[1]
        self.assertEqual(oauth_account["email"], "two@outlook.com")
        self.assertEqual(oauth_account["password"], "backup-pass")
        self.assertEqual(oauth_account["refresh_token"], "refresh-token")
        self.assertEqual(oauth_account["client_id"], "client-id")

    def test_create_outlook_alias_and_limit(self):
        service = EmailService()

        # Call 1 -> user1 alias 1
        jwt1, email1 = service.create_email()
        self.assertIsNotNone(email1)
        self.assertTrue(email1.startswith("user1+"))
        self.assertTrue(email1.endswith("@outlook.com"))

        # Call 2 -> user2 alias 1 (round robin balance)
        jwt2, email2 = service.create_email()
        self.assertIsNotNone(email2)
        self.assertTrue(email2.startswith("user2+"))
        self.assertTrue(email2.endswith("@hotmail.com"))

        # Call 3 -> user1 alias 2 (user1 reaches limit 2)
        jwt3, email3 = service.create_email()
        self.assertIsNotNone(email3)
        self.assertTrue(email3.startswith("user1+"))

        # Call 4 -> user2 alias 2 (user2 reaches limit 2)
        jwt4, email4 = service.create_email()
        self.assertIsNotNone(email4)
        self.assertTrue(email4.startswith("user2+"))

        # Exceeds total limit (2*2 = 4)
        jwt5, email5 = service.create_email()
        self.assertIsNone(jwt5)
        self.assertIsNone(email5)

    @patch("imaplib.IMAP4_SSL")
    def test_fetch_outlook_verification_code_mock_imap(self, mock_imap_cls):
        EmailService._shared_outlook_usage.clear()
        EmailService._shared_outlook_map.clear()
        mock_imap = MagicMock()
        mock_imap_cls.return_value = mock_imap
        mock_imap.login.return_value = ("OK", [b"Logged in"])
        mock_imap.select.return_value = ("OK", [b"1"])
        mock_imap.search.return_value = ("OK", [b"1"])

        service = EmailService()
        jwt, email = service.create_email()

        raw_msg = (
            b"From: verify@x.ai\r\n"
            b"To: " + email.encode() + b"\r\n"
            b"Subject: Your Grok Verification Code\r\n\r\n"
            b"Your verification code is: MM0-SF3\r\n"
        )
        mock_imap.fetch.return_value = ("OK", [(b"1 (RFC822)", raw_msg)])

        code = service.fetch_verification_code(email, max_attempts=1)
        self.assertEqual(code, "MM0-SF3")
        mock_imap.login.assert_called_with("user1@outlook.com", "pass123")

    @patch("g.email_service.requests.post")
    @patch("imaplib.IMAP4_SSL")
    def test_fetch_outlook_code_with_oauth2(
        self, mock_imap_cls, mock_token_post
    ):
        mock_token_post.return_value.status_code = 200
        mock_token_post.return_value.json.return_value = {
            "access_token": "access-token",
            "expires_in": 3600,
        }
        mock_imap = MagicMock()
        mock_imap_cls.return_value = mock_imap
        mock_imap.select.return_value = ("OK", [b"1"])
        mock_imap.search.return_value = ("OK", [b"1"])

        with patch.dict(
            os.environ,
            {
                "OUTLOOK_ACCOUNTS": (
                    "oauth@outlook.com----app-pass"
                    "----refresh-token----client-id"
                )
            },
        ):
            service = EmailService()
            _jwt, alias = service.create_email()

        raw_msg = (
            b"From: verify@x.ai\r\n"
            b"To: " + alias.encode() + b"\r\n"
            b"Subject: Verification Code\r\n\r\n"
            b"Your verification code is: ABC-123\r\n"
        )
        mock_imap.fetch.return_value = (
            "OK",
            [(b"1 (RFC822)", raw_msg)],
        )

        code = service.fetch_verification_code(alias, max_attempts=1)

        self.assertEqual(code, "ABC-123")
        mock_imap.authenticate.assert_called_once()
        mechanism, callback = mock_imap.authenticate.call_args.args
        self.assertEqual(mechanism, "XOAUTH2")
        self.assertIn(b"auth=Bearer access-token", callback(None))
        mock_imap.login.assert_not_called()

    @patch("imaplib.IMAP4_SSL")
    def test_outlook_ignores_code_for_another_alias(self, mock_imap_cls):
        mock_imap = MagicMock()
        mock_imap_cls.return_value = mock_imap
        mock_imap.select.return_value = ("OK", [b"1"])
        mock_imap.search.return_value = ("OK", [b"1"])

        service = EmailService()
        _jwt, alias = service.create_email()
        raw_msg = (
            b"From: verify@x.ai\r\n"
            b"To: user1+different@outlook.com\r\n"
            b"Subject: Verification Code\r\n\r\n"
            b"Your verification code is: BAD-999\r\n"
        )
        mock_imap.fetch.return_value = (
            "OK",
            [(b"1 (RFC822)", raw_msg)],
        )

        self.assertIsNone(
            service.fetch_verification_code(alias, max_attempts=1)
        )

    def test_delete_plus_address_releases_local_limit(self):
        service = EmailService()
        _jwt, alias = service.create_email()

        self.assertTrue(service.delete_email(alias))
        self.assertNotIn(alias.lower(), EmailService._shared_outlook_map)
        self.assertEqual(
            EmailService._shared_outlook_usage.get("user1@outlook.com", 0),
            0,
        )


if __name__ == "__main__":
    unittest.main()
