import json
import tempfile
import unittest
from pathlib import Path

from grok import RegisterEngine


class RegisterEngineAccountJsonTests(unittest.TestCase):
    def test_record_success_writes_requested_account_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "grok_ss_test_1.txt"
            engine = RegisterEngine(log_fn=lambda *_args: None)
            engine.output_file = str(output)
            engine.target_count = 10
            engine.start_time = 1.0

            success_id = engine._record_success(
                email="user@example.com",
                sso="header.payload.signature",
                unhinged_ok=False,
            )

            self.assertTrue(success_id)
            account_path = Path(tmp) / "grok_ss_test_1_accounts.json"
            accounts = json.loads(account_path.read_text(encoding="utf-8"))
            self.assertEqual(
                accounts,
                [
                    {
                        "name": "user@example.com",
                        "email": "user@example.com",
                        "user_id": "",
                        "sso_token": "header.payload.signature",
                        "token": "",
                        "tier": "basic",
                        "cloudflare_cookies": "",
                    }
                ],
            )

    def test_account_json_upsert_backfills_user_id_without_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = RegisterEngine(log_fn=lambda *_args: None)
            engine.output_file = str(Path(tmp) / "accounts.txt")

            self.assertTrue(
                engine._write_account_json(
                    email="user@example.com",
                    sso="header.payload.signature",
                )
            )
            self.assertTrue(
                engine._write_account_json(
                    email="user@example.com",
                    sso="header.payload.signature",
                    user_id="user-id-123",
                )
            )

            accounts = json.loads(
                (Path(tmp) / "accounts_accounts.json").read_text(encoding="utf-8")
            )
            self.assertEqual(len(accounts), 1)
            self.assertEqual(accounts[0]["user_id"], "user-id-123")


if __name__ == "__main__":
    unittest.main()
