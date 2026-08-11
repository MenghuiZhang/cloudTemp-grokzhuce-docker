"""Tests for Outlook account-list persistence in the web configuration."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app


class OutlookConfigPersistenceTests(unittest.TestCase):
    def test_multiline_accounts_round_trip_as_one_env_line(self):
        accounts = (
            "one@outlook.com:app-pass\n"
            "two@outlook.com----backup-pass----refresh-token----client-id"
        )
        values = dict(app.DEFAULTS)
        values["EMAIL_TYPE"] = "outlook-hotmail"
        values["OUTLOOK_ACCOUNTS"] = accounts

        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = Path(temp_dir) / ".env"
            with patch.object(app, "ENV_PATH", env_path):
                app.write_env_file(values)
                content = env_path.read_text(encoding="utf-8")
                loaded = app.read_env_file()

        account_lines = [
            line
            for line in content.splitlines()
            if line.startswith("OUTLOOK_ACCOUNTS=")
        ]
        self.assertEqual(len(account_lines), 1)
        self.assertIn("\\n", account_lines[0])
        self.assertEqual(loaded["OUTLOOK_ACCOUNTS"], accounts)


if __name__ == "__main__":
    unittest.main()
