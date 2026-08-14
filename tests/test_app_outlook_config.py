"""Tests for Outlook account-list persistence in the web configuration."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

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

    def test_solver_only_save_does_not_test_legacy_sub2api(self):
        values = dict(app.DEFAULTS)
        values.update({
            "UPSTREAM_ADMIN_EMAIL": "legacy@example.com",
            "UPSTREAM_ADMIN_PASSWORD": "legacy-secret",
            "SUB2API_URL": "http://127.0.0.1:9898",
        })

        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = Path(temp_dir) / ".env"
            upstream_test = Mock(return_value={"ok": False, "message": "must not run"})
            with (
                patch.object(app, "ENV_PATH", env_path),
                patch.object(app.engine, "is_running", return_value=False),
                patch.object(app, "test_upstream_connectivity", upstream_test),
            ):
                app.write_env_file(values)
                response = app.app.test_client().post("/api/config", json={
                    "SOLVER_URL": "http://solver.internal:5072",
                    "SOLVER_BROWSER": "camoufox",
                    "SOLVER_THREADS": "4",
                    "SOLVER_CAPTURE_DUMPS": "0",
                    "SOLVER_CAPTURE_MAX_GROUPS": "20",
                    "SOLVER_CAPTURE_MAX_MB": "50",
                    "LOG_MAX_MB": "10",
                    "LOG_ROTATE_FILE_COUNT": "3",
                    "UI_HOST": "127.0.0.1",
                    "UI_PORT": "3333",
                    "captcha_mode": "local",
                })

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("sub2api", response.get_json()["message"].lower())
        upstream_test.assert_not_called()


if __name__ == "__main__":
    unittest.main()
