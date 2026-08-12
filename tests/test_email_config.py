import tempfile
import unittest
import json
from pathlib import Path
from unittest.mock import patch

import app
from g.email_config import redact_config, resolved_email_config, serialize_structured_config


class EmailConfigTests(unittest.TestCase):
    def test_legacy_cloudflare_temp_migrates_without_data_loss(self):
        cfg = {
            "EMAIL_TYPE": "freemail",
            "FREEMAIL_API_STYLE": "cf_temp",
            "WORKER_DOMAIN": "mail.example.workers.dev",
            "FREEMAIL_TOKEN": "site-secret",
            "FREEMAIL_ADMIN_KEY": "admin-secret",
            "FREEMAIL_DOMAIN": "example.com",
            "FREEMAIL_RANDOM_SUBDOMAIN": "1",
        }
        resolved = resolved_email_config(cfg)
        self.assertEqual(resolved["provider"], "cloudflare_temp")
        self.assertEqual(resolved["providers"]["cloudflare_temp"]["domains"], ["example.com"])
        self.assertEqual(resolved["providers"]["cloudflare_temp"]["site_token"], "site-secret")

    def test_empty_secret_retains_existing_and_redaction_never_returns_it(self):
        current = dict(app.DEFAULTS)
        current.update({
            "EMAIL_PROVIDER": "yyds",
            "EMAIL_YYDS_API_KEY": "AC-super-secret",
        })
        values = serialize_structured_config(current, {
            "provider": "yyds",
            "providers": {"yyds": {"api_key": "", "domain": "auto"}},
        })
        self.assertEqual(values["EMAIL_YYDS_API_KEY"], "AC-super-secret")
        public = redact_config(resolved_email_config(values), app.mask_secret)
        self.assertEqual(public["providers"]["yyds"]["api_key"], "")
        self.assertTrue(public["providers"]["yyds"]["api_key_set"])
        self.assertNotIn("super-secret", str(public))

    def test_explicit_provider_with_missing_optional_secrets_uses_empty_strings(self):
        resolved = resolved_email_config({
            "EMAIL_PROVIDER": "freemail",
            "EMAIL_FREEMAIL_BASE_URL": "https://mail.example",
        })
        self.assertEqual(resolved["providers"]["freemail"]["token"], "")
        self.assertEqual(resolved["providers"]["cloudflare_temp"]["site_token"], "")

    def test_email_config_api_saves_draft_without_activating(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / ".env"
            initial = dict(app.DEFAULTS)
            initial["EMAIL_PROVIDER"] = "cloudflare_temp"
            initial["EMAIL_CF_TEMP_BASE_URL"] = "https://old.example"
            with patch.object(app, "ENV_PATH", env_path):
                app.write_env_file(initial)
                with patch.object(app, "apply_env_to_process"):
                    response = app.app.test_client().post(
                        "/api/email-config",
                        json={"providers": {"yyds": {"api_key": "AC-test", "domain": "auto"}}},
                    )
                    loaded = app.read_env_file()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(loaded["EMAIL_PROVIDER"], "cloudflare_temp")
        self.assertEqual(loaded["EMAIL_YYDS_API_KEY"], "AC-test")
        self.assertEqual(response.json["config"]["providers"]["yyds"]["api_key"], "")

    def test_start_accepts_outlook_without_cloudflare_credentials(self):
        cfg = dict(app.DEFAULTS)
        cfg.update({
            "EMAIL_PROVIDER": "outlook",
            "EMAIL_OUTLOOK_ACCOUNTS_JSON": json.dumps([{
                "email": "user@outlook.com", "password": "app-pass", "alias_limit": 5,
            }]),
            "WORKER_DOMAIN": "",
            "FREEMAIL_TOKEN": "",
            "YESCAPTCHA_KEY": "configured-to-skip-local-solver",
        })
        with patch.object(app, "read_env_file", return_value=cfg), patch.object(
            app.engine, "start", return_value={"ok": True, "message": "started"}
        ) as start_mock:
            response = app.app.test_client().post("/api/start", json={"workers": 1, "target": 1})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(start_mock.call_args.kwargs["risk_check_enabled"])

    def test_start_forwards_disabled_risk_check(self):
        cfg = dict(app.DEFAULTS)
        cfg.update({
            "EMAIL_PROVIDER": "outlook",
            "EMAIL_OUTLOOK_ACCOUNTS_JSON": json.dumps([{
                "email": "user@outlook.com", "password": "app-pass", "alias_limit": 5,
            }]),
            "YESCAPTCHA_KEY": "configured-to-skip-local-solver",
        })
        with patch.object(app, "read_env_file", return_value=cfg), patch.object(
            app.engine, "start", return_value={"ok": True, "message": "started"}
        ) as start_mock:
            response = app.app.test_client().post(
                "/api/start",
                json={
                    "workers": 1,
                    "target": 1,
                    "mode": "same_session",
                    "risk_check_enabled": False,
                },
            )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(start_mock.call_args.kwargs["risk_check_enabled"])

    def test_start_rejects_invalid_risk_check_value(self):
        response = app.app.test_client().post(
            "/api/start",
            json={"workers": 1, "target": 1, "risk_check_enabled": {"bad": True}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("risk_check_enabled", response.json["message"])

    def test_partial_general_save_does_not_duplicate_email_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / ".env"
            values = dict(app.DEFAULTS)
            values["EMAIL_PROVIDER"] = "yyds"
            with patch.object(app, "ENV_PATH", env_path):
                app.write_env_file(values)
                app.write_env_file({"YESCAPTCHA_KEY": "changed"})
                lines = env_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(sum(line.startswith("EMAIL_PROVIDER=") for line in lines), 1)


if __name__ == "__main__":
    unittest.main()
