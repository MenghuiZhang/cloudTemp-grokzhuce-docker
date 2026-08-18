import tempfile
import unittest
import json
from pathlib import Path
from unittest.mock import patch

import app
from g.domain_pool import DomainPool


class DomainApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pool = DomainPool(Path(self.tmp.name) / "domain_pool.json")
        self.pool.sync_configured([f"d{i}.example.com" for i in range(250)])
        self.pool_patch = patch.object(app, "domain_pool", self.pool)
        self.sync_patch = patch.object(app, "_sync_cf_domain_env")
        self.pool_patch.start()
        self.sync_mock = self.sync_patch.start()
        self.client = app.app.test_client()

    def tearDown(self):
        self.sync_patch.stop()
        self.pool_patch.stop()
        self.tmp.cleanup()

    def test_list_accepts_two_thousand_page_size(self):
        response = self.client.get("/api/domains?per_page=2000")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["per_page"], 2000)
        self.assertEqual(len(response.json["items"]), 250)

    def test_added_domain_is_immediately_enabled(self):
        response = self.client.post("/api/domains", json={"domain": "new.example.com"})
        self.assertEqual(response.status_code, 200)
        row = next(x for x in self.pool.list_public(per_page=1000)["items"] if x["domain"] == "new.example.com")
        self.assertEqual(row["status"], "enabled")

    def test_batch_add_reports_duplicates_and_invalid_domains(self):
        response = self.client.post("/api/domains", json={
            "domains": ["D0.EXAMPLE.COM.", "new.example.com", "NEW.EXAMPLE.COM.", "not a domain"],
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["added"], 1)
        self.assertEqual(response.json["duplicates"], 2)
        self.assertEqual(response.json["invalid"], 1)

    def test_batch_add_is_rejected_while_running(self):
        with patch.object(app.engine, "is_running", return_value=True):
            response = self.client.post("/api/domains", json={"domains": ["running.example.com"]})
        self.assertEqual(response.status_code, 409)
        self.assertNotIn("running.example.com", self.pool.active_domains())
        self.sync_mock.assert_not_called()

    def test_delete_permanently_removes_domain_history(self):
        row = self.pool.list_public(per_page=1000)["items"][0]
        self.pool.set_email_health(row["id"], ok=True, message="ok")
        response = self.client.post(
            "/api/domains/bulk",
            json={"ids": [row["id"]], "action": "delete"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["removed"], 1)
        with self.assertRaises(KeyError):
            self.pool.get_public(row["id"])

    def test_delete_is_rejected_while_running(self):
        row = self.pool.list_public(per_page=1000)["items"][0]
        with patch.object(app.engine, "is_running", return_value=True):
            response = self.client.post(
                "/api/domains/bulk",
                json={"ids": [row["id"]], "action": "delete"},
            )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.pool.get_public(row["id"])["domain"], row["domain"])

    def test_archive_bulk_action_is_rejected(self):
        row = self.pool.list_public(per_page=1000)["items"][0]
        response = self.client.post(
            "/api/domains/bulk",
            json={"ids": [row["id"]], "action": "archive"},
        )
        self.assertEqual(response.status_code, 400)

    def test_bulk_enable_does_not_run_connection_test(self):
        self.pool.add(["new.example.com"])
        row = next(x for x in self.pool.list_public(per_page=1000)["items"] if x["domain"] == "new.example.com")

        with patch.object(app, "_test_domain") as test_domain:
            response = self.client.post(
                "/api/domains/bulk",
                json={"ids": [row["id"]], "action": "enable"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["changed"], 1)
        self.assertEqual(self.pool.get_public(row["id"])["status"], "enabled")
        self.assertEqual(self.pool.get_public(row["id"])["email_health"], "untested")
        test_domain.assert_not_called()

    def test_disabled_only_pool_never_falls_back_to_auto_domain(self):
        with tempfile.TemporaryDirectory() as tmp:
            disabled_pool = DomainPool(Path(tmp) / "domain_pool.json")
            disabled_pool.add(["disabled.example.com"])
            with (
                patch.object(app, "domain_pool", disabled_pool),
                patch.object(app, "read_env_file", return_value={}),
            ):
                response = self.client.get("/api/email-config")
        self.assertEqual(response.status_code, 200)
        cloudflare = response.json["config"]["providers"]["cloudflare_temp"]
        self.assertEqual(cloudflare["domains"], [])
        self.assertIs(cloudflare["auto_domain"], False)

    def test_replace_reconciles_active_list_without_testing(self):
        with patch.object(app, "_test_domain") as test_domain:
            response = self.client.post("/api/domains", json={
                "domains": ["fresh.example.com", "d1.example.com"],
                "replace": True,
            })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.pool.active_domains(), ["fresh.example.com", "d1.example.com"])
        self.assertEqual(response.json["disabled"], 249)
        test_domain.assert_not_called()

    def test_empty_replace_keeps_current_pool(self):
        before = self.pool.active_domains()
        response = self.client.post("/api/domains", json={"domains": [], "replace": True})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.pool.active_domains(), before)

    def test_start_rejects_configured_pool_with_no_active_domain(self):
        for row in self.pool.list_public(per_page=1000)["items"]:
            self.pool.update(row["id"], {"enabled": False})
        with (
            patch.object(app, "read_env_file", return_value={}),
            patch.object(app, "resolved_email_config", return_value={"provider": "cloudflare_temp"}),
        ):
            response = self.client.post("/api/start", json={"workers": 1, "target": 1})
        self.assertEqual(response.status_code, 409)
        self.assertIn("没有已启用域名", response.json["message"])

    def test_general_save_cannot_restore_stale_cloudflare_domains(self):
        current = dict(app.DEFAULTS)
        current["EMAIL_PROVIDER"] = "cloudflare_temp"
        current["EMAIL_CF_TEMP_DOMAINS_JSON"] = '["stale.example.com"]'
        with (
            patch.object(app, "read_env_file", return_value=current),
            patch.object(app, "write_env_file") as write_env,
            patch.object(app, "apply_env_to_process"),
        ):
            response = self.client.post("/api/email-config", json={
                "providers": {
                    "cloudflare_temp": {
                        "domains": ["stale.example.com"],
                        "auto_domain": True,
                    }
                }
            })
        self.assertEqual(response.status_code, 200)
        saved = write_env.call_args.args[0]
        self.assertEqual(
            json.loads(saved["EMAIL_CF_TEMP_DOMAINS_JSON"]),
            self.pool.active_domains(),
        )
        self.assertNotIn("stale.example.com", self.pool.active_domains())
        self.assertEqual(saved["EMAIL_CF_TEMP_AUTO_DOMAIN"], "0")


class DomainEnvSyncTests(unittest.TestCase):
    def test_sync_never_uses_auto_mode_when_pool_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            pool = DomainPool(Path(tmp) / "domain_pool.json")
            pool.add(["new.example.com"])
            with (
                patch.object(app, "domain_pool", pool),
                patch.object(app, "read_env_file", return_value={"EMAIL_CF_TEMP_AUTO_DOMAIN": "0"}),
                patch.object(app, "write_env_file") as write_env,
                patch.dict(app.os.environ, {}, clear=False),
            ):
                app._sync_cf_domain_env()
                disabled_values = write_env.call_args.args[0]
                self.assertEqual(disabled_values["EMAIL_CF_TEMP_DOMAINS_JSON"], "[]")
                self.assertEqual(disabled_values["EMAIL_CF_TEMP_AUTO_DOMAIN"], "0")

                row = pool.list_public()["items"][0]
                pool.update(row["id"], {"enabled": True})
                app._sync_cf_domain_env()
                enabled_values = write_env.call_args.args[0]
                self.assertEqual(enabled_values["EMAIL_CF_TEMP_DOMAINS_JSON"], '["new.example.com"]')
                self.assertEqual(enabled_values["EMAIL_CF_TEMP_AUTO_DOMAIN"], "0")


if __name__ == "__main__":
    unittest.main()
