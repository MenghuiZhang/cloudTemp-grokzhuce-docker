import tempfile
import unittest
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

    def test_added_domain_starts_disabled(self):
        response = self.client.post("/api/domains", json={"domain": "new.example.com"})
        self.assertEqual(response.status_code, 200)
        row = next(x for x in self.pool.list_public(per_page=1000)["items"] if x["domain"] == "new.example.com")
        self.assertEqual(row["status"], "disabled")

    def test_batch_add_reports_duplicates_and_invalid_domains(self):
        response = self.client.post("/api/domains", json={
            "domains": ["D0.EXAMPLE.COM.", "new.example.com", "NEW.EXAMPLE.COM.", "not a domain"],
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["added"], 1)
        self.assertEqual(response.json["duplicates"], 2)
        self.assertEqual(response.json["invalid"], 1)

    def test_batch_add_is_allowed_while_running_without_env_sync(self):
        with patch.object(app.engine, "is_running", return_value=True):
            response = self.client.post("/api/domains", json={"domains": ["running.example.com"]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["added"], 1)
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

    def test_bulk_enable_tests_before_enabling(self):
        self.pool.add(["new.example.com"])
        row = next(x for x in self.pool.list_public(per_page=1000)["items"] if x["domain"] == "new.example.com")

        def fake_test(domain_id):
            self.pool.set_email_health(domain_id, ok=True, message="ok")
            return {"id": domain_id, "ok": True, "message": "ok"}

        with patch.object(app, "_test_domain", side_effect=fake_test):
            response = self.client.post(
                "/api/domains/bulk",
                json={"ids": [row["id"]], "action": "enable"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["changed"], 1)
        self.assertEqual(self.pool.get_public(row["id"])["status"], "enabled")

    def test_disabled_only_pool_is_presented_in_auto_domain_mode(self):
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
        self.assertIs(cloudflare["auto_domain"], True)


class DomainEnvSyncTests(unittest.TestCase):
    def test_sync_uses_auto_mode_until_a_domain_is_enabled(self):
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
                self.assertEqual(disabled_values["EMAIL_CF_TEMP_AUTO_DOMAIN"], "1")

                row = pool.list_public()["items"][0]
                pool.set_email_health(row["id"], ok=True, message="ok")
                pool.update(row["id"], {"enabled": True})
                app._sync_cf_domain_env()
                enabled_values = write_env.call_args.args[0]
                self.assertEqual(enabled_values["EMAIL_CF_TEMP_DOMAINS_JSON"], '["new.example.com"]')
                self.assertEqual(enabled_values["EMAIL_CF_TEMP_AUTO_DOMAIN"], "0")


if __name__ == "__main__":
    unittest.main()
