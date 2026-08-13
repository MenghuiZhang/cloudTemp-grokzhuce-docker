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
        self.sync_patch.start()
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


if __name__ == "__main__":
    unittest.main()
