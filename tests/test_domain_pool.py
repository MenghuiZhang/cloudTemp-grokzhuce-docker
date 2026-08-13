import json
import tempfile
import unittest
from pathlib import Path

from g.domain_pool import DomainPool


class DomainPoolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "domain_pool.json"
        self.pool = DomainPool(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_config_migration_preserves_order_and_enables(self):
        self.assertEqual(self.pool.sync_configured(["a.example", "b.example"]), 2)
        rows = self.pool.list_public(per_page=10)["items"]
        self.assertEqual([x["domain"] for x in rows], ["a.example", "b.example"])
        self.assertTrue(all(x["status"] == "enabled" for x in rows))

    def test_new_domain_requires_health_before_enable(self):
        self.pool.add(["new.example"])
        row = self.pool.list_public()["items"][0]
        self.assertEqual(row["status"], "disabled")
        with self.assertRaisesRegex(ValueError, "测试通过"):
            self.pool.update(row["id"], {"enabled": True})
        self.pool.set_email_health(row["id"], ok=True, message="ok")
        enabled = self.pool.update(row["id"], {"enabled": True})
        self.assertEqual(enabled["status"], "enabled")

    def test_first_marked_locks_and_second_marked_disables(self):
        self.pool.sync_configured(["a.example"])
        lease = self.pool.acquire("logical-1")
        self.assertTrue(self.pool.begin_revalidation(lease, proxy="p1"))
        row = self.pool.list_public(status="verifying")["items"][0]
        self.assertEqual(row["bot_first_failures"], 1)
        self.assertIsNone(self.pool.acquire("logical-2"))
        self.pool.complete_revalidation(lease, clean=False, proxy="p2")
        row = self.pool.list_public(status="disabled")["items"][0]
        self.assertEqual(row["disabled_reason"], "BOT_MARKED_TWICE")
        self.assertEqual(row["bot_second_failures"], 1)

    def test_clean_revalidation_reenables_and_retains_history(self):
        self.pool.sync_configured(["a.example"])
        lease = self.pool.acquire("logical-1")
        self.pool.begin_revalidation(lease, proxy="p1")
        self.pool.complete_revalidation(lease, clean=True, proxy="p2")
        row = self.pool.list_public()["items"][0]
        self.assertEqual(row["status"], "enabled")
        self.assertEqual(row["bot_first_failures"], 1)
        self.assertEqual(row["bot_second_failures"], 0)

    def test_parallel_marked_does_not_complete_owner_chain(self):
        self.pool.sync_configured(["a.example"])
        owner = self.pool.acquire("owner")
        parallel = self.pool.acquire("parallel")
        self.pool.begin_revalidation(owner, proxy="p1")
        self.assertFalse(self.pool.begin_revalidation(parallel, proxy="p2"))
        self.pool.record_parallel_marked(parallel, proxy="p2")
        row = self.pool.list_public(status="verifying")["items"][0]
        self.assertEqual(row["bot_second_failures"], 0)
        self.assertEqual(row["bot_failures"], 2)
        self.pool.complete_revalidation(owner, clean=True, proxy="p3")

    def test_restart_recovers_interrupted_revalidation(self):
        self.pool.sync_configured(["a.example"])
        lease = self.pool.acquire("logical-1")
        self.pool.begin_revalidation(lease, proxy="p1")
        restored = DomainPool(self.path)
        row = restored.list_public()["items"][0]
        self.assertEqual(row["status"], "enabled")
        self.assertEqual(row["events"][-1]["code"], "REVALIDATION_INTERRUPTED")

    def test_page_size_supports_two_thousand(self):
        self.pool.sync_configured([f"d{i}.example.com" for i in range(250)])
        data = self.pool.list_public(per_page=2000)
        self.assertEqual(data["per_page"], 2000)
        self.assertEqual(len(data["items"]), 250)

    def test_archive_is_persistent_and_filterable(self):
        self.pool.sync_configured(["a.example"])
        row = self.pool.list_public()["items"][0]
        self.pool.archive([row["id"]])
        self.assertEqual(self.pool.list_public()["total"], 0)
        archived = DomainPool(self.path).list_public(status="archived")
        self.assertEqual(archived["total"], 1)
        stored = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(stored["domains"][0]["status"], "archived")

    def test_pristine_delete_is_hard_but_history_is_archived(self):
        self.pool.add(["new.example"])
        pristine = self.pool.list_public()["items"][0]
        result = self.pool.delete_or_archive([pristine["id"]])
        self.assertEqual(result, {"removed": 1, "archived": 0})

        self.pool.sync_configured(["used.example"])
        used = self.pool.list_public()["items"][0]
        self.pool.set_email_health(used["id"], ok=True, message="ok")
        result = self.pool.delete_or_archive([used["id"]])
        self.assertEqual(result, {"removed": 0, "archived": 1})


if __name__ == "__main__":
    unittest.main()
