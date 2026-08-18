import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from g.domain_pool import DomainPool, DomainPoolError


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

    def test_new_domain_can_enable_without_health_check(self):
        self.pool.add(["new.example"])
        row = self.pool.list_public()["items"][0]
        self.assertEqual(row["status"], "disabled")
        enabled = self.pool.update(row["id"], {"enabled": True})
        self.assertEqual(enabled["status"], "enabled")
        self.assertEqual(enabled["email_health"], "untested")

    def test_reconcile_replaces_active_list_and_retains_history(self):
        self.pool.sync_configured(["old.example", "keep.example"])
        old = next(x for x in self.pool.list_public(per_page=10)["items"] if x["domain"] == "old.example")
        self.pool.set_email_health(old["id"], ok=True, message="historical")
        self.pool.update(old["id"], {"enabled": False})

        result = self.pool.reconcile_configured(["KEEP.EXAMPLE.", "new.example", "old.example"])

        self.assertEqual(result["active"], 3)
        self.assertEqual(result["added"], 1)
        rows = self.pool.list_public(per_page=10)["items"]
        self.assertEqual([x["domain"] for x in rows[:3]], ["keep.example", "new.example", "old.example"])
        restored = next(x for x in rows if x["domain"] == "old.example")
        self.assertEqual(restored["status"], "enabled")
        self.assertEqual(restored["email_health"], "healthy")

        result = self.pool.reconcile_configured(["new.example"])
        self.assertEqual(result["disabled"], 2)
        self.assertEqual(self.pool.active_domains(), ["new.example"])
        history = {x["domain"]: x for x in self.pool.list_public(per_page=10)["items"]}
        self.assertEqual(history["old.example"]["disabled_reason"], "CONFIG_REMOVED")
        self.assertEqual(history["old.example"]["email_health"], "healthy")

    def test_empty_reconcile_is_atomic(self):
        self.pool.sync_configured(["keep.example"])
        before = self.pool.list_public(per_page=10)["items"]
        with self.assertRaisesRegex(DomainPoolError, "域名列表为空"):
            self.pool.reconcile_configured(["", "not a domain"])
        self.assertEqual(self.pool.list_public(per_page=10)["items"], before)

    def test_reconcile_capacity_error_preserves_history_atomically(self):
        self.pool.sync_configured(["one.example", "two.example"])
        before = self.pool.list_public(per_page=10)["items"]
        with patch("g.domain_pool.MAX_DOMAINS", 2):
            with self.assertRaisesRegex(DomainPoolError, "旧域历史会保留"):
                self.pool.reconcile_configured(["one.example", "three.example"])
        self.assertEqual(self.pool.list_public(per_page=10)["items"], before)

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

    def test_archived_rows_migrate_to_disabled_with_history(self):
        self.path.write_text(json.dumps({
            "version": 1,
            "domains": [{
                "id": "legacy-id",
                "domain": "Legacy.Example.",
                "status": "archived",
                "events": [{"code": "OLD_EVENT", "message": "old"}],
            }],
        }), encoding="utf-8")

        restored = DomainPool(self.path)
        row = restored.list_public()["items"][0]
        self.assertEqual(row["domain"], "legacy.example")
        self.assertEqual(row["status"], "disabled")
        self.assertEqual(row["disabled_reason"], "MIGRATED_FROM_ARCHIVE")
        self.assertEqual([event["code"] for event in row["events"]], ["OLD_EVENT", "MIGRATED_FROM_ARCHIVE"])
        stored = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(stored["domains"][0]["status"], "disabled")

    def test_delete_removes_rows_even_with_history(self):
        self.pool.add(["new.example"])
        pristine = self.pool.list_public()["items"][0]
        result = self.pool.delete([pristine["id"]])
        self.assertEqual(result, {"removed": 1})

        self.pool.sync_configured(["used.example"])
        used = self.pool.list_public()["items"][0]
        self.pool.set_email_health(used["id"], ok=True, message="ok")
        result = self.pool.delete([used["id"]])
        self.assertEqual(result, {"removed": 1})
        self.assertEqual(self.pool.list_public()["total"], 0)

    def test_batch_add_normalizes_deduplicates_and_skips_invalid(self):
        self.pool.add(["existing.example"])
        result = self.pool.add([
            " Existing.Example. ",
            "new.example",
            "NEW.EXAMPLE.",
            "not a domain",
            "",
        ])
        self.assertEqual(result["added"], 1)
        self.assertEqual(result["duplicates"], 2)
        self.assertEqual(result["invalid"], 2)
        self.assertEqual(
            [row["domain"] for row in self.pool.list_public(per_page=10)["items"]],
            ["existing.example", "new.example"],
        )

    def test_batch_add_capacity_error_is_atomic(self):
        self.pool.add(["existing.example"])
        with patch("g.domain_pool.MAX_DOMAINS", 2):
            with self.assertRaises(DomainPoolError):
                self.pool.add(["one.example", "two.example"])
        self.assertEqual(
            [row["domain"] for row in self.pool.list_public(per_page=10)["items"]],
            ["existing.example"],
        )


if __name__ == "__main__":
    unittest.main()
