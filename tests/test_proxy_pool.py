import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from g.proxy_pool import (
    ProxyPool,
    expand_proxy_template,
    mask_proxy,
    parse_proxy_line,
    parse_proxy_lines,
)
from g.same_session_register import parse_proxy_spec


class ProxyParserTests(unittest.TestCase):
    def test_supported_formats_normalize(self):
        cases = {
            "host.test:8080": "http://host.test:8080",
            "user:pass@host.test:8080": "http://user:pass@host.test:8080",
            "host.test:8080:user:pass": "http://user:pass@host.test:8080",
            "socks5h://user:pass@host.test:1080": "socks5h://user:pass@host.test:1080",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(parse_proxy_line(raw)["spec"], expected)

    def test_invalid_lines_report_line_and_duplicates(self):
        rows, errors, duplicates = parse_proxy_lines(
            "host.test:8080\ninvalid\nhost.test:8080\n"
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(duplicates, 1)
        self.assertEqual(errors[0]["line"], 2)

    def test_credentials_are_masked_and_templates_expand(self):
        spec = parse_proxy_line("user-{session}:secret@host.test:8080")["spec"]
        self.assertNotIn("secret", mask_proxy(spec))
        expanded = expand_proxy_template(spec, account="a@example.com", session="abc123")
        self.assertIn("user-abc123", expanded)
        self.assertNotIn("{session}", expanded)

    def test_special_credentials_are_decoded_once_for_browser(self):
        normalized = parse_proxy_line("http://user%40name:p%3Aass@host.test:8080")["spec"]
        parsed = parse_proxy_spec(normalized)
        self.assertEqual(parsed["username"], "user@name")
        self.assertEqual(parsed["password"], "p:ass")


class ProxyPoolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "proxy_pool.json"
        self.pool = ProxyPool(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_empty_pool_is_explicit_direct(self):
        lease = self.pool.acquire("account")
        self.assertTrue(lease.direct)
        self.assertEqual(lease.audit(), {"proxy_mode": "direct"})

    def test_round_robin_and_per_proxy_exclusion(self):
        result = self.pool.import_text("one.test:8001\ntwo.test:8002")
        self.assertTrue(result["ok"])
        first = self.pool.acquire("one")
        second = self.pool.acquire("two")
        self.assertNotEqual(first.proxy_id, second.proxy_id)
        self.pool.release(first, "success")
        self.pool.release(second, "success")
        third = self.pool.acquire("three", exclude={first.proxy_id}, wait=False)
        self.assertEqual(third.proxy_id, second.proxy_id)
        self.pool.release(third)

    def test_concurrency_cap_is_atomic(self):
        self.pool.import_text("one.test:8001")
        lease = self.pool.acquire("one")
        self.assertIsNone(self.pool.acquire("two", wait=False))
        self.pool.release(lease)
        self.assertIsNotNone(self.pool.acquire("two", wait=False))

    def test_network_failure_cools_proxy(self):
        self.pool.import_text("one.test:8001")
        lease = self.pool.acquire("one")
        self.pool.release(lease, "network", "timeout")
        public = self.pool.list_public()["items"][0]
        self.assertGreater(public["cooldown_remaining"], 0)
        self.assertEqual(public["health"], "unhealthy")
        self.assertIsNone(self.pool.acquire("two", wait=False))

    def test_failed_health_recheck_resets_cooldown(self):
        self.pool.import_text("one.test:8001")
        proxy_id = self.pool.list_public()["items"][0]["id"]
        self.pool.set_health(proxy_id, {"ok": False, "error": "timeout"})
        first_deadline = self.pool._runtime[proxy_id]["cooldown_until"]
        self.pool._runtime[proxy_id]["cooldown_until"] = time.time() - 1
        self.assertEqual(self.pool.begin_due_health_checks(), [proxy_id])

        self.pool.set_health(proxy_id, {"ok": False, "error": "timeout again"})
        second_deadline = self.pool._runtime[proxy_id]["cooldown_until"]
        self.assertGreater(second_deadline, first_deadline)
        self.assertEqual(self.pool.begin_due_health_checks(), [])

    def test_persistence_contains_secret_but_public_api_does_not(self):
        self.pool.import_text("user:secret@one.test:8001")
        stored = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertIn("secret", stored["proxies"][0]["spec"])
        public = json.dumps(self.pool.list_public(), ensure_ascii=False)
        self.assertNotIn("secret", public)
        self.assertIn("******", public)

    def test_delete_busy_proxy_is_deferred(self):
        self.pool.import_text("one.test:8001")
        lease = self.pool.acquire("one")
        result = self.pool.delete([lease.proxy_id])
        self.assertEqual(result["pending"], 1)
        self.pool.release(lease)
        self.assertEqual(self.pool.summary()["total"], 0)

    def test_replace_keeps_busy_entry_until_release(self):
        self.pool.import_text("one.test:8001")
        lease = self.pool.acquire("one")
        result = self.pool.import_text("two.test:8002", mode="replace")
        self.assertTrue(result["ok"])
        items = self.pool.list_public(per_page=10)["items"]
        self.assertEqual(len(items), 2)
        self.assertTrue(any(x["pending_delete"] for x in items))
        self.pool.release(lease)
        self.assertEqual(self.pool.summary()["total"], 1)

    def test_bot_failure_atomically_disables_and_persists(self):
        self.pool.import_text("one.test:8001")
        lease = self.pool.acquire("one")
        isolated = self.pool.disable_for_bot(
            lease,
            domain="mail.example",
            logical_id="logical-1",
            message="policy=deny",
        )
        self.assertFalse(isolated["enabled"])
        self.assertEqual(isolated["disabled_reason"], "BOT_MARKED")
        self.assertEqual(isolated["bot_failures"], 1)
        self.assertEqual(isolated["in_use"], 0)
        self.assertIsNone(self.pool.acquire("two", wait=False))

        restored = ProxyPool(self.path).list_public()["items"][0]
        self.assertFalse(restored["enabled"])
        self.assertEqual(restored["isolation_events"][-1]["domain"], "mail.example")

    def test_retry_excludes_same_known_egress(self):
        self.pool.import_text("one.test:8001\ntwo.test:8002\nthree.test:8003")
        ids = [x["id"] for x in self.pool.list_public(per_page=10)["items"]]
        self.pool.set_health(ids[0], {"ok": True, "egress_ip": "1.2.3.4"})
        self.pool.set_health(ids[1], {"ok": True, "egress_ip": "1.2.3.4"})
        self.pool.set_health(ids[2], {"ok": True, "egress_ip": "5.6.7.8"})
        excluded = self.pool.retry_exclusions({ids[0]}, "1.2.3.4")
        self.assertEqual(excluded, {ids[0], ids[1]})
        lease = self.pool.acquire("retry", exclude=excluded, wait=False)
        self.assertEqual(lease.proxy_id, ids[2])
        self.pool.release(lease)


if __name__ == "__main__":
    unittest.main()
