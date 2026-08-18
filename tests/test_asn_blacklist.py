import tempfile
import unittest
from pathlib import Path

from g.asn_blacklist import AsnBlacklistStore, AUTO_TTL_SECONDS


class AsnBlacklistTests(unittest.TestCase):
    def test_manual_entry_is_persistent(self):
        with tempfile.TemporaryDirectory() as temp:
            store = AsnBlacklistStore(Path(temp) / "asn.json")
            store.add_manual("AS64500", "operator", now=100)
            blocked, meta = store.is_blocked(64500, now=10_000_000)
            self.assertTrue(blocked)
            self.assertEqual(meta["source"], "manual")

    def test_requires_five_distinct_ips_and_auto_expires(self):
        with tempfile.TemporaryDirectory() as temp:
            store = AsnBlacklistStore(Path(temp) / "asn.json")
            now = 1_000_000.0
            for index in range(4):
                result = store.record_risk_marked(asn=64501, ip=f"192.0.2.{index + 1}", now=now + index)
                self.assertFalse(result["learned"])
            store.record_risk_marked(asn=64501, ip="192.0.2.1", now=now + 5)
            self.assertFalse(store.is_blocked(64501, now=now + 5)[0])
            result = store.record_risk_marked(asn=64501, ip="192.0.2.5", now=now + 6)
            self.assertTrue(result["learned"])
            self.assertTrue(store.is_blocked(64501, now=now + 7)[0])
            self.assertFalse(store.is_blocked(64501, now=now + 6 + AUTO_TTL_SECONDS + 1)[0])


if __name__ == "__main__":
    unittest.main()

