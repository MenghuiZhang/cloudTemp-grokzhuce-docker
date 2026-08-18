import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as webapp
from g.asn_blacklist import AsnBlacklistStore


class SecurityApiTests(unittest.TestCase):
    def test_asn_write_api_requires_monitor_token(self):
        client = webapp.app.test_client()
        with patch.object(webapp, "MONITOR_TOKEN", "test-monitor-token"):
            response = client.post("/api/asn-blacklist", json={"asn": "AS64500"})
        self.assertEqual(response.status_code, 401)

    def test_authorized_asn_write_uses_header_and_returns_redacted_state(self):
        with tempfile.TemporaryDirectory() as temp:
            client = webapp.app.test_client()
            store = AsnBlacklistStore(Path(temp) / "asn.json")
            with (
                patch.object(webapp, "MONITOR_TOKEN", "test-monitor-token"),
                patch.object(webapp, "asn_blacklist", store),
            ):
                response = client.post(
                    "/api/asn-blacklist",
                    json={"asn": "AS64500", "note": "example"},
                    headers={"X-Monitor-Token": "test-monitor-token"},
                )
            self.assertEqual(response.status_code, 201)
            payload = response.get_json()
            self.assertEqual(payload["items"][0]["asn"], 64500)
            self.assertNotIn("ip", payload["items"][0])


if __name__ == "__main__":
    unittest.main()
