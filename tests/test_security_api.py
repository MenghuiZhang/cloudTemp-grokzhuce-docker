import unittest
from unittest.mock import patch

import app as webapp


class SecurityApiTests(unittest.TestCase):
    def test_bfs_write_api_requires_monitor_token(self):
        client = webapp.app.test_client()
        with patch.object(webapp, "MONITOR_TOKEN", "test-monitor-token"):
            response = client.post("/api/bfs-scan/preview")
        self.assertEqual(response.status_code, 401)

    def test_authorized_bfs_write_uses_header_and_redacts_paths(self):
        client = webapp.app.test_client()
        report = {
            "report_path": "/private/example/bfs-scan-example.json",
            "items": [{"path": "/private/example/account.json", "status": "clean"}],
        }
        with (
            patch.object(webapp, "MONITOR_TOKEN", "test-monitor-token"),
            patch.object(webapp, "preview_scan", return_value=report),
        ):
            response = client.post(
                "/api/bfs-scan/preview",
                headers={"X-Monitor-Token": "test-monitor-token"},
            )
        self.assertEqual(response.status_code, 201)
        payload = response.get_json()
        self.assertEqual(payload["report"], "bfs-scan-example.json")
        self.assertEqual(payload["items"][0]["file"], "account.json")
        self.assertNotIn("path", payload["items"][0])


if __name__ == "__main__":
    unittest.main()
