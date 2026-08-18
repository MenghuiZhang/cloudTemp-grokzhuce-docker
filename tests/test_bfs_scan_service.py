import base64
import json
import tempfile
import unittest
from pathlib import Path

from g.bfs_scan_service import apply_scan_report, preview_scan, set_token_bound_override


def jwt(payload):
    enc = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'none'})}.{enc(payload)}.sig"


class BfsScanServiceTests(unittest.TestCase):
    def test_preview_then_apply_disables_flagged_without_reporting_token(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            auth = root / "auth" / "flag.json"
            auth.parent.mkdir()
            token = jwt({"sub": "one", "bfs": 0})
            auth.write_text(json.dumps({"email": "one@example.test", "access_token": token}), encoding="utf-8")
            result = preview_scan([auth.parent], root / "reports")
            report_text = Path(result["report_path"]).read_text(encoding="utf-8")
            self.assertNotIn(token, report_text)
            self.assertEqual(result["counts"]["flagged"], 1)
            applied = apply_scan_report(result["report_path"])
            self.assertEqual(applied["changed"], 1)
            saved = json.loads(auth.read_text(encoding="utf-8"))
            self.assertTrue(saved["disabled"])
            self.assertEqual(saved["bfs_status"], "flagged")

    def test_override_is_bound_to_current_token(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "flag.json"
            path.write_text(json.dumps({"access_token": jwt({"bfs": 2}), "disabled": True}), encoding="utf-8")
            result = set_token_bound_override(path, reason="reviewed")
            saved = json.loads(path.read_text(encoding="utf-8"))
            self.assertFalse(saved["disabled"])
            self.assertEqual(saved["bfs_override"]["token_fingerprint"], result["token_fingerprint"])


if __name__ == "__main__":
    unittest.main()
