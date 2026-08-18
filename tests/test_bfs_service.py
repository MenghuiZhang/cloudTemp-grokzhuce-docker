import base64
import json
import tempfile
import unittest
from pathlib import Path

from g.bfs_service import (
    apply_bfs_metadata,
    inspect_jwt_bfs,
    inspect_token_bundle_bfs,
    scan_auth_dirs,
)


def jwt(payload):
    enc = lambda obj: base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    return f"{enc({'alg': 'none'})}.{enc(payload)}.sig"


class BfsServiceTests(unittest.TestCase):
    def test_key_presence_including_zero_is_flagged(self):
        self.assertFalse(inspect_jwt_bfs(jwt({"sub": "clean"}))["has_bfs"])
        self.assertTrue(inspect_jwt_bfs(jwt({"sub": "flag", "bfs": 0}))["has_bfs"])

    def test_bundle_prefers_flagged_source(self):
        info = inspect_token_bundle_bfs(
            access_token=jwt({"sub": "clean"}),
            sso=jwt({"sub": "flag", "bfs": 2}),
        )
        self.assertTrue(info["has_bfs"])
        self.assertEqual(info["source"], "sso")

    def test_unknown_is_disabled_not_clean(self):
        record = {"access_token": "opaque", "disabled": False}
        apply_bfs_metadata(record)
        self.assertIsNone(record["bfs"])
        self.assertFalse(record["bfs_checked"])
        self.assertEqual(record["bfs_status"], "unknown")
        self.assertTrue(record["disabled"])

    def test_opaque_issued_token_is_not_cleaned_by_readable_sso(self):
        info = inspect_token_bundle_bfs(
            access_token="opaque-access-token",
            sso=jwt({"sub": "old-session"}),
        )
        self.assertFalse(info["ok"])
        self.assertFalse(info["has_bfs"])

    def test_scan_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "flag.json").write_text(
                json.dumps({"email": "flag@example.test", "access_token": jwt({"bfs": 2})}),
                encoding="utf-8",
            )
            (root / "clean.json").write_text(
                json.dumps({"email": "clean@example.test", "access_token": jwt({"sub": "clean"})}),
                encoding="utf-8",
            )
            summary = scan_auth_dirs([root])
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["bfs_count"], 1)
        self.assertEqual(summary["clean_count"], 1)


if __name__ == "__main__":
    unittest.main()
