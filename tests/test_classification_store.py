import json
import tempfile
import unittest
from pathlib import Path

from g.classification_store import ClassificationStore


class ClassificationStoreTests(unittest.TestCase):
    def test_final_classification_is_mutually_exclusive(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ClassificationStore(Path(temp) / "batch.txt")
            store.finalize(email="a@example.test", sso="sso-a", state="clean")
            store.finalize(
                email="a@example.test",
                sso="sso-a",
                state="marked",
                reason="BFS",
                metadata={"bfs": 2},
            )
            self.assertEqual(store.path_for("clean").read_text(encoding="utf-8"), "")
            self.assertIn("a@example.test----sso-a", store.path_for("marked").read_text(encoding="utf-8"))
            meta = json.loads(store.marked_meta_path.read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(meta["reason"], "BFS")
            self.assertNotIn("sso", meta)

    def test_pending_journal_is_removed_on_finalize(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ClassificationStore(Path(temp) / "batch.txt")
            store.add_pending(email="a@example.test", sso="sso-a", data={"proxy_id": "p1"})
            self.assertEqual(len(store.pending()), 1)
            store.finalize(email="a@example.test", sso="sso-a", state="clean")
            self.assertEqual(store.pending(), [])


if __name__ == "__main__":
    unittest.main()

