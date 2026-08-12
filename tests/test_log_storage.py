import tempfile
import unittest
from pathlib import Path

from log_storage import (
    append_rotating_text,
    capture_stats,
    clear_capture_dirs,
    enforce_rotated_log,
    prune_capture_dirs,
)


class LogStorageTests(unittest.TestCase):
    def test_rotating_text_keeps_configured_total_file_count(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "service.log"
            for _ in range(8):
                append_rotating_text(path, "12345", max_bytes=10, file_count=3)

            files = sorted(path.parent.glob("service.log*"))
            self.assertEqual(
                [item.name for item in files],
                ["service.log", "service.log.1", "service.log.2"],
            )
            self.assertTrue(all(item.stat().st_size <= 10 for item in files))

    def test_capture_pruning_enforces_count_and_bytes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "fo_captures"
            for index in range(4):
                group = root / f"20260101_00000{index}_task"
                group.mkdir(parents=True)
                (group / "response.txt").write_bytes(b"x" * 10)

            result = prune_capture_dirs(root, max_groups=3, max_bytes=20)

            self.assertEqual(result["groups"], 2)
            self.assertEqual(result["bytes"], 20)
            self.assertEqual(result["removed_groups"], 2)
            self.assertFalse((root / "20260101_000000_task").exists())
            self.assertFalse((root / "20260101_000001_task").exists())

    def test_enforce_rotated_log_trims_files_and_removes_extra_backups(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "service.log"
            path.write_bytes(b"a" * 30)
            path.with_name("service.log.1").write_bytes(b"b" * 20)
            path.with_name("service.log.2").write_bytes(b"c" * 20)
            path.with_name("service.log.3").write_bytes(b"d" * 20)

            enforce_rotated_log(path, max_bytes=10, file_count=3)

            self.assertEqual(path.stat().st_size, 10)
            self.assertEqual(path.with_name("service.log.1").stat().st_size, 10)
            self.assertEqual(path.with_name("service.log.2").stat().st_size, 10)
            self.assertFalse(path.with_name("service.log.3").exists())

    def test_clear_capture_dirs_leaves_empty_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "fo_captures"
            group = root / "one"
            group.mkdir(parents=True)
            (group / "token.txt").write_text("secret", encoding="utf-8")

            result = clear_capture_dirs(root)

            self.assertEqual(result["removed_groups"], 1)
            self.assertEqual(capture_stats(root), {"groups": 0, "bytes": 0})
            self.assertTrue(root.exists())


if __name__ == "__main__":
    unittest.main()
