import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock

from g.import_services import ImportConfigStore, ImportJobManager, ImportTargets


class ImportConfigStoreTests(unittest.TestCase):
    def test_migrates_sub2api_and_never_returns_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = ImportConfigStore(
                root,
                env_reader=lambda: {
                    "SUB2API_URL": "https://sub.example",
                    "UPSTREAM_ADMIN_EMAIL": "admin@example.com",
                    "UPSTREAM_ADMIN_PASSWORD": "secret-value",
                    "SUB2API_GROK_GROUP_NAME": "paid-grok",
                },
            )
            config = store.load()
            self.assertEqual(config["services"]["sub2api"]["base_url"], "https://sub.example")
            redacted = store.redacted(config)
            sub2 = redacted["services"]["sub2api"]
            self.assertEqual(sub2["password"], "")
            self.assertTrue(sub2["password_set"])
            self.assertNotIn("secret-value", json.dumps(redacted))

    def test_blank_secret_keeps_saved_value_and_change_resets_test(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = ImportConfigStore(root, env_reader=lambda: {})
            saved = store.save({
                "services": {
                    "cpa": {
                        "base_url": "https://cap.example",
                        "management_key": "first-key",
                    }
                }
            })
            saved["test_states"]["cpa"] = {"status": "passed", "message": "ok", "tested_at": "now"}
            saved["services"]["cpa"]["auto_targets"] = ["cpa_local"]
            from g.import_services import _atomic_json

            _atomic_json(store.path, saved)
            changed = store.save({"services": {"cpa": {"base_url": "https://cap-2.example", "management_key": ""}}})
            self.assertEqual(changed["services"]["cpa"]["management_key"], "first-key")
            self.assertEqual(changed["services"]["cpa"]["auto_targets"], [])
            self.assertEqual(changed["test_states"]["cpa"]["status"], "untested")

    def test_browser_save_cannot_override_paths_or_test_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = ImportConfigStore(root, env_reader=lambda: {})
            saved = store.save({
                "paths": {"cpa_dir": "/tmp/escape"},
                "test_states": {"cpa": {"status": "passed"}},
            })
            self.assertEqual(saved["test_states"]["cpa"]["status"], "untested")
            self.assertEqual(saved["paths"]["cpa_dir"], str((root / "converted_auth" / "cpa").resolve()))


class ImportTargetTests(unittest.TestCase):
    def test_local_pool_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = ImportConfigStore(root, env_reader=lambda: {})
            targets = ImportTargets(root, store)
            cfg = store.load()
            first = targets.add_local("sso=abc.def.ghi", "one@example.com", cfg)
            second = targets.add_local("abc.def.ghi", "one@example.com", cfg)
            self.assertFalse(first["duplicate"])
            self.assertTrue(second["duplicate"])
            payload = json.loads(Path(cfg["paths"]["grok2api_token_file"]).read_text())
            self.assertEqual(len(payload["ssoBasic"]), 1)
            self.assertEqual(payload["ssoBasic"][0]["token"], "abc.def.ghi")

    def test_cpa_upload_uses_management_headers_and_singular_file_field(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = ImportConfigStore(root, env_reader=lambda: {})
            cfg = store.load()
            cfg["services"]["cpa"].update({"base_url": "https://cap.example", "management_key": "key"})
            targets = ImportTargets(root, store)
            response = Mock(status_code=200, text="ok")
            targets._request = Mock(return_value=response)
            result = targets.upload_cpa({"email": "a@example.com", "access_token": "token"}, cfg)
            self.assertTrue(result["ok"])
            args, kwargs = targets._request.call_args
            self.assertEqual(args[0], "POST")
            self.assertTrue(args[1].endswith("/v0/management/auth-files"))
            self.assertEqual(kwargs["headers"]["X-Management-Key"], "key")
            self.assertIn("file", kwargs["files"])
            self.assertNotIn("files", kwargs["files"])

    def test_chenyme_import_parses_complete_event(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = ImportConfigStore(root, env_reader=lambda: {})
            cfg = store.load()
            cfg["services"]["grok2api"].update({
                "base_url": "https://grok.example",
                "username": "admin",
                "password": "pw",
            })
            targets = ImportTargets(root, store)
            targets._chenyme_login = Mock(return_value="jwt")
            targets._request = Mock(return_value=Mock(
                status_code=200,
                text='event: complete\ndata: {"created":1,"updated":0,"synced":1,"syncFailed":0}\n\n',
            ))
            result = targets.import_chenyme_sso("web", "sso=value", "a@example.com", cfg)
            self.assertEqual(result["created"], 1)
            _, kwargs = targets._request.call_args
            self.assertIn("files", kwargs["files"])

    def test_jiujiu_legacy_fallback_requires_etag_and_uses_if_match(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = ImportConfigStore(root, env_reader=lambda: {})
            cfg = store.load()
            cfg["services"]["grok2api"].update({
                "remote_type": "jiujiu",
                "base_url": "https://old.example",
                "app_key": "app-key",
                "allow_legacy_full_save": True,
            })
            targets = ImportTargets(root, store)
            responses = [
                Mock(status_code=404, text="missing"),
                Mock(status_code=404, text="missing"),
                Mock(status_code=200, text="", headers={"ETag": '"v1"'}, json=Mock(return_value={"ssoBasic": []})),
                Mock(status_code=200, text="saved"),
            ]
            targets._request = Mock(side_effect=responses)
            result = targets.import_jiujiu("abc.def.ghi", cfg)
            self.assertTrue(result["legacy"])
            args, kwargs = targets._request.call_args
            self.assertEqual(args[0], "POST")
            self.assertEqual(kwargs["headers"]["If-Match"], '"v1"')


class ImportJobManagerTests(unittest.TestCase):
    def test_oauth_is_exchanged_once_and_reused_across_cpa_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = ImportConfigStore(root, env_reader=lambda: {})
            targets = ImportTargets(root, store)
            targets.upload_cpa = Mock(return_value={"ok": True})
            targets.import_chenyme_build = Mock(return_value={"ok": True, "created": 1})
            exchanger = Mock(return_value={
                "ok": True,
                "token": {
                    "access_token": "header.payload.signature",
                    "refresh_token": "refresh",
                    "expires_in": 3600,
                },
            })
            manager = ImportJobManager(
                root,
                store,
                targets,
                sub2api_importer=Mock(return_value={"ok": True, "success": 1}),
                token_exchanger=exchanger,
            )
            job = manager.create_job(
                [{"id": "clean-1", "email": "c@example.com", "sso": "aaa.bbb.ccc", "clean": True}],
                ["cpa_local", "cpa_remote", "grok2api_build"],
                source={"type": "test"},
            )
            deadline = time.time() + 5
            while time.time() < deadline:
                current = manager.get(job["id"])
                if current and current["status"] not in ("queued", "running", "cancelling"):
                    break
                time.sleep(0.02)
            self.assertEqual(current["status"], "completed")
            self.assertEqual(exchanger.call_count, 1)
            self.assertEqual(targets.upload_cpa.call_count, 1)
            self.assertEqual(targets.import_chenyme_build.call_count, 1)
            self.assertTrue((root / "converted_auth" / "cpa" / "xai-c@example.com.json").is_file())

    def test_marked_account_only_runs_web_console(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = ImportConfigStore(root, env_reader=lambda: {})
            cfg = store.load()
            cfg["runtime"]["upload_workers"] = 2
            from g.import_services import _atomic_json

            _atomic_json(store.path, cfg)
            targets = ImportTargets(root, store)
            targets.import_chenyme_sso = Mock(return_value={"ok": True, "created": 1})
            manager = ImportJobManager(
                root,
                store,
                targets,
                sub2api_importer=Mock(return_value={"ok": True, "success": 1}),
                token_exchanger=Mock(return_value={"ok": False, "error": "must not exchange"}),
            )
            job = manager.create_job(
                [{"id": "marked-1", "email": "m@example.com", "sso": "aaa.bbb.ccc", "clean": False}],
                ["sub2api", "cpa_local", "grok2api_web", "grok2api_console"],
                source={"type": "test"},
            )
            deadline = time.time() + 5
            while time.time() < deadline:
                current = manager.get(job["id"])
                if current and current["status"] not in ("queued", "running", "cancelling"):
                    break
                time.sleep(0.02)
            current = manager.get(job["id"])
            self.assertEqual(current["status"], "completed")
            states = current["accounts"][0]["targets"]
            self.assertEqual(set(states), {"grok2api_web", "grok2api_console"})
            self.assertTrue(all(item["status"] == "success" for item in states.values()))

    def test_unchecked_account_cannot_auto_enter_sensitive_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = ImportConfigStore(root, env_reader=lambda: {})
            targets = ImportTargets(root, store)
            targets.import_chenyme_sso = Mock(return_value={"ok": True, "created": 1})
            sub2api = Mock(return_value={"ok": True, "success": 1})
            exchanger = Mock(return_value={"ok": False, "error": "must not exchange"})
            manager = ImportJobManager(
                root,
                store,
                targets,
                sub2api_importer=sub2api,
                token_exchanger=exchanger,
            )

            job = manager.create_job(
                [{
                    "id": "unchecked-1",
                    "email": "u@example.com",
                    "sso": "aaa.bbb.ccc",
                    "clean": None,
                }],
                ["sub2api", "cpa_local", "grok2api_build", "grok2api_web"],
                source={"type": "automatic"},
                automatic=True,
            )
            deadline = time.time() + 5
            while time.time() < deadline:
                current = manager.get(job["id"])
                if current and current["status"] not in ("queued", "running", "cancelling"):
                    break
                time.sleep(0.02)

            states = manager.get(job["id"])["accounts"][0]["targets"]
            self.assertEqual(set(states), {"grok2api_web"})
            sub2api.assert_not_called()
            exchanger.assert_not_called()


if __name__ == "__main__":
    unittest.main()
