import base64
import copy
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from flask import Flask

from g.account_check import (AccountChecker, CheckRegistry, chat_url, credential_version,
                             inspect_stream, now, parse_bot_page, risk_state)
from g.account_check_api import create_check_blueprint
from g.account_check_jobs import CheckJobs
from g.classification_store import ClassificationStore


def jwt(claims):
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return "eyJhbGciOiJub25lIn0." + payload + ".signature"


def account(bfs=False):
    return {"id": "one", "email": "private@example.test", "sso": jwt({"session_id": "private"}),
            "auth_token": {"access_token": jwt({"sub": "private", **({"bfs": 0} if bfs else {})}), "refresh_token": "private-refresh"}}


class Response:
    def __init__(self, code=200, text="{}", headers=None, payload=None, lines=None):
        self.status_code = code
        self.text = text
        self.headers = headers or {}
        self.payload = payload or {}
        self.lines = lines or []
        self.closed = False

    def json(self):
        return self.payload

    def close(self):
        self.closed = True

    def iter_lines(self):
        return iter(self.lines)


class NoWait:
    def is_set(self):
        return False

    def wait(self, _seconds):
        return False


def healthy(*_args, **_kwargs):
    return {"state": "clean", "reason": "HEALTHY", "checked_at": now()}


class DetectorTests(unittest.TestCase):
    def test_numeric_bot_flag_is_auxiliary_but_policy_deny_blocks(self):
        self.assertEqual(risk_state({"ok": True, "bot_flag_source": 1, "clean": False}), "review")
        self.assertEqual(risk_state({"ok": True, "policy": "deny"}), "marked")
        self.assertEqual(risk_state({"ok": False, "infra_error": True}), "infra_retry")

    def test_page_policy_and_escaped_rsc_are_auxiliary(self):
        self.assertEqual(parse_bot_page(r'{\"botFlagSource\":2}')["state"], "review")
        self.assertEqual(parse_bot_page('{"botFlagDetails":"policy=deny"}')["state"], "review")
        self.assertEqual(parse_bot_page("<html>challenge</html>")["state"], "unknown")

    def test_sse_metrics_require_usage_and_complete_output(self):
        events = [
            {"choices": [{"delta": {"reasoning_content": "thinking"}}]},
            {"choices": [{"delta": {"content": "reply"}}]},
            {"choices": [{"finish_reason": "stop"}], "usage": {"completion_tokens": 64}},
        ]
        lines = ["data: " + json.dumps(e) for e in events] + ["data: [DONE]"]
        clock = iter([1.0, 2.0, 3.0]).__next__
        result = inspect_stream(lines, clock=clock, started=0)
        self.assertEqual(result["state"], "clean")
        self.assertEqual(result["tps"], 64.0)
        events[2].pop("usage")
        lines = ["data: " + json.dumps(e) for e in events]
        result = inspect_stream(lines, clock=iter([1, 2, 3]).__next__, started=0)
        self.assertEqual(result["reason"], "INSUFFICIENT_SAMPLE")

    def test_incomplete_stream_is_not_clean(self):
        result = inspect_stream(['data: {"choices":[{"delta":{"content":"x"}}]}'],
                                clock=iter([1, 2]).__next__, started=0)
        self.assertEqual(result["reason"], "INCOMPLETE_STREAM")

    def test_passive_mode_has_no_network_or_oauth_and_never_claims_full_clean(self):
        network = Mock(side_effect=AssertionError("network must not run"))
        checker = AccountChecker(get=network, post=network, risk_probe=network, exchange=network)
        self.assertEqual(checker.check(account(), passive=True)["reason"], "PASSIVE_ONLY")
        self.assertEqual(checker.check(account(True), passive=True)["state"], "marked")
        network.assert_not_called()

    def test_bfs_stops_chat_before_any_message(self):
        post = Mock(side_effect=AssertionError("chat must not run"))
        checker = AccountChecker(post=post)
        self.assertEqual(checker.check(account(True))["state"], "marked")
        post.assert_not_called()

    def test_403_must_have_explicit_account_error(self):
        for response, expected in [
            (Response(403, headers={"Content-Type": "application/json"}, payload={"error": {"code": "gateway_denied"}}), "review"),
            (Response(403, headers={"Content-Type": "text/html"}), "infra_retry"),
            (Response(403, headers={"Content-Type": "application/json"}, payload={"error": {"code": "account_disabled"}}), "marked"),
            (Response(403, headers={"Content-Type": "application/json"}, payload={"error": {"code": "insufficient_quota"}}), "review"),
        ]:
            with self.subTest(expected=expected):
                checker = AccountChecker(post=Mock(return_value=response))
                result = checker._chat(account(), {"base_url": "https://example.test/v1", "model": "test", "max_tokens": 256, "timeout": 10}, "", lambda: False)
                self.assertEqual(result["state"], expected)
                self.assertTrue(response.closed)

    def test_401_refresh_once_and_rechecks_bfs(self):
        checker = AccountChecker(get=lambda *a, **k: Response(), refresh=Mock(return_value=account(True)["auth_token"]))
        checker._chat = Mock(return_value={"state": "marked", "reason": "UNAUTHORIZED", "status_code": 401})
        self.assertEqual(checker.check(account(), cancel=NoWait())["state"], "marked")
        self.assertEqual(checker._chat.call_count, 1)
        self.assertEqual(checker.refresh.call_count, 1)

    def test_refresh_transports_are_not_misreported_as_account_bans(self):
        checker = AccountChecker(get=lambda *a, **k: Response(), refresh=Mock(side_effect=RuntimeError("secret")))
        checker._chat = Mock(return_value={"state": "marked", "reason": "UNAUTHORIZED", "status_code": 401})
        self.assertEqual(checker.check(account())["reason"], "REFRESH_UNAVAILABLE")

    def test_429_waits_retry_after_without_changing_proxy(self):
        checker = AccountChecker(get=lambda *a, **k: Response())
        checker._chat = Mock(side_effect=[{"state": "review", "reason": "RATE_LIMIT", "status_code": 429, "retry_after": 12}, healthy()])
        cancel = Mock(wraps=NoWait())
        self.assertEqual(checker.check(account(), cancel=cancel)["state"], "clean")
        cancel.wait.assert_called_with(12)
        self.assertEqual(checker._chat.call_count, 2)
        self.assertEqual(checker._chat.call_args_list[0].args[2], checker._chat.call_args_list[1].args[2])

    def test_large_retry_after_is_deferred(self):
        checker = AccountChecker(get=lambda *a, **k: Response())
        checker._chat = Mock(return_value={"state": "review", "reason": "RATE_LIMIT", "status_code": 429, "retry_after": 600})
        result = checker.check(account(), cancel=NoWait())
        self.assertEqual(result["quality"]["retry_after"], 600)
        self.assertEqual(checker._chat.call_count, 1)

    def test_degradation_retest_cannot_silently_upgrade_disagreement(self):
        checker = AccountChecker(get=lambda *a, **k: Response())
        checker._chat = Mock(side_effect=[{"state": "review", "reason": "MISSING_THINKING"}, healthy()])
        self.assertEqual(checker.check(account(), cancel=NoWait())["reason"], "INCONSISTENT_SAMPLES")

    def test_headers_redirects_and_transport_error_redaction(self):
        post = Mock(side_effect=RuntimeError("private-refresh user:password@proxy"))
        checker = AccountChecker(post=post)
        result = checker._chat(account(), {"base_url": "https://example.test/v1", "model": "test", "max_tokens": 256, "timeout": 10}, "", lambda: False)
        self.assertEqual(result["reason"], "TRANSPORT_ERROR")
        self.assertNotIn("private-refresh", json.dumps(result))
        self.assertFalse(post.call_args.kwargs["allow_redirects"])
        self.assertEqual(post.call_args.kwargs["proxies"], {"http": "", "https": ""})

    def test_destination_cannot_include_embedded_credentials(self):
        for url in ("http://example.test/v1", "https://user:password@example.test", "https://example.test?a=key"):
            with self.assertRaises(ValueError):
                chat_url(url)


class CheckJobTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.checker = Mock()
        self.checker.check.side_effect = healthy
        self.jobs = CheckJobs(self.root, self.checker)
        self.addCleanup(self.jobs.executor.shutdown)

    def wait(self):
        self.jobs.executor.submit(lambda: None).result(timeout=5)

    def run_upload(self, raw=None, passive=False):
        preview = self.jobs.preview("upload", text=json.dumps(raw or account()), json_format=True)
        job = self.jobs.start(preview["preview_id"], passive=passive)
        self.wait()
        return self.jobs.get(job["id"])

    def test_reports_and_api_never_contain_credentials_email_or_proxy(self):
        raw = account()
        raw["_proxy_spec"] = "http://user:password@proxy.test:80"
        job = self.run_upload(raw)
        report = (self.jobs.directory / (job["id"] + ".json")).read_text()
        for secret in (raw["email"], raw["sso"], raw["auth_token"]["access_token"], "private-refresh", "user:password"):
            self.assertNotIn(secret, report)
            self.assertNotIn(secret, json.dumps(job))
        self.assertFalse(any(k.startswith("_") for k in job["items"][0]))
        self.assertEqual((self.jobs.directory / (job["id"] + ".json")).stat().st_mode & 0o777, 0o600)

    def test_preview_does_not_apply_then_apply_is_idempotent(self):
        self.checker.check.side_effect = lambda *a, **k: {"state": "review", "reason": "MISSING_THINKING", "checked_at": now()}
        job = self.run_upload()
        self.assertFalse(self.jobs.registry.blocked(account()))
        self.assertEqual(self.jobs.apply(job["id"])["changed"], 1)
        self.assertTrue(self.jobs.registry.blocked(account()))
        self.assertEqual(self.jobs.apply(job["id"])["changed"], 0)

    def test_passive_clean_cannot_clear_an_existing_block(self):
        self.jobs.registry.put(account(), {"state": "marked", "reason": "PREVIOUS"})
        self.checker.check.side_effect = lambda *a, **k: {"state": "unchecked", "reason": "PASSIVE_ONLY", "checked_at": now()}
        job = self.run_upload(passive=True)
        self.assertEqual(self.jobs.apply(job["id"])["changed"], 0)
        self.assertTrue(self.jobs.registry.blocked(account()))

    def test_apply_rejects_rotated_source_credentials(self):
        root = self.root / "converted_auth" / "cpa"
        root.mkdir(parents=True)
        path = root / "one.json"
        raw = account()
        path.write_text(json.dumps(raw))
        preview = self.jobs.preview("cpa", names=[path.name])
        job = self.jobs.start(preview["preview_id"])
        self.wait()
        raw["auth_token"]["access_token"] = jwt({"sub": "different"})
        path.write_text(json.dumps(raw))
        self.assertEqual(self.jobs.apply(job["id"]), {"changed": 0, "skipped": 1})
        self.assertNotIn("account_check", json.loads(path.read_text()))

    def test_older_report_cannot_overwrite_newer_applied_result(self):
        job = self.run_upload()
        self.jobs.registry.put(account(), {"state": "marked", "reason": "NEWER", "checked_at": "9999-01-01T00:00:00"})
        self.assertEqual(self.jobs.apply(job["id"])["changed"], 0)
        self.assertTrue(self.jobs.registry.blocked(account()))

    def test_manually_disabled_file_stays_disabled_after_clean(self):
        root = self.root / "converted_auth" / "cpa"
        root.mkdir(parents=True)
        path = root / "one.json"
        path.write_text(json.dumps({**account(), "disabled": True}))
        p = self.jobs.preview("cpa", names=[path.name])
        job = self.jobs.start(p["preview_id"])
        self.wait()
        self.jobs.apply(job["id"])
        self.assertTrue(json.loads(path.read_text())["disabled"])

    def test_restarts_mark_inflight_interrupted_without_replaying_requests(self):
        with self.jobs.lock:
            job = self.jobs._new_job(1, "upload")
        recovered = CheckJobs(self.root, self.checker)
        self.addCleanup(recovered.executor.shutdown)
        self.assertEqual(recovered.get(job["id"])["status"], "interrupted")
        self.checker.check.assert_not_called()

    def test_cancelled_queued_job_does_not_call_checker(self):
        gate = threading.Event()
        self.jobs.executor.submit(lambda: gate.wait(3))
        p = self.jobs.preview("upload", text=json.dumps(account()), json_format=True)
        job = self.jobs.start(p["preview_id"])
        self.jobs.cancel(job["id"])
        gate.set()
        self.wait()
        result = self.jobs.get(job["id"])
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(result["cancelled_count"], 1)
        self.checker.check.assert_not_called()

    def test_cooldown_does_not_start_another_request(self):
        raw = account()
        from g.account_check import fingerprints
        self.jobs.cooldowns[fingerprints(raw)[0]] = time.time() + 600
        result = self.run_upload(raw)
        self.assertEqual(result["items"][0]["reason"], "RATE_LIMIT")
        self.checker.check.assert_not_called()

    def test_path_traversal_and_symlinks_rejected(self):
        with self.assertRaises(ValueError):
            self.jobs.preview("keys", names=["../secret.txt"])
        root = self.root / "keys"
        root.mkdir()
        (self.root / "secret.txt").write_text("sso")
        (root / "link.txt").symlink_to(self.root / "secret.txt")
        with self.assertRaises(ValueError):
            self.jobs.preview("keys", names=["link.txt"])

    def test_review_classification_is_mutually_exclusive(self):
        store = ClassificationStore(self.root / "batch.txt")
        store.finalize(email="a", sso="token", state="clean")
        store.finalize(email="a", sso="token", state="review")
        self.assertEqual(store.path_for("clean").read_text(), "")
        self.assertEqual(store.path_for("review").read_text(), "a----token\n")

    def test_refreshed_credentials_are_private_reused_and_applied(self):
        root = self.root / "converted_auth" / "cpa"
        root.mkdir(parents=True)
        path = root / "one.json"
        raw = account()["auth_token"]
        path.write_text(json.dumps(raw))
        replacement = {"access_token": jwt({"sub": "rotated"}), "refresh_token": "rotated-secret"}
        def rotate(a, *args, **kwargs):
            a["auth_token"] = dict(replacement)
            return healthy()
        self.checker.check.side_effect = rotate
        p = self.jobs.preview("cpa", names=[path.name])
        job = self.jobs.start(p["preview_id"])
        self.wait()
        self.assertEqual(json.loads(path.read_text())["access_token"], raw["access_token"])
        p2 = self.jobs.preview("cpa", names=[path.name])
        cached = self.jobs.previews[p2["preview_id"]][1][0]
        from g.account_check import normalize_account
        self.assertEqual(normalize_account(cached)["auth_token"]["access_token"], replacement["access_token"])
        self.assertNotIn("rotated-secret", json.dumps(self.jobs.get(job["id"])))
        self.assertEqual(self.jobs.apply(job["id"])["changed"], 1)
        self.assertEqual(json.loads(path.read_text())["refresh_token"], "rotated-secret")

    def test_registry_blocks_pending_and_review_for_all_import_targets(self):
        from g.import_services import ImportConfigStore, ImportJobManager, ImportTargets
        config = ImportConfigStore(self.root, env_reader=lambda: {})
        manager = ImportJobManager(self.root, config, ImportTargets(self.root, config),
                                   sub2api_importer=Mock(), token_exchanger=Mock())
        self.addCleanup(manager._executor.shutdown)
        for state, reason in [("unchecked", "CHECK_PENDING"), ("review", "MISSING_THINKING")]:
            self.jobs.registry.put(account(), {"state": state, "reason": reason})
            with self.assertRaises(ValueError):
                manager.create_job([{**account(), "clean": True}], ["grok2api_web"], source={})

    def test_report_retention_prunes_only_generated_completed_reports(self):
        for _ in range(102):
            job = self.jobs._new_job(1, "upload")
            job["status"] = "completed"
            self.jobs._persist(job)
        self.jobs._prune()
        self.assertEqual(len(self.jobs.jobs), 100)
        self.assertEqual(len(list(self.jobs.directory.glob("*.json"))), 100)

    def test_report_retention_uses_creation_time_not_last_apply(self):
        job = self.jobs._new_job(1, "upload")
        job.update(status="completed", created_at="2000-01-01T00:00:00+00:00")
        self.jobs._persist(job)
        self.jobs._prune()
        self.assertNotIn(job["id"], self.jobs.jobs)


class CheckAPITests(unittest.TestCase):
    def test_all_data_and_write_routes_require_monitor_token(self):
        import app as webapp
        with tempfile.TemporaryDirectory() as temp:
            jobs = CheckJobs(Path(temp), Mock())
            self.addCleanup(jobs.executor.shutdown)
            app = Flask(__name__)
            app.register_blueprint(create_check_blueprint(jobs, webapp.require_monitor_token))
            client = app.test_client()
            with patch.object(webapp, "MONITOR_TOKEN", "test-only"):
                for method, path in [("get", ""), ("get", "/jobs"), ("get", "/jobs/id"), ("post", "/config"),
                                     ("post", "/preview"), ("post", "/jobs"), ("post", "/jobs/id/apply"), ("post", "/jobs/id/cancel")]:
                    with self.subTest(path=path):
                        self.assertEqual(getattr(client, method)("/api/account-checks" + path).status_code, 401)
                self.assertEqual(client.get("/api/account-checks", headers={"X-Monitor-Token": "test-only"}).status_code, 200)


class CheckRegistrationTests(unittest.TestCase):
    def test_review_never_auto_imports_clean_is_queued_once(self):
        import grok
        for state in ("review", "clean"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                (root / "keys").mkdir()
                engine = grok.RegisterEngine(log_fn=lambda *args: None)
                self.addCleanup(engine._enrich_pool.shutdown)
                engine.output_file = str(root / "keys" / "batch.txt")
                engine._classification_store = ClassificationStore(engine.output_file)
                engine._enrich_pending = engine.pending_bfs_count = 1
                engine.account_check_callback = Mock(return_value={"state": state, "reason": "TEST"})
                engine.auto_import_callback = Mock()
                token = {**account()["auth_token"], "expires_in": 3600}
                with patch.object(grok, "_BASE_DIR", root), patch.object(engine, "_exchange_token_after_clean", return_value=token), \
                     patch.object(grok, "UserAgreementService", return_value=Mock(accept_tos_version=Mock(return_value={"ok": False}))), \
                     patch.object(grok, "NsfwSettingsService", Mock()):
                    engine._enrich_after_sso(email="a@example.test", sso=account()["sso"], sso_rw="", success_id="",
                                             impersonate="", user_agent="", risk_gated=True)
                self.assertEqual(engine.pending_bfs_count, 0)
                self.assertEqual(engine._enrich_pending, 0)
                self.assertEqual(engine.recent_success[0]["risk_status"], state)
                if state == "review":
                    engine.auto_import_callback.assert_not_called()
                    self.assertTrue(CheckRegistry(root).blocked(account()))
                else:
                    engine.auto_import_callback.assert_called_once()
                    self.assertTrue(engine.recent_success[0]["auto_queued"])


if __name__ == "__main__":
    unittest.main()
