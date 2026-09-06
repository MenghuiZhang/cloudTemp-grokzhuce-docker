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
from g.account_check_jobs import ActiveJobError, CheckJobs, account_check_delay_seconds
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

    def test_delayed_registration_path_sends_exactly_one_chat_on_same_proxy(self):
        raw = {**account(), "_proxy_spec": "http://register-proxy.test:8080"}
        checker = AccountChecker()
        checker._chat = Mock(return_value=healthy())
        result = checker.check_chat_once(raw)
        self.assertEqual(result["state"], "clean")
        checker._chat.assert_called_once()
        self.assertEqual(checker._chat.call_args.args[2], raw["_proxy_spec"])

    def test_delay_setting_defaults_and_clamps(self):
        self.assertEqual(account_check_delay_seconds("invalid"), 60)
        self.assertEqual(account_check_delay_seconds(-1), 0)
        self.assertEqual(account_check_delay_seconds(5000), 3600)


class CheckJobTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.checker = Mock()
        self.checker.check.side_effect = healthy
        self.jobs = CheckJobs(self.root, self.checker)
        self.addCleanup(self.jobs.shutdown)

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
        self.addCleanup(recovered.shutdown)
        self.assertEqual(recovered.get(job["id"])["status"], "interrupted")
        self.checker.check.assert_not_called()

    def test_registration_check_waits_then_finishes_with_private_state_removed(self):
        checker = Mock()
        checker.check_chat_once.side_effect = healthy
        applied = Mock()
        clock = [1000.0]
        jobs = CheckJobs(
            self.root / "delayed",
            checker,
            registration_result=applied,
            delay_seconds=60,
            clock=lambda: clock[0],
        )
        self.addCleanup(jobs.shutdown)
        raw = {**account(), "_proxy_spec": "http://same-session.test:8080"}
        pending = jobs.check_registration(raw)
        self.assertEqual(pending["state"], "pending_check")
        checker.check_chat_once.assert_not_called()
        pending_path = jobs._pending_path(pending["job_id"])
        self.assertEqual(pending_path.stat().st_mode & 0o777, 0o600)
        report = (jobs.directory / f"{pending['job_id']}.json").read_text()
        for secret in (raw["email"], raw["sso"], raw["_proxy_spec"], "private-refresh"):
            self.assertNotIn(secret, report)

        clock[0] = 1060.0
        jobs._scheduler_wake.set()
        deadline = time.time() + 5
        while time.time() < deadline and jobs.get(pending["job_id"])["status"] != "completed":
            time.sleep(0.01)
        final = jobs.get(pending["job_id"])
        self.assertEqual(final["status"], "completed")
        self.assertEqual(final["items"][0]["state"], "clean")
        checker.check_chat_once.assert_called_once()
        self.assertEqual(checker.check_chat_once.call_args.args[0]["_proxy_spec"], raw["_proxy_spec"])
        applied.assert_called_once()
        self.assertEqual(jobs.registry.get(raw)["state"], "clean")
        self.assertFalse(pending_path.exists())

    def test_scheduled_registration_check_resumes_after_restart(self):
        root = self.root / "resume"
        clock = [1000.0]
        first = CheckJobs(root, Mock(), delay_seconds=60, clock=lambda: clock[0])
        pending = first.check_registration(account())
        first.shutdown()

        clock[0] = 1060.0
        checker = Mock()
        checker.check_chat_once.side_effect = healthy
        applied = Mock()
        recovered = CheckJobs(
            root,
            checker,
            registration_result=applied,
            delay_seconds=60,
            clock=lambda: clock[0],
        )
        self.addCleanup(recovered.shutdown)
        deadline = time.time() + 5
        while time.time() < deadline and recovered.get(pending["job_id"])["status"] != "completed":
            time.sleep(0.01)
        self.assertEqual(recovered.get(pending["job_id"])["status"], "completed")
        checker.check_chat_once.assert_called_once()
        applied.assert_called_once()

    def test_running_registration_check_is_not_replayed_after_restart(self):
        root = self.root / "at-most-once"
        first = CheckJobs(root, Mock(), delay_seconds=60, clock=lambda: 1000.0)
        pending = first.check_registration(account())
        with first.lock:
            job = first.jobs[pending["job_id"]]
            job.update(status="running", started_at=now(), attempt_started_at=now())
            first._persist(job)
        first.shutdown()

        checker = Mock()
        applied = Mock()
        recovered = CheckJobs(root, checker, registration_result=applied)
        self.addCleanup(recovered.shutdown)
        job = recovered.get(pending["job_id"])
        self.assertEqual(job["status"], "interrupted")
        self.assertEqual(job["items"][0]["reason"], "CHECK_INTERRUPTED")
        checker.check_chat_once.assert_not_called()
        applied.assert_called_once()
        self.assertEqual(recovered.registry.get(account())["state"], "infra_retry")

    def test_committed_chat_result_is_preserved_and_only_application_resumes(self):
        root = self.root / "result-ready"
        first = CheckJobs(root, Mock(), delay_seconds=60, clock=lambda: 1000.0)
        pending = first.check_registration(account())
        with first.lock:
            job = first.jobs[pending["job_id"]]
            row = first._pending_row(account(), state="clean", reason="HEALTHY")
            job.update(status="running", completed=1, items=[row])
            job["counts"]["pending_check"] = 0
            job["counts"]["clean"] = 1
            first._persist(job)
            # Simulate a crash after the idempotent registry write but before
            # the durable ``applying`` marker. The callback has not started.
            first.registry.put(account(), row)
        first.shutdown()

        checker = Mock()
        applied = Mock()
        recovered = CheckJobs(root, checker, registration_result=applied)
        self.addCleanup(recovered.shutdown)
        job = recovered.get(pending["job_id"])
        self.assertEqual(job["status"], "completed")
        self.assertEqual(job["items"][0]["state"], "clean")
        checker.check_chat_once.assert_not_called()
        applied.assert_called_once()
        self.assertEqual(recovered.registry.get(account())["state"], "clean")

    def test_application_stage_is_not_replayed_after_restart(self):
        root = self.root / "application-at-most-once"
        first = CheckJobs(root, Mock(), delay_seconds=60, clock=lambda: 1000.0)
        pending = first.check_registration(account())
        with first.lock:
            job = first.jobs[pending["job_id"]]
            row = first._pending_row(account(), state="clean", reason="HEALTHY")
            job.update(status="applying", completed=1, items=[row], application_started_at=now())
            job["counts"]["pending_check"] = 0
            job["counts"]["clean"] = 1
            first._persist(job)
        first.shutdown()

        checker = Mock()
        applied = Mock()
        recovered = CheckJobs(root, checker, registration_result=applied)
        self.addCleanup(recovered.shutdown)
        job = recovered.get(pending["job_id"])
        self.assertEqual(job["status"], "interrupted")
        self.assertEqual(job["items"][0]["state"], "clean")
        self.assertIn("未重放副作用", job["message"])
        checker.check_chat_once.assert_not_called()
        applied.assert_not_called()
        self.assertEqual(recovered.registry.get(account())["state"], "clean")
        self.assertFalse(recovered._pending_path(pending["job_id"]).exists())
        with self.assertRaisesRegex(ValueError, "不允许手动重放"):
            recovered.apply(pending["job_id"])

    def test_initial_job_persist_failure_leaves_no_in_memory_orphan(self):
        root = self.root / "persist-failure"
        jobs = CheckJobs(root, Mock(), delay_seconds=60)
        self.addCleanup(jobs.shutdown)
        with patch.object(jobs, "_persist", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                jobs.check_registration(account())
        self.assertEqual(jobs.jobs, {})
        self.assertEqual(jobs.cancels, {})

    def test_result_callback_failure_does_not_replace_real_check_state(self):
        root = self.root / "callback-failure"
        checker = Mock()
        checker.check_chat_once.side_effect = healthy
        jobs = CheckJobs(
            root,
            checker,
            registration_result=Mock(side_effect=RuntimeError("apply failed")),
            delay_seconds=0,
        )
        self.addCleanup(jobs.shutdown)
        pending = jobs.check_registration(account())
        deadline = time.time() + 5
        while time.time() < deadline and jobs.get(pending["job_id"])["status"] != "completed":
            time.sleep(0.01)
        job = jobs.get(pending["job_id"])
        self.assertEqual(job["items"][0]["state"], "clean")
        self.assertFalse(job["items"][0]["applied"])
        self.assertEqual(jobs.registry.get(account())["state"], "clean")

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
        for state, reason in [("pending_check", "CHECK_PENDING"), ("review", "MISSING_THINKING")]:
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

    def test_delete_finished_history_removes_report_but_keeps_registry(self):
        job = self.run_upload()
        self.jobs.registry.put(account(), {"state": "marked", "reason": "TEST"})
        self.jobs._write_pending_account(job["id"], account())
        report_path = self.jobs.directory / (job["id"] + ".json")
        pending_path = self.jobs._pending_path(job["id"])

        self.assertEqual(self.jobs.delete(job["id"]), {"id": job["id"]})

        self.assertFalse(report_path.exists())
        self.assertFalse(pending_path.exists())
        self.assertTrue(self.jobs.registry.blocked(account()))
        with self.assertRaises(KeyError):
            self.jobs.get(job["id"])

    def test_delete_rejects_active_jobs_and_clear_history_keeps_them(self):
        active_job = self.jobs._new_job(1, "upload")
        finished_job = self.jobs._new_job(1, "upload")
        finished_job["status"] = "failed"
        self.jobs._persist(finished_job)

        with self.assertRaises(ActiveJobError):
            self.jobs.delete(active_job["id"])
        self.assertEqual(self.jobs.clear_history(), 1)
        self.assertIn(active_job["id"], self.jobs.jobs)
        self.assertNotIn(finished_job["id"], self.jobs.jobs)
        self.assertTrue((self.jobs.directory / (active_job["id"] + ".json")).exists())


class CheckAPITests(unittest.TestCase):
    def test_routes_need_no_token_and_delete_only_finished_jobs(self):
        with tempfile.TemporaryDirectory() as temp:
            jobs = CheckJobs(Path(temp), Mock())
            self.addCleanup(jobs.shutdown)
            app = Flask(__name__)
            app.register_blueprint(create_check_blueprint(jobs))
            client = app.test_client()
            self.assertEqual(client.get("/api/account-checks").status_code, 200)

            finished_job = jobs._new_job(1, "upload")
            finished_job["status"] = "completed"
            jobs._persist(finished_job)
            response = client.delete("/api/account-checks/jobs/" + finished_job["id"])
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["job"]["id"], finished_job["id"])

            active_job = jobs._new_job(1, "upload")
            response = client.delete("/api/account-checks/jobs/" + active_job["id"])
            self.assertEqual(response.status_code, 409)
            self.assertIn("不能删除", response.get_json()["message"])

            response = client.delete("/api/account-checks/jobs")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["deleted"], 0)


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
                engine.account_check_callback = Mock(return_value={"state": "pending_check", "reason": "CHECK_PENDING"})
                engine.auto_import_callback = Mock()
                token = {**account()["auth_token"], "expires_in": 3600}
                with patch.object(grok, "_BASE_DIR", root), patch.object(engine, "_exchange_token_after_clean", return_value=token), \
                     patch.object(grok, "UserAgreementService", return_value=Mock(accept_tos_version=Mock(return_value={"ok": False}))), \
                     patch.object(grok, "NsfwSettingsService", Mock()):
                    engine._enrich_after_sso(email="a@example.test", sso=account()["sso"], sso_rw="", success_id="",
                                             impersonate="", user_agent="", risk_gated=True)
                self.assertEqual(engine.pending_bfs_count, 0)
                self.assertEqual(engine._enrich_pending, 0)
                self.assertEqual(engine.recent_success[0]["risk_status"], "pending_check")
                engine.auto_import_callback.assert_not_called()
                queued_account = engine.account_check_callback.call_args.args[0]
                result = {"state": state, "reason": "TEST", "checked_at": now()}
                CheckRegistry(root).put(queued_account, result)
                engine.apply_delayed_account_check(queued_account, result)
                self.assertEqual(engine.recent_success[0]["risk_status"], state)
                if state == "review":
                    engine.auto_import_callback.assert_not_called()
                    self.assertTrue(CheckRegistry(root).blocked(account()))
                else:
                    engine.auto_import_callback.assert_called_once()
                    self.assertTrue(engine.recent_success[0]["auto_queued"])


if __name__ == "__main__":
    unittest.main()
