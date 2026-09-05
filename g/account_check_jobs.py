"""Bounded check jobs, private source loading and explicit historical application."""
from __future__ import annotations

import copy
import json
import os
import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from g.account_check import (AccountChecker, CheckRegistry, DEFAULTS, STATES, chat_url,
                             credential_version, fingerprints, masked_email, normalize_account, now)
from g.bfs_service import atomic_write_json, token_fingerprint
from g.classification_store import ClassificationStore

SOURCE_DIRS = {"keys": "keys", "register_sso": "register_sso", "cpa": "converted_auth/cpa", "accounts": "keys"}


def account_check_delay_seconds(raw=None) -> int:
    value = raw if raw is not None else os.getenv("GROK_ACCOUNT_CHECK_DELAY_SECONDS", "60")
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        seconds = 60
    return max(0, min(seconds, 3600))


def record_rows(payload):
    if isinstance(payload, list):
        for value in payload:
            yield from record_rows(value)
    elif isinstance(payload, dict):
        if fingerprints(payload):
            yield payload
        else:
            for value in payload.values():
                if isinstance(value, (list, dict)):
                    yield from record_rows(value)


def parse_accounts(text: str, json_format: bool) -> list[dict]:
    if json_format:
        return [normalize_account({k: v for k, v in row.items() if not k.startswith("_")})
                for row in record_rows(json.loads(text))]
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        email, sso = line.rsplit("----", 1) if "----" in line else ("", line)
        rows.append(normalize_account({"email": email.split("----")[0], "sso": sso}))
    return rows


class CheckJobs:
    def __init__(self, base_dir, checker=None, *, recent=None, apply_recent=None,
                 registration_result=None, file_lock=None, proxy_pool=None,
                 delay_seconds=None, clock=None):
        self.base = Path(base_dir).resolve()
        self.directory = self.base / "data" / "account_checks"
        self.pending_directory = self.base / "data" / "account_check_pending"
        self.config_path = self.base / "data" / "account_checks_config.json"
        self.registry = CheckRegistry(self.base)
        self.checker = checker or AccountChecker()
        self.recent = recent or (lambda: [])
        self.apply_recent = apply_recent or (lambda account, result: None)
        self.registration_result = registration_result or (lambda account, result: None)
        self.file_lock = file_lock or threading.RLock()
        self.proxy_pool = proxy_pool
        self.delay_seconds = account_check_delay_seconds(delay_seconds)
        self.clock = clock or time.time
        self.lock = threading.RLock()
        self.slots = threading.BoundedSemaphore(2)
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="account-check-jobs")
        self.delayed_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="account-check-delayed")
        self.jobs = {}
        self.cancels = {}
        self.previews = {}
        self.cooldowns = {}
        self._scheduler_stop = threading.Event()
        self._scheduler_wake = threading.Event()
        self._scheduler_thread = None
        self._scheduled_inflight = set()
        self._load()

    def _load(self):
        if not self.directory.exists():
            return
        resume_scheduled = False
        interrupted = []
        resume_results = []
        uncertain_applications = []
        for path in self.directory.glob("*.json"):
            try:
                row = json.loads(path.read_text(encoding="utf-8"))
                delayed = bool(row.get("delayed_registration"))
                status = row.get("status")
                if delayed and status == "scheduled":
                    self.cancels[row["id"]] = threading.Event()
                    resume_scheduled = True
                elif delayed and status == "running" and row.get("items"):
                    # The chat response was already durably recorded. Resume
                    # only local result application; never replay the request.
                    row.update(status="result_ready", message="对话结果已恢复，等待应用")
                    atomic_write_json(path, row)
                    self.cancels[row["id"]] = threading.Event()
                    resume_results.append(row)
                elif delayed and status in ("running", "queued", "cancelling"):
                    # The request may already have left the process and no
                    # response was committed. Never replay it after a crash.
                    self.cancels[row["id"]] = threading.Event()
                    interrupted.append(row)
                elif delayed and status == "result_ready":
                    self.cancels[row["id"]] = threading.Event()
                    resume_results.append(row)
                elif delayed and status == "applying":
                    # The callback may already have queued an import. Preserve
                    # the real check result, but do not replay its side effects.
                    uncertain_applications.append(row)
                elif status in ("running", "queued", "cancelling", "scheduled"):
                    row.update(status="interrupted", finished_at=now())
                    atomic_write_json(path, row)
                self.jobs[row["id"]] = row
            except (OSError, ValueError, KeyError):
                continue
        for job in interrupted:
            self._finalize_interrupted_registration(job)
        for job in resume_results:
            self._apply_delayed_result(job["id"])
        for job in uncertain_applications:
            self._finalize_uncertain_application(job)
        self._prune()
        if resume_scheduled:
            self._ensure_scheduler()

    def _pending_path(self, job_id):
        return self.pending_directory / (str(job_id) + ".json")

    def _write_pending_account(self, job_id, account):
        atomic_write_json(self._pending_path(job_id), {"account": account})

    def _read_pending_account(self, job_id):
        path = self._pending_path(job_id)
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            account = value.get("account") if isinstance(value, dict) else None
            return account if isinstance(account, dict) else None
        except (OSError, ValueError):
            return None

    def _remove_pending_account(self, job_id):
        try:
            self._pending_path(job_id).unlink(missing_ok=True)
        except OSError:
            pass

    def _pending_row(self, account, *, state, reason):
        fp = fingerprints(account)
        return {
            "email": masked_email(account.get("email")),
            "fingerprint": fp[0][:16] if fp else "",
            "state": state,
            "reason": reason,
            "checked_at": now(),
            "_fingerprints": fp,
            "_version": credential_version(account),
            "_origin": None,
            "applied": False,
        }

    def _finalize_interrupted_registration(self, job):
        account = self._read_pending_account(job["id"])
        if not account:
            with self.lock:
                job.update(status="failed", finished_at=now(), message="运行中断，且待检测凭据无法恢复")
                self._persist(job)
                self.cancels.pop(job["id"], None)
            self._remove_pending_account(job["id"])
            return
        row = self._pending_row(account, state="infra_retry", reason="CHECK_INTERRUPTED")
        with self.lock:
            job["items"] = [row]
            job["completed"] = 1
            job["counts"] = {state: 0 for state in STATES}
            job["counts"]["infra_retry"] = 1
            job["status"] = "result_ready"
            job["interrupted_request"] = True
            job["message"] = "请求阶段中断，不重放对话"
            self._persist(job)
        self._apply_delayed_result(job["id"])

    def _apply_delayed_result(self, job_id):
        account = self._read_pending_account(job_id)
        with self.lock:
            job = self.jobs.get(job_id)
            if not job or job.get("status") != "result_ready":
                return
            row = job.get("items", [])[-1] if job.get("items") else None
            if not account or not isinstance(row, dict):
                job.update(status="failed", finished_at=now(), message="待应用的检测结果无法恢复")
                self._persist(job)
                self.cancels.pop(job_id, None)
                self._scheduled_inflight.discard(job_id)
                self._remove_pending_account(job_id)
                return

        errors = []
        try:
            self.registry.put(account, row)
        except Exception:
            errors.append("门禁状态保存失败")

        # Persist before invoking the callback. If the process dies during the
        # callback, startup sees ``applying`` and does not replay side effects.
        with self.lock:
            job["status"] = "applying"
            job["application_started_at"] = now()
            job["message"] = "正在应用延迟检测结果"
            self._persist(job)
        try:
            self.registration_result(account, row)
            row["applied"] = True
        except Exception:
            errors.append("结果应用失败")

        with self.lock:
            cancelled = bool(job.get("cancel_requested"))
            interrupted = bool(job.get("interrupted_request"))
            job["status"] = "interrupted" if interrupted else "cancelled" if cancelled else "completed"
            job["message"] = "、".join(errors) if errors else (
                "请求阶段中断，已按 INFRA_RETRY 收尾"
                if interrupted else "延迟检测已取消"
                if cancelled else "延迟对话检测完成"
            )
            job["finished_at"] = now()
            self._persist(job)
            self.cancels.pop(job_id, None)
            self._scheduled_inflight.discard(job_id)
        self._remove_pending_account(job_id)
        self._scheduler_wake.set()

    def _finalize_uncertain_application(self, job):
        account = self._read_pending_account(job["id"])
        row = job.get("items", [])[-1] if job.get("items") else None
        registry_failed = False
        if account and isinstance(row, dict):
            try:
                # Idempotent and safe to repeat; the external callback below is
                # intentionally not repeated.
                self.registry.put(account, row)
            except Exception:
                registry_failed = True
        with self.lock:
            job.update(
                status="interrupted",
                finished_at=now(),
                message=("结果应用阶段中断；未重放副作用"
                         + ("；门禁状态保存失败" if registry_failed else "")),
            )
            self._persist(job)
            self.cancels.pop(job["id"], None)
            self._scheduled_inflight.discard(job["id"])
        self._remove_pending_account(job["id"])

    def _ensure_scheduler(self):
        with self.lock:
            if self._scheduler_thread is not None and self._scheduler_thread.is_alive():
                self._scheduler_wake.set()
                return
            self._scheduler_stop.clear()
            self._scheduler_thread = threading.Thread(
                target=self._scheduler_loop,
                name="account-check-scheduler",
                daemon=True,
            )
            thread = self._scheduler_thread
        thread.start()

    def _scheduler_loop(self):
        while not self._scheduler_stop.is_set():
            due_job = None
            wait_for = None
            with self.lock:
                scheduled = [
                    job for job in self.jobs.values()
                    if job.get("delayed_registration")
                    and job.get("status") == "scheduled"
                    and job.get("id") not in self._scheduled_inflight
                ]
                if scheduled:
                    job = min(scheduled, key=lambda item: float(item.get("scheduled_epoch") or 0))
                    wait_for = max(0.0, float(job.get("scheduled_epoch") or 0) - float(self.clock()))
                    if wait_for <= 0:
                        due_job = str(job["id"])
                        self._scheduled_inflight.add(due_job)
            if due_job:
                try:
                    self.delayed_executor.submit(self._run_delayed_registration, due_job)
                except RuntimeError:
                    with self.lock:
                        self._scheduled_inflight.discard(due_job)
                continue
            self._scheduler_wake.wait(timeout=wait_for if wait_for is not None else 3600)
            self._scheduler_wake.clear()

    def _run_delayed_registration(self, job_id):
        account = self._read_pending_account(job_id)
        with self.lock:
            job = self.jobs.get(job_id)
            if not job or job.get("status") != "scheduled":
                self._scheduled_inflight.discard(job_id)
                return
            if not account:
                job.update(status="failed", finished_at=now(), message="待检测凭据无法恢复")
                self._persist(job)
                self._scheduled_inflight.discard(job_id)
                self.cancels.pop(job_id, None)
                self._remove_pending_account(job_id)
                return
            job.update(status="running", started_at=now(), attempt_started_at=now(),
                       message="正在执行延迟对话检测")
            job["counts"]["pending_check"] = 0
            self._persist(job)
        row = self._one(job, account, risk_prechecked=True, chat_once=True)
        if row is None:
            row = self._pending_row(account, state="unchecked", reason="CANCELLED")
            with self.lock:
                job["items"].append(row)
                job["completed"] = 1
                job["counts"]["unchecked"] = 1
                self._persist(job)
        with self.lock:
            job["status"] = "result_ready"
            job["message"] = "对话结果已持久化，等待应用"
            self._persist(job)
        self._apply_delayed_result(job_id)

    def shutdown(self, wait=True):
        self._scheduler_stop.set()
        self._scheduler_wake.set()
        thread = self._scheduler_thread
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=2 if wait else 0)
        self.executor.shutdown(wait=wait)
        self.delayed_executor.shutdown(wait=wait)

    def _prune(self):
        # Only generated, completed report files are subject to retention.
        finished = sorted((j for j in self.jobs.values() if j["status"] not in (
            "running", "queued", "cancelling", "scheduled", "result_ready", "applying"
        )),
                          key=lambda j: j["created_at"], reverse=True)
        cutoff = time.time() - 30 * 86400
        for index, job in enumerate(finished):
            path = self.directory / (job["id"] + ".json")
            created = datetime.fromisoformat(job["created_at"]).timestamp()
            if index >= 100 or created < cutoff:
                path.unlink(missing_ok=True)
                self._remove_pending_account(job["id"])
                self.jobs.pop(job["id"], None)

    def config(self):
        if not self.config_path.exists():
            return dict(DEFAULTS)
        return {**DEFAULTS, **json.loads(self.config_path.read_text(encoding="utf-8"))}

    def save_config(self, body):
        cfg = self.config()
        for key in DEFAULTS:
            if key in body:
                cfg[key] = body[key]
        if not isinstance(cfg["automatic"], bool):
            raise ValueError("automatic 必须是布尔值")
        chat_url(cfg["base_url"])
        if not isinstance(cfg["model"], str) or not cfg["model"].strip() or len(cfg["model"]) > 100:
            raise ValueError("模型名称无效")
        for key, lo, hi in (("workers", 1, 2), ("timeout", 10, 120), ("max_tokens", 32, 256)):
            cfg[key] = int(cfg[key])
            if not lo <= cfg[key] <= hi:
                raise ValueError(f"{key} 必须在 {lo}–{hi} 之间")
        atomic_write_json(self.config_path, cfg)
        return cfg

    @staticmethod
    def public(job):
        result = copy.deepcopy(job)
        result.pop("config", None)
        for row in result.get("items", []):
            for key in list(row):
                if key.startswith("_"):
                    row.pop(key)
        return result

    def list_jobs(self):
        with self.lock:
            return [{k: v for k, v in self.public(j).items() if k != "items"}
                    for j in sorted(self.jobs.values(), key=lambda j: j["created_at"], reverse=True)]

    def get(self, job_id):
        with self.lock:
            if job_id not in self.jobs:
                raise KeyError("任务不存在")
            return self.public(self.jobs[job_id])

    def _persist(self, job):
        atomic_write_json(self.directory / (job["id"] + ".json"), job)

    def files(self):
        result = {}
        for source, rel in SOURCE_DIRS.items():
            suffix = "*.txt" if source == "keys" else "*_accounts.json" if source == "accounts" else "*.json"
            root = self.base / rel
            result[source] = [p.name for p in sorted(root.glob(suffix)) if not p.is_symlink() and p.is_file()][:2000]
        return result

    def _safe_file(self, source, name):
        if source not in SOURCE_DIRS or Path(name).name != name or "\\" in name:
            raise ValueError("无效来源文件")
        root = self.base / SOURCE_DIRS[source]
        path = root / name
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError("来源文件不存在或不在允许目录")
        if path.stat().st_size > 10 * 1024 * 1024:
            raise ValueError("来源文件不能超过 10 MB")
        return path

    def preview(self, source, *, names=None, ids=None, text="", json_format=False):
        rows = []
        if source == "recent":
            rows = [normalize_account(r) for r in self.recent() if ids is None or str(r.get("id")) in ids]
        elif source == "upload":
            rows = parse_accounts(text, json_format)
        elif source in SOURCE_DIRS:
            if not isinstance(names, list) or not names or len(names) > 2000:
                raise ValueError("请选择来源文件（最多 2000 个）")
            total_bytes = 0
            for name in names:
                path = self._safe_file(source, str(name))
                total_bytes += path.stat().st_size
                if total_bytes > 20 * 1024 * 1024:
                    raise ValueError("本次来源总大小不能超过 20 MB")
                parsed = parse_accounts(path.read_text(encoding="utf-8-sig"), path.suffix == ".json")
                for row in parsed:
                    row["_origin"] = {"source": source, "file_hash": token_fingerprint(path.name)}
                rows.extend(parsed)
        else:
            raise ValueError("未知账号来源")
        unique = {}
        for row in rows:
            fp = fingerprints(row)
            if fp:
                unique.setdefault(fp[0], row)
        rows = list(unique.values())
        if not rows or len(rows) > 2000:
            raise ValueError("每个任务需要 1–2000 个有效账号")
        for row in rows:
            version = credential_version(row)
            row["_source_version"] = version
            row["_source_fingerprints"] = fingerprints(row)
            cache = self.base / "data" / "account_check_credentials" / (version + ".json")
            if cache.is_file():
                # A previously rotated refresh token must not be used a second time.
                bundle = json.loads(cache.read_text(encoding="utf-8"))
                if isinstance(bundle, dict) and bundle.get("access_token"):
                    row["auth_token"] = bundle
                    row["_credential_cache_id"] = token_fingerprint(version + credential_version(row))
        preview_id = uuid.uuid4().hex
        with self.lock:
            self.previews = {k: v for k, v in self.previews.items() if time.time() - v[0] < 1800}
            if len(self.previews) >= 10:
                self.previews.pop(next(iter(self.previews)))
            self.previews[preview_id] = (time.time(), rows, source)
        return {"preview_id": preview_id, "total": len(rows), "accounts": [
            {"email": masked_email(r.get("email")), "fingerprint": fingerprints(r)[0][:16],
             "has_token": bool(r["auth_token"]), "state": self.registry.get(r).get("state", "unchecked")}
            for r in rows]}

    def start(self, preview_id, passive=False):
        with self.lock:
            preview = self.previews.get(preview_id)
            if not preview or time.time() - preview[0] >= 1800:
                raise ValueError("预览已过期，请重新选择来源")
            if sum(j["status"] in ("running", "queued", "cancelling") for j in self.jobs.values()) >= 8:
                raise ValueError("检测队列已满，请等待当前任务结束")
            _, rows, source = self.previews.pop(preview_id)
            job = self._new_job(len(rows), source, passive)
            self.executor.submit(self._run, job["id"], rows)
            return self.public(job)

    def _new_job(self, total, source, passive=False):
        job_id = uuid.uuid4().hex
        job = {"id": job_id, "source": source, "passive": bool(passive), "status": "queued", "created_at": now(),
               "completed": 0, "total": total, "counts": {s: 0 for s in STATES}, "items": [], "config": self.config()}
        self.jobs[job_id] = job
        self.cancels[job_id] = threading.Event()
        try:
            self._persist(job)
        except Exception:
            self.jobs.pop(job_id, None)
            self.cancels.pop(job_id, None)
            raise
        return job

    def cancel(self, job_id):
        apply_now = False
        with self.lock:
            if job_id not in self.jobs:
                raise KeyError("任务不存在")
            if job_id in self.cancels:
                self.cancels[job_id].set()
                job = self.jobs[job_id]
                status = job.get("status")
                if job.get("delayed_registration") and status == "scheduled":
                    account = self._read_pending_account(job_id)
                    if account:
                        row = self._pending_row(account, state="unchecked", reason="CANCELLED")
                        job["items"] = [row]
                        job["completed"] = 1
                        job["counts"] = {state: 0 for state in STATES}
                        job["counts"]["unchecked"] = 1
                        job.update(status="result_ready", cancel_requested=True,
                                   message="延迟检测取消中")
                        apply_now = True
                    else:
                        job.update(status="failed", finished_at=now(), message="取消时待检测凭据无法恢复")
                        self.cancels.pop(job_id, None)
                        self._remove_pending_account(job_id)
                    self._scheduler_wake.set()
                elif job.get("delayed_registration") and status in ("running", "result_ready", "applying"):
                    job["cancel_requested"] = True
                    job["message"] = "正在取消；不会再发起新的对话请求"
                else:
                    job["status"] = "cancelling"
                self._persist(job)
            result = self.public(self.jobs[job_id])
        if apply_now:
            self._apply_delayed_result(job_id)
            with self.lock:
                result = self.public(self.jobs[job_id])
        return result

    def _one(self, job, account, *, risk_prechecked=False, chat_once=False):
        cancel = self.cancels[job["id"]]
        original = copy.deepcopy(account)
        lease = None
        try:
            while not self.slots.acquire(timeout=0.2):
                if cancel.is_set():
                    return None
            try:
                if cancel.is_set():
                    return None
                fp = fingerprints(account)[0]
                with self.lock:
                    remaining = self.cooldowns.get(fp, 0) - time.time()
                if remaining > 0:
                    result = {"state": "review", "reason": "RATE_LIMIT", "checked_at": now(),
                              "quality": {"retry_after": round(remaining)}}
                else:
                    if not job["passive"] and "_proxy_spec" not in account and self.proxy_pool:
                        original_proxy = ""
                        proxy_id = str(account.get("proxy_id") or "")
                        if proxy_id and proxy_id != "direct":
                            try:
                                from g.proxy_pool import expand_proxy_template
                                original_proxy = expand_proxy_template(self.proxy_pool.secret_spec(proxy_id), account="account-check", session=uuid.uuid4().hex[:16])
                            except KeyError:
                                pass
                        if original_proxy:
                            account["_proxy_spec"] = original_proxy
                        else:
                            lease = self.proxy_pool.acquire("account-check", wait=False)
                            account["_proxy_spec"] = lease.spec if lease else ""
                    if chat_once:
                        result = self.checker.check_chat_once(
                            account, job["config"], cancel=cancel
                        )
                    else:
                        result = self.checker.check(account, job["config"], passive=job["passive"],
                                                    risk_prechecked=risk_prechecked, cancel=cancel)
                delay = (result.get("quality") or {}).get("retry_after")
                if delay:
                    with self.lock:
                        self.cooldowns[fp] = time.time() + float(delay)
            finally:
                self.slots.release()
        except Exception:
            result = {"state": "infra_retry", "reason": "CHECK_FAILED", "checked_at": now()}
        finally:
            if lease is not None:
                self.proxy_pool.release(lease, "neutral")
        row = {"email": masked_email(account.get("email")), "fingerprint": fingerprints(original)[0][:16],
               **result, "_fingerprints": list(dict.fromkeys(original.get("_source_fingerprints", []) + fingerprints(original) + fingerprints(account))),
               "_version": original.get("_source_version") or credential_version(original), "_origin": original.get("_origin"), "applied": False}
        if original.get("_credential_cache_id"):
            row["_credential_cache"] = original["_credential_cache_id"]
        if credential_version(account) != credential_version(original) and account.get("auth_token"):
            # OAuth refresh can rotate credentials even before Apply. Keep the replacement
            # in a separate private credential store, never in a report/API response.
            cache_id = token_fingerprint(row["_version"] + credential_version(account))
            atomic_write_json(self.base / "data" / "account_check_credentials" / (cache_id + ".json"), account["auth_token"])
            atomic_write_json(self.base / "data" / "account_check_credentials" / (row["_version"] + ".json"), account["auth_token"])
            row["_credential_cache"] = cache_id
        with self.lock:
            job["items"].append(row)
            job["completed"] += 1
            job["counts"][row["state"]] += 1
            self._persist(job)
        return row

    def _run(self, job_id, rows):
        job = self.jobs[job_id]
        try:
            with self.lock:
                job["status"] = "running"
                self._persist(job)
            with ThreadPoolExecutor(max_workers=job["config"]["workers"], thread_name_prefix="account-check") as pool:
                futures = [pool.submit(self._one, job, account) for account in rows]
                for future in as_completed(futures):
                    future.result()
            job["status"] = "cancelled" if self.cancels[job_id].is_set() else "completed"
            job["cancelled_count"] = job["total"] - job["completed"] if job["status"] == "cancelled" else 0
        except Exception:
            job["status"] = "failed"
        finally:
            with self.lock:
                job["finished_at"] = now()
                self._persist(job)
                self.cancels.pop(job_id, None)
                self._prune()
            rows.clear()

    def check_registration(self, account):
        if not self.config()["automatic"]:
            return {"state": "unchecked", "reason": "AUTO_CHECK_DISABLED", "checked_at": now()}
        if not fingerprints(account):
            return {"state": "unchecked", "reason": "MISSING_CREDENTIALS", "checked_at": now()}
        scheduled_epoch = float(self.clock()) + self.delay_seconds
        scheduled_for = datetime.fromtimestamp(scheduled_epoch, timezone.utc).isoformat(timespec="seconds")
        with self.lock:
            job = self._new_job(1, "automatic")
            try:
                job.update(
                    status="scheduled",
                    delayed_registration=True,
                    scheduled_epoch=scheduled_epoch,
                    scheduled_for=scheduled_for,
                    message=f"等待 {self.delay_seconds} 秒后执行首次对话检测",
                )
                job["counts"]["pending_check"] = 1
                self._write_pending_account(job["id"], copy.deepcopy(account))
                self._persist(job)
            except Exception:
                job.update(status="failed", finished_at=now(), message="延迟检测任务持久化失败")
                self.cancels.pop(job["id"], None)
                self._remove_pending_account(job["id"])
                try:
                    self._persist(job)
                except Exception:
                    pass
                raise
        pending = {
            "state": "pending_check",
            "reason": "CHECK_PENDING",
            "checked_at": now(),
            "scheduled_for": scheduled_for,
            "job_id": job["id"],
        }
        try:
            self.registry.put(account, pending)
        except Exception:
            with self.lock:
                job.update(status="failed", finished_at=now(), message="PENDING_CHECK 门禁状态保存失败")
                self._persist(job)
                self.cancels.pop(job["id"], None)
            self._remove_pending_account(job["id"])
            raise
        self._ensure_scheduler()
        self._scheduler_wake.set()
        return pending

    def record_registration_observation(self, account, result):
        """Record an early Risk/BFS rejection without starting a chat request."""
        with self.lock:
            job = self._new_job(1, "automatic")
            row = {"email": masked_email(account.get("email")), "fingerprint": fingerprints(account)[0][:16],
                   "state": result["state"], "reason": result["reason"], "checked_at": now(), "applied": True}
            job.update(status="completed", completed=1, items=[row], finished_at=now())
            job["counts"][row["state"]] = 1
            self._persist(job)
            self.cancels.pop(job["id"], None)
            self._prune()

    def _resolve_row(self, row):
        origin = row.get("_origin")
        if not origin:
            for account in self.recent():
                if credential_version(account) == row["_version"]:
                    return account, None, None
            return None, None, None
        source = origin["source"]
        for name in self.files().get(source, []):
            if token_fingerprint(name) != origin["file_hash"]:
                continue
            path = self._safe_file(source, name)
            text = path.read_text(encoding="utf-8-sig")
            payload = json.loads(text) if path.suffix == ".json" else None
            records = record_rows(payload) if payload is not None else parse_accounts(text, False)
            for record in records:
                if credential_version(record) == row["_version"]:
                    return record, path, payload
        return None, None, None

    def apply(self, job_id):
        with self.lock, self.file_lock, self.registry._lock:
            job = self.jobs.get(job_id)
            if not job:
                raise KeyError("任务不存在")
            if job.get("delayed_registration"):
                raise ValueError("自动延迟检测结果由系统应用，不允许手动重放")
            if job["status"] not in ("completed", "cancelled", "interrupted"):
                raise ValueError("任务尚未结束")
            changed = skipped = 0
            for row in job["items"]:
                if row.get("applied") or row.get("reason") == "CANCELLED" or (job["passive"] and row["state"] != "marked"):
                    skipped += 1
                    continue
                account, path, payload = self._resolve_row(row)
                if account is None and job["source"] != "upload":
                    skipped += 1
                    continue
                # Uploads can apply their credential fingerprints without retaining secrets.
                with self.registry._lock:
                    data = self.registry._read()
                    if any(data.get(fp, {}).get("checked_at", "") > row["checked_at"] for fp in row["_fingerprints"]):
                        skipped += 1
                        continue
                    for fp in row["_fingerprints"]:
                        data[fp] = {k: row[k] for k in ("state", "reason", "checked_at")}
                    if row["state"] != "clean":
                        atomic_write_json(self.registry.path, data)
                if account is not None:
                    metadata = {k: row[k] for k in ("state", "reason", "checked_at")}
                    applied_account = dict(account)
                    cache_id = row.get("_credential_cache")
                    if cache_id:
                        if not re.fullmatch(r"[0-9a-f]{64}", cache_id):
                            raise ValueError("凭据缓存标识无效")
                        cache_path = self.base / "data" / "account_check_credentials" / (cache_id + ".json")
                        if cache_path.is_file():
                            bundle = json.loads(cache_path.read_text(encoding="utf-8"))
                            if account.get("access_token") or account.get("key"):
                                applied_account.update(bundle)
                            else:
                                applied_account["auth_token"] = bundle
                    self.apply_recent(applied_account, row)
                    account.update(applied_account)
                    account.update(account_check=metadata, risk_status=row["state"], clean=row["state"] == "clean")
                    if row["state"] != "clean":
                        if not account.get("disabled"):
                            account["account_check_disabled"] = True
                        account["disabled"] = True
                    elif account.pop("account_check_disabled", False):
                        account["disabled"] = False
                    if path is not None and payload is not None:
                        atomic_write_json(path, payload)
                    elif path is not None:
                        # Keep the source SSO text intact; classification is a sidecar.
                        ClassificationStore(path).finalize(email=str(account.get("email") or ""),
                            sso=normalize_account(account)["sso"], state=row["state"], reason=row["reason"])
                if row["state"] == "clean":
                    atomic_write_json(self.registry.path, data)
                row["applied"] = True
                changed += 1
            self._persist(job)
            return {"changed": changed, "skipped": skipped}


def runtime_checker():
    # Existing local adapters are imported lazily to avoid app/engine cycles.
    from curl_cffi import requests
    from g.antibot_service import AntibotService
    from grok import sso_device_flow_to_token
    from convert_sso_json import XAI_TOKEN_ENDPOINT, XAI_CLIENT_ID

    def exchange(sso, proxy, timeout):
        result = sso_device_flow_to_token(sso, timeout=timeout, issue_token=True, proxy_spec=proxy)
        token = result.get("token")
        if not isinstance(token, dict) or not token.get("access_token"):
            raise ValueError("OAuth unavailable")
        return token

    def refresh(account, proxy, timeout):
        token = account["auth_token"]
        if not token.get("refresh_token"):
            return exchange(account["sso"], proxy, timeout) if account["sso"] else None
        response = requests.post(XAI_TOKEN_ENDPOINT, data={"grant_type": "refresh_token", "client_id": XAI_CLIENT_ID,
            "refresh_token": token["refresh_token"]}, timeout=timeout, allow_redirects=False, proxies={"http": proxy, "https": proxy})
        try:
            if response.status_code in (400, 401, 403):
                return {"_rejected": True}
            if response.status_code != 200:
                raise ValueError("Refresh unavailable")
            data = response.json()
            if not data.get("access_token"):
                raise ValueError("Refresh unavailable")
            return {**token, **data}
        finally:
            response.close()

    return AccountChecker(risk_probe=lambda sso, proxy: AntibotService().probe_account_risk(sso, proxy_spec=proxy, timeout=20),
                          exchange=exchange, refresh=refresh)
