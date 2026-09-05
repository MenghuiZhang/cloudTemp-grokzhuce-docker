"""Bounded check jobs, private source loading and explicit historical application."""
from __future__ import annotations

import copy
import json
import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from g.account_check import (AccountChecker, CheckRegistry, DEFAULTS, STATES, chat_url,
                             credential_version, fingerprints, masked_email, normalize_account, now)
from g.bfs_service import atomic_write_json, token_fingerprint
from g.classification_store import ClassificationStore

SOURCE_DIRS = {"keys": "keys", "register_sso": "register_sso", "cpa": "converted_auth/cpa", "accounts": "keys"}


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
    def __init__(self, base_dir, checker=None, *, recent=None, apply_recent=None, file_lock=None, proxy_pool=None):
        self.base = Path(base_dir).resolve()
        self.directory = self.base / "data" / "account_checks"
        self.config_path = self.base / "data" / "account_checks_config.json"
        self.registry = CheckRegistry(self.base)
        self.checker = checker or AccountChecker()
        self.recent = recent or (lambda: [])
        self.apply_recent = apply_recent or (lambda account, result: None)
        self.file_lock = file_lock or threading.RLock()
        self.proxy_pool = proxy_pool
        self.lock = threading.RLock()
        self.slots = threading.BoundedSemaphore(2)
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="account-check-jobs")
        self.jobs = {}
        self.cancels = {}
        self.previews = {}
        self.cooldowns = {}
        self._load()

    def _load(self):
        if not self.directory.exists():
            return
        for path in self.directory.glob("*.json"):
            try:
                row = json.loads(path.read_text(encoding="utf-8"))
                if row.get("status") in ("running", "queued", "cancelling"):
                    row.update(status="interrupted", finished_at=now())
                    atomic_write_json(path, row)
                self.jobs[row["id"]] = row
            except (OSError, ValueError, KeyError):
                continue
        self._prune()

    def _prune(self):
        # Only generated, completed report files are subject to retention.
        finished = sorted((j for j in self.jobs.values() if j["status"] not in ("running", "queued", "cancelling")),
                          key=lambda j: j["created_at"], reverse=True)
        cutoff = time.time() - 30 * 86400
        for index, job in enumerate(finished):
            path = self.directory / (job["id"] + ".json")
            created = datetime.fromisoformat(job["created_at"]).timestamp()
            if index >= 100 or created < cutoff:
                path.unlink(missing_ok=True)
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
        self._persist(job)
        return job

    def cancel(self, job_id):
        with self.lock:
            if job_id not in self.jobs:
                raise KeyError("任务不存在")
            if job_id in self.cancels:
                self.cancels[job_id].set()
                self.jobs[job_id]["status"] = "cancelling"
                self._persist(self.jobs[job_id])
            return self.public(self.jobs[job_id])

    def _one(self, job, account, *, risk_prechecked=False):
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
        with self.lock:
            job = self._new_job(1, "automatic")
            job["status"] = "running"
        try:
            row = self._one(job, account, risk_prechecked=True)
            if row is None:
                row = {"state": "unchecked", "reason": "CANCELLED", "checked_at": now()}
            self.registry.put(account, row)
            row["applied"] = True
            job["status"] = "completed"
            return row
        finally:
            with self.lock:
                job["finished_at"] = now()
                if job["status"] == "running":
                    job["status"] = "failed"
                self._persist(job)
                self.cancels.pop(job["id"], None)
                self._prune()

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
