"""Account health checks. Responses are observations, never authentication proofs."""
from __future__ import annotations

import json
import math
import re
import threading
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlsplit

from curl_cffi import requests

from g.bfs_service import atomic_write_json, inspect_token_bundle_bfs, token_fingerprint

DEFAULT_BASE_URL = "https://cli-chat-proxy.grok.com/v1"
DEFAULT_MODEL = "grok-4.5"
STATES = ("clean", "marked", "review", "infra_retry", "unchecked", "pending_check")
DEFAULTS = {"automatic": True, "base_url": DEFAULT_BASE_URL, "model": DEFAULT_MODEL,
            "workers": 2, "timeout": 90, "max_tokens": 256}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def normalize_account(raw: dict) -> dict:
    result = dict(raw)
    result["sso"] = str(raw.get("sso") or raw.get("sso_cookie") or raw.get("sso_token") or "").removeprefix("sso=").strip()
    bundle = raw.get("auth_token") or raw.get("token")
    bundle = dict(bundle) if isinstance(bundle, dict) else {}
    for key in ("access_token", "refresh_token", "id_token", "key"):
        if raw.get(key):
            bundle.setdefault(key, str(raw[key]))
    result["auth_token"] = bundle
    return result


def fingerprints(account: dict) -> list[str]:
    a = normalize_account(account)
    values = [a["sso"], a["auth_token"].get("access_token") or a["auth_token"].get("key")]
    return list(dict.fromkeys(token_fingerprint(str(v)) for v in values if v))


def credential_version(account: dict) -> str:
    a = normalize_account(account)
    return token_fingerprint(json.dumps([a["sso"], a["auth_token"]], sort_keys=True))


def masked_email(value: str) -> str:
    local, sep, domain = str(value or "").partition("@")
    return f"{local[:1]}***@{domain[:1]}***" if sep else "未提供邮箱"


def chat_url(base: str) -> str:
    base = str(base or DEFAULT_BASE_URL).strip().rstrip("/")
    parts = urlsplit(base)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("检测地址须为不含凭据、查询串的 HTTP(S) 地址")
    if parts.scheme == "http" and parts.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("非本机检测地址必须使用 HTTPS")
    return base if parts.path.endswith("/chat/completions") else base + "/chat/completions"


def risk_state(risk: dict) -> str:
    if risk.get("infra_error") or not risk.get("ok"):
        return "infra_retry"
    if risk.get("denied") or str(risk.get("policy") or "").lower() == "deny":
        return "marked"
    if str(risk.get("bot_flag_source")) in ("1", "2") or risk.get("false_clean"):
        return "review"
    return "clean" if risk.get("clean") is True else "review"


def parse_bot_page(text: str) -> dict:
    # HTML and escaped RSC strings share the same field names.
    plain = str(text or "").replace('\\"', '"')
    source = re.search(r'"botFlagSource"\s*:\s*(?:"([^"]{0,80})"|([0-9]+))', plain)
    detail = re.search(r'"botFlagDetails"\s*:\s*"([^"\n]{0,2000})"', plain)
    value = (source.group(1) or source.group(2)) if source else ""
    # Page fields are auxiliary evidence, including page policy strings.
    suspicious = value in ("1", "2") or bool(detail and "policy=deny" in detail.group(1).lower())
    return {"state": "review" if suspicious else ("clean" if source or detail else "unknown"),
            "reason": "BOT_PAGE_FLAG" if suspicious else "BOT_PAGE_OBSERVATION"}


def retry_after(value: str) -> float:
    try:
        seconds = float(value)
    except (ValueError, TypeError):
        try:
            seconds = parsedate_to_datetime(value).timestamp() - time.time()
        except (ValueError, TypeError, OverflowError):
            return 30.0
    return max(1.0, seconds) if math.isfinite(seconds) else 30.0


def inspect_stream(lines, *, clock=time.monotonic, started=None, cancelled=lambda: False) -> dict:
    started = clock() if started is None else started
    first = last = None
    tokens = reasoning = 0
    thinking = output = finished = False
    size = 0
    for raw in lines:
        if cancelled():
            return {"state": "unchecked", "reason": "CANCELLED"}
        size += len(raw)
        if size > 2_000_000:
            return {"state": "infra_retry", "reason": "STREAM_TOO_LARGE"}
        line = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
        if not line.startswith("data:"):
            continue
        value = line[5:].strip()
        if value == "[DONE]":
            finished = True
            break
        try:
            event = json.loads(value)
        except (TypeError, ValueError):
            continue
        if not isinstance(event, dict):
            continue
        if event.get("error"):
            return {"state": "review", "reason": "STREAM_ERROR"}
        usage = event.get("usage") or {}
        if isinstance(usage, dict):
            try:
                tokens = max(tokens, int(usage.get("completion_tokens") or usage.get("output_tokens") or 0))
                details = usage.get("completion_tokens_details") or usage.get("output_tokens_details") or {}
                reasoning = max(reasoning, int(usage.get("reasoning_tokens") or details.get("reasoning_tokens") or 0))
            except (ValueError, TypeError, AttributeError):
                pass
        for choice in event.get("choices") or []:
            if not isinstance(choice, dict):
                continue
            finished |= bool(choice.get("finish_reason"))
            delta = choice.get("delta") or choice.get("message") or {}
            if not isinstance(delta, dict):
                continue
            has_thinking = any(delta.get(k) for k in ("reasoning_content", "thinking_content", "reasoning", "thinking"))
            thinking |= has_thinking
            if delta.get("content") or has_thinking:
                tick = clock()
                first = tick if first is None else first
                last = tick
                output |= bool(delta.get("content"))
    duration = max(0.0, clock() - started)
    gen = max(0.0, last - first) if first is not None and last is not None else 0
    tps = tokens / gen if gen > 0 else 0
    stats = {"output_tokens": tokens, "reasoning_tokens": reasoning, "has_thinking": thinking or reasoning > 0,
             "duration_ms": round(duration * 1000), "first_token_ms": round((first - started) * 1000) if first is not None else None,
             "gen_ms": round(gen * 1000), "tps": round(tps, 2)}
    reason = "HEALTHY"
    state = "clean"
    if not finished or not output:
        state, reason = "infra_retry", "INCOMPLETE_STREAM"
    elif tokens < 32 or gen <= 0:
        state, reason = "review", "INSUFFICIENT_SAMPLE"
    elif not stats["has_thinking"]:
        state, reason = "review", "MISSING_THINKING"
    elif tps >= 200:
        state, reason = "review", ("BURST" if gen < 1 else ("HIGH_TPS" if tps >= 1000 else "FAST_TPS"))
    return {"state": state, "reason": reason, **stats}


class CheckRegistry:
    """Token-bound import gate; no raw credentials or email addresses on disk."""
    _lock = threading.RLock()

    def __init__(self, base_dir: Path):
        self.path = Path(base_dir) / "data" / "account_check_states.json"

    def _read(self):
        if not self.path.exists():
            return {}
        value = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("检测状态文件损坏")
        return value

    def get(self, account: dict) -> dict:
        with self._lock:
            data = self._read()
            rows = [data[f] for f in fingerprints(account) if f in data]
            return max(rows, key=lambda r: r.get("checked_at", "")) if rows else {}

    def put(self, account: dict, result: dict) -> None:
        if result.get("state") not in STATES:
            raise ValueError("无效检测状态")
        with self._lock:
            data = self._read()
            row = {"state": result["state"], "reason": result["reason"],
                   "checked_at": result.get("checked_at") or now()}
            if result.get("scheduled_for"):
                row["scheduled_for"] = str(result["scheduled_for"])
            for fp in fingerprints(account):
                data[fp] = dict(row)
            atomic_write_json(self.path, data)

    def blocked(self, account: dict) -> bool:
        saved = self.get(account)
        if saved and saved.get("reason") in ("CHECK_PENDING", "OAUTH_PENDING"):
            return True
        state = saved.get("state") or account.get("check_state") or account.get("risk_status")
        return bool(state in ("marked", "risk_marked", "review", "infra_retry", "pending_check"))


class AccountChecker:
    def __init__(self, *, risk_probe=None, exchange=None, refresh=None, get=None, post=None, proxy_resolver=None):
        self.risk_probe = risk_probe
        self.exchange = exchange
        self.refresh = refresh
        self.get = get or requests.get
        self.post = post or requests.post
        self.proxy_resolver = proxy_resolver or (lambda account: str(account.get("_proxy_spec") or ""))

    def _chat(self, account, config, proxy, cancelled):
        bundle = account["auth_token"]
        token = bundle.get("access_token") or bundle.get("key") or ""
        if not token:
            return {"state": "unchecked", "reason": "MISSING_ACCESS_TOKEN"}
        endpoint = chat_url(config["base_url"])
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "text/event-stream"}
        if urlsplit(endpoint).hostname == "cli-chat-proxy.grok.com":
            from convert_sso_json import GROK_BUILD_HEADERS
            headers.update(GROK_BUILD_HEADERS)
        response = None
        try:
            started = time.monotonic()
            response = self.post(endpoint, headers=headers, json={"model": config["model"],
                "messages": [{"role": "user", "content": "Explain TCP slow start and congestion avoidance in twelve sentences."}],
                "max_tokens": config["max_tokens"], "temperature": 0.7, "stream": True,
                "stream_options": {"include_usage": True}},
                stream=True, timeout=config["timeout"], allow_redirects=False,
                proxies={"http": proxy, "https": proxy})
            code = response.status_code
            common = {"status_code": code}
            if code == 429:
                return {**common, "state": "review", "reason": "RATE_LIMIT", "retry_after": retry_after(response.headers.get("Retry-After", ""))}
            if code == 401:
                return {**common, "state": "marked", "reason": "UNAUTHORIZED"}
            if code == 403:
                # A gateway/challenge HTML page is not evidence of an account ban.
                is_json = "json" in str(response.headers.get("Content-Type") or "").lower()
                if is_json:
                    try:
                        body = response.json()
                        error = body.get("error") or body
                        error_code = str(error.get("code") or error.get("type") or "").lower() if isinstance(error, dict) else ""
                    except (ValueError, AttributeError):
                        error_code = ""
                    if error_code in ("insufficient_quota", "quota_exceeded", "rate_limit_exceeded"):
                        return {**common, "state": "review", "reason": "QUOTA_LIMIT"}
                    explicit = error_code in ("permission_denied", "permission-denied", "account_disabled", "account_banned", "access_denied")
                    return {**common, "state": "marked" if explicit else "review", "reason": "FORBIDDEN" if explicit else "UNCONFIRMED_FORBIDDEN"}
                return {**common, "state": "infra_retry", "reason": "GATEWAY_FORBIDDEN"}
            if code >= 500 or code == 407:
                return {**common, "state": "infra_retry", "reason": "UPSTREAM_ERROR"}
            if code != 200:
                return {**common, "state": "review", "reason": "REQUEST_REJECTED"}
            return {**common, **inspect_stream(response.iter_lines(), started=started, cancelled=cancelled)}
        except Exception:
            # Transport errors often embed request URLs, auth headers or proxy passwords.
            return {"state": "infra_retry", "reason": "TRANSPORT_ERROR"}
        finally:
            if response is not None:
                response.close()

    def check_chat_once(self, raw, config=None, *, cancel=None):
        """Run exactly one delayed registration chat check.

        Risk, OAuth and BFS have already completed before a registration enters
        the delayed queue.  Re-check BFS locally to avoid sending a token whose
        claims changed, but do not perform page probes, refreshes or chat
        retries here: the first and only conversation request must happen after
        the configured delay.
        """
        config = {**DEFAULTS, **(config or {})}
        account = normalize_account(raw)
        cancel = cancel or threading.Event()
        signals = []

        def finish(state, reason, **extra):
            return {"state": state, "reason": reason, "checked_at": now(),
                    "signals": signals, **extra}

        if cancel.is_set():
            return finish("unchecked", "CANCELLED")
        if not fingerprints(account):
            return finish("unchecked", "MISSING_CREDENTIALS")
        bundle = account["auth_token"]
        bfs = inspect_token_bundle_bfs(
            sso=account["sso"],
            access_token=str(bundle.get("access_token") or bundle.get("key") or ""),
            id_token=str(bundle.get("id_token") or ""),
            refresh_token=str(bundle.get("refresh_token") or ""),
        )
        signals.append({"layer": "bfs", "state": "marked" if bfs.get("has_bfs")
                        else "clean" if bfs.get("ok") else "unknown"})
        if bfs.get("has_bfs"):
            return finish("marked", "BFS_PRESENT")
        if not bfs.get("ok"):
            return finish("review" if bundle else "unchecked", "BFS_UNKNOWN")
        if cancel.is_set():
            return finish("unchecked", "CANCELLED")
        proxy = self.proxy_resolver(account)
        result = self._chat(account, config, proxy, cancel.is_set)
        signals.append({"layer": "chat", **result})
        return finish(result["state"], result["reason"], quality=result)

    def check(self, raw, config=None, *, passive=False, risk_prechecked=False, cancel=None):
        config = {**DEFAULTS, **(config or {})}
        account = normalize_account(raw)
        cancel = cancel or threading.Event()
        signals = []
        def finish(state, reason, **extra):
            return {"state": state, "reason": reason, "checked_at": now(), "signals": signals, **extra}
        if cancel.is_set():
            return finish("unchecked", "CANCELLED")
        if not fingerprints(account):
            return finish("unchecked", "MISSING_CREDENTIALS")
        proxy = self.proxy_resolver(account)
        sso = account["sso"]
        if sso and not passive and not risk_prechecked and self.risk_probe:
            risk = self.risk_probe(sso, proxy)
            state = risk_state(risk)
            if state == "marked" and not cancel.wait(1):
                confirmation = risk_state(self.risk_probe(sso, proxy))
                state = "marked" if confirmation == "marked" else "review"
            signals.append({"layer": "risk", "state": state})
            if state != "clean":
                return finish(state, "RISK_" + state.upper())
        if not passive and not (account["auth_token"].get("access_token") or account["auth_token"].get("key")) and sso and self.exchange:
            if cancel.is_set():
                return finish("unchecked", "CANCELLED")
            try:
                account["auth_token"] = self.exchange(sso, proxy, config["timeout"]) or {}
                raw["auth_token"] = dict(account["auth_token"])
            except Exception:
                return finish("unchecked", "OAUTH_UNAVAILABLE")
        bundle = account["auth_token"]
        bfs = inspect_token_bundle_bfs(sso=sso, access_token=str(bundle.get("access_token") or bundle.get("key") or ""),
                                      id_token=str(bundle.get("id_token") or ""), refresh_token=str(bundle.get("refresh_token") or ""))
        signals.append({"layer": "bfs", "state": "marked" if bfs.get("has_bfs") else "clean" if bfs.get("ok") else "unknown"})
        if bfs.get("has_bfs"):
            return finish("marked", "BFS_PRESENT")
        if not bfs.get("ok"):
            return finish("review" if bundle else "unchecked", "BFS_UNKNOWN")
        if passive:
            return finish("unchecked", "PASSIVE_ONLY")
        if sso:
            page = None
            try:
                page = self.get("https://grok.com/", cookies={"sso": sso}, proxies={"http": proxy, "https": proxy},
                                timeout=min(20, config["timeout"]), allow_redirects=False)
                observation = parse_bot_page(page.text) if page.status_code == 200 else {"state": "unknown", "reason": "BOT_PAGE_UNAVAILABLE"}
            except Exception:
                observation = {"state": "unknown", "reason": "BOT_PAGE_UNAVAILABLE"}
            finally:
                if page is not None:
                    page.close()
            signals.append({"layer": "bot_page", **observation})
            if observation["state"] == "review":
                return finish("review", "BOT_PAGE_FLAG")
        if cancel.is_set():
            return finish("unchecked", "CANCELLED")
        result = self._chat(account, config, proxy, cancel.is_set)
        if result.get("status_code") == 401 and self.refresh:
            try:
                refreshed = self.refresh(account, proxy, config["timeout"])
                if refreshed and refreshed.get("_rejected"):
                    return finish("marked", "CREDENTIAL_REJECTED")
                if refreshed:
                    account["auth_token"] = dict(refreshed)
                    raw["auth_token"] = dict(refreshed)
                    check = inspect_token_bundle_bfs(access_token=str(refreshed.get("access_token") or ""),
                        id_token=str(refreshed.get("id_token") or ""), refresh_token=str(refreshed.get("refresh_token") or ""), sso=sso)
                    if check.get("has_bfs") or not check.get("ok"):
                        return finish("marked" if check.get("has_bfs") else "review", "REFRESH_BFS")
                    result = self._chat(account, config, proxy, cancel.is_set)
            except Exception:
                return finish("unchecked", "REFRESH_UNAVAILABLE")
        first = dict(result)
        if result.get("status_code") == 429:
            delay = result.get("retry_after", 30)
            # Long Retry-After values are deferred rather than holding a worker.
            if delay <= 60:
                if cancel.wait(delay):
                    return finish("unchecked", "CANCELLED")
                result = self._chat(account, config, proxy, cancel.is_set)
        if result["state"] == "infra_retry":
            for delay in (1, 2):
                if cancel.wait(delay):
                    return finish("unchecked", "CANCELLED")
                result = self._chat(account, config, proxy, cancel.is_set)
                if result["state"] != "infra_retry":
                    break
        if result.get("reason") == "FORBIDDEN" or result.get("reason") in ("MISSING_THINKING", "BURST", "HIGH_TPS", "FAST_TPS"):
            first = dict(result)
            if cancel.wait(1):
                return finish("unchecked", "CANCELLED")
            result = self._chat(account, config, proxy, cancel.is_set)
            if result["state"] != first["state"]:
                result = {**result, "state": "review", "reason": "INCONSISTENT_SAMPLES"}
        signals.append({"layer": "chat", **result})
        return finish(result["state"], result["reason"], quality=result)
