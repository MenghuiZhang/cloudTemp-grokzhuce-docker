"""账号风控探测 + 网页发消息 anti-bot 处理。

两层：
1) 账号策略：GetUser / session 里的 botFlagDetails=policy=deny
2) 请求层：纯 HTTP 打 /responses 常被 anti-bot 403；
   用真实 Chrome（Playwright channel=chrome）带 SSO 在页面上下文 fetch，
   走浏览器 CF/jsd/statsig，才能过网页发消息。
"""
from __future__ import annotations

import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from curl_cffi import requests

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

# curl_cffi + 本地代理时 chrome131 常炸 curl(35) OPENSSL invalid library；
# chrome124 实测经 7897 稳定。探测按此顺序回退，禁止把基建错误当 MARKED。
_IMPERSONATE_FALLBACKS = (
    "chrome124",
    "chrome123",
    "chrome120",
    "chrome131",
    "chrome110",
    "chrome",
)

_INFRA_ERR_MARKERS = (
    "curl: (35)",
    "curl: (56)",
    "curl: (7)",
    "curl: (28)",
    "tls connect error",
    "openssl_internal",
    "invalid library",
    "ssl connect error",
    "connection reset",
    "failed to perform",
    "proxy connect",
    "tunnel connection failed",
)


def _is_infra_error_text(msg: str) -> bool:
    low = (msg or "").lower()
    if not low:
        return False
    return any(m in low for m in _INFRA_ERR_MARKERS)


def _impersonate_chain(preferred: str = "") -> list[str]:
    pref = (preferred or "").strip() or "chrome124"
    out: list[str] = []
    for x in (pref, *_IMPERSONATE_FALLBACKS):
        if x and x not in out:
            out.append(x)
    return out


def _proxy_kwargs(*, force_direct: bool = False) -> dict:
    # 业务代理优先（与 grok._curl_proxy_kwargs 对齐）
    # force_direct：代理 TLS 炸穿时直连兜底读 risk（不经 7897）
    if force_direct or (os.environ.get("GROK_RISK_FORCE_DIRECT") or "").strip().lower() in (
        "1",
        "true",
        "yes",
    ):
        return {"proxies": {"http": "", "https": ""}}
    for key in ("GROK_PROXY", "XAI_PROXY", "SAME_SESSION_PROXY"):
        raw = (os.environ.get(key) or "").strip()
        if not raw:
            continue
        if "://" in raw:
            url = raw
        else:
            parts = raw.split(":")
            if len(parts) >= 4 and parts[1].isdigit():
                from urllib.parse import quote

                host, port = parts[0], parts[1]
                user = ":".join(parts[2:-1])
                pw = parts[-1]
                url = (
                    f"http://{quote(user, safe='')}:{quote(pw, safe='')}@{host}:{port}"
                )
            elif len(parts) == 2 and parts[1].isdigit():
                url = f"http://{parts[0]}:{parts[1]}"
            else:
                url = f"http://{raw}" if "://" not in raw else raw
        return {"proxies": {"http": url, "https": url}}
    if (os.environ.get("XAI_USE_SYSTEM_PROXY") or "").strip().lower() in (
        "1",
        "true",
        "yes",
    ):
        return {}
    return {"proxies": {"http": "", "https": ""}}


def _printable(body: bytes) -> list[str]:
    return [x.decode() for x in re.findall(rb"[\x20-\x7e]{3,}", body or b"")]


# 注册时 Castle 写入的 bot 细节：无 policy=deny 也会挡 CLI/device
_CASTLE_BAD_MARKERS = (
    "no_token",
    "invalid_token",
    "castle_token:",
    "castle_token: no_token",
    "castle_token: invalid_token",
)
_HIGH_RISK_LEVELS = frozenset(
    {
        "USER_RISK_LEVEL_HIGH",
        "USER_RISK_LEVEL_VERY_HIGH",
        "HIGH",
        "VERY_HIGH",
    }
)


def _normalize_bot_detail(s: str) -> str:
    """去掉 protobuf 打印前缀噪声。"""
    t = (s or "").strip()
    t = t.lstrip(").:; \t$0123456789")
    # 再剥一次常见前缀
    for prefix in ("castle_token:", "policy="):
        idx = t.find(prefix)
        if idx > 0 and idx < 8:
            t = t[idx:]
            break
    return t.strip()


def _parse_bot_flag_details(detail: str) -> dict[str, Any]:
    """从 botFlagDetails / grpc 字符串解析 policy / risk / event / castle 状态。"""
    d = _normalize_bot_detail(detail)
    out: dict[str, Any] = {
        "bot_flag_details": d or None,
        "policy": None,
        "risk_score": None,
        "event": None,
        "castle_status": None,
        "has_no_token": False,
        "has_invalid_token": False,
        "has_policy_deny": False,
    }
    if not d:
        return out

    m = re.search(r"policy=([a-zA-Z_]+)", d)
    if m:
        out["policy"] = m.group(1)
        if m.group(1).lower() == "deny":
            out["has_policy_deny"] = True
    if "policy=deny" in d:
        out["has_policy_deny"] = True
        out["policy"] = out["policy"] or "deny"

    m = re.search(r"risk=([0-9.]+)", d)
    if m:
        try:
            out["risk_score"] = float(m.group(1))
        except ValueError:
            pass

    m = re.search(r"event=([^,\s]+)", d)
    if m:
        out["event"] = m.group(1)

    # castle_token: no_token / invalid_token ...
    m = re.search(r"castle_token:\s*([a-zA-Z0-9_]+)", d)
    if m:
        out["castle_status"] = m.group(1)
    if "no_token" in d:
        out["has_no_token"] = True
        out["castle_status"] = out["castle_status"] or "no_token"
    if "invalid_token" in d:
        out["has_invalid_token"] = True
        out["castle_status"] = out["castle_status"] or "invalid_token"
    return out


class AntibotService:
    """风控探测 + 浏览器态网页聊天。"""

    def __init__(self) -> None:
        pass

    # ---------- 账号风险 ----------
    def probe_account_risk(
        self,
        sso: str,
        *,
        sso_rw: str = "",
        impersonate: str = "chrome131",
        user_agent: Optional[str] = None,
        timeout: int = 15,
    ) -> dict[str, Any]:
        """
        读 GetUser(grpc) + REST /rest/auth/get-user + session，判定风控。

        硬拒：
          - policy=deny → denied
          - castle no_token/invalid_token 或 botFlag 坏细节 → false_clean
        可换 token（clean=True）：
          - 无 deny、无 false_clean（含 USER_RISK_LEVEL_HIGH 且无 botFlag）

        返回关键字段:
          ok, denied, false_clean, cli_usable, cli_blocked_reason, clean,
          risk_level, risk_score, bot_flag_source, bot_flag_details,
          policy, event, castle_status, acl_strings, email_domain,
          user_id, email, signals, raw_strings, rest_user, error,
          infra_error（TLS/代理等基建失败，禁止当 MARKED）
        """
        sso = (sso or "").strip()
        rw = (sso_rw or sso or "").strip()
        out: dict[str, Any] = {
            "ok": False,
            "denied": False,
            "false_clean": False,
            "cli_usable": None,
            "cli_blocked_reason": None,
            "risk_level": None,
            "risk_score": None,
            "bot_flag_source": None,
            "bot_flag_details": None,
            "policy": None,
            "event": None,
            "castle_status": None,
            "acl_strings": [],
            "email_domain": None,
            "user_id": None,
            "email": None,
            "signals": [],
            "raw_strings": [],
            "rest_user": None,
            "error": None,
            "infra_error": False,
            "impersonate_used": None,
        }
        if not sso:
            out["error"] = "缺少 sso"
            return out

        ua = user_agent or DEFAULT_UA
        last_infra_err: Optional[str] = None
        # 路径：代理×多 impersonate → 直连×稳 impersonate
        # chrome131+本地代理常 curl(35) OPENSSL invalid library；chrome124 稳
        path_specs: list[tuple[str, bool]] = [
            (imp, False) for imp in _impersonate_chain(impersonate or "chrome124")
        ]
        # 代理全挂后直连兜底（只试最稳的几个，避免拖太久）
        for imp in ("chrome124", "chrome123", "chrome120"):
            path_specs.append((imp, True))

        for imp, direct in path_specs:
            tag = f"{'direct' if direct else 'proxy'}:{imp}"
            try:
                result = self._probe_account_risk_once(
                    sso,
                    sso_rw=rw,
                    impersonate=imp,
                    user_agent=ua,
                    timeout=timeout,
                    base_out=out,
                    force_direct=direct,
                )
                if result.get("infra_error"):
                    last_infra_err = str(result.get("error") or "infra")
                    out["signals"] = list(
                        dict.fromkeys(
                            list(out.get("signals") or [])
                            + list(result.get("signals") or [])
                            + [f"infra_try:{tag}"]
                        )
                    )
                    time.sleep(0.2)
                    continue
                result["impersonate_used"] = imp
                if direct:
                    result.setdefault("signals", [])
                    sigs = list(result.get("signals") or [])
                    if "risk_via_direct" not in sigs:
                        sigs.append("risk_via_direct")
                    result["signals"] = sorted(set(sigs))
                return result
            except Exception as e:
                err_s = str(e)
                if _is_infra_error_text(err_s):
                    last_infra_err = err_s
                    out["signals"] = list(
                        dict.fromkeys(
                            list(out.get("signals") or [])
                            + [f"infra_try:{tag}:{err_s[:40]}"]
                        )
                    )
                    time.sleep(0.2)
                    continue
                out["error"] = err_s
                return out

        # 全部路径基建失败：明确 infra_error，调用方不得记 MARKED
        out["infra_error"] = True
        out["ok"] = False
        out["denied"] = False
        out["false_clean"] = False
        out["clean"] = False
        out["cli_usable"] = None
        out["error"] = last_infra_err or "risk probe TLS/proxy failed"
        out["cli_blocked_reason"] = f"infra_error: {out['error']}"
        return out

    def _probe_account_risk_once(
        self,
        sso: str,
        *,
        sso_rw: str = "",
        impersonate: str = "chrome124",
        user_agent: Optional[str] = None,
        timeout: int = 15,
        base_out: Optional[dict[str, Any]] = None,
        force_direct: bool = False,
    ) -> dict[str, Any]:
        """单次 impersonate 探测；TLS 类异常设 infra_error=True 供外层回退。"""
        rw = (sso_rw or sso or "").strip()
        # 不继承上一轮业务字段；signals 只保留外层 infra_try 轨迹，本轮判定用本地列表
        prev_signals = list((base_out or {}).get("signals") or [])
        out = {
            "ok": False,
            "denied": False,
            "false_clean": False,
            "cli_usable": None,
            "cli_blocked_reason": None,
            "risk_level": None,
            "risk_score": None,
            "bot_flag_source": None,
            "bot_flag_details": None,
            "policy": None,
            "event": None,
            "castle_status": None,
            "acl_strings": [],
            "email_domain": None,
            "user_id": None,
            "email": None,
            "signals": [],
            "raw_strings": [],
            "rest_user": None,
            "error": None,
            "infra_error": False,
            "impersonate_used": impersonate,
            "clean": False,
        }
        ua = user_agent or DEFAULT_UA
        try:
            sess = requests.Session(**_proxy_kwargs(force_direct=force_direct))
            for d in (".x.ai", ".grok.com", "accounts.x.ai", "grok.com"):
                try:
                    sess.cookies.set("sso", sso, domain=d)
                    sess.cookies.set("sso-rw", rw, domain=d)
                except Exception:
                    pass

            # 本轮本地 signals；历史 infra_try 仅在返回时合并，避免污染本轮判定
            signals: list[str] = []
            if force_direct:
                signals.append("force_direct")

            def _merge_signals(extra: Optional[list] = None) -> list[str]:
                bag: list[str] = []
                for s in prev_signals + signals + list(extra or []):
                    if s and s not in bag:
                        bag.append(str(s))
                return bag

            # 1) GetUser grpc-web（兼容旧路径）
            grpc_ok = False
            try:
                r = sess.post(
                    "https://accounts.x.ai/auth_mgmt.AuthManagement/GetUser",
                    data=b"\x00\x00\x00\x00\x00",
                    headers={
                        "content-type": "application/grpc-web+proto",
                        "x-grpc-web": "1",
                        "x-user-agent": "connect-es/2.1.1",
                        "origin": "https://accounts.x.ai",
                        "referer": "https://accounts.x.ai/",
                        "user-agent": ua,
                    },
                    impersonate=impersonate or "chrome124",
                    timeout=timeout,
                )
            except Exception as e:
                err_s = str(e)
                if _is_infra_error_text(err_s):
                    out["infra_error"] = True
                    out["error"] = err_s
                    signals.append(f"grpc_infra:{impersonate}")
                    out["signals"] = _merge_signals()
                    return out
                raise
            body = r.content or b""
            strings = _printable(body)
            out["raw_strings"] = strings
            grpc_status = r.headers.get("grpc-status")
            if r.status_code == 200 and (
                grpc_status in (None, "0", 0) or any("@" in s for s in strings)
            ):
                # 有 email / uuid 才算读到用户
                if any("@" in s for s in strings) or any(
                    re.fullmatch(
                        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                        s.lstrip("$"),
                    )
                    for s in strings
                ):
                    grpc_ok = True
            if grpc_status and str(grpc_status) not in ("0", "None"):
                signals.append(f"grpc_status:{grpc_status}")
            for s in strings:
                low = s.lower()
                if (
                    "policy=" in s
                    or "castle_token" in low
                    or "no_token" in low
                    or "invalid_token" in low
                ):
                    parsed = _parse_bot_flag_details(s)
                    if parsed.get("bot_flag_details") and not out.get("bot_flag_details"):
                        out["bot_flag_details"] = parsed["bot_flag_details"]
                    if parsed.get("policy") and not out.get("policy"):
                        out["policy"] = parsed["policy"]
                    if parsed.get("risk_score") is not None and out.get("risk_score") is None:
                        out["risk_score"] = parsed["risk_score"]
                    if parsed.get("event") and not out.get("event"):
                        out["event"] = parsed["event"]
                    if parsed.get("castle_status") and not out.get("castle_status"):
                        out["castle_status"] = parsed["castle_status"]
                    if parsed.get("has_policy_deny"):
                        signals.append("grpc_policy_deny")
                    if parsed.get("has_no_token"):
                        signals.append("grpc_castle_no_token")
                    if parsed.get("has_invalid_token"):
                        signals.append("grpc_castle_invalid_token")
                if re.fullmatch(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                    s.lstrip("$"),
                ):
                    out["user_id"] = out["user_id"] or s.lstrip("$")
                if "@" in s and "." in s and not out["email"]:
                    em = re.search(
                        r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})", s
                    )
                    if em:
                        out["email"] = em.group(1)

            # 2) REST get-user（结构化 risk/bot，主判定源）
            rest_ok = False
            try:
                ru = sess.get(
                    "https://grok.com/rest/auth/get-user",
                    headers={
                        "user-agent": ua,
                        "accept": "application/json",
                        "referer": "https://grok.com/",
                        "origin": "https://grok.com",
                    },
                    impersonate=impersonate or "chrome124",
                    timeout=timeout,
                )
                if ru.status_code in (401, 403):
                    signals.append(f"rest_get_user_http:{ru.status_code}")
                if ru.status_code == 200:
                    try:
                        uj = ru.json()
                    except Exception:
                        uj = {}
                    if isinstance(uj, dict) and uj.get("userId"):
                        rest_ok = True
                    if isinstance(uj, dict) and uj:
                        out["rest_user"] = {
                            k: uj.get(k)
                            for k in (
                                "userId",
                                "email",
                                "emailDomain",
                                "riskLevel",
                                "botFlagSource",
                                "botFlagDetails",
                                "aclStrings",
                                "givenName",
                                "familyName",
                                "sessionTierId",
                                "allowNsfwContent",
                                "alwaysShowNsfwContent",
                            )
                            if k in uj
                        }
                        out["user_id"] = out["user_id"] or uj.get("userId")
                        out["email"] = out["email"] or uj.get("email")
                        out["email_domain"] = uj.get("emailDomain") or out["email_domain"]
                        out["risk_level"] = uj.get("riskLevel") or out["risk_level"]
                        out["bot_flag_source"] = (
                            uj.get("botFlagSource") or out["bot_flag_source"]
                        )
                        out["acl_strings"] = list(uj.get("aclStrings") or [])

                        rest_detail = uj.get("botFlagDetails")
                        if rest_detail:
                            parsed = _parse_bot_flag_details(str(rest_detail))
                            # REST 细节优先（完整可读）
                            out["bot_flag_details"] = parsed.get("bot_flag_details") or str(
                                rest_detail
                            )
                            if parsed.get("policy"):
                                out["policy"] = parsed["policy"]
                            if parsed.get("risk_score") is not None:
                                out["risk_score"] = parsed["risk_score"]
                            if parsed.get("event"):
                                out["event"] = parsed["event"]
                            if parsed.get("castle_status"):
                                out["castle_status"] = parsed["castle_status"]
                            if parsed.get("has_policy_deny"):
                                signals.append("rest_policy_deny")
                            if parsed.get("has_no_token"):
                                signals.append("rest_castle_no_token")
                            if parsed.get("has_invalid_token"):
                                signals.append("rest_castle_invalid_token")

                        rl = str(out.get("risk_level") or "")
                        if rl in _HIGH_RISK_LEVELS or rl.endswith("_HIGH") or rl.endswith(
                            "_VERY_HIGH"
                        ):
                            signals.append(f"rest_risk_level:{rl}")

                        bfs = str(out.get("bot_flag_source") or "")
                        if bfs and bfs not in (
                            "",
                            "BOT_FLAG_SOURCE_UNSPECIFIED",
                            "BOT_FLAG_SOURCE_NONE",
                            "0",
                        ):
                            signals.append(f"rest_bot_flag_source:{bfs}")
                            # CASTLE 源 + 坏 token/deny 细节 = 强信号
                            if "CASTLE" in bfs.upper():
                                signals.append("rest_bot_source_castle")
            except Exception as rest_err:
                err_s = str(rest_err)
                if _is_infra_error_text(err_s):
                    # grpc 已通但 rest TLS 炸：仍尝试 session；全挂则 infra
                    signals.append(f"rest_infra:{impersonate}")
                    if not grpc_ok:
                        out["infra_error"] = True
                        out["error"] = err_s
                        out["signals"] = _merge_signals()
                        return out
                else:
                    signals.append(f"rest_get_user_err:{rest_err}")

            # 3) session JSON（补 userId/email/domain）
            session_ok = False
            try:
                rs = sess.get(
                    "https://grok.com/api/auth/session",
                    headers={
                        "user-agent": ua,
                        "accept": "application/json",
                        "referer": "https://grok.com/",
                    },
                    impersonate=impersonate or "chrome124",
                    timeout=timeout,
                )
                if rs.status_code == 200:
                    try:
                        sj = rs.json()
                    except Exception:
                        sj = {}
                    status = (sj or {}).get("status")
                    sess_obj = (sj or {}).get("session") or {}
                    if status == "authenticated" and sess_obj.get("userId"):
                        session_ok = True
                    elif status and status != "authenticated":
                        signals.append(f"session_status:{status}")
                    out["user_id"] = out["user_id"] or sess_obj.get("userId")
                    out["email"] = out["email"] or sess_obj.get("email")
                    out["email_domain"] = (
                        out["email_domain"] or sess_obj.get("emailDomain")
                    )
            except Exception as sess_err:
                if _is_infra_error_text(str(sess_err)):
                    signals.append(f"session_infra:{impersonate}")
                    if not rest_ok and not grpc_ok:
                        out["infra_error"] = True
                        out["error"] = str(sess_err)
                        out["signals"] = _merge_signals()
                        return out

            # 若 email_domain 仍空，从 email 推
            if not out.get("email_domain") and out.get("email") and "@" in str(out["email"]):
                out["email_domain"] = str(out["email"]).split("@", 1)[-1]

            # 会话全挂：不要误报 cli_usable=True（soft-delete / 过期 SSO）
            authenticated = bool(rest_ok or grpc_ok or session_ok or out.get("user_id"))
            if not authenticated:
                # 本轮是否拿到过「业务层」HTTP 响应（401/session JSON 等）
                # 有业务响应 = 链路通了，SSO 无效；绝不能因历史 infra_try 信号误标基建
                got_business_http = any(
                    str(s).startswith("rest_get_user_http:")
                    or str(s).startswith("session_status:")
                    or str(s).startswith("grpc_status:")
                    for s in signals
                )
                # 仅本轮 TLS/连接噪声、且无任何业务响应 → 真基建失败
                this_round_infra = any(
                    str(s).startswith(p)
                    for p in (
                        "grpc_infra:",
                        "rest_infra:",
                        "session_infra:",
                    )
                    for s in signals
                ) or _is_infra_error_text(str(out.get("error") or ""))
                if this_round_infra and not got_business_http:
                    out["infra_error"] = True
                    out["ok"] = False
                    out["denied"] = False
                    out["false_clean"] = False
                    out["clean"] = False
                    out["cli_usable"] = None
                    out["error"] = out.get("error") or "risk probe infra (no auth body)"
                    out["cli_blocked_reason"] = f"infra_error: {out['error']}"
                    signals.append("unauthenticated_infra")
                    out["signals"] = _merge_signals()
                    return out
                signals.append("unauthenticated_or_dead_session")
                out["signals"] = _merge_signals()
                out["ok"] = False
                out["cli_usable"] = False
                out["cli_blocked_reason"] = "unauthenticated: SSO 无效或会话已删"
                out["error"] = "SSO 无效或 get-user/session 未认证"
                out["denied"] = False
                out["false_clean"] = False
                out["infra_error"] = False
                out["clean"] = False
                return out

            # ---- 判定 ----
            detail_s = str(out.get("bot_flag_details") or "")
            detail_low = detail_s.lower()
            policy_deny = (
                out.get("policy") == "deny"
                or "policy=deny" in detail_low
                or "rest_policy_deny" in signals
                or "grpc_policy_deny" in signals
            )
            castle_bad = bool(
                out.get("castle_status") in ("no_token", "invalid_token")
                or any(m in detail_low for m in ("no_token", "invalid_token"))
                or "grpc_castle_no_token" in signals
                or "grpc_castle_invalid_token" in signals
                or "rest_castle_no_token" in signals
                or "rest_castle_invalid_token" in signals
            )
            risk_high = False
            rl = str(out.get("risk_level") or "")
            if rl in _HIGH_RISK_LEVELS or rl.endswith("_HIGH") or rl.endswith("_VERY_HIGH"):
                risk_high = True
            if out.get("risk_score") is not None:
                try:
                    if float(out["risk_score"]) >= 0.9:
                        risk_high = True
                        signals.append(f"risk_score_high:{out['risk_score']}")
                except (TypeError, ValueError):
                    pass

            # denied：明确 policy=deny（硬拒）
            out["denied"] = bool(policy_deny)
            # false_clean：未 policy=deny，但 castle 坏 / 高风险 / CASTLE 源带坏细节
            # → GetUser 看起来“没 deny 字符串”，device/CLI 仍挂
            bfs = str(out.get("bot_flag_source") or "")
            castle_source = "CASTLE" in bfs.upper()
            out["false_clean"] = bool(
                (not out["denied"])
                and (
                    castle_bad
                    or (risk_high and (castle_bad or castle_source or bool(detail_s)))
                    or (castle_source and bool(detail_s) and castle_bad)
                )
            )
            # 无 deny 但 risk HIGH + botFlagDetails 非空（即便解析不全）也视为假干净
            if (
                not out["denied"]
                and not out["false_clean"]
                and risk_high
                and detail_s
                and any(m in detail_low for m in _CASTLE_BAD_MARKERS)
            ):
                out["false_clean"] = True
                signals.append("false_clean_high_plus_castle_detail")

            # 再兜底：HIGH + BOT_FLAG_SOURCE_CASTLE + 有任何 botFlagDetails
            if (
                not out["denied"]
                and not out["false_clean"]
                and risk_high
                and castle_source
                and detail_s
            ):
                out["false_clean"] = True
                signals.append("false_clean_high_castle_source")

            # cli_usable：既非 deny 也非 false_clean 才可能（最终仍以 device 为准）
            if out["denied"]:
                out["cli_usable"] = False
                out["cli_blocked_reason"] = (
                    f"policy_deny: {out.get('bot_flag_details') or 'policy=deny'}"
                )
            elif out["false_clean"]:
                out["cli_usable"] = False
                parts = []
                if out.get("castle_status"):
                    parts.append(f"castle={out['castle_status']}")
                if out.get("risk_level"):
                    parts.append(f"riskLevel={out['risk_level']}")
                if out.get("bot_flag_source"):
                    parts.append(f"source={out['bot_flag_source']}")
                if out.get("bot_flag_details"):
                    parts.append(str(out["bot_flag_details"])[:120])
                out["cli_blocked_reason"] = "false_clean: " + (
                    "; ".join(parts) if parts else "castle/risk"
                )
            else:
                # 无 deny / 无 false_clean：可换 token（含 HIGH 但无 botFlag）
                # 实测：USER_RISK_LEVEL_HIGH + 无 botFlagDetails 仍能 sso-to-oauth 入库
                out["cli_usable"] = True
                out["cli_blocked_reason"] = None
                if risk_high and not detail_s and not castle_source:
                    signals.append("risk_high_no_botflag_importable")
                elif risk_high and not detail_s:
                    # 有 CASTLE 源但无 details：仍不挡入库，仅留信号
                    signals.append("risk_high_castle_source_no_detail")

            # acl 陷阱提示：有 grok-code-cli 仍可能 CLI 不可用
            acls = out.get("acl_strings") or []
            if any("grok-code-cli" in str(a) for a in acls) and out["cli_usable"] is False:
                signals.append("acl_cli_string_but_blocked")

            out["signals"] = _merge_signals()
            out["ok"] = True
            if out["denied"]:
                out["error"] = (
                    f"账号风控 deny: {out.get('bot_flag_details') or 'policy=deny'}"
                )
            elif out["false_clean"]:
                out["error"] = out.get("cli_blocked_reason") or "false_clean"
            # 可入库门槛：无 deny、无 false_clean（含 botFlag/castle 坏）
            # HIGH 无 botFlag 也算 clean
            out["clean"] = bool(
                out.get("ok")
                and not out.get("denied")
                and not out.get("false_clean")
                and out.get("cli_usable") is not False
            )
            out["infra_error"] = False
            return out
        except Exception as e:
            err_s = str(e)
            out["error"] = err_s
            if _is_infra_error_text(err_s):
                out["infra_error"] = True
                out["ok"] = False
                out["denied"] = False
                out["false_clean"] = False
                out["clean"] = False
                out["cli_usable"] = None
                out["cli_blocked_reason"] = f"infra_error: {err_s}"
                try:
                    out["signals"] = _merge_signals([f"once_exc:{impersonate}"])
                except Exception:
                    out["signals"] = list(prev_signals) + [f"once_exc:{impersonate}"]
            return out

    @staticmethod
    def is_risk_infra_error(risk: Optional[dict[str, Any]]) -> bool:
        """TLS/代理/curl 基建失败：不是业务 MARKED。"""
        if not isinstance(risk, dict):
            return False
        if risk.get("infra_error") is True:
            return True
        blob = " ".join(
            str(x)
            for x in (
                risk.get("error"),
                risk.get("cli_blocked_reason"),
                " ".join(str(s) for s in (risk.get("signals") or [])),
            )
            if x
        )
        return _is_infra_error_text(blob)

    @staticmethod
    def is_risk_clean(risk: Optional[dict[str, Any]]) -> bool:
        """
        可换 token / 计入 CLEAN 门槛：
        - denied（policy=deny）→ 否
        - false_clean（castle 坏 / botFlag 坏细节）→ 否
        - HIGH 但无 botFlag / 无 deny → 是（可 sso-to-oauth）
        - cli_usable is False → 否；True / None 在无 deny+无 false_clean 时放行
        - 基建 TLS 失败 → 否（但也不算 MARKED，见 is_risk_infra_error）
        """
        if not isinstance(risk, dict):
            return False
        if AntibotService.is_risk_infra_error(risk):
            return False
        if risk.get("clean") is True:
            return True
        if risk.get("denied") or risk.get("false_clean"):
            return False
        if risk.get("cli_usable") is False:
            return False
        # ok 明确为 False（死会话等）不放行
        if risk.get("ok") is False:
            return False
        # 无 botFlag 硬拒信号即可（含 HIGH / UNCERTAIN 历史口径）
        bfs = str(risk.get("bot_flag_source") or "").strip()
        bfd = str(risk.get("bot_flag_details") or "").strip()
        if bfs and "CASTLE" in bfs.upper() and bfd:
            return False
        return True

    @staticmethod
    def is_token_importable(risk: Optional[dict[str, Any]]) -> bool:
        """与 is_risk_clean 同口径：无 deny、无 botFlag 坏信号即可换 token。"""
        return AntibotService.is_risk_clean(risk)

    @staticmethod
    def risk_mark_summary(risk: Optional[dict[str, Any]]) -> str:
        """人读摘要：deny / false_clean / clean / infra（含 HIGH 无 botFlag）。"""
        if not isinstance(risk, dict):
            return "no_risk"
        if AntibotService.is_risk_infra_error(risk):
            return (
                "INFRA "
                f"{str(risk.get('cli_blocked_reason') or risk.get('error') or 'tls/proxy')[:120]}"
            )
        if risk.get("denied"):
            return (
                "DENIED "
                f"score={risk.get('risk_score')} "
                f"src={risk.get('bot_flag_source')} "
                f"detail={str(risk.get('bot_flag_details') or risk.get('cli_blocked_reason') or '')[:100]}"
            )
        if risk.get("false_clean"):
            return (
                "FALSE_CLEAN "
                f"detail={str(risk.get('cli_blocked_reason') or risk.get('bot_flag_details') or '')[:100]}"
            )
        if AntibotService.is_risk_clean(risk):
            lvl = risk.get("risk_level") or "n/a"
            extra = ""
            rl = str(lvl)
            if rl in _HIGH_RISK_LEVELS or rl.endswith("_HIGH") or rl.endswith("_VERY_HIGH"):
                extra = " high_ok_no_botflag"
            imp = risk.get("impersonate_used")
            if imp:
                extra += f" imp={imp}"
            return (
                "CLEAN "
                f"policy={risk.get('policy') or 'n/a'} "
                f"level={lvl}{extra}"
            )
        return f"UNCERTAIN {risk.get('cli_blocked_reason') or risk.get('error') or 'unknown'}"

    # ---------- 纯 HTTP 发消息（常 403，作对照） ----------
    def send_http(
        self,
        sso: str,
        message: str,
        *,
        sso_rw: str = "",
        model: str = "grok-3",
        impersonate: str = "chrome131",
        user_agent: Optional[str] = None,
        device_id: Optional[str] = None,
        timeout: int = 30,
    ) -> dict[str, Any]:
        sso = (sso or "").strip()
        rw = (sso_rw or sso or "").strip()
        ua = user_agent or DEFAULT_UA
        did = device_id or str(uuid.uuid4())
        sess = requests.Session(**_proxy_kwargs())
        for d in (".x.ai", ".grok.com", "grok.com"):
            try:
                sess.cookies.set("sso", sso, domain=d)
                sess.cookies.set("sso-rw", rw, domain=d)
                sess.cookies.set("grok_device_id", did, domain=".grok.com")
            except Exception:
                pass

        H = {
            "content-type": "application/json",
            "origin": "https://grok.com",
            "referer": "https://grok.com/",
            "user-agent": ua,
            "accept": "*/*",
            "accept-language": "en-US,en;q=0.9",
            "x-xai-request-id": str(uuid.uuid4()),
            # 浏览器失败时会有 TypeError 占位；正常是 base64 指纹。先给合理占位再靠浏览器路径。
            "x-statsig-id": "eDA6",
            "sec-ch-ua": '"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
        }
        # warm
        try:
            sess.get("https://grok.com/", headers={"user-agent": ua}, impersonate=impersonate, timeout=15)
        except Exception:
            pass

        r = sess.post(
            "https://grok.com/rest/app-chat/conversations",
            json={"temporary": True},
            headers=H,
            impersonate=impersonate,
            timeout=timeout,
        )
        cid = None
        try:
            cid = r.json().get("conversationId")
        except Exception:
            pass
        if not cid:
            return {
                "ok": False,
                "via": "http",
                "status": r.status_code,
                "error": f"create_conv failed: {(r.text or '')[:200]}",
                "body": (r.text or "")[:400],
            }

        H2 = dict(H)
        H2["referer"] = f"https://grok.com/c/{cid}"
        H2["x-xai-request-id"] = str(uuid.uuid4())
        payload = {
            "message": message,
            "modelNameOverride": model,
            "fileAttachments": [],
            "toolOverrides": {},
            "enableImageGeneration": False,
            "returnImageBytes": False,
            "returnRawGrokInXaiRequest": False,
            "enableImageStreaming": True,
            "imageGenerationCount": 2,
            "forceConcise": False,
            "enableSideBySide": True,
            "sendFinalMetadata": True,
            "isReasoning": False,
            "disableMemory": False,
            "forceSideBySide": False,
            "isPreload": False,
        }
        r2 = sess.post(
            f"https://grok.com/rest/app-chat/conversations/{cid}/responses",
            json=payload,
            headers=H2,
            impersonate=impersonate,
            timeout=timeout,
        )
        text = r2.text or ""
        ok = r2.status_code == 200 and "anti-bot" not in text.lower()
        return {
            "ok": ok,
            "via": "http",
            "status": r2.status_code,
            "conversation_id": cid,
            "body": text[:800],
            "error": None if ok else text[:300],
        }

    # ---------- 浏览器 UI 发消息（过 anti-bot 主路径） ----------
    def send_browser(
        self,
        sso: str,
        message: str,
        *,
        sso_rw: str = "",
        model: str = "grok-3",
        headless: bool = True,
        timeout_ms: int = 90000,
        profile_dir: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        过 anti-bot 的稳定路径（实测）：
        1) 本机 Chrome + 持久化 profile（保留 cf_clearance / __cf_bm / statsig）
        2) 注入 sso/sso-rw
        3) 在页面 UI 打字 + 点「提交」发送（不要用 page.evaluate fetch，会被 anti-bot 403）

        注意：账号 policy=deny 时 OIDC/CLI 仍会 Access denied，但网页 UI 聊天可以通。
        """
        del model  # UI 走页面当前模型（Fast 等），不靠 body 字段
        sso = (sso or "").strip()
        rw = (sso_rw or sso or "").strip()
        if not sso:
            return {"ok": False, "via": "browser_ui", "error": "缺少 sso"}

        try:
            from playwright.sync_api import sync_playwright
        except Exception as e:
            return {
                "ok": False,
                "via": "browser_ui",
                "error": f"playwright 不可用: {e}",
            }

        # 默认 profile：项目 logs/chrome_chat_profile（与注册抓包 profile 隔离可复用）
        if profile_dir:
            pdir = Path(profile_dir)
        else:
            env_p = (os.environ.get("GROK_CHAT_PROFILE") or "").strip()
            if env_p:
                pdir = Path(env_p)
            else:
                pdir = (
                    Path(__file__).resolve().parents[1]
                    / "logs"
                    / "chrome_chat_profile"
                )
        pdir.mkdir(parents=True, exist_ok=True)

        result: dict[str, Any] = {
            "ok": False,
            "via": "browser_ui",
            "profile": str(pdir),
            "events": [],
        }
        try:
            with sync_playwright() as p:
                ctx = p.chromium.launch_persistent_context(
                    user_data_dir=str(pdir),
                    channel="chrome",
                    headless=headless,
                    viewport={"width": 1400, "height": 900},
                    locale="en-US",
                    user_agent=DEFAULT_UA,
                    args=[
                        "--disable-blink-features=AutomationControlled",
                        "--no-first-run",
                        "--no-default-browser-check",
                    ],
                )
                ctx.add_init_script(
                    "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
                )
                cookies = []
                for domain in (
                    ".x.ai",
                    ".grok.com",
                    ".grokipedia.com",
                    ".grokusercontent.com",
                ):
                    cookies.append(
                        {
                            "name": "sso",
                            "value": sso,
                            "domain": domain,
                            "path": "/",
                            "secure": True,
                            "httpOnly": True,
                        }
                    )
                    cookies.append(
                        {
                            "name": "sso-rw",
                            "value": rw,
                            "domain": domain,
                            "path": "/",
                            "secure": True,
                            "httpOnly": True,
                        }
                    )
                try:
                    ctx.add_cookies(cookies)
                except Exception as ce:
                    result["cookie_err"] = str(ce)

                page = ctx.pages[0] if ctx.pages else ctx.new_page()
                events: list[dict] = []

                def on_req(req):
                    if req.method != "POST":
                        return
                    u = req.url
                    if "app-chat" not in u and "responses" not in u:
                        return
                    events.append(
                        {
                            "side": "req",
                            "url": u[:240],
                            "statsig": (req.headers.get("x-statsig-id") or "")[:120],
                            "post": (req.post_data or "")[:300],
                        }
                    )

                def on_resp(resp):
                    if resp.request.method != "POST":
                        return
                    u = resp.url
                    if "app-chat" not in u and "responses" not in u:
                        return
                    try:
                        body = resp.text()[:800]
                    except Exception:
                        body = ""
                    events.append(
                        {
                            "side": "resp",
                            "status": resp.status,
                            "url": u[:240],
                            "body": body,
                        }
                    )

                page.on("request", on_req)
                page.on("response", on_resp)

                page.goto(
                    "https://grok.com/",
                    wait_until="domcontentloaded",
                    timeout=timeout_ms,
                )
                # CF jsd / 首屏 statsig
                page.wait_for_timeout(6000)

                # session 探测
                try:
                    sess_info = page.evaluate(
                        """async () => {
                          const r = await fetch('/api/auth/session', {credentials:'include'});
                          return {status: r.status, body: (await r.text()).slice(0, 400)};
                        }"""
                    )
                    result["session"] = sess_info
                except Exception as se:
                    result["session_err"] = str(se)

                # UI 输入
                box = page.locator(
                    'div[contenteditable="true"][role="textbox"]'
                ).first
                try:
                    box.click(timeout=15000)
                except Exception:
                    # 新会话入口
                    try:
                        page.get_by_text("新建聊天").first.click(timeout=3000)
                        page.wait_for_timeout(1500)
                        box = page.locator(
                            'div[contenteditable="true"][role="textbox"]'
                        ).first
                        box.click(timeout=10000)
                    except Exception as be:
                        result["error"] = f"找不到输入框: {be}"
                        ctx.close()
                        result["events"] = events
                        return result

                page.wait_for_timeout(400)
                # 清空再输入
                try:
                    page.keyboard.press("Control+A")
                    page.keyboard.press("Backspace")
                except Exception:
                    pass
                page.keyboard.type(message, delay=35)
                page.wait_for_timeout(500)

                clicked = False
                for sel in (
                    'button[aria-label*="提交" i]',
                    'button[aria-label*="Send" i]',
                    'button[aria-label*="发送" i]',
                    'button[type="submit"]',
                ):
                    loc = page.locator(sel)
                    try:
                        if loc.count() == 0:
                            continue
                        loc.last.click(timeout=4000)
                        clicked = True
                        result["send_btn"] = sel
                        break
                    except Exception:
                        continue

                if not clicked:
                    clicked = bool(
                        page.evaluate(
                            """() => {
                              const box = document.querySelector(
                                'div[contenteditable=\"true\"][role=\"textbox\"]'
                              );
                              if (!box) return false;
                              let root = box.closest('form') || box.parentElement;
                              for (let i = 0; i < 8 && root; i++) {
                                const btns = [...root.querySelectorAll('button')];
                                // 右侧圆形提交按钮通常在最后
                                if (btns.length) {
                                  btns[btns.length - 1].click();
                                  return true;
                                }
                                root = root.parentElement;
                              }
                              return false;
                            }"""
                        )
                    )
                    result["send_btn"] = "js_fallback" if clicked else None

                if not clicked:
                    page.keyboard.press("Control+Enter")
                    page.wait_for_timeout(300)
                    page.keyboard.press("Enter")
                    result["send_btn"] = "keyboard"

                # 等网络 / 页面出现回复
                deadline = time.time() + max(12, timeout_ms / 1000.0 * 0.25)
                while time.time() < deadline:
                    page.wait_for_timeout(800)
                    # 有 load-responses 或 responses 200 即可
                    if any(
                        e.get("side") == "resp" and e.get("status") == 200
                        for e in events
                    ):
                        break
                    # 或者页面可见 assistant 文本
                    try:
                        body_txt = page.locator("body").inner_text(timeout=1000)
                        if message[:20] in body_txt and len(body_txt) > len(message) + 10:
                            # 粗判有回复
                            if body_txt.strip().count("\n") >= 2:
                                break
                    except Exception:
                        pass

                try:
                    visible = page.locator("body").inner_text(timeout=3000)
                except Exception:
                    visible = ""
                result["visible"] = (visible or "")[:1500]
                result["events"] = events

                # 成功判定：UI 发出去后能在历史/正文看到用户消息，且无 anti-bot 403
                has_403 = any(
                    e.get("side") == "resp"
                    and (
                        e.get("status") == 403
                        or "anti-bot" in (e.get("body") or "").lower()
                    )
                    for e in events
                )
                has_200 = any(
                    e.get("side") == "resp" and e.get("status") == 200 for e in events
                )
                # 页面可见用户消息 + 额外内容（模型回复）
                msg_seen = message[:40] in (visible or "")
                # 截一段可能的回复：visible 里用户消息后的文本
                reply_snip = ""
                if msg_seen and visible:
                    idx = visible.find(message[:40])
                    reply_snip = visible[idx : idx + 400]
                result["reply_snip"] = reply_snip

                if has_403 and not has_200:
                    result["ok"] = False
                    result["error"] = "anti-bot 403（浏览器 UI 仍被拦）"
                elif has_200 or (msg_seen and "pong" in (visible or "").lower()) or (
                    msg_seen and len(visible or "") > len(message) + 30
                ):
                    result["ok"] = True
                    result["error"] = None
                elif msg_seen:
                    # 消息进了会话列表/输入历史，算半成功
                    result["ok"] = True
                    result["partial"] = True
                    result["error"] = None
                else:
                    result["ok"] = False
                    result["error"] = "未观察到发送成功网络/页面回执"

                try:
                    names = sorted({c["name"] for c in ctx.cookies("https://grok.com/")})
                    result["cookie_names"] = names
                except Exception:
                    pass

                ctx.close()
        except Exception as e:
            result["ok"] = False
            result["error"] = str(e)
        return result

    def send(
        self,
        sso: str,
        message: str,
        *,
        sso_rw: str = "",
        model: str = "grok-3",
        prefer_browser: bool = True,
        headless: bool = True,
        impersonate: str = "chrome131",
        user_agent: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        先 probe 风控；发消息默认走浏览器。prefer_browser=False 时先试 HTTP。
        """
        risk = self.probe_account_risk(
            sso,
            sso_rw=sso_rw,
            impersonate=impersonate,
            user_agent=user_agent,
        )
        out: dict[str, Any] = {"risk": risk}

        if not prefer_browser:
            http_res = self.send_http(
                sso,
                message,
                sso_rw=sso_rw,
                model=model,
                impersonate=impersonate,
                user_agent=user_agent,
            )
            out["http"] = http_res
            if http_res.get("ok"):
                out["ok"] = True
                out["via"] = "http"
                out["result"] = http_res
                return out

        br = self.send_browser(
            sso, message, sso_rw=sso_rw, model=model, headless=headless
        )
        out["browser"] = br
        out["ok"] = bool(br.get("ok"))
        out["via"] = "browser"
        out["result"] = br
        if not out["ok"] and risk.get("denied"):
            out["error"] = (
                "浏览器发消息失败，且账号 policy=deny："
                f"{risk.get('bot_flag_details')}"
            )
        elif not out["ok"]:
            out["error"] = br.get("error") or "浏览器发消息失败"
        return out
