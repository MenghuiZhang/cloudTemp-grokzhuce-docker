import base64
import json
import os
import random
import string
import time
import re
import struct
import threading
import concurrent.futures
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urljoin

from curl_cffi import requests
from bs4 import BeautifulSoup

from g import (
    EmailService,
    TurnstileService,
    UserAgreementService,
    NsfwSettingsService,
    CastleService,
    same_session_register,
    parse_proxy_spec,
)
from g.proxy_pool import ProxyLease, get_proxy_pool, parse_proxy_line
from g.domain_pool import DomainLease, get_domain_pool
from g.bfs_service import atomic_write_json, inspect_token_bundle_bfs
from g.classification_store import ClassificationStore
from g.account_check import CheckRegistry, risk_state

try:
    from g import AntibotService
except Exception:  # pragma: no cover
    AntibotService = None  # type: ignore


# 基础配置
site_url = "https://accounts.x.ai"
_BASE_DIR = Path(__file__).resolve().parent
_ACTION_CACHE_FILE = _BASE_DIR / "logs" / "action_id_cache.json"
# chrome120 在部分 Windows/curl_cffi 组合下连 accounts.x.ai 会 curl(28) 超时，改用更稳指纹
DEFAULT_IMPERSONATE = "chrome131"
# device flow / 导入专用指纹池（TLS 失败时轮换）
DEVICE_FLOW_IMPERSONATES = ("chrome131", "chrome136", "chrome124", "chrome")
# 与 grokcli-2api sso_to_auth_json 保持一致：只有 device flow 换到 token 才算可导入
OIDC_ISSUER = "https://auth.x.ai"
GROK_CLI_CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
OIDC_SCOPES = (
    "openid profile email offline_access grok-cli:access "
    "api:access conversations:read conversations:write"
)
CHROME_PROFILES = [
    {"impersonate": "chrome124", "version": "124.0.0.0", "brand": "chrome"},
    {"impersonate": "chrome131", "version": "131.0.0.0", "brand": "chrome"},
    {"impersonate": "chrome136", "version": "136.0.0.0", "brand": "chrome"},
    {"impersonate": "chrome120", "version": "120.0.0.0", "brand": "chrome"},
    {"impersonate": "edge101", "version": "101.0.1210.47", "brand": "edge"},
]
# device flow 有限并发：默认仍保守为 2；批量转换脚本可通过环境变量提升。
# 上限 32，避免配置错误产生无界并发。
try:
    _DEVICE_FLOW_MAX_CONCURRENT = max(
        1,
        min(int(os.environ.get("GROK_DEVICE_FLOW_MAX_CONCURRENT") or "2"), 32),
    )
except (TypeError, ValueError):
    _DEVICE_FLOW_MAX_CONCURRENT = 2
_DEVICE_FLOW_SEM = threading.Semaphore(_DEVICE_FLOW_MAX_CONCURRENT)
# 全局冷却：遇到 rate_limited 后，后续 device flow 至少隔这么久
_device_flow_cooldown_until = 0.0
_device_flow_cooldown_lock = threading.Lock()
# 成功后的轻冷却：压连打限流，又别像旧 2s 那样白白垫时间
_DEVICE_FLOW_SUCCESS_COOLDOWN = 0.6
# 是否在 device approve 后轮询 token。默认开启（生产要最终换到 token）。
# 仅诊断「假批准」时设 GROK_DEVICE_FLOW_ISSUE_TOKEN=0 跳过换票。
DEVICE_FLOW_ISSUE_TOKEN = os.environ.get("GROK_DEVICE_FLOW_ISSUE_TOKEN", "1").strip().lower() not in (
    "0",
    "false",
    "no",
    "off",
)
# Action ID 缓存：页面发版后 id 会变，过长缓存会让注册 server action 打空
_ACTION_CACHE_TTL = int(os.environ.get("GROK_ACTION_CACHE_TTL", str(30 * 60)))  # 默认 30 分钟

# 注册路径：
#   same_session = 同页 castle mint + 页内 fetch（CLEAN 主路径，默认）
#   protocol     = 旧混合协议（Camoufox 拆会话 mint + curl signup，易 CASTLE deny）
_REGISTER_MODE_DEFAULT = "same_session"
_VALID_REGISTER_MODES = ("same_session", "protocol", "legacy", "hybrid")


def resolve_register_mode(raw: Optional[str] = None) -> str:
    """归一化注册模式。legacy/hybrid 等同 protocol。"""
    m = (raw if raw is not None else os.environ.get("GROK_REGISTER_MODE") or _REGISTER_MODE_DEFAULT)
    m = str(m or "").strip().lower()
    if m in ("same_session", "ss", "clean", "same-session", "samesession"):
        return "same_session"
    if m in ("protocol", "legacy", "hybrid", "curl", "old"):
        return "protocol"
    return _REGISTER_MODE_DEFAULT


# same_session 指纹地区（locale/timezone；代理默认本机）
# 多区 + 双 OS，配合 camoufox 池限次/冷启，压 Castle $registration 连号 deny
_SS_FP_REGIONS = [
    {"tag": "US-W", "locale": "en-US", "timezone": "America/Los_Angeles", "fp_os": "windows"},
    {"tag": "US-E", "locale": "en-US", "timezone": "America/New_York", "fp_os": "windows"},
    {"tag": "US-C", "locale": "en-US", "timezone": "America/Chicago", "fp_os": "macos"},
    {"tag": "US-DEN", "locale": "en-US", "timezone": "America/Denver", "fp_os": "windows"},
    {"tag": "US-PHX", "locale": "en-US", "timezone": "America/Phoenix", "fp_os": "macos"},
    {"tag": "US-SEA", "locale": "en-US", "timezone": "America/Los_Angeles", "fp_os": "macos"},
    {"tag": "CA", "locale": "en-CA", "timezone": "America/Toronto", "fp_os": "macos"},
    {"tag": "CA-W", "locale": "en-CA", "timezone": "America/Vancouver", "fp_os": "windows"},
    {"tag": "GB", "locale": "en-GB", "timezone": "Europe/London", "fp_os": "windows"},
    {"tag": "IE", "locale": "en-IE", "timezone": "Europe/Dublin", "fp_os": "macos"},
    {"tag": "DE", "locale": "de-DE", "timezone": "Europe/Berlin", "fp_os": "windows"},
    {"tag": "DE-MUC", "locale": "de-DE", "timezone": "Europe/Berlin", "fp_os": "macos"},
    {"tag": "FR", "locale": "fr-FR", "timezone": "Europe/Paris", "fp_os": "windows"},
    {"tag": "NL", "locale": "nl-NL", "timezone": "Europe/Amsterdam", "fp_os": "macos"},
    {"tag": "ES", "locale": "es-ES", "timezone": "Europe/Madrid", "fp_os": "windows"},
    {"tag": "IT", "locale": "it-IT", "timezone": "Europe/Rome", "fp_os": "macos"},
    {"tag": "SE", "locale": "sv-SE", "timezone": "Europe/Stockholm", "fp_os": "windows"},
    {"tag": "PL", "locale": "pl-PL", "timezone": "Europe/Warsaw", "fp_os": "windows"},
    {"tag": "CH", "locale": "de-CH", "timezone": "Europe/Zurich", "fp_os": "macos"},
    {"tag": "JP", "locale": "ja-JP", "timezone": "Asia/Tokyo", "fp_os": "windows"},
    {"tag": "JP-OSK", "locale": "ja-JP", "timezone": "Asia/Tokyo", "fp_os": "macos"},
    {"tag": "KR", "locale": "ko-KR", "timezone": "Asia/Seoul", "fp_os": "windows"},
    {"tag": "TW", "locale": "zh-TW", "timezone": "Asia/Taipei", "fp_os": "macos"},
    {"tag": "HK", "locale": "zh-HK", "timezone": "Asia/Hong_Kong", "fp_os": "windows"},
    {"tag": "SG", "locale": "en-SG", "timezone": "Asia/Singapore", "fp_os": "windows"},
    {"tag": "SG-M", "locale": "en-SG", "timezone": "Asia/Singapore", "fp_os": "macos"},
    {"tag": "MY", "locale": "en-MY", "timezone": "Asia/Kuala_Lumpur", "fp_os": "windows"},
    {"tag": "IN", "locale": "en-IN", "timezone": "Asia/Kolkata", "fp_os": "windows"},
    {"tag": "AU", "locale": "en-AU", "timezone": "Australia/Sydney", "fp_os": "windows"},
    {"tag": "AU-MEL", "locale": "en-AU", "timezone": "Australia/Melbourne", "fp_os": "macos"},
    {"tag": "AU-PER", "locale": "en-AU", "timezone": "Australia/Perth", "fp_os": "windows"},
    {"tag": "NZ", "locale": "en-NZ", "timezone": "Pacific/Auckland", "fp_os": "macos"},
    {"tag": "BR", "locale": "pt-BR", "timezone": "America/Sao_Paulo", "fp_os": "windows"},
    {"tag": "MX", "locale": "es-MX", "timezone": "America/Mexico_City", "fp_os": "macos"},
]
_SS_FP_OS_POOL = ("windows", "macos")
_SS_VIEWPORT_BASES = (
    (1280, 720),
    (1280, 800),
    (1360, 768),
    (1366, 768),
    (1400, 900),
    (1440, 900),
    (1470, 956),
    (1512, 982),  # mac-ish
    (1536, 864),
    (1600, 900),
    (1680, 1050),
    (1728, 1117),
    (1792, 1120),
    (1920, 1080),
    (1920, 1200),
    (2048, 1152),
    (2560, 1440),
)
# 近期指纹签名去重：避免同批连号撞同一 locale/OS/时区簇
_SS_RECENT_FP_LOCK = threading.Lock()
_SS_RECENT_FP_SIGS: deque = deque(maxlen=48)


def _ss_local_proxy_spec() -> str:
    """仅保留给旧调用方的兼容函数。Web/主 CLI 不再读全局单代理。"""
    return ""


def _proxy_map(proxy_spec: str = "") -> dict[str, str]:
    raw = str(proxy_spec or "").strip()
    if not raw:
        return {"http": "", "https": ""}
    try:
        url = parse_proxy_line(raw)["spec"]
    except Exception:
        url = raw if "://" in raw else f"http://{raw}"
    return {"http": url, "https": url}


def _is_proxy_network_error(value: object) -> bool:
    low = str(value or "").lower()
    return any(
        marker in low
        for marker in (
            "proxy", "socks", "tunnel", "econnreset", "econnrefused",
            "etimedout", "timed out", "timeout", "curl: (5", "curl: (7",
            "curl: (28", "curl: (35", "curl: (56", "tls connect",
            "connection reset", "connection refused", "failed to connect",
        )
    )


def _safe_to_retry_with_new_proxy(result: dict[str, Any]) -> bool:
    """只在 signup POST 尚未发生时允许换代理重放。"""
    if not _is_proxy_network_error(result.get("error")):
        return False
    steps = [str(x).lower() for x in (result.get("steps") or [])]
    return not any(step.startswith("signup") for step in steps)


def _protocol_safe_to_retry_with_new_proxy(error: object) -> bool:
    text = str(error or "")
    if not _is_proxy_network_error(text):
        return False
    low = text.lower()
    # POST 可能已被服务端接收；这类不确定结果绝不重放。
    return not any(
        marker in low
        for marker in (
            "提交注册", "注册 http", "set-cookie", "未拿到 sso",
            "signup", "/sign-up",
        )
    )


def _ss_fp_sig(fp: dict[str, Any]) -> str:
    """粗粒度签名：区 + OS + 时区 + 时序档（分辨率故意不进，避免过严）。"""
    return "|".join(
        [
            str(fp.get("tag") or ""),
            str(fp.get("fp_os") or ""),
            str(fp.get("timezone") or ""),
            str(fp.get("locale") or ""),
            str(fp.get("timing") or ""),
        ]
    )


def _ss_pick_fp(idx: int = 0) -> dict[str, Any]:
    """
    打散指纹：地区/时区/OS/分辨率/时序轮转+抖动+近期去重，
    压同 worker 连号撞同一 camoufox 出口画像（Castle $registration deny 簇）。
    """
    n = len(_SS_FP_REGIONS)
    jump_p = 0.55  # 默认更爱跳区
    try:
        jump_p = float(
            (
                os.environ.get("GROK_SS_FP_JUMP_PROB")
                or os.environ.get("STANDALONE_FP_JUMP")
                or "0.55"
            ).strip()
            or "0.55"
        )
    except ValueError:
        jump_p = 0.55
    jump_p = max(0.15, min(0.95, jump_p))

    def _one_region() -> dict[str, Any]:
        if idx and n:
            # 主序跨步更大（*5），邻域更宽，减少周期感
            base = (max(0, int(idx) - 1) * 5 + random.randint(0, 4)) % n
            if random.random() < jump_p:
                return random.choice(_SS_FP_REGIONS)
            return _SS_FP_REGIONS[base]
        return random.choice(_SS_FP_REGIONS)

    timing_env = (
        os.environ.get("STANDALONE_TIMING")
        or os.environ.get("GROK_SS_TIMING")
        or "rotate"
    ).strip().lower()

    def _one_timing() -> str:
        if timing_env in ("rotate", "random", "rand", "mix", ""):
            # 略抬 normal，压纯 turbo 连发
            return random.choices(
                ["turbo", "fast", "normal", "human"],
                weights=[32, 38, 22, 8],
                k=1,
            )[0]
        if timing_env in ("turbo", "fast", "normal", "human", "slow"):
            if random.random() < 0.35:
                return random.choice(["turbo", "fast", "normal", "human"])
            return timing_env
        return random.choice(["turbo", "fast", "normal"])

    os_env = (
        os.environ.get("STANDALONE_FP_OS") or os.environ.get("GROK_SS_FP_OS") or ""
    ).strip().lower()

    def _one_os(region: dict[str, Any]) -> str:
        if os_env in ("win", "windows"):
            return "windows"
        if os_env in ("mac", "macos", "osx"):
            return "macos"
        if os_env in ("rotate", "random", "mix", "auto", ""):
            pref = str(region.get("fp_os") or "windows").strip().lower()
            if pref not in _SS_FP_OS_POOL:
                pref = "windows"
            # 55% 池内随机，更打散 OS
            if random.random() < 0.55:
                return random.choice(list(_SS_FP_OS_POOL))
            return pref
        return "windows"

    hum_env = (
        os.environ.get("STANDALONE_HUMANIZE")
        or os.environ.get("GROK_SAME_SESSION_HUMANIZE")
        or ""
    ).strip().lower()

    def _one_humanize(timing: str) -> bool:
        if hum_env in ("1", "true", "yes", "on"):
            return True
        if hum_env in ("0", "false", "no", "off"):
            return False
        if timing in ("turbo", "fast"):
            return random.random() < 0.28
        if timing == "human":
            return True
        return random.random() < 0.75

    #  ass 最多 8 次：撞近期签名就换区/OS/时序
    fp: dict[str, Any] = {}
    for _try in range(8):
        region = _one_region()
        timing = _one_timing()
        fp_os = _one_os(region)
        vw, vh = random.choice(_SS_VIEWPORT_BASES)
        # 分辨率再抖一截
        vw = max(1180, min(2560, vw + random.randint(-36, 40)))
        vh = max(700, min(1600, vh + random.randint(-28, 32)))
        # 偶发非 16:9 常见比，再打散
        if random.random() < 0.12:
            vw = max(1200, vw + random.randint(-80, 120))
            vh = max(720, int(vw * random.uniform(0.55, 0.72)))
        cand = {
            "tag": region.get("tag") or "LOCAL",
            "locale": region.get("locale") or "en-US",
            "timezone": region.get("timezone") or "America/Los_Angeles",
            "fp_os": fp_os,
            "timing": timing,
            "viewport": {"width": int(vw), "height": int(vh)},
            "humanize": _one_humanize(timing),
        }
        sig = _ss_fp_sig(cand)
        with _SS_RECENT_FP_LOCK:
            recent = set(_SS_RECENT_FP_SIGS)
            # 同 tag+os+tz 在近 12 条里出现过 → 重抽
            coarse = f"{cand['tag']}|{cand['fp_os']}|{cand['timezone']}"
            coarse_hit = any(
                s.startswith(coarse + "|") or s.startswith(coarse)
                for s in list(_SS_RECENT_FP_SIGS)[-16:]
            )
            if sig in recent or coarse_hit:
                continue
            _SS_RECENT_FP_SIGS.append(sig)
            fp = cand
            break
    if not fp:
        # 兜底：强制随机区 + 记签名
        region = random.choice(_SS_FP_REGIONS)
        timing = _one_timing()
        vw, vh = random.choice(_SS_VIEWPORT_BASES)
        vw = max(1200, vw + random.randint(-20, 20))
        vh = max(700, vh + random.randint(-16, 16))
        fp = {
            "tag": region.get("tag") or "LOCAL",
            "locale": region.get("locale") or "en-US",
            "timezone": region.get("timezone") or "America/Los_Angeles",
            "fp_os": _one_os(region),
            "timing": timing,
            "viewport": {"width": int(vw), "height": int(vh)},
            "humanize": _one_humanize(timing),
        }
        with _SS_RECENT_FP_LOCK:
            _SS_RECENT_FP_SIGS.append(_ss_fp_sig(fp))
    return fp


def _ss_deny_break_n() -> int:
    """
    连续 risk MARKED/deny 熔断阈值（对齐 standalone）。
    默认 3：同出口 Castle deny 簇打开后继续硬刚只会空烧。
    覆盖：GROK_SS_DENY_BREAK / STANDALONE_DENY_BREAK；0/off 关闭。
    """
    raw = (
        os.environ.get("GROK_SS_DENY_BREAK")
        or os.environ.get("STANDALONE_DENY_BREAK")
        or "3"
    ).strip().lower()
    if raw in ("0", "off", "false", "no", "none"):
        return 0
    try:
        return max(0, int(raw))
    except Exception:
        return 3


def _ss_inter_account_delay(workers: int = 1, consecutive_deny: int = 0) -> float:
    """
    号间抖动秒数：压同出口短时 $registration 密度。
    GROK_SS_JITTER_MS=800-2800 或 单值；0 关闭。
    连续 MARKED 时指数加冷（对齐 standalone）。
    """
    raw = (
        os.environ.get("GROK_SS_JITTER_MS")
        or os.environ.get("STANDALONE_SS_JITTER_MS")
        or "900-3200"
    ).strip().lower()
    if raw in ("0", "off", "no", "false", "none", ""):
        # 空默认仍给一点底噪
        if raw == "":
            lo, hi = 900, 3200
        else:
            base = 0.0
            if consecutive_deny > 0:
                base += min(20.0, 4.0 * (2 ** (max(0, consecutive_deny) - 1)))
            return max(0.0, base)
    else:
        try:
            if "-" in raw:
                a, b = raw.split("-", 1)
                lo, hi = int(a.strip()), int(b.strip())
            else:
                lo = hi = int(raw)
        except ValueError:
            lo, hi = 900, 3200
    if hi < lo:
        lo, hi = hi, lo
    lo = max(0, lo)
    hi = max(lo, hi)
    # 并发越高，单号再多等一点，摊平出口
    w = max(1, int(workers or 1))
    bump = min(1800, 180 * max(0, w - 1))
    ms = random.randint(lo, hi + bump)
    base = ms / 1000.0
    # 连续 deny：指数加冷（1→+4s, 2→+8s, 3→+16s… 封顶 +20s）
    if consecutive_deny > 0:
        base += min(20.0, 4.0 * (2 ** (max(0, int(consecutive_deny)) - 1)))
    return max(0.0, base)


def get_random_chrome_profile():
    profile = random.choice(CHROME_PROFILES)
    if profile.get("brand") == "edge":
        chrome_major = profile["version"].split(".")[0]
        chrome_version = f"{chrome_major}.0.0.0"
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{chrome_version} Safari/537.36 Edg/{profile['version']}"
        )
    else:
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{profile['version']} Safari/537.36"
        )
    return profile["impersonate"], ua


PROXIES = {
    # "http": "http://127.0.0.1:10808",
    # "https": "http://127.0.0.1:10808"
}


def generate_random_name() -> str:
    length = random.randint(4, 6)
    return random.choice(string.ascii_uppercase) + "".join(
        random.choice(string.ascii_lowercase) for _ in range(length - 1)
    )


def generate_random_string(length: int = 15) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))


def _b64url_decode(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg)


def decode_jwt_payload(token: str) -> dict:
    """解析 JWT payload（不验签），失败返回空 dict。"""
    try:
        parts = (token or "").strip().split(".")
        if len(parts) != 3:
            return {}
        return json.loads(_b64url_decode(parts[1]))
    except Exception:
        return {}


def is_auth_token_usable(token: Any, *, skew_seconds: float = 60.0) -> bool:
    """
    判断注册时缓存的 device flow token 是否还能直接写上游。
    有 access_token，且 JWT exp 未过期（留 skew 余量）才算可用。
    """
    if not isinstance(token, dict):
        return False
    access = (token.get("access_token") or token.get("key") or "").strip()
    if not access:
        return False
    payload = decode_jwt_payload(access)
    exp = payload.get("exp")
    if exp is not None:
        try:
            if float(exp) <= time.time() + float(skew_seconds):
                return False
        except (TypeError, ValueError):
            return False
    return True


def is_sso_jwt_shape(sso: str) -> bool:
    """粗检：xAI sso cookie 一般为 eyJ 开头的 JWT。"""
    s = (sso or "").strip()
    if not s or not s.startswith("eyJ"):
        return False
    parts = s.split(".")
    if len(parts) != 3:
        return False
    payload = decode_jwt_payload(s)
    return bool(payload)


def _device_flow_error_kind(err: str) -> str:
    """分类 device flow 错误，便于退避策略。"""
    e = (err or "").lower()
    if "rate_limited" in e or "rate limit" in e or "too many" in e:
        return "rate_limited"
    if "curl: (35)" in e or "tls" in e or "ssl" in e or "openssl" in e:
        return "tls"
    if (
        "timed out" in e
        or "timeout" in e
        or "curl: (28)" in e
        or "connection timed out" in e
    ):
        return "timeout"
    if "device/code" in e or "device code" in e:
        return "device_code"
    if "authorization_pending" in e or "未拿到 access_token" in e:
        return "token_poll"
    if "会话无效" in e or "非有效 jwt" in e:
        return "invalid"
    return "other"


def _device_flow_wait_seconds(err: str, attempt: int = 1) -> float:
    """按错误类型返回建议等待秒数。"""
    kind = _device_flow_error_kind(err)
    a = max(1, int(attempt))
    if kind == "rate_limited":
        return min(90.0, 18.0 * a + random.uniform(2, 6))
    if kind == "timeout":
        return min(45.0, 6.0 * a + random.uniform(1, 3))
    if kind == "tls":
        return min(30.0, 4.0 * a + random.uniform(0.5, 2))
    if kind == "device_code":
        return min(40.0, 8.0 * a)
    if kind == "token_poll":
        return min(20.0, 3.0 * a)
    return min(20.0, 3.0 * a)


def _mark_device_flow_cooldown(seconds: float) -> None:
    global _device_flow_cooldown_until
    until = time.time() + max(0.0, float(seconds))
    with _device_flow_cooldown_lock:
        if until > _device_flow_cooldown_until:
            _device_flow_cooldown_until = until


def _wait_device_flow_cooldown() -> None:
    """若处于 rate_limited 冷却期则阻塞等待。"""
    with _device_flow_cooldown_lock:
        until = float(_device_flow_cooldown_until or 0.0)
    remain = until - time.time()
    if remain > 0:
        time.sleep(min(remain, 120.0))


def _proxy_kw(proxy_spec: str | None = None, *, force_direct: bool = False) -> dict:
    """统一代理参数；账号级显式值优先，空值表示直连。"""
    if force_direct:
        return {"proxies": {"http": "", "https": ""}}
    if proxy_spec is not None:
        mapped = _proxy_map(proxy_spec)
        return {"proxies": mapped} if mapped else {"proxies": {"http": "", "https": ""}}
    return {"proxies": PROXIES} if PROXIES else {}


def _extract_signup_action_id(js_or_html: str) -> Optional[str]:
    """
    从 Next.js chunk / HTML 提取 sign-up 的 server action id。
    优先 createServerReference(\"...\", ..., \"default\")，兼容裸 7f… 哈希。
    """
    text = js_or_html or ""
    # 命名 default 的注册 action（当前页面真源）
    m = re.search(
        r'createServerReference\)?\(\s*["\']([a-f0-9]{40,44})["\'][^)]*?["\']default["\']',
        text,
    )
    if m:
        return m.group(1)
    m = re.search(
        r'createServerReference\)?\(\s*["\'](7f[a-f0-9]{40})["\']',
        text,
    )
    if m:
        return m.group(1)
    m = re.search(r"\b(7f[a-fA-F0-9]{40})\b", text)
    if m:
        return m.group(1)
    return None


def _parse_device_consent_page(html: str, page_url: str = "") -> dict[str, str]:
    """
    从 OAuth 同意页 HTML 解析当前版本的 approve form。
    页面仍是 form POST（非 server action）；字段/action URL 以页面为准自动跟随。
    """
    out = {
        "approve_url": f"{OIDC_ISSUER}/oauth2/device/approve",
        "user_code": "",
        "principal_type": "User",
        "principal_id": "",
        "user_id": "",
    }
    text = html or ""
    try:
        soup = BeautifulSoup(text, "html.parser")
        form = None
        for f in soup.find_all("form"):
            action = (f.get("action") or "").lower()
            if "device/approve" in action or "approve" in action:
                form = f
                break
        if form is None and soup.find("form"):
            form = soup.find("form")
        if form is not None:
            action = (form.get("action") or "").strip()
            if action:
                out["approve_url"] = urljoin(page_url or f"{site_url}/", action)
            for inp in form.find_all("input"):
                name = (inp.get("name") or "").strip()
                val = inp.get("value")
                if val is None:
                    val = ""
                if name == "user_code" and val:
                    out["user_code"] = str(val)
                elif name == "principal_type" and val:
                    out["principal_type"] = str(val)
                elif name == "principal_id":
                    out["principal_id"] = str(val)
    except Exception:
        pass
    # RSC/flight 里的 userId（表单 principal_id 常为空，由前端 state 填）
    m = re.search(r'"userId":"([0-9a-fA-F-]{36})"', text)
    if m:
        out["user_id"] = m.group(1)
        if not out["principal_id"]:
            out["principal_id"] = m.group(1)
    m = re.search(
        r'approveUrl\\?":\\?"(https:[^"\\]+device/approve[^"\\]*)"',
        text,
    )
    if m and not out.get("approve_url"):
        out["approve_url"] = m.group(1).replace("\\/", "/")
    m = re.search(r'"approveUrl":"(https:[^"]+device/approve[^"]*)"', text)
    if m:
        out["approve_url"] = m.group(1)
    return out


def _request_device_code(timeout: int = 20, *, proxy_spec: str | None = None) -> dict | None:
    """申请 device_code；优先 curl_cffi（与 session 同栈），失败再回落 urllib。"""
    data = {
        "client_id": GROK_CLI_CLIENT_ID,
        "scope": OIDC_SCOPES,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
    }
    curl_error = ""
    for attempt in range(2):
        try:
            r = requests.post(
                f"{OIDC_ISSUER}/oauth2/device/code",
                data=data,
                headers=headers,
                impersonate=DEFAULT_IMPERSONATE,
                timeout=timeout,
                **_proxy_kw(proxy_spec),
            )
            if r.status_code == 429 or "rate" in (r.text or "").lower():
                return {
                    "_error": f"device/code rate_limited HTTP {r.status_code}: {(r.text or '')[:200]}"
                }
            if r.status_code >= 400:
                return {
                    "_error": f"device/code HTTP {r.status_code}: {(r.text or '')[:200]}"
                }
            return r.json()
        except Exception as e:
            curl_error = str(e)
            if attempt == 0:
                time.sleep(0.25)
    # 仅直连时回落 urllib；代理租约不得中途变为直连。
    if proxy_spec:
        return {"_error": f"device/code 异常: {curl_error or '代理请求失败'}"}
    try:
        req = urllib.request.Request(
            f"{OIDC_ISSUER}/oauth2/device/code",
            data=urllib.parse.urlencode(data).encode(),
            method="POST",
            headers=headers,
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="ignore")[:200]
        except Exception:
            pass
        if e.code == 429 or "rate" in body.lower():
            return {"_error": f"device/code rate_limited HTTP {e.code}: {body}"}
        return {"_error": f"device/code HTTP {e.code}: {body}"}
    except Exception as e:
        detail = f"{e}"
        if curl_error:
            detail += f"；curl_cffi: {curl_error}"
        return {"_error": f"device/code 异常: {detail}"}


def _poll_device_token(
    device_code: str,
    interval: int,
    expires_in: int,
    timeout: int = 60,
    *,
    proxy_spec: str | None = None,
) -> dict | None:
    """
    approve 之后立刻查 token，不再先傻等一个 interval。
    仍遵守 slow_down / authorization_pending，保证成功率。

    成功返回 token dict；失败返回 None 或 {"_error": "..."}。
    """
    deadline = time.time() + min(int(expires_in or 1800), timeout)
    # 服务端 interval 常为 5；我们用更短的本地间隔，被 slow_down 再拉长
    server_interval = max(1, int(interval or 5))
    wait = min(1.2, float(server_interval))
    net_fail = 0
    first = True
    last_err = "token poll timeout"
    form = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": GROK_CLI_CLIENT_ID,
        "device_code": device_code,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    while time.time() < deadline:
        if not first:
            time.sleep(wait)
        first = False
        try:
            r = requests.post(
                f"{OIDC_ISSUER}/oauth2/token",
                data=form,
                headers=headers,
                impersonate=DEFAULT_IMPERSONATE,
                timeout=20,
                **_proxy_kw(proxy_spec),
            )
            body_text = r.text or ""
            try:
                body = r.json() if body_text else {}
            except Exception:
                body = {}
            if r.status_code < 400 and (body.get("access_token") or body.get("key")):
                return body
            error = (body.get("error") if isinstance(body, dict) else "") or ""
            if error == "authorization_pending":
                net_fail = 0
                wait = min(max(wait, float(server_interval) * 0.6), 6.0)
                last_err = "authorization_pending"
                continue
            if error == "slow_down":
                wait = min(wait + 3.0, 15.0)
                last_err = "slow_down"
                continue
            if error:
                desc = body.get("error_description") or ""
                last_err = f"{error}" + (f": {desc}" if desc else "")
                # invalid_grant / access_denied / expired_token：别空转
                return {"_error": last_err}
            net_fail += 1
            last_err = f"token HTTP {r.status_code}: {body_text[:160]}"
            if net_fail >= 5:
                return {"_error": last_err}
            wait = min(wait + 1.5, 12.0)
            continue
        except Exception as e:
            # 瞬时网络：多试几次，别一次超时就放弃已 approve 的 flow
            net_fail += 1
            last_err = f"token poll 异常: {e}"
            if net_fail >= 6:
                return {"_error": last_err}
            wait = min(wait + 1.0, 10.0)
            continue
    return {"_error": last_err}


def _rfc3339_ns(ts: float) -> str:
    """与 grokcli-2api 一致的 expires_at 格式。"""
    from datetime import datetime, timezone

    dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(dt.microsecond * 1000):09d}Z"


def token_to_auth_entry(token: dict, email: str = "") -> dict[str, Any]:
    """
    将 device flow 得到的 token 转成上游 /accounts/import 可接受的 entry。
    与 grokcli-2api sso_to_auth_json.token_to_auth_entry 字段对齐。
    """
    access = (token or {}).get("access_token") or (token or {}).get("key") or ""
    refresh = (token or {}).get("refresh_token") or ""
    payload = decode_jwt_payload(access)

    user_id = payload.get("sub") or payload.get("principal_id") or ""
    principal_id = payload.get("principal_id") or user_id
    principal_type = payload.get("principal_type") or "User"

    expires_in = int((token or {}).get("expires_in") or 21600)
    if "exp" in payload:
        expires_at = _rfc3339_ns(float(payload["exp"]))
    else:
        expires_at = _rfc3339_ns(time.time() + expires_in)

    iat = payload.get("iat")
    create_time = _rfc3339_ns(float(iat) if iat else time.time())

    return {
        "key": access,
        "auth_mode": "oidc",
        "create_time": create_time,
        "user_id": user_id,
        "email": email or payload.get("email") or "",
        "principal_type": principal_type,
        "principal_id": principal_id,
        "refresh_token": refresh,
        "expires_at": expires_at,
        "oidc_issuer": OIDC_ISSUER,
        "oidc_client_id": GROK_CLI_CLIENT_ID,
    }


def sso_device_flow_to_token(
    sso: str,
    *,
    impersonate: str | None = None,
    timeout: int = 28,
    issue_token: bool | None = None,
    proxy_spec: str | None = None,
) -> dict[str, Any]:
    """
    与 grokcli-2api sso_to_auth_json.sso_to_token 同路径：
    SSO cookie → 登录态探测 → OIDC device verify/approve → access_token。

    issue_token:
      - None: 跟全局 DEVICE_FLOW_ISSUE_TOKEN（默认 True，换到 access_token）
      - True: 批准后轮询 token（生产路径）
      - False: 批准成功即返回（仅诊断用）

    加固：
    - 同意页字段/approve URL 从当前 HTML 自动解析（跟随页面版本）
    - 全局冷却（rate_limited 后拉长间隔）
    - TLS/超时失败时轮换 impersonate
    """
    s = (sso or "").strip()
    if not s:
        return {"ok": False, "error": "空 sso", "token": None, "payload": {}}
    if not is_sso_jwt_shape(s):
        return {"ok": False, "error": "非有效 JWT 形态", "token": None, "payload": {}}

    do_token = DEVICE_FLOW_ISSUE_TOKEN if issue_token is None else bool(issue_token)
    payload = decode_jwt_payload(s)
    proxy_kw = _proxy_kw(proxy_spec)

    # 指纹列表：调用方指定的优先，再轮换稳妥指纹
    fps: list[str] = []
    if impersonate:
        fps.append(impersonate)
    for x in DEVICE_FLOW_IMPERSONATES:
        if x not in fps:
            fps.append(x)
    # 最多试 3 个指纹，避免一次导入拖太久
    fps = fps[:3]

    # 有限并发 + 全局冷却：限流时大家一起让路，不把成功率打穿
    with _DEVICE_FLOW_SEM:
        _wait_device_flow_cooldown()
        last_err = "device flow 失败"

        for fp_idx, fp in enumerate(fps):
            try:
                sess = requests.Session(impersonate=fp)
                # 浏览器同源 cookie：.x.ai 即可覆盖 accounts / auth
                sess.cookies.set("sso", s, domain=".x.ai", path="/")

                r = sess.get(
                    "https://accounts.x.ai/",
                    timeout=timeout,
                    allow_redirects=True,
                    **proxy_kw,
                )
                final_url = (r.url or "").lower()
                if "error=rate_limited" in final_url or "rate_limited" in final_url:
                    last_err = f"探测 rate_limited: {r.url}"
                    _mark_device_flow_cooldown(25 + 10 * fp_idx)
                    # 限流：立刻让路，别继续换指纹连打
                    break
                if "sign-in" in final_url or "sign-up" in final_url:
                    return {
                        "ok": False,
                        "error": f"会话无效（跳转 {r.url}）",
                        "token": None,
                        "payload": payload,
                    }
                if r.status_code >= 400:
                    last_err = f"探测 HTTP {r.status_code}"
                    continue
            except Exception as e:
                last_err = f"探测异常: {e}"
                kind = _device_flow_error_kind(last_err)
                if kind in ("timeout", "tls"):
                    # 换指纹再试
                    time.sleep(0.6 + 0.4 * fp_idx)
                    continue
                return {
                    "ok": False,
                    "error": last_err,
                    "token": None,
                    "payload": payload,
                }

            dc = _request_device_code(timeout=max(15, int(timeout)), proxy_spec=proxy_spec)
            if not dc or dc.get("_error"):
                last_err = (dc or {}).get("_error") or "device/code 申请失败"
                if _device_flow_error_kind(last_err) == "rate_limited":
                    _mark_device_flow_cooldown(30)
                # device/code 与指纹无关，不必换指纹空转
                return {
                    "ok": False,
                    "error": last_err,
                    "token": None,
                    "payload": payload,
                }
            if not dc.get("device_code") or not dc.get("user_code"):
                last_err = "device/code 申请失败（无 device_code）"
                return {
                    "ok": False,
                    "error": last_err,
                    "token": None,
                    "payload": payload,
                }

            user_code = str(dc["user_code"])
            verify_uri = (
                dc.get("verification_uri_complete")
                or f"{site_url}/oauth2/device?user_code={user_code}"
            )
            consent_html = ""
            consent_url = ""
            try:
                # 浏览器顺序：先打开 complete URI，再 POST verify
                sess.get(
                    verify_uri,
                    timeout=timeout,
                    allow_redirects=True,
                    **proxy_kw,
                )
                r = sess.post(
                    f"{OIDC_ISSUER}/oauth2/device/verify",
                    data={"user_code": user_code},
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Origin": site_url,
                        "Referer": verify_uri,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    },
                    timeout=timeout,
                    allow_redirects=True,
                    **proxy_kw,
                )
                ru = r.url or ""
                consent_url = ru
                consent_html = r.text or ""
                if "rate_limited" in ru.lower() or "error=rate_limited" in ru.lower():
                    last_err = f"device verify 失败: {ru}"
                    _mark_device_flow_cooldown(30 + 10 * fp_idx)
                    time.sleep(1.5)
                    break
                if "consent" not in ru:
                    last_err = f"device verify 失败: {ru}"
                    # 非限流的 verify 失败（如 code 过期）换指纹意义不大，直接返回
                    if "error=" in ru.lower() and "rate_limited" not in ru.lower():
                        return {
                            "ok": False,
                            "error": last_err,
                            "token": None,
                            "payload": payload,
                        }
                    continue
            except Exception as e:
                last_err = f"device verify 异常: {e}"
                kind = _device_flow_error_kind(last_err)
                if kind in ("timeout", "tls"):
                    time.sleep(0.6 + 0.4 * fp_idx)
                    continue
                return {
                    "ok": False,
                    "error": last_err,
                    "token": None,
                    "payload": payload,
                }

            # 关键：同意页 form 字段 / approve URL 跟随当前页面版本，不写死
            page = _parse_device_consent_page(consent_html, consent_url)
            approve_url = page.get("approve_url") or f"{OIDC_ISSUER}/oauth2/device/approve"
            # 浏览器 SSR 表单 principal_id 为空；部分号带 userId 也能过——两种都试
            pid_candidates: list[str] = []
            page_pid = (page.get("principal_id") or page.get("user_id") or "").strip()
            # 先空（与页面 hidden 默认一致），再 userId
            pid_candidates.append("")
            if page_pid and page_pid not in pid_candidates:
                pid_candidates.append(page_pid)

            approve_headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": site_url,
                "Referer": consent_url or verify_uri,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "same-site",
                "Sec-Fetch-User": "?1",
            }
            approved_ok = False
            try:
                for pid in pid_candidates:
                    approve_data = {
                        "user_code": page.get("user_code") or user_code,
                        "action": "allow",
                        "principal_type": page.get("principal_type") or "User",
                        "principal_id": pid,
                    }
                    r = sess.post(
                        approve_url,
                        data=approve_data,
                        headers=approve_headers,
                        timeout=timeout,
                        allow_redirects=True,
                        **proxy_kw,
                    )
                    ru = r.url or ""
                    body_low = (r.text or "").lower()
                    if "rate_limited" in ru.lower():
                        last_err = f"device approve 失败: {ru}"
                        _mark_device_flow_cooldown(30)
                        approved_ok = False
                        break
                    # deny 会落到 done?denied=1 —— 这是真拒绝，不是假成功
                    if "denied=1" in ru.lower():
                        last_err = f"device approve 被拒绝: {ru}"
                        return {
                            "ok": False,
                            "error": last_err,
                            "token": None,
                            "payload": payload,
                            "approved": False,
                        }
                    if "done" in ru or "authorized" in body_low:
                        approved_ok = True
                        # 有多个 pid 候选时，本轮只 approve 一次（code 已消耗）
                        break
                if not approved_ok and "rate_limited" not in str(last_err):
                    last_err = f"device approve 失败: {ru if 'ru' in locals() else 'no response'}"
                    return {
                        "ok": False,
                        "error": last_err,
                        "token": None,
                        "payload": payload,
                        "approved": False,
                    }
                if not approved_ok:
                    break
            except Exception as e:
                last_err = f"device approve 异常: {e}"
                kind = _device_flow_error_kind(last_err)
                if kind in ("timeout", "tls"):
                    time.sleep(0.6 + 0.4 * fp_idx)
                    continue
                return {
                    "ok": False,
                    "error": last_err,
                    "token": None,
                    "payload": payload,
                }

            # 诊断模式：只验证同意授权，不下发 token
            if not do_token:
                _mark_device_flow_cooldown(_DEVICE_FLOW_SUCCESS_COOLDOWN)
                return {
                    "ok": True,
                    "error": None,
                    "token": None,
                    "payload": payload,
                    "has_refresh": False,
                    "impersonate": fp,
                    "approved": True,
                    "issue_token": False,
                    "approve_url": approve_url,
                    "user_code": user_code,
                    "note": "device approve 成功；已跳过 token 下发（GROK_DEVICE_FLOW_ISSUE_TOKEN=0）",
                }

            token = _poll_device_token(
                dc["device_code"],
                int(dc.get("interval") or 5),
                int(dc.get("expires_in") or 1800),
                timeout=45,
                proxy_spec=proxy_spec,
            )
            if isinstance(token, dict) and token.get("_error"):
                last_err = (
                    f"device approve 后 token 失败: {token.get('_error')}"
                )
                # code 已完成 approve 后仍 invalid_grant / access_denied，属于明确终止；
                # 换 TLS 指纹重做整条 flow 不会修复，只会把坏号耗时放大数倍。
                terminal = str(token.get("_error") or "").lower()
                if any(
                    marker in terminal
                    for marker in ("invalid_grant", "access denied", "access_denied")
                ):
                    return {
                        "ok": False,
                        "error": last_err,
                        "token": None,
                        "payload": payload,
                        "approved": True,
                    }
                time.sleep(1.0)
                continue
            if not token or not (token.get("access_token") or token.get("key")):
                # 假批准典型症状：页面已 done，但 token 仍 invalid_grant
                last_err = (
                    "device approve 后未拿到 access_token"
                    "（常见 invalid_grant/Access denied：会话无法真正授权）"
                )
                # approve 已成功但 token 轮询失败：短歇后换指纹整条重来
                time.sleep(1.0)
                continue

            # 成功后轻冷却，降低连打 rate_limited（比旧 2s 更省）
            _mark_device_flow_cooldown(_DEVICE_FLOW_SUCCESS_COOLDOWN)
            return {
                "ok": True,
                "error": None,
                "token": token,
                "payload": payload,
                "has_refresh": bool(token.get("refresh_token")),
                "impersonate": fp,
                "approved": True,
                "issue_token": True,
            }

        if _device_flow_error_kind(last_err) == "rate_limited":
            _mark_device_flow_cooldown(20)
        return {
            "ok": False,
            "error": last_err,
            "token": None,
            "payload": payload,
        }


def validate_sso_cookie(
    sso: str,
    *,
    impersonate: str = DEFAULT_IMPERSONATE,
    user_agent: Optional[str] = None,
    timeout: int = 15,
    require_device_flow: bool = True,
    retries: int = 2,
    issue_token: bool | None = None,
    proxy_spec: str | None = None,
) -> dict[str, Any]:
    """
    校验换到的 sso 是否真正可导入上游。

    默认 require_device_flow=True：走 OIDC device flow（与 import-sso 同路径）。
    issue_token 默认跟随 GROK_DEVICE_FLOW_ISSUE_TOKEN（默认 True，换到 access_token）。

    返回: {ok, error, payload, token?, approved?}
    """
    del user_agent  # 保留签名兼容
    s = (sso or "").strip()
    if not s:
        return {"ok": False, "error": "空 sso", "payload": {}}
    if not is_sso_jwt_shape(s):
        return {"ok": False, "error": "非有效 JWT 形态", "payload": {}}

    if not require_device_flow:
        # 浅校验（不推荐用于记成功）
        payload = decode_jwt_payload(s)
        try:
            sess = requests.Session(impersonate=impersonate or DEFAULT_IMPERSONATE)
            sess.cookies.set("sso", s, domain=".x.ai", path="/")
            r = sess.get(
                "https://accounts.x.ai/",
                timeout=timeout,
                allow_redirects=True,
                **_proxy_kw(proxy_spec),
            )
            final_url = (r.url or "").lower()
            if "sign-in" in final_url or "sign-up" in final_url:
                return {"ok": False, "error": f"会话无效（跳转 {r.url}）", "payload": payload}
            if r.status_code >= 400:
                return {"ok": False, "error": f"探测 HTTP {r.status_code}", "payload": payload}
            return {"ok": True, "error": None, "payload": payload}
        except Exception as e:
            return {"ok": False, "error": f"探测异常: {e}", "payload": payload}

    last_err = "device flow 失败"
    attempts = max(1, int(retries or 1))
    for i in range(1, attempts + 1):
        result = sso_device_flow_to_token(
            s,
            impersonate=None,  # 内部轮换稳妥指纹
            timeout=max(int(timeout or 20), 28),
            issue_token=issue_token,
            proxy_spec=proxy_spec,
        )
        if result.get("ok"):
            return result
        last_err = result.get("error") or last_err
        # 会话明确无效则不必重试
        if "会话无效" in str(last_err) or "非有效 JWT" in str(last_err):
            break
        if i < attempts:
            wait = _device_flow_wait_seconds(str(last_err), i)
            if _device_flow_error_kind(str(last_err)) == "rate_limited":
                _mark_device_flow_cooldown(wait)
            time.sleep(wait)
    return {
        "ok": False,
        "error": last_err,
        "payload": decode_jwt_payload(s),
        "token": None,
    }


def _protobuf_varint(n: int) -> bytes:
    out = bytearray()
    while n > 0x7F:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n & 0x7F)
    return bytes(out)


def encode_grpc_string_field(field_id: int, string_value: str) -> bytes:
    """protobuf length-delimited string field (wire type 2)."""
    value_bytes = string_value.encode("utf-8")
    key = (field_id << 3) | 2
    return bytes([key]) + _protobuf_varint(len(value_bytes)) + value_bytes


def encode_grpc_message(field_id, string_value):
    """兼容旧调用：单 string 字段 + grpc-web 帧。"""
    payload = encode_grpc_string_field(field_id, string_value)
    return b"\x00" + struct.pack(">I", len(payload)) + payload


def encode_create_email_validation_code(
    email: str, castle_request_token: Optional[str] = None
) -> bytes:
    """
    CreateEmailValidationCodeRequest:
      string email = 1;
      EmailTemplate email_template = 2;          # optional
      optional string castle_request_token = 3;
    """
    parts = [encode_grpc_string_field(1, email)]
    if castle_request_token is not None:
        parts.append(encode_grpc_string_field(3, castle_request_token))
    payload = b"".join(parts)
    return b"\x00" + struct.pack(">I", len(payload)) + payload


def encode_grpc_message_verify(email, code):
    p1 = encode_grpc_string_field(1, email)
    p2 = encode_grpc_string_field(2, code)
    payload = p1 + p2
    return b"\x00" + struct.pack(">I", len(payload)) + payload


class LogBuffer:
    """线程安全日志缓冲，供控制台与 Web UI 共用。"""

    def __init__(self, maxlen: int = 2000):
        self._lock = threading.Lock()
        self._seq = 0
        self._entries = deque(maxlen=maxlen)

    def emit(self, message: str, level: str = "info"):
        ts = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self._seq += 1
            entry = {
                "id": self._seq,
                "time": ts,
                "level": level,
                "message": message,
            }
            self._entries.append(entry)
        print(f"[{ts}] {message}")
        return entry

    def latest_id(self) -> int:
        with self._lock:
            return int(self._seq)

    def since(self, after_id: int = 0, limit: int = 200):
        with self._lock:
            # 服务重启后 seq 从 0 起，浏览器仍可能带着旧 after_id → 永远空结果（日志“卡住”）
            if after_id > self._seq:
                items = list(self._entries)[-limit:]
            else:
                items = [e for e in self._entries if e["id"] > after_id]
                items = items[-limit:]
            return items

    def clear(self):
        with self._lock:
            self._entries.clear()


class RegisterEngine:
    """可被 CLI 与 Web UI 共用的注册引擎。"""

    def __init__(self, log_fn: Optional[Callable[[str, str], None]] = None):
        self.site_url = site_url
        self.config = {
            "site_key": "0x4AAAAAAAhr9JGVDZbrZOo0",
            "action_id": None,
            "state_tree": (
                "%5B%22%22%2C%7B%22children%22%3A%5B%22(app)%22%2C%7B%22children%22%3A%5B%22"
                "(auth)%22%2C%7B%22children%22%3A%5B%22sign-up%22%2C%7B%22children%22%3A%5B%22"
                "__PAGE__%22%2C%7B%7D%2C%22%2Fsign-up%22%2C%22refresh%22%5D%7D%5D%7D%2Cnull%2C"
                "null%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D"
            ),
        }
        self.post_lock = threading.Lock()
        self.file_lock = threading.Lock()
        self.stop_event = threading.Event()
        self._run_lock = threading.Lock()
        self._executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
        self._worker_thread: Optional[threading.Thread] = None
        self.proxy_pool = get_proxy_pool(_BASE_DIR)
        self.domain_pool = get_domain_pool(_BASE_DIR)
        # 注册 POST 起步节流（不包整次 HTTP，允许多线程并行飞）
        self._post_min_interval = 0.25
        self._last_post_start = 0.0
        # SSO 后的 device flow / 协议 / NSFW：后台跑，不堵下一号
        # enrich 线程可多开，真正卡点在 device flow 信号量（默认 2）
        self._enrich_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=6, thread_name_prefix="RegEnrich"
        )
        self._enrich_pending = 0
        self._enrich_lock = threading.Lock()

        self.success_count = 0
        self.fail_count = 0
        self.clean_count = 0
        self.marked_count = 0
        self.review_count = 0
        self.infra_retry_count = 0
        self.unchecked_count = 0
        self.pending_bfs_count = 0
        self.oauth_infra_streak = 0
        self._classification_store: Optional[ClassificationStore] = None
        self._bfs_lock = threading.RLock()
        # 批次目标按成功创建邮箱计；attempt_count 只记录邮箱 API 尝试。
        self.attempt_count = 0
        self.email_create_count = 0
        self._email_create_reserved = 0
        self.bot_retry_count = 0
        self._ss_attempt_lock = threading.Lock()
        # 连续 risk MARKED（跨线程）：触顶熔断，避免同出口 deny 簇空烧
        self._ss_consecutive_deny = 0
        self._ss_deny_lock = threading.Lock()
        self.target_count = 0
        self.workers = 0
        self.start_time: Optional[float] = None
        # 任务结束后冻结耗时，避免 get_status 继续 now-start 空转计时
        self.end_time: Optional[float] = None
        self.output_file: Optional[str] = None
        self.status = "idle"  # idle | initializing | running | stopping | done | error
        self.error_message = ""
        self.resource_exhausted_reason = ""
        # 默认同会话 CLEAN；可被 start(mode=) / GROK_REGISTER_MODE 覆盖
        self.register_mode = resolve_register_mode()
        # 每批任务快照：仅控制 SSO 到手后的账号 Risk 探测。
        # Turnstile / Castle 是注册必需流程，不受此开关影响。
        self.risk_check_enabled = True
        self._ss_idx = 0
        self._ss_idx_lock = threading.Lock()
        # 足够覆盖大批量注册；过小会导致「成功 100、可导入只剩 50」
        self.recent_success: deque = deque(maxlen=5000)
        # Web runtime may inject a non-blocking multi-target auto-import queue.
        # CLI/standalone modes leave it unset and keep their existing behavior.
        self.auto_import_callback = None
        self.account_check_callback = None
        self.account_check_observer = None
        self.on_run_start = None
        self.on_run_complete = None
        self._log_fn = log_fn or (lambda msg, level="info": print(msg))
        # Action ID 缓存：内存 + 磁盘，避免每次/重启都扫 JS（通常 5~20 秒）
        self._action_cache: dict = {
            "action_id": None,
            "site_key": None,
            "state_tree": None,
            "ts": 0.0,
        }
        # 页面发版后 server action id 会变；默认 30 分钟，可用 GROK_ACTION_CACHE_TTL 覆盖
        self._action_cache_ttl = max(60, int(_ACTION_CACHE_TTL))
        self._load_action_cache_disk()

    def log(self, message: str, level: str = "info"):
        self._log_fn(message, level)

    def _next_ss_idx(self) -> int:
        with self._ss_idx_lock:
            self._ss_idx += 1
            return self._ss_idx

    def _reserve_email_creation(self) -> int:
        """Reserve one exact creation slot and return the API-attempt number."""
        with self._ss_attempt_lock:
            target = max(1, int(self.target_count or 1))
            used = int(self.email_create_count or 0) + int(self._email_create_reserved or 0)
            if used >= target:
                return 0
            self._email_create_reserved += 1
            self.attempt_count = int(self.attempt_count or 0) + 1
            return self.attempt_count

    def _finish_email_creation(self, *, success: bool) -> None:
        with self._ss_attempt_lock:
            self._email_create_reserved = max(0, int(self._email_create_reserved or 0) - 1)
            if success:
                self.email_create_count = int(self.email_create_count or 0) + 1

    def _freeze_elapsed(self) -> None:
        """任务结束时钉死 end_time，页面耗时不再往上爬。"""
        if self.start_time and self.end_time is None:
            self.end_time = time.time()

    def get_status(self) -> dict:
        elapsed = 0.0
        avg = 0.0
        if self.start_time:
            # 运行中：实时；已结束：用 end_time 冻结，禁止空转计时
            if self.status in ("initializing", "running", "stopping"):
                end = time.time()
            else:
                end = self.end_time if self.end_time is not None else self.start_time
                # 兼容旧进程：done 了但没 end_time，立刻钉死一次
                if self.end_time is None and self.status in ("done", "error", "idle", "resource_exhausted"):
                    self.end_time = time.time()
                    end = self.end_time
            elapsed = max(0.0, float(end) - float(self.start_time))
            if self.email_create_count > 0:
                avg = elapsed / self.email_create_count
        progress = 0.0
        attempts = int(getattr(self, "attempt_count", 0) or 0)
        if self.target_count > 0:
            progress = min(100.0, float(self.email_create_count) / self.target_count * 100)
        return {
            "status": self.status,
            "success_count": self.success_count,
            "fail_count": self.fail_count,
            "clean_count": int(getattr(self, "clean_count", 0) or 0),
            "marked_count": int(getattr(self, "marked_count", 0) or 0),
            "review_count": int(getattr(self, "review_count", 0) or 0),
            "infra_retry_count": int(getattr(self, "infra_retry_count", 0) or 0),
            "unchecked_count": int(getattr(self, "unchecked_count", 0) or 0),
            "pending_bfs_count": int(getattr(self, "pending_bfs_count", 0) or 0),
            "attempt_count": attempts,
            "email_create_count": int(getattr(self, "email_create_count", 0) or 0),
            "email_create_reserved": int(getattr(self, "_email_create_reserved", 0) or 0),
            "bot_retry_count": int(getattr(self, "bot_retry_count", 0) or 0),
            "target_count": self.target_count,
            "workers": self.workers,
            "register_mode": getattr(self, "register_mode", None) or resolve_register_mode(),
            "risk_check_enabled": bool(getattr(self, "risk_check_enabled", True)),
            "elapsed": round(elapsed, 1),
            "avg_seconds": round(avg, 1),
            "progress": round(progress, 1),
            "output_file": self.output_file or "",
            "accounts_file": str(self._accounts_json_path() or ""),
            "action_id": self.config.get("action_id") or "",
            "site_key": self.config.get("site_key") or "",
            "error_message": self.error_message,
            "enrich_pending": int(getattr(self, "_enrich_pending", 0) or 0),
            "token_ready_count": sum(
                1
                for it in self.recent_success
                if is_auth_token_usable(it.get("auth_token"))
            ),
            # 不把完整 sso / token 暴露给前端轮询；导入走服务端 id 匹配
            "recent_success": [
                {
                    "id": it.get("id"),
                    "email": it.get("email"),
                    "sso_preview": it.get("sso_preview"),
                    "sso": bool(it.get("sso")),  # 仅布尔，表示可导入
                    "has_token": is_auth_token_usable(it.get("auth_token")),
                    "nsfw": it.get("nsfw"),
                    "clean": it.get("clean"),
                    "risk_status": it.get("risk_status") or (
                        "clean"
                        if it.get("clean") is True
                        else ("marked" if it.get("clean") is False else "unchecked")
                    ),
                    "time": it.get("time"),
                    "imported": bool(it.get("imported")),
                    "email_provider": it.get("email_provider") or "",
                    "email_domain": it.get("email_domain") or "",
                }
                for it in self.recent_success
            ],
            "running": self.status in ("initializing", "running", "stopping"),
        }

    def is_running(self) -> bool:
        return self.status in ("initializing", "running", "stopping")

    def _load_action_cache_disk(self) -> None:
        """进程启动时从磁盘恢复 Action ID，避免重启后又扫 10+ 秒。"""
        try:
            if not _ACTION_CACHE_FILE.is_file():
                return
            data = json.loads(_ACTION_CACHE_FILE.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or not data.get("action_id"):
                return
            ts = float(data.get("ts") or 0)
            if time.time() - ts > self._action_cache_ttl:
                return
            self._action_cache = {
                "action_id": data.get("action_id"),
                "site_key": data.get("site_key"),
                "state_tree": data.get("state_tree"),
                "ts": ts,
            }
        except Exception:
            pass

    def _apply_action_cache(self) -> bool:
        cache = self._action_cache
        if not cache.get("action_id"):
            # 内存空时再试一次磁盘（热更新/其他进程写过）
            self._load_action_cache_disk()
            cache = self._action_cache
        if not cache.get("action_id"):
            return False
        if time.time() - float(cache.get("ts") or 0) > self._action_cache_ttl:
            return False
        self.config["action_id"] = cache["action_id"]
        if cache.get("site_key"):
            self.config["site_key"] = cache["site_key"]
        if cache.get("state_tree"):
            self.config["state_tree"] = cache["state_tree"]
        return True

    def _save_action_cache(self) -> None:
        self._action_cache = {
            "action_id": self.config.get("action_id"),
            "site_key": self.config.get("site_key"),
            "state_tree": self.config.get("state_tree"),
            "ts": time.time(),
        }
        try:
            _ACTION_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            _ACTION_CACHE_FILE.write_text(
                json.dumps(self._action_cache, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass

    def initialize(self, force_rescan: bool = False) -> bool:
        self.status = "initializing"
        mode = resolve_register_mode(getattr(self, "register_mode", None))
        self.register_mode = mode
        # 同会话 CLEAN 路径不依赖 Next.js Server Action ID（页内 fetch 自取）
        if mode == "same_session":
            if not self.config.get("site_key"):
                self.config["site_key"] = "0x4AAAAAAAhr9JGVDZbrZOo0"
            # 尽量用缓存 action_id（不强制）；没有也不阻塞
            self._apply_action_cache()
            self.log(
                "路径=same_session（同页 castle mint + 页内 fetch · CLEAN 主路径）",
                "success",
            )
            self.log(
                f"代理={_ss_local_proxy_spec() or '直连'} · "
                "Turnstile 并行预解 · camoufox",
                "info",
            )
            return True

        self.log("路径=protocol（旧混合协议，拆会话 castle 易 deny）", "warn")
        # 优先用缓存，启动几乎立刻进入注册
        if not force_rescan and self._apply_action_cache():
            aid = self.config["action_id"] or ""
            self.log(
                f"使用缓存 Action ID: {aid[:18]}…（TTL {self._action_cache_ttl // 60}m，"
                f"过期会自动跟页面版本）",
                "success",
            )
            return True

        self.log(
            "正在初始化：扫描 accounts.x.ai/sign-up 提取当前页面 Server Action ID…",
            "info",
        )
        t0 = time.time()
        start_url = f"{self.site_url}/sign-up"
        proxy_kw = _proxy_kw()
        with requests.Session(impersonate=DEFAULT_IMPERSONATE) as s:
            try:
                html = s.get(start_url, timeout=20, **proxy_kw).text
                key_match = re.search(r'sitekey":"(0x4[a-zA-Z0-9_-]+)"', html)
                if key_match:
                    self.config["site_key"] = key_match.group(1)
                # 优先 next-router-state-tree；部分构建写在 flight 里
                tree_match = re.search(
                    r'next-router-state-tree":"([^"]+)"', html
                ) or re.search(
                    r'"children":\["sign-up"', html
                )
                if tree_match and hasattr(tree_match, "group") and tree_match.lastindex:
                    self.config["state_tree"] = tree_match.group(1)
                soup = BeautifulSoup(html, "html.parser")
                js_urls = [
                    urljoin(start_url, script["src"])
                    for script in soup.find_all("script", src=True)
                    if "_next/static" in script.get("src", "")
                ]
                # 1) HTML 内联 flight 也可能带 id
                aid = _extract_signup_action_id(html)
                # 2) 扫 JS chunk：优先 createServerReference(..., "default")
                if not aid:
                    for js_url in js_urls:
                        try:
                            js_content = s.get(js_url, timeout=15, **proxy_kw).text
                        except Exception:
                            continue
                        aid = _extract_signup_action_id(js_content)
                        if aid:
                            break
                self.config["action_id"] = aid
                if aid:
                    cost = time.time() - t0
                    self.log(
                        f"Action ID: {aid}（扫描耗时 {cost:.1f}s，已跟随当前页面版本）",
                        "success",
                    )
            except Exception as e:
                self.error_message = f"初始化扫描失败: {e}"
                self.log(self.error_message, "error")
                self.status = "error"
                return False

        if not self.config["action_id"]:
            self.error_message = "未找到 Action ID（页面结构可能已变）"
            self.log(self.error_message, "error")
            self.status = "error"
            return False
        self._save_action_cache()
        return True

    def send_email_code_grpc(self, session, email, castle_request_token: Optional[str] = None):
        """协议发码。可选带 castle_request_token（field 3）。"""
        url = f"{self.site_url}/auth_mgmt.AuthManagement/CreateEmailValidationCode"
        data = encode_create_email_validation_code(email, castle_request_token)
        headers = {
            "content-type": "application/grpc-web+proto",
            "x-grpc-web": "1",
            "x-user-agent": "connect-es/2.1.1",
            "origin": self.site_url,
            "referer": f"{self.site_url}/sign-up?redirect=grok-com",
        }
        try:
            res = session.post(url, data=data, headers=headers, timeout=15)
            # grpc-web: HTTP 200 + body trailer grpc-status:0 也算成功；
            # 部分失败会在 header 带 grpc-status。
            if res.status_code != 200:
                return False
            gs = res.headers.get("grpc-status") or res.headers.get("Grpc-Status")
            if gs is not None and str(gs) not in ("0", ""):
                return False
            body = res.content or b""
            if b"grpc-status:" in body and b"grpc-status:0" not in body:
                # trailer 非 0
                if b"grpc-status:0\r\n" not in body and b"grpc-status:0\n" not in body:
                    # 可能只有非 0 status
                    if b"grpc-status:" in body:
                        # 粗判：出现 status 且不是 0
                        text = body.decode("latin1", errors="replace")
                        if "grpc-status:0" not in text:
                            return False
            return True
        except Exception as e:
            self.log(f"{email} 发送验证码异常: {e}", "error")
            return False

    def verify_email_code_grpc(self, session, email, code):
        url = f"{self.site_url}/auth_mgmt.AuthManagement/VerifyEmailValidationCode"
        data = encode_grpc_message_verify(email, code)
        headers = {
            "content-type": "application/grpc-web+proto",
            "x-grpc-web": "1",
            "x-user-agent": "connect-es/2.1.1",
            "origin": self.site_url,
            "referer": f"{self.site_url}/sign-up?redirect=grok-com",
        }
        try:
            res = session.post(url, data=data, headers=headers, timeout=15)
            return res.status_code == 200
        except Exception as e:
            self.log(f"{email} 验证验证码异常: {e}", "error")
            return False

    def _sleep(self, seconds: float) -> bool:
        """可中断 sleep。返回 True 表示已被 stop。"""
        if seconds <= 0:
            return self.stop_event.is_set()
        return self.stop_event.wait(timeout=seconds)

    def _fail_account(
        self,
        email_service: Optional[EmailService],
        email: Optional[str],
        reason: str,
        level: str = "error",
        *,
        count_fail: bool = True,
    ) -> None:
        """
        单个账号失败：记失败、删邮箱、本账号结束。
        不置 stop_event，其它线程与后续账号继续跑到达目标。
        （同一邮箱不再换号死磕；新一轮会开新邮箱，属于新账号。）

        count_fail=False：仅收尾（如 MARKED 已记 marked_count），避免和「失败尝试」重复加。
        """
        if count_fail:
            self.fail_count += 1
        self.error_message = reason
        self.log(f"{reason} — 本账号结束，任务继续", level)
        if email and email_service is not None:
            try:
                email_service.delete_email(email)
            except Exception:
                pass

    def _emergency_save_sso(self, email: str, sso: str, reason: str = "") -> bool:
        """
        紧急落盘：任何已拿到的 SSO 都必须写文件，避免账号创建成功却因后续步骤丢号。
        不计入 success_count 上限拦截——宁可多写一行，也不能吞掉已建账号。
        返回 True 表示至少写入成功一处。
        """
        s = (sso or "").strip()
        if not s:
            return False
        ok = False
        try:
            emergency = _BASE_DIR / "keys" / "emergency_sso.txt"
            emergency.parent.mkdir(parents=True, exist_ok=True)
            with self.file_lock:
                with open(emergency, "a", encoding="utf-8") as f:
                    f.write(f"{email}----{s}\n" if email else f"{s}\n")
                    ok = True
                try:
                    emergency.chmod(0o600)
                except OSError:
                    pass
                if self.output_file:
                    with open(self.output_file, "a", encoding="utf-8") as f:
                        f.write(s + "\n")
                        ok = True
                    try:
                        Path(self.output_file).chmod(0o600)
                    except OSError:
                        pass
                # 与 TXT 并行维护便于其他程序直接读取的账号 JSON。
                self._write_account_json_unlocked(email=email, sso=s)
            self.log(
                f"{email} SSO 已紧急落盘（{reason or '防丢号'}）→ keys/emergency_sso.txt + 任务文件",
                "success",
            )
        except Exception as e:
            self.log(f"{email} 紧急落盘失败: {e} | SSO 前缀 {s[:20]}…", "error")
        return ok

    def _record_success(
        self,
        email: str,
        sso: str,
        unhinged_ok: bool,
        email_service: Optional[EmailService] = None,
        note: str = "",
        *,
        already_written: bool = False,
        auth_token: Optional[dict] = None,
        proxy_audit: Optional[dict] = None,
        clean: Optional[bool] = None,
        check_state: str = "",
    ) -> str:
        """
        写入 SSO 并计入成功。返回 success_id（空串表示未计入成功列表）。
        same_session：停批看创邮次数，成功数可超过 target（在飞号收尾仍计成功）。
        protocol：仍按成功数顶 target。
        already_written=True：SSO 已在紧急落盘写过，只更新计数/UI，避免重复行。
        auth_token：注册时 device flow 换到的 token，导入上游可直写，免二次换票。
        clean=True 表示已通过 Risk；None 表示未检测（UNCHECKED）。
        """
        classification_store = self._classification_store
        if classification_store is None and self.output_file:
            classification_path = Path(self.output_file)
            if not classification_path.is_absolute():
                classification_path = _BASE_DIR / classification_path
            classification_store = ClassificationStore(classification_path)
            self._classification_store = classification_store
        with self.file_lock:
            email_meta = (
                email_service.get_email_metadata(email)
                if email_service is not None and hasattr(email_service, "get_email_metadata")
                else {}
            )
            if not already_written:
                try:
                    with open(self.output_file, "a", encoding="utf-8") as f:
                        f.write(sso + "\n")
                    try:
                        Path(self.output_file).chmod(0o600)
                    except OSError:
                        pass
                except Exception as write_err:
                    self.log(f"{email} 写入文件失败: {write_err}，尝试紧急落盘", "error")
                    try:
                        emergency = _BASE_DIR / "keys" / "emergency_sso.txt"
                        with open(emergency, "a", encoding="utf-8") as f:
                            f.write(f"{email}----{sso}\n")
                        try:
                            emergency.chmod(0o600)
                        except OSError:
                            pass
                    except Exception as e2:
                        self.log(f"{email} 紧急落盘也失败: {e2}", "error")
                        self.fail_count += 1
                        return ""

            # already_written 只表示 TXT 已由紧急落盘写过；JSON 使用 upsert，
            # 因此这里始终再保证一次，避免任一旧调用路径漏掉结构化输出。
            self._write_account_json_unlocked(
                email=email, sso=sso, proxy_audit=proxy_audit, **email_meta
            )

            if check_state in ("marked", "review", "infra_retry"):
                clean = False if check_state == "marked" else None
                field = {"marked": "marked_count", "review": "review_count", "infra_retry": "infra_retry_count"}[check_state]
                setattr(self, field, getattr(self, field, 0) + 1)
                if classification_store is not None:
                    classification_store.finalize(email=email, sso=sso, state=check_state, reason="ACCOUNT_CHECK")
            elif clean is None:
                self.unchecked_count += 1
                if classification_store is not None:
                    classification_store.finalize(
                        email=email, sso=sso, state="unchecked", reason="RISK_DISABLED"
                    )
            elif clean is True:
                self.clean_count += 1
                if classification_store is not None:
                    classification_store.finalize(
                        email=email, sso=sso, state="clean", reason="BFS_CLEAN"
                    )

            self.success_count += 1
            avg = (time.time() - (self.start_time or time.time())) / max(1, self.success_count)
            nsfw_tag = "✓" if unhinged_ok else "…"
            # 浅拷贝 token，避免后续引用被外部改写
            cached_token = None
            if isinstance(auth_token, dict) and is_auth_token_usable(auth_token):
                cached_token = dict(auth_token)
            success_id = f"{int(time.time() * 1000)}_{self.success_count}"
            success_item = {
                    "id": success_id,
                    "email": email,
                    "sso": sso,
                    "sso_preview": (sso[:18] + "...") if len(sso) > 18 else sso,
                    "auth_token": cached_token,
                    "nsfw": unhinged_ok,
                    "clean": clean,
                    "risk_status": check_state or ("clean" if clean is True else "unchecked"),
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "imported": False,
                    "auto_queued": bool(check_state == "clean" and callable(self.auto_import_callback)),
                    "email_provider": email_meta.get("email_provider") or "",
                    "email_domain": email_meta.get("email_domain") or "",
                }
            if proxy_audit:
                success_item.update(dict(proxy_audit))
            self.recent_success.appendleft(success_item)
            extra = f" | {note}" if note else ""
            created = int(getattr(self, "email_create_count", 0) or 0)
            risk_label = check_state.upper() if check_state else ("CLEAN" if clean is True else "UNCHECKED")
            self.log(
                f"{risk_label} · 成功 {self.success_count} · 创邮 {created}/{self.target_count} | {email} | "
                f"SSO: {sso[:15]}... | 平均: {avg:.1f}s | NSFW: {nsfw_tag}{extra}",
                "success",
            )
            if email_service is not None:
                try:
                    email_service.delete_email(email)
                except Exception:
                    pass
            return success_id

    def _update_success_meta(
        self,
        success_id: str,
        *,
        auth_token: Optional[dict] = None,
        unhinged_ok: Optional[bool] = None,
        clean: Optional[bool] = None,
        note: str = "",
    ) -> None:
        """后台 enrich 完成后回填 token / NSFW / risk 状态（按 id 匹配）。"""
        if not success_id:
            return
        with self.file_lock:
            for item in self.recent_success:
                if item.get("id") != success_id:
                    continue
                if isinstance(auth_token, dict) and is_auth_token_usable(auth_token):
                    item["auth_token"] = dict(auth_token)
                    access = auth_token.get("access_token") or auth_token.get("key") or ""
                    payload = decode_jwt_payload(str(access))
                    user_id = payload.get("sub") or payload.get("principal_id") or ""
                    if user_id:
                        self._write_account_json_unlocked(
                            email=str(item.get("email") or ""),
                            sso=str(item.get("sso") or ""),
                            user_id=str(user_id),
                        )
                if unhinged_ok is not None:
                    item["nsfw"] = bool(unhinged_ok)
                if clean is not None:
                    item["clean"] = bool(clean)
                    item["risk_status"] = "clean" if bool(clean) else "marked"
                if note:
                    item["note"] = note
                break

    def _revoke_marked_success(
        self,
        success_id: str,
        *,
        email: str = "",
        summary: str = "",
    ) -> None:
        """
        MARKED 账号若已误入成功列表：踢出、回滚 success_count，禁止导入。
        主路径应在 risk 通过后再 _record_success；本方法仅兜底。
        """
        if not success_id:
            return
        removed = False
        with self.file_lock:
            keep: deque = deque(maxlen=self.recent_success.maxlen)
            for item in self.recent_success:
                if item.get("id") == success_id:
                    removed = True
                    continue
                keep.append(item)
            if removed:
                self.recent_success.clear()
                self.recent_success.extend(keep)
                if self.success_count > 0:
                    self.success_count -= 1
        if removed:
            self.log(
                f"{email or success_id} 已从成功列表移除（MARKED）"
                + (f" · {summary}" if summary else ""),
                "warn",
            )

    def _append_line(self, path: Path | str, line: str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with self.file_lock:
            with open(p, "a", encoding="utf-8") as f:
                f.write(line if line.endswith("\n") else line + "\n")
            try:
                p.chmod(0o600)
            except OSError:
                pass

    def _accounts_json_path(self) -> Optional[Path]:
        """返回当前任务的结构化账号文件路径。"""
        if not self.output_file:
            return None
        output = Path(self.output_file)
        if not output.is_absolute():
            output = _BASE_DIR / output
        return output.with_name(output.stem + "_accounts.json")

    def _write_account_json_unlocked(
        self,
        *,
        email: str,
        sso: str,
        user_id: str = "",
        email_provider: str = "",
        email_domain: str = "",
        proxy_audit: Optional[dict] = None,
    ) -> bool:
        """调用方持有 file_lock 时，按邮箱/SSO upsert 一条账号记录。"""
        path = self._accounts_json_path()
        email = (email or "").strip()
        sso = (sso or "").strip()
        user_id = (user_id or "").strip()
        email_provider = (email_provider or "").strip()
        email_domain = (email_domain or "").strip()
        if path is None or not sso:
            return False

        accounts: list[dict[str, str]] = []
        try:
            if path.is_file():
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, list):
                    accounts = [item for item in loaded if isinstance(item, dict)]
        except (OSError, json.JSONDecodeError):
            # 输出文件由本进程维护；若旧文件损坏则用当前内存记录重建。
            accounts = []

        found = None
        for item in accounts:
            if item.get("sso_token") == sso or (
                email and str(item.get("email") or "").lower() == email.lower()
            ):
                found = item
                break

        old_user_id = str((found or {}).get("user_id") or "")
        old_email_provider = str((found or {}).get("email_provider") or "")
        old_email_domain = str((found or {}).get("email_domain") or "")
        record = {
            "name": email,
            "email": email,
            "user_id": user_id or old_user_id,
            "sso_token": sso,
            "token": "",
            "tier": "basic",
            "cloudflare_cookies": "",
        }
        # Upserts must preserve a completed check and its disabled provenance.
        for key in ("account_check", "risk_status", "clean", "disabled", "account_check_disabled"):
            if found and key in found:
                record[key] = found[key]
        resolved_provider = email_provider or old_email_provider
        resolved_domain = email_domain or old_email_domain
        if resolved_provider:
            record["email_provider"] = resolved_provider
        if resolved_domain:
            record["email_domain"] = resolved_domain
        old_proxy = {
            key: (found or {}).get(key)
            for key in ("proxy_mode", "proxy_id", "proxy", "proxy_egress", "proxy_region")
            if (found or {}).get(key) not in (None, "")
        }
        for key, value in (proxy_audit or old_proxy).items():
            if key in ("proxy_mode", "proxy_id", "proxy", "proxy_egress", "proxy_region") and value not in (None, ""):
                record[key] = value
        if found is None:
            accounts.append(record)
        else:
            found.clear()
            found.update(record)

        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            temp = path.with_name(path.name + ".tmp")
            temp.write_text(
                json.dumps(accounts, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            temp.replace(path)
            try:
                path.chmod(0o600)
            except OSError:
                pass
            return True
        except OSError as exc:
            self.log(f"结构化账号 JSON 写入失败: {exc}", "error")
            return False

    def _write_account_json(
        self,
        *,
        email: str,
        sso: str,
        user_id: str = "",
        email_provider: str = "",
        email_domain: str = "",
        proxy_audit: Optional[dict] = None,
    ) -> bool:
        with self.file_lock:
            return self._write_account_json_unlocked(
                email=email,
                sso=sso,
                user_id=user_id,
                email_provider=email_provider,
                email_domain=email_domain,
                proxy_audit=proxy_audit,
            )

    def _probe_and_mark_clean(
        self,
        *,
        email: str,
        sso: str,
        sso_rw: str = "",
        success_id: str = "",
        proxy_spec: str = "",
        foreground: bool = True,
    ) -> Optional[bool]:
        """
        risk 探测：CLEAN 写 _clean.txt，MARKED 写 _marked.txt。
        默认前台串行（foreground=True）——和注册同线程整号跑完再开下一号。
        返回 True=CLEAN / False=MARKED / None=跳过或异常。
        """
        try:
            if AntibotService is None:
                self.log(f"{email} risk 跳过：AntibotService 不可用", "warn")
                return None
            CheckRegistry(_BASE_DIR).put({"sso": sso}, {"state": "unchecked", "reason": "CHECK_PENDING"})
            self.log(f"{email} risk 探测开始…", "info")
            t0 = time.time()
            ab = AntibotService()
            # chrome124 经本地代理稳；chrome131 易 curl(35) OPENSSL invalid library
            # probe 内部：多 impersonate + 代理失败后直连兜底
            risk = ab.probe_account_risk(
                sso,
                sso_rw=sso_rw or sso,
                impersonate="chrome124",
                timeout=20,
                proxy_spec=proxy_spec,
            )
            # 直连模式保留稳妥指纹重试；有租约时不得换出口。
            if not proxy_spec and AntibotService.is_risk_infra_error(risk):
                self.log(
                    f"{email} risk 基建抖动 · {AntibotService.risk_mark_summary(risk)[:80]} · 直连重试…",
                    "warn",
                )
                time.sleep(0.4)
                prev_force = os.environ.get("GROK_RISK_FORCE_DIRECT")
                try:
                    os.environ["GROK_RISK_FORCE_DIRECT"] = "1"
                    risk = ab.probe_account_risk(
                        sso,
                        sso_rw=sso_rw or sso,
                        impersonate="chrome124",
                        timeout=25,
                        proxy_spec="",
                    )
                finally:
                    if prev_force is None:
                        os.environ.pop("GROK_RISK_FORCE_DIRECT", None)
                    else:
                        os.environ["GROK_RISK_FORCE_DIRECT"] = prev_force
            state = risk_state(risk)
            if state == "marked":
                time.sleep(1)
                confirmation = ab.probe_account_risk(sso, sso_rw=sso_rw or sso,
                    impersonate="chrome124", timeout=20, proxy_spec=proxy_spec)
                if risk_state(confirmation) != "marked":
                    state = "review"
            clean = state == "clean"
            summary = AntibotService.risk_mark_summary(risk)
            elapsed = round(time.time() - t0, 1)
            # SSO JWT 通常只有 session_id；risk 接口拿到 user_id 后及时回填。
            self._write_account_json(
                email=email,
                sso=sso,
                user_id=str(risk.get("user_id") or ""),
            )
            if clean:
                if success_id:
                    self._update_success_meta(
                        success_id, clean=True, note=f"risk=CLEAN {summary}"
                    )
                self.log(
                    f"{email} risk CLEAN · {summary} · {elapsed}s · "
                    "已进入 PENDING_BFS",
                    "success",
                )
                return True
            CheckRegistry(_BASE_DIR).put({"sso": sso}, {"state": state, "reason": "RISK_" + state.upper()})
            if callable(self.account_check_observer):
                self.account_check_observer({"email": email, "sso": sso}, {"state": state, "reason": "RISK_" + state.upper()})
            if state == "review":
                with self.file_lock:
                    self.review_count += 1
                if self._classification_store is not None:
                    self._classification_store.finalize(email=email, sso=sso, state="review", reason="RISK_REVIEW")
                self.log(f"{email} risk REVIEW · 辅助信号或两次结果不一致 · 暂停导入", "warn")
                return None
            # TLS/代理基建失败：SSO 可能仍是好号，禁止记 MARKED、不进 _marked
            if AntibotService.is_risk_infra_error(risk):
                if self._classification_store is not None:
                    self._classification_store.finalize(
                        email=email, sso=sso, state="infra_retry", reason="RISK_INFRA"
                    )
                self.log(
                    f"{email} risk INFRA（TLS/代理探测失败，非业务 MARKED）· "
                    f"{summary} · {elapsed}s · SSO 已落 emergency，本号暂不进成功列表",
                    "warn",
                )
                # None = 探测失败（非 MARKED），调用方按失败尝试处理，不叠 marked_count
                return None
            # 真 MARKED（DENIED / false_clean / botFlag）：落盘，不进成功/导入
            with self.file_lock:
                self.marked_count += 1
            if self._classification_store is not None:
                self._classification_store.finalize(
                    email=email,
                    sso=sso,
                    state="marked",
                    reason="RISK_MARKED",
                    metadata={
                        "source": "risk",
                        "summary": summary[:240],
                        "policy": risk.get("policy"),
                        "event": risk.get("event"),
                        "bot_flag_source": risk.get("bot_flag_source"),
                        "risk_score": risk.get("risk_score"),
                    },
                )
            if success_id:
                # 若历史上已进成功列表，踢掉并回滚成功计数
                self._revoke_marked_success(success_id, email=email, summary=summary)
            self.log(
                f"{email} risk MARKED · {summary} · {elapsed}s · "
                f"绕过成功列表/导入 · MARKED累计 {self.marked_count}",
                "warn",
            )
            return False
        except Exception as e:
            err_s = str(e)
            # 外层异常若是 curl TLS，同样不当 MARKED
            low = err_s.lower()
            if any(
                m in low
                for m in (
                    "curl: (35)",
                    "tls connect",
                    "openssl",
                    "invalid library",
                    "failed to perform",
                )
            ):
                self.log(
                    f"{email} risk 探测异常(INFRA): {err_s[:120]} · 非 MARKED",
                    "warn",
                )
                return None
            self.log(f"{email} risk 探测异常: {e}", "warn")
            return None
        finally:
            # 仅后台调度时扣 pending；前台不走 enrich 计数
            if not foreground:
                with self._enrich_lock:
                    self._enrich_pending = max(0, self._enrich_pending - 1)

    def _schedule_risk_probe(
        self,
        *,
        email: str,
        sso: str,
        sso_rw: str,
        success_id: str,
        proxy_spec: str = "",
    ) -> None:
        """兼容旧调用：后台 risk（same_session 已改前台，一般不再走这里）。"""
        with self._enrich_lock:
            self._enrich_pending += 1
        try:
            self._enrich_pool.submit(
                self._probe_and_mark_clean,
                email=email,
                sso=sso,
                sso_rw=sso_rw or "",
                success_id=success_id,
                proxy_spec=proxy_spec or "",
                foreground=False,
            )
        except Exception as e:
            with self._enrich_lock:
                self._enrich_pending = max(0, self._enrich_pending - 1)
            self.log(f"{email} 调度 risk 失败: {e}", "warn")

    def _throttle_signup_post(self) -> None:
        """注册 POST 起步节流：保证间隔，但不把整个 HTTP 锁死。"""
        with self.post_lock:
            now = time.time()
            wait = self._post_min_interval - (now - self._last_post_start)
            if wait > 0:
                time.sleep(wait)
            self._last_post_start = time.time()

    def _exchange_token_after_clean(
        self,
        *,
        email: str,
        sso: str,
        success_id: str = "",
        impersonate: str = "chrome131",
        user_agent: str = "",
        retries: int = 3,
        async_mode: bool = False,
        proxy_spec: str = "",
    ) -> Optional[dict]:
        """
        换 token（device flow 发票）。
        默认由后台 enrich 池调用（async_mode=True），不堵注册主路径。
        成功则缓存到 recent_success，导入时优先直写；失败不改成功计数，
        导入侧仍可用 sso-to-oauth / 本机 device flow 兜底。
        """
        tag = "[后台] " if async_mode else ""
        self.log(f"{email} {tag}换 token 开始…", "info")
        t0 = time.time()
        try:
            check = validate_sso_cookie(
                sso,
                impersonate=impersonate or "chrome131",
                user_agent=user_agent or (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/131.0.0.0 Safari/537.36"
                ),
                require_device_flow=True,
                retries=max(1, int(retries or 3)),
                timeout=28,
                issue_token=True,
                proxy_spec=proxy_spec,
            )
            elapsed = round(time.time() - t0, 1)
            if check.get("ok") and isinstance(check.get("token"), dict):
                token = check.get("token")
                if is_auth_token_usable(token):
                    self._update_success_meta(
                        success_id,
                        auth_token=token,
                        note=f"token=cached · device_flow=ok · async={int(async_mode)} · {elapsed}s",
                    )
                    self.log(
                        f"{email} {tag}换 token 成功 · 已缓存 · {elapsed}s（导入可直写）",
                        "success",
                    )
                    return token
                self._update_success_meta(
                    success_id,
                    note=f"token=unusable · async={int(async_mode)} · {elapsed}s",
                )
                self.log(
                    f"{email} {tag}换 token 返回体不可用 · {elapsed}s（导入走兜底）",
                    "warn",
                )
                return None
            if check.get("ok") and check.get("approved") and not check.get("token"):
                self._update_success_meta(
                    success_id,
                    note=f"token=approved_no_body · async={int(async_mode)} · {elapsed}s",
                )
                self.log(
                    f"{email} {tag}换 token：approve 成功但无 token 体 · {elapsed}s（导入兜底）",
                    "warn",
                )
                return None
            err = check.get("error") or "device flow 失败"
            self._update_success_meta(
                success_id,
                note=f"token=fail · {str(err)[:60]} · async={int(async_mode)} · {elapsed}s",
            )
            self.log(
                f"{email} {tag}换 token 失败 · {err} · {elapsed}s（导入走 sso-to-oauth/兜底）",
                "warn",
            )
            return None
        except Exception as e:
            elapsed = round(time.time() - t0, 1)
            self.log(f"{email} {tag}换 token 异常 · {e} · {elapsed}s", "warn")
            self._update_success_meta(
                success_id,
                note=f"token=exc · {str(e)[:60]} · async={int(async_mode)}",
            )
            return None

    def _enrich_after_sso(
        self,
        *,
        email: str,
        sso: str,
        sso_rw: str,
        success_id: str,
        impersonate: str,
        user_agent: str,
        skip_token: bool = False,
        risk_gated: bool = False,
        proxy_lease: Optional[ProxyLease] = None,
    ) -> None:
        """
        SSO 后后台收尾（enrich 池，不堵注册主路径）：
        - skip_token=False（same_session 默认）：先异步换 token，再协议/NSFW
        - skip_token=True：只做协议/NSFW（token 已在别处处理）
        失败不影响成功计数；导入侧可对缺 token 号走兜底。
        """
        try:
            user_agreement_service = UserAgreementService()
            nsfw_service = NsfwSettingsService()
            note_parts: list[str] = []
            auth_token = None

            if not skip_token:
                # 异步换 token：与下一号注册重叠
                auth_token = self._exchange_token_after_clean(
                    email=email,
                    sso=sso,
                    success_id=success_id,
                    impersonate=impersonate or "chrome131",
                    user_agent=user_agent or "",
                    async_mode=True,
                    proxy_spec=(proxy_lease.spec if proxy_lease else ""),
                )
                if isinstance(auth_token, dict) and is_auth_token_usable(auth_token):
                    note_parts.append("token=async_cached")
                else:
                    note_parts.append("token=async_pending_or_fail")
            else:
                note_parts.append("token=skipped")

            if risk_gated:
                if not isinstance(auth_token, dict) or not is_auth_token_usable(auth_token):
                    CheckRegistry(_BASE_DIR).put({"sso": sso}, {"state": "infra_retry", "reason": "OAUTH_NO_TOKEN"})
                    if callable(self.account_check_observer):
                        self.account_check_observer({"email": email, "sso": sso}, {"state": "infra_retry", "reason": "OAUTH_NO_TOKEN"})
                    if self._classification_store is not None:
                        self._classification_store.finalize(
                            email=email,
                            sso=sso,
                            state="infra_retry",
                            reason="OAUTH_NO_TOKEN",
                        )
                    with self._bfs_lock:
                        self.oauth_infra_streak += 1
                        streak = self.oauth_infra_streak
                    self.log(
                        f"{email} OAuth 未取得 token · 归入 INFRA_RETRY · 连续 {streak}/3",
                        "warn",
                    )
                    if streak >= 3:
                        self.resource_exhausted_reason = "OAUTH_INFRA_EXHAUSTED"
                        self.error_message = "连续 3 个账号 OAuth 基础设施失败"
                    return

                bfs = inspect_token_bundle_bfs(
                    access_token=str(auth_token.get("access_token") or auth_token.get("key") or ""),
                    id_token=str(auth_token.get("id_token") or ""),
                    refresh_token=str(auth_token.get("refresh_token") or ""),
                    sso=sso,
                )
                if bfs.get("has_bfs") or not bfs.get("ok"):
                    from convert_sso_json import SSORecord, build_cpa_record, cpa_path_for_record

                    cpa_path = cpa_path_for_record(
                        _BASE_DIR / "converted_auth",
                        SSORecord(source=Path("runtime.json"), email=email, sso=sso),
                    )
                    auth = build_cpa_record(auth_token, email=email, sso=sso, disabled=True)
                    atomic_write_json(cpa_path, auth)
                    reason = "BFS_MARKED" if bfs.get("has_bfs") else "BFS_UNKNOWN"
                    bfs_state = "marked" if bfs.get("has_bfs") else "review"
                    CheckRegistry(_BASE_DIR).put({"sso": sso, "auth_token": auth_token}, {"state": bfs_state, "reason": reason})
                    if callable(self.account_check_observer):
                        self.account_check_observer({"email": email, "sso": sso, "auth_token": auth_token}, {"state": bfs_state, "reason": reason})
                    if self._classification_store is not None:
                        self._classification_store.finalize(
                            email=email,
                            sso=sso,
                            state=bfs_state,
                            reason=reason,
                            metadata={
                                "source": "bfs",
                                "bfs_status": "flagged" if bfs.get("has_bfs") else "unknown",
                                "bfs_value": bfs.get("bfs"),
                                "token_fingerprint": __import__("hashlib").sha256(
                                    str(auth_token.get("access_token") or auth_token.get("key") or "").encode()
                                ).hexdigest(),
                            },
                        )
                    with self._bfs_lock:
                        if bfs_state == "marked":
                            self.marked_count += 1
                        else:
                            self.review_count += 1
                        self.oauth_infra_streak = 0
                    self.log(f"{email} {reason} · CPA 已本地禁用保存 · 不进入下游", "warn")
                    return

                with self._bfs_lock:
                    self.oauth_infra_streak = 0
                account = {"email": email, "sso": sso, "auth_token": auth_token,
                           "_proxy_spec": proxy_lease.spec if proxy_lease else ""}
                callback = self.account_check_callback
                if callback is None:
                    from g.account_check_jobs import CheckJobs, runtime_checker
                    with self._bfs_lock:
                        if not hasattr(self, "_standalone_checks"):
                            self._standalone_checks = CheckJobs(_BASE_DIR, runtime_checker(), proxy_pool=self.proxy_pool)
                    callback = self._standalone_checks.check_registration
                self.log(f"{email} [后台] 账号检测开始 · Risk/BFS 初筛通过", "info")
                try:
                    outcome = callback(account)
                except Exception:
                    outcome = {"state": "infra_retry", "reason": "CHECK_FAILED"}
                state = outcome.get("state", "infra_retry")
                CheckRegistry(_BASE_DIR).put(account, {"state": state, "reason": outcome.get("reason", "ACCOUNT_CHECK")})
                auth_token = account.get("auth_token") or auth_token
                success_id = self._record_success(
                    email=email,
                    sso=sso,
                    unhinged_ok=False,
                    note=f"account_check={state.upper()} · {outcome.get('reason', '')}",
                    already_written=False,
                    auth_token=auth_token,
                    proxy_audit=self.proxy_pool.lease_audit(proxy_lease),
                    clean=True if state == "clean" else None,
                    check_state=state,
                )
                if not success_id:
                    return
                with self.file_lock:
                    path = self._accounts_json_path()
                    if path and path.is_file():
                        records = json.loads(path.read_text(encoding="utf-8"))
                        for record in records:
                            if record.get("sso_token") == sso:
                                record.update(account_check={"state": state, "reason": outcome.get("reason", "ACCOUNT_CHECK")},
                                              risk_status=state, clean=state == "clean")
                        atomic_write_json(path, records)
                if state != "clean":
                    from convert_sso_json import SSORecord, build_cpa_record, cpa_path_for_record
                    cpa_path = cpa_path_for_record(_BASE_DIR / "converted_auth", SSORecord(source=Path("runtime.json"), email=email, sso=sso))
                    auth = build_cpa_record(auth_token, email=email, sso=sso, disabled=True)
                    auth.update(account_check={"state": state, "reason": outcome.get("reason", "ACCOUNT_CHECK")}, account_check_disabled=True)
                    atomic_write_json(cpa_path, auth)
                    return
                callback = self.auto_import_callback
                if callable(callback):
                    try:
                        callback([{**account, "id": success_id, "clean": True, "risk_status": "clean"}])
                        with self.file_lock:
                            for item in self.recent_success:
                                if item.get("id") == success_id:
                                    item["auto_queued"] = True
                    except Exception:
                        with self.file_lock:
                            for item in self.recent_success:
                                if item.get("id") == success_id:
                                    item["auto_queued"] = False
                        self.log("账号检测通过，但自动导入排队失败，可手动重试", "warn")

            unhinged_ok = False
            try:
                tos_result = user_agreement_service.accept_tos_version(
                    sso=sso,
                    sso_rw=sso_rw or "",
                    impersonate=impersonate,
                    user_agent=user_agent,
                    proxy_spec=(proxy_lease.spec if proxy_lease else ""),
                )
                tos_hex = tos_result.get("hex_reply") or ""
                if not tos_result.get("ok") or not tos_hex:
                    note_parts.append(
                        f"协议失败: {tos_result.get('error') or tos_result}"
                    )
                else:
                    nsfw_result = nsfw_service.enable_nsfw(
                        sso=sso,
                        sso_rw=sso_rw or "",
                        impersonate=impersonate,
                        user_agent=user_agent,
                        proxy_spec=(proxy_lease.spec if proxy_lease else ""),
                    )
                    nsfw_hex = nsfw_result.get("hex_reply") or ""
                    if not nsfw_result.get("ok") or not nsfw_hex:
                        note_parts.append(
                            f"NSFW失败: {nsfw_result.get('error') or nsfw_result}"
                        )
                    else:
                        unhinged_result = nsfw_service.enable_unhinged(
                            sso, proxy_spec=(proxy_lease.spec if proxy_lease else "")
                        )
                        unhinged_ok = unhinged_result.get("ok", False)
                        if not unhinged_ok:
                            note_parts.append("unhinged失败")
                        else:
                            note_parts.append("nsfw=ok")
            except Exception as post_err:
                note_parts.append(f"协议/NSFW异常: {post_err}")
                self.log(f"{email} [后台] 协议/NSFW 异常: {post_err}", "warn")

            note = "; ".join(str(x)[:80] for x in note_parts)
            # token 已在 _exchange_token_after_clean 里写过；这里再合并 note/nsfw
            self._update_success_meta(
                success_id,
                auth_token=auth_token if isinstance(auth_token, dict) else None,
                unhinged_ok=unhinged_ok,
                note=note,
            )
            if unhinged_ok:
                self.log(f"{email} [后台] NSFW/unhinged 已开", "success")
        except Exception as e:
            self.log(f"{email} [后台] enrich 异常: {e}", "warn")
        finally:
            if proxy_lease is not None:
                self.proxy_pool.release(proxy_lease, "success")
            if risk_gated:
                with self._bfs_lock:
                    self.pending_bfs_count = max(0, self.pending_bfs_count - 1)
            with self._enrich_lock:
                self._enrich_pending = max(0, self._enrich_pending - 1)

    def _schedule_enrich(
        self,
        *,
        email: str,
        sso: str,
        sso_rw: str,
        success_id: str,
        impersonate: str,
        user_agent: str,
        skip_token: bool = False,
        risk_gated: bool = False,
        proxy_lease: Optional[ProxyLease] = None,
    ) -> None:
        if risk_gated:
            with self._bfs_lock:
                self.pending_bfs_count += 1
            CheckRegistry(_BASE_DIR).put({"sso": sso}, {"state": "unchecked", "reason": "CHECK_PENDING"})
            if self._classification_store is not None:
                self._classification_store.add_pending(
                    email=email, sso=sso, data={"state": "PENDING_BFS"}
                )
        with self._enrich_lock:
            self._enrich_pending += 1
        try:
            self._enrich_pool.submit(
                self._enrich_after_sso,
                email=email,
                sso=sso,
                sso_rw=sso_rw or "",
                success_id=success_id,
                impersonate=impersonate,
                user_agent=user_agent,
                skip_token=skip_token,
                risk_gated=risk_gated,
                proxy_lease=proxy_lease,
            )
        except Exception as e:
            if proxy_lease is not None:
                self.proxy_pool.release(proxy_lease, "success", str(e))
            with self._enrich_lock:
                self._enrich_pending = max(0, self._enrich_pending - 1)
            if risk_gated:
                with self._bfs_lock:
                    self.pending_bfs_count = max(0, self.pending_bfs_count - 1)
                if self._classification_store is not None:
                    self._classification_store.finalize(
                        email=email,
                        sso=sso,
                        state="infra_retry",
                        reason="ENRICH_SUBMIT_FAILED",
                    )
            self.log(f"{email} 调度后台 enrich 失败: {e}", "warn")

    def register_single_thread_same_session(self):
        """
        CLEAN 主路径：同页 fiber mint castle + 页内 fetch 发码/验码/signup。
        对齐 standalone_same_session_n；禁止拆会话 mint 再外层 curl。
        """
        if self.workers > 1:
            if self._sleep(random.uniform(0, min(1.2, 0.12 * self.workers))):
                return

        try:
            email_service = EmailService(log_fn=self.log)
            turnstile_service = TurnstileService()
        except Exception as e:
            self.log(f"服务初始化失败: {e}", "error")
            self.stop_event.set()
            return

        site_key = self.config.get("site_key") or "0x4AAAAAAAhr9JGVDZbrZOo0"
        current_email = None
        # 数量 N = 成功创建 N 个邮箱；后续分类不改变目标口径。
        max_attempts = max(1, int(self.target_count or 1))
        consecutive_browser_fails = 0
        deny_break_n = _ss_deny_break_n()
        risk_enabled = bool(getattr(self, "risk_check_enabled", True))
        configured_domains = list(
            (email_service.structured_config.get("providers", {}).get("cloudflare_temp", {}) or {}).get("domains") or []
        )
        if email_service.provider_name == "cloudflare_temp" and self.domain_pool.summary().get("total"):
            configured_domains = self.domain_pool.active_domains()
        if email_service.provider_name == "cloudflare_temp" and configured_domains:
            self.domain_pool.sync_configured(configured_domains)
        use_domain_pool = bool(
            email_service.provider_name == "cloudflare_temp"
            and self.domain_pool.summary().get("total")
        )
        # 代理节点阶梯冷却取代全局连续 MARKED 熔断。
        deny_break_n = 0

        def _resource_exhausted(code: str, message: str) -> None:
            self.resource_exhausted_reason = code
            self.error_message = message
            self.log(message, "error")

        self.log(
            f"same_session · 创邮目标={max_attempts}"
            f" · Risk={'ON' if risk_enabled else 'OFF/UNCHECKED'}"
            f" · 域名轮询={'ON' if use_domain_pool else 'OFF'}"
            f" · 代理池={self.proxy_pool.summary().get('enabled', 0)} 条",
            "info",
        )

        while not self.stop_event.is_set():
            if self.resource_exhausted_reason:
                return
            with self._ss_attempt_lock:
                if int(self.email_create_count or 0) + int(self._email_create_reserved or 0) >= max_attempts:
                    return
            logical_id = uuid.uuid4().hex
            attempt_i = 0
            domain_lease: Optional[DomainLease] = None
            # 连续 MARKED 熔断：同出口 Castle deny 簇打开后别硬刚
            with self._ss_deny_lock:
                cur_deny = int(self._ss_consecutive_deny or 0)
            if risk_enabled and deny_break_n > 0 and cur_deny >= deny_break_n:
                self.log(
                    f"连续 MARKED/deny {cur_deny}/{deny_break_n} · 熔断停批"
                    f"（同出口 registration 密度过高，换出口/冷却后再开）",
                    "error",
                )
                self.stop_event.set()
                return
            idx = self._next_ss_idx()
            # 号间抖动：压同出口短时 registration 密度（Castle deny 簇）
            # 连续 MARKED 时自动加长冷却
            jitter = _ss_inter_account_delay(
                self.workers, consecutive_deny=cur_deny if risk_enabled else 0
            )
            if jitter > 0 and idx > 1:
                if cur_deny > 0 and jitter >= 1.0:
                    self.log(
                        f"号间冷却 {jitter:.1f}s（连续MARKED={cur_deny}）",
                        "info",
                    )
                if self._sleep(jitter):
                    return
            fp = _ss_pick_fp(idx)
            email = None
            proxy_lease: Optional[ProxyLease] = None
            proxy_handed_off = False
            email_slot_reserved = False
            try:
                # 每号开始：force 清本线程 Playwright loop，防池线程复用脏 loop
                try:
                    from g.same_session_register import (
                        _clear_thread_event_loop,
                        _drop_thread_pool,
                    )

                    _drop_thread_pool(None, reason="")
                    _clear_thread_event_loop(force=True)
                except Exception:
                    pass

                # Solver 不在线不建邮
                if not (turnstile_service.yescaptcha_key or "").strip():
                    try:
                        turnstile_service._ensure_local_solver(stop_event=self.stop_event)
                    except RuntimeError as te:
                        if str(te) == "stopped" or self.stop_event.is_set():
                            return
                        self.log(f"Solver 未就绪: {te}，等待后重试（未创建邮箱）", "warn")
                        if self._sleep(3):
                            return
                        continue
                    except Exception as se:
                        if self.stop_event.is_set():
                            return
                        self.log(f"Solver 未就绪: {se}，等待后重试", "warn")
                        if self._sleep(5):
                            return
                        continue

                # 连续浏览器/loop 炸：先歇一会再清，别狂建邮
                if consecutive_browser_fails >= 3:
                    self.log(
                        f"连续浏览器失败 {consecutive_browser_fails} 次 · "
                        f"强制清 loop 并冷却 2s（暂不建邮）",
                        "warn",
                    )
                    try:
                        from g.same_session_register import (
                            _clear_thread_event_loop,
                            _drop_thread_pool,
                            shutdown_camoufox_pool,
                        )

                        _drop_thread_pool(None, reason="连续失败")
                        _clear_thread_event_loop(force=True)
                    except Exception:
                        pass
                    if self._sleep(2.0):
                        return
                    consecutive_browser_fails = 0

                attempt_i = self._reserve_email_creation()
                if not attempt_i:
                    return
                email_slot_reserved = True

                if use_domain_pool and domain_lease is None:
                    domain_lease = self.domain_pool.acquire(logical_id)
                    if domain_lease is None:
                        _resource_exhausted("DOMAIN_EXHAUSTED", "没有可用的 Cloudflare Temp 域名，任务需要人工处理")
                        return

                # Turnstile 预解与建邮/浏览器重叠
                ts_pre: dict[str, Any] = {
                    "token": None,
                    "error": None,
                    "t0": time.time(),
                    "done": threading.Event(),
                    "used": False,
                }

                def _ts_prewarm() -> None:
                    try:
                        task_id = turnstile_service.create_task(
                            self.site_url, site_key, stop_event=self.stop_event
                        )
                        tok = turnstile_service.get_response(
                            task_id, stop_event=self.stop_event
                        )
                        ts_pre["token"] = tok
                        if not tok or tok == "CAPTCHA_FAIL":
                            ts_pre["error"] = turnstile_service.last_error or "empty"
                    except Exception as e:
                        ts_pre["error"] = str(e)
                    finally:
                        ts_pre["done"].set()

                threading.Thread(
                    target=_ts_prewarm, daemon=True, name=f"ss-ts-{idx}"
                ).start()

                proxy_summary = self.proxy_pool.summary()
                if (
                    int(proxy_summary.get("enabled") or 0) > 0
                    and int(proxy_summary.get("cooldown") or 0) >= int(proxy_summary.get("enabled") or 0)
                ):
                    if domain_lease is not None:
                        self.domain_pool.release(domain_lease)
                        domain_lease = None
                    _resource_exhausted("PROXY_COOLDOWN_EXHAUSTED", "所有启用代理均在冷却，任务已停止")
                    return
                proxy_lease = self.proxy_pool.acquire(
                    f"attempt-{idx}",
                    stop_event=self.stop_event,
                    wait=True,
                    wait_timeout=30.0,
                )
                if proxy_lease is None:
                    if domain_lease is not None:
                        self.domain_pool.release(domain_lease)
                        domain_lease = None
                    _resource_exhausted("PROXY_EXHAUSTED", "没有可用代理，任务需要人工添加或启用代理")
                    return
                if hasattr(email_service, "set_register_proxy"):
                    email_service.set_register_proxy(proxy_lease.spec)
                if self.proxy_pool.settings().get("align_geo"):
                    geo = self.proxy_pool.lease_geo(proxy_lease)
                    cc = str(geo.get("cc") or "").upper()
                    matched = [
                        row for row in _SS_FP_REGIONS
                        if str(row.get("tag") or "").split("-", 1)[0] == cc
                    ]
                    if matched:
                        region_fp = random.choice(matched)
                        fp["tag"] = str(region_fp.get("tag") or fp.get("tag"))
                        fp["locale"] = str(region_fp.get("locale") or fp.get("locale"))
                        fp["timezone"] = str(geo.get("timezone") or region_fp.get("timezone") or fp.get("timezone"))

                try:
                    if domain_lease is not None:
                        _jwt, email = email_service.create_email_for_domain(domain_lease.domain)
                    else:
                        _jwt, email = email_service.create_email()
                    current_email = email
                except Exception as e:
                    # 未真正建邮成功：不占创邮额度、不记过程失败
                    self.log(f"邮箱服务异常（未建邮）: {e}", "warn")
                    self.proxy_pool.release(
                        proxy_lease,
                        "network" if _is_proxy_network_error(e) else "failure",
                        str(e),
                    )
                    proxy_lease = None
                    if domain_lease is not None:
                        self.domain_pool.release(domain_lease)
                        domain_lease = None
                    if self._sleep(2):
                        return
                    continue
                if not email:
                    self.log("创建邮箱失败（未建邮）", "warn")
                    self.proxy_pool.release(proxy_lease, "failure", "create email failed")
                    proxy_lease = None
                    if domain_lease is not None:
                        self.domain_pool.release(domain_lease)
                        domain_lease = None
                    if self._sleep(1):
                        return
                    continue
                self._finish_email_creation(success=True)
                email_slot_reserved = False
                email_meta = email_service.get_email_metadata(email)
                proxy_spec_str = proxy_lease.spec
                self.log(
                    f"{email} 分配代理 "
                    f"{'直连' if proxy_lease.direct else proxy_lease.proxy_id[:8] + ' ' + proxy_lease.masked}",
                    "info",
                )
                # 注意：额度已占就绝不能因 stop_event 直接删邮 return。
                # 其它线程「创邮达量」停批时，本号必须继续跑完 risk/落盘。

                password = generate_random_string(14)
                given = generate_random_name()
                family = generate_random_name()
                vp = fp.get("viewport") or {}
                # 语言包跟随地区，传给 same_session（Accept-Language / navigator）
                try:
                    from g.same_session_register import locale_language_pack

                    _lp = locale_language_pack(fp.get("locale") or "en-US")
                    fp["locale"] = _lp["locale"]
                    fp["accept_language"] = _lp["accept_language"]
                    fp["languages"] = _lp["languages"]
                    fp["lang"] = _lp["lang"]
                except Exception:
                    fp.setdefault("accept_language", "")
                self.log(
                    f"开始注册[same_session]: {email} · "
                    f"{email_meta.get('email_provider') or '?'} / {email_meta.get('email_domain') or '?'} · "
                    f"创邮 {self.email_create_count}/{max_attempts} · API尝试 {attempt_i} · "
                    f"{fp['tag']}/{fp['fp_os']}/{fp['timing']} · "
                    f"{fp.get('locale')}/{fp.get('timezone')} · "
                    f"al={str(fp.get('accept_language') or '')[:28]} · "
                    f"vp={vp.get('width')}x{vp.get('height')}"
                    f"{' · humanize' if fp.get('humanize') else ''} · "
                    f"CLEAN={getattr(self, 'clean_count', 0)} "
                    f"UNCHECKED={getattr(self, 'unchecked_count', 0)} "
                    f"MARKED={getattr(self, 'marked_count', 0)} "
                    f"fail={self.fail_count}",
                    "info",
                )

                def fetch_code(em: str):
                    return email_service.fetch_verification_code(
                        em, stop_event=self.stop_event
                    )

                def solve_ts(sk: str):
                    if not ts_pre["done"].is_set():
                        remain = max(1.0, 90.0 - (time.time() - float(ts_pre["t0"])))
                        ts_pre["done"].wait(timeout=remain)
                    tok = ts_pre.get("token")
                    if tok and tok != "CAPTCHA_FAIL" and not ts_pre["used"]:
                        ts_pre["used"] = True
                        return tok
                    task_id = turnstile_service.create_task(
                        self.site_url, sk or site_key, stop_event=self.stop_event
                    )
                    return turnstile_service.get_response(
                        task_id, stop_event=self.stop_event
                    )

                pre_token = None
                if ts_pre["done"].is_set():
                    t = ts_pre.get("token")
                    if t and t != "CAPTCHA_FAIL":
                        pre_token = t
                        ts_pre["used"] = True

                def _ss_log(msg: str, level: str = "info") -> None:
                    # same_session_register 回调只有 msg；级别固定 info
                    self.log(f"{email} {msg}", level if level in ("info", "warn", "error", "success") else "info")

                # same_session_register 的 log 只收 msg
                def _ss_log_msg(msg: str) -> None:
                    self.log(f"{email} {msg}", "info")

                attempted_proxy_ids: set[str] = set()
                ss: dict[str, Any] = {}
                for proxy_try in range(1, 4):
                    if proxy_lease is None:
                        break
                    if not proxy_lease.direct:
                        attempted_proxy_ids.add(proxy_lease.proxy_id)
                    proxy_spec_str = proxy_lease.spec
                    ss = same_session_register(
                        email=email,
                        password=password,
                        given_name=given,
                        family_name=family,
                        fetch_code=fetch_code,
                        turnstile_token=pre_token,
                        solve_turnstile=solve_ts,
                        headless=None,
                        browser="camoufox",
                        proxy=proxy_spec_str,
                        locale=fp["locale"],
                        timezone_id=fp["timezone"],
                        fp_os=fp["fp_os"],
                        timing=fp["timing"],
                        viewport=fp["viewport"],
                        humanize=fp.get("humanize", False),
                        log=_ss_log_msg,
                    )
                    err_now = ss.get("error") or ""
                    if ss.get("ok") or not _safe_to_retry_with_new_proxy(ss) or proxy_lease.direct:
                        break
                    self.proxy_pool.release(proxy_lease, "network", str(err_now))
                    retry_exclude = self.proxy_pool.retry_exclusions(
                        attempted_proxy_ids,
                        "",
                    )
                    proxy_lease = self.proxy_pool.acquire(
                        email,
                        stop_event=self.stop_event,
                        exclude=retry_exclude,
                        wait=False,
                    )
                    if proxy_lease is None:
                        self.log(f"{email} 无新的健康代理可重试", "warn")
                        break
                    if hasattr(email_service, "set_register_proxy"):
                        email_service.set_register_proxy(proxy_lease.spec)
                    self.log(
                        f"{email} 代理网络故障，改用 {proxy_lease.proxy_id[:8]} "
                        f"重新发码（{proxy_try + 1}/3）",
                        "warn",
                    )

                # 手动强停之外，已成功创邮的本号必须继续完成分类和落盘。
                stopped_mid = self.stop_event.is_set()

                if not ss.get("ok"):
                    err = ss.get("error") or "same_session failed"
                    err_l = str(err).lower()
                    if (
                        "asyncio loop" in err_l
                        or "sync api" in err_l
                        or "camoufox 启动" in err_l
                        or "playwright" in err_l
                    ):
                        consecutive_browser_fails += 1
                    else:
                        consecutive_browser_fails = 0
                    self._fail_account(
                        email_service, email, f"{email} same_session 失败: {err}"
                    )
                    if proxy_lease is not None:
                        self.proxy_pool.release(
                            proxy_lease,
                            "network" if _is_proxy_network_error(err) else "failure",
                            str(err),
                        )
                        proxy_lease = None
                    if domain_lease is not None:
                        self.domain_pool.release(domain_lease)
                        domain_lease = None
                    current_email = None
                    # 已停批且本号失败：本线程退出（别再开新邮）
                    if stopped_mid:
                        return
                    # 浏览器 loop 类失败：本线程多歇一会再接下号
                    cool = 1.2 if consecutive_browser_fails else 0.3
                    if self._sleep(cool):
                        return
                    continue

                sso = (ss.get("sso") or "").strip()
                sso_rw = (ss.get("sso_rw") or sso or "").strip()
                if not sso:
                    consecutive_browser_fails = 0
                    self._fail_account(
                        email_service, email, f"{email} same_session 无 sso"
                    )
                    if proxy_lease is not None:
                        self.proxy_pool.release(proxy_lease, "failure", "no sso")
                        proxy_lease = None
                    if domain_lease is not None:
                        self.domain_pool.release(domain_lease)
                        domain_lease = None
                    current_email = None
                    if stopped_mid:
                        return
                    continue
                consecutive_browser_fails = 0

                castle_len = ss.get("castle_len") or 0
                castle_method = ss.get("castle_method") or ""
                steps_tail = ""
                try:
                    steps = ss.get("steps") or []
                    if isinstance(steps, list) and steps:
                        steps_tail = " · " + " > ".join(str(x) for x in steps[-6:])
                except Exception:
                    steps_tail = ""
                risk_enabled = bool(getattr(self, "risk_check_enabled", True))
                if stopped_mid:
                    finish_action = "继续 risk/落盘" if risk_enabled else "落盘"
                    self.log(
                        f"{email} 停批后仍拿到 SSO · {finish_action}（不丢号）"
                        f" · castle={castle_len}/{castle_method}{steps_tail}",
                        "warn",
                    )
                else:
                    self.log(
                        f"{email} same_session SSO 到手 · castle={castle_len}"
                        f"/{castle_method}{steps_tail} · "
                        + (
                            "先 risk 再决定是否计成功"
                            if risk_enabled
                            else "Risk 已关闭，将记为 UNCHECKED"
                        ),
                        "info",
                    )
                # 仅 forensic 紧急盘，不写主成功文件、不进成功列表
                # （MARKED 会被绕过，绝不进 recent_success / 不导入）
                try:
                    emergency = _BASE_DIR / "keys" / "emergency_sso.txt"
                    emergency.parent.mkdir(parents=True, exist_ok=True)
                    with self.file_lock:
                        with open(emergency, "a", encoding="utf-8") as f:
                            f.write(f"{email}----{sso}\n")
                        try:
                            emergency.chmod(0o600)
                        except OSError:
                            pass
                        self._write_account_json_unlocked(email=email, sso=sso)
                except Exception:
                    pass

                # 前台 risk 门禁：开启时只有 CLEAN 才计成功 / 可自动导入。
                # 关闭时保留注册必需的 Turnstile/Castle，但不执行 OAuth/BFS。
                if risk_enabled:
                    clean = self._probe_and_mark_clean(
                        email=email,
                        sso=sso,
                        sso_rw=sso_rw,
                        success_id="",
                        proxy_spec=proxy_spec_str,
                        foreground=True,
                    )
                else:
                    # 仅作流程放行哨兵；落库时仍传 clean=None，禁止伪装 CLEAN。
                    clean = True
                    self.log(
                        f"{email} Risk 探测已跳过 · 账号状态=UNCHECKED "
                        "· 敏感目标不会自动导入",
                        "warn",
                    )
                if clean is not True:
                    # MARKED / 探测失败：已写 _marked，不进成功列表、不换票、不入库
                    # MARKED 只记 marked_count，不再叠 fail_count（避免「目标5却失败7」误解）
                    if clean is False:
                        if proxy_lease is not None:
                            self.proxy_pool.release(proxy_lease, "marked", "risk MARKED")
                            proxy_lease = None
                        if domain_lease is not None:
                            self.domain_pool.release(domain_lease)
                            domain_lease = None
                        callback = getattr(self, "auto_import_callback", None)
                        if callable(callback):
                            try:
                                callback([{
                                    "id": f"marked_{int(time.time() * 1000)}",
                                    "email": email,
                                    "sso": sso,
                                    "auth_token": None,
                                    "clean": False,
                                }])
                            except Exception as auto_exc:
                                self.log(f"{email} MARKED 自动导入排队失败: {auto_exc}", "warn")
                        with self._ss_deny_lock:
                            self._ss_consecutive_deny = (
                                int(self._ss_consecutive_deny or 0) + 1
                            )
                            streak = self._ss_consecutive_deny
                        reason = (
                            f"{email} risk MARKED，绕过成功列表与导入"
                            f"（MARKED累计 {getattr(self, 'marked_count', 0)}"
                            f" · 连续 {streak}"
                            + (f"/{deny_break_n}" if deny_break_n else "")
                            + "）"
                        )
                        self._fail_account(
                            email_service,
                            email,
                            reason,
                            level="warn",
                            count_fail=False,
                        )
                    else:
                        if proxy_lease is not None:
                            self.proxy_pool.release(proxy_lease, "network", "risk infra")
                            proxy_lease = None
                        reason = f"{email} risk 探测失败，绕过成功列表与导入"
                        self._fail_account(
                            email_service, email, reason, level="warn"
                        )
                        if domain_lease is not None:
                            self.domain_pool.release(domain_lease)
                            domain_lease = None
                    current_email = None
                    # 停批后本号已收尾：退出本线程，不再开新邮
                    if stopped_mid or self.stop_event.is_set():
                        return
                    if self._sleep(0.2):
                        return
                    continue

                # —— 仅实际 CLEAN 路径：清零连续 MARKED ——
                if risk_enabled:
                    with self._ss_deny_lock:
                        self._ss_consecutive_deny = 0
                    self.proxy_pool.mark_risk_clean(proxy_lease)
                if domain_lease is not None:
                    self.domain_pool.release(domain_lease)
                    domain_lease = None
                ua = (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/131.0.0.0 Safari/537.36"
                )
                if risk_enabled:
                    self.log(f"{email} Risk CLEAN · 进入 PENDING_BFS · 异步 OAuth/BFS", "info")
                    self._schedule_enrich(
                        email=email,
                        sso=sso,
                        sso_rw=sso_rw,
                        success_id="",
                        impersonate="chrome131",
                        user_agent=ua,
                        skip_token=False,
                        risk_gated=True,
                        proxy_lease=proxy_lease,
                    )
                    proxy_handed_off = proxy_lease is not None
                    proxy_lease = None
                    try:
                        email_service.delete_email(email)
                    except Exception:
                        pass
                    current_email = None
                    if stopped_mid or self.stop_event.is_set():
                        return
                    continue
                sid = self._record_success(
                    email=email,
                    sso=sso,
                    unhinged_ok=False,
                    email_service=email_service,
                    note=(
                        f"mode=same_session castle={castle_len} "
                        f"method={castle_method} "
                        f"risk={'CLEAN' if risk_enabled else 'UNCHECKED'}"
                    ),
                    already_written=False,
                    auth_token=None,
                    proxy_audit=self.proxy_pool.lease_audit(proxy_lease),
                    clean=True if risk_enabled else None,
                )
                if sid:
                    if risk_enabled:
                        self._update_success_meta(
                            sid, clean=True, note="risk=CLEAN · token=async"
                        )
                    # 换 token + 协议/NSFW 全部丢 enrich 池，主路径立刻开下一号
                    self.log(
                        f"{email} {'CLEAN' if risk_enabled else 'UNCHECKED'} 已计成功 "
                        "· 换 token/协议/NSFW 异步处理中",
                        "info",
                    )
                    self._schedule_enrich(
                        email=email,
                        sso=sso,
                        sso_rw=sso_rw,
                        success_id=sid,
                        impersonate="chrome131",
                        user_agent=ua,
                        skip_token=True,
                        risk_gated=False,
                        proxy_lease=proxy_lease,
                    )
                    proxy_handed_off = proxy_lease is not None
                    proxy_lease = None
                elif stopped_mid:
                    # 目标已满但仍拿到 CLEAN SSO：_record_success 已写 emergency
                    self.log(
                        f"{email} CLEAN 但目标已满 · SSO 已进 emergency（不进成功列表）",
                        "warn",
                    )
                    if proxy_lease is not None:
                        self.proxy_pool.release(proxy_lease, "success")
                        proxy_lease = None
                elif proxy_lease is not None:
                    self.proxy_pool.release(proxy_lease, "success")
                    proxy_lease = None
                current_email = None
                # 停批后本号收尾完，退出；不 continue 再开新邮
                if stopped_mid or self.stop_event.is_set():
                    return
                continue
            except Exception as e:
                if proxy_lease is not None and not proxy_handed_off:
                    self.proxy_pool.release(
                        proxy_lease,
                        "network" if _is_proxy_network_error(e) else "failure",
                        str(e),
                    )
                    proxy_lease = None
                if domain_lease is not None:
                    self.domain_pool.release(domain_lease)
                    domain_lease = None
                if self.stop_event.is_set():
                    if current_email:
                        try:
                            email_service.delete_email(current_email)
                        except Exception:
                            pass
                    return
                self._fail_account(
                    email_service,
                    current_email,
                    f"same_session 异常: {str(e)[:120]}",
                )
                current_email = None
                if self._sleep(1):
                    return
                continue
            finally:
                if email_slot_reserved:
                    self._finish_email_creation(success=False)

    def register_single_thread(self):
        # 多线程时轻微错开，单线程几乎立刻开跑
        if self.workers > 1:
            if self._sleep(random.uniform(0, min(1.5, 0.15 * self.workers))):
                return

        try:
            email_service = EmailService(log_fn=self.log)
            turnstile_service = TurnstileService()
            castle_service = CastleService()
            # 协议/NSFW 已挪到后台 enrich 池，主线程不再初始化
        except Exception as e:
            self.log(f"服务初始化失败: {e}", "error")
            self.stop_event.set()
            return

        final_action_id = self.config["action_id"]
        if not final_action_id:
            self.log("线程退出：缺少 Action ID", "error")
            self.stop_event.set()
            return

        current_email = None
        protocol_retry: Optional[dict[str, Any]] = None
        use_domain_pool = bool(
            email_service.provider_name == "cloudflare_temp"
            and self.domain_pool.summary().get("total")
        )

        # 失败只丢弃当前账号；目标只按成功创建邮箱数计算。
        while not self.stop_event.is_set():
            if self.resource_exhausted_reason:
                return
            if protocol_retry is None:
                with self._ss_attempt_lock:
                    if int(self.email_create_count or 0) + int(self._email_create_reserved or 0) >= int(self.target_count or 0):
                        return
            proxy_summary = self.proxy_pool.summary()
            if (
                int(proxy_summary.get("enabled") or 0) > 0
                and int(proxy_summary.get("cooldown") or 0) >= int(proxy_summary.get("enabled") or 0)
            ):
                self.resource_exhausted_reason = "PROXY_COOLDOWN_EXHAUSTED"
                self.error_message = "所有启用代理均在冷却，任务已停止"
                self.log(self.error_message, "error")
                return
            proxy_lease: Optional[ProxyLease] = self.proxy_pool.acquire(
                str((protocol_retry or {}).get("email") or f"protocol-{uuid.uuid4().hex[:12]}"),
                stop_event=self.stop_event,
                exclude=set((protocol_retry or {}).get("attempted_proxy_ids") or set()),
                wait=protocol_retry is None,
            )
            proxy_handed_off = False
            proxy_outcome = "failure"
            email_slot_reserved = False
            domain_lease: Optional[DomainLease] = None
            if proxy_lease is None:
                if protocol_retry is not None:
                    self._fail_account(
                        email_service,
                        str(protocol_retry.get("email") or ""),
                        f"{protocol_retry.get('email')} 无新的健康代理可重试",
                    )
                    protocol_retry = None
                    current_email = None
                    continue
                return
            if protocol_retry is not None and not proxy_lease.direct:
                attempted = set(protocol_retry.get("attempted_proxy_ids") or set())
                attempted.add(proxy_lease.proxy_id)
                protocol_retry["attempted_proxy_ids"] = attempted
            try:
                if hasattr(email_service, "set_register_proxy"):
                    email_service.set_register_proxy(proxy_lease.spec)
                impersonate_fingerprint, account_user_agent = get_random_chrome_profile()
                with requests.Session(
                    impersonate=impersonate_fingerprint,
                    proxies=_proxy_map(proxy_lease.spec),
                ) as session:
                    try:
                        session.get(self.site_url, timeout=8)
                    except Exception:
                        pass

                    if self.stop_event.is_set():
                        return

                    password = str((protocol_retry or {}).get("password") or generate_random_string())

                    # 硬规则：Solver 不在线绝不创建邮箱，避免解不出验证码白耗配额
                    if not (turnstile_service.yescaptcha_key or "").strip():
                        try:
                            turnstile_service._ensure_local_solver(
                                stop_event=self.stop_event
                            )
                        except RuntimeError as te:
                            if str(te) == "stopped" or self.stop_event.is_set():
                                return
                            self.log(f"Solver 未就绪: {te}，等待后重试（未创建邮箱）", "warn")
                            if self._sleep(3):
                                return
                            continue
                        except Exception as se:
                            if self.stop_event.is_set():
                                return
                            self.log(
                                f"Solver 未就绪: {se}，等待后重试（未创建邮箱，不浪费配额）",
                                "warn",
                            )
                            if self._sleep(5):
                                return
                            continue

                    if protocol_retry is not None:
                        jwt = protocol_retry.get("jwt")
                        email = str(protocol_retry.get("email") or "")
                        current_email = email
                        self.log(
                            f"{email} 旧协议路径改用新代理重新发码 "
                            f"({len(protocol_retry.get('attempted_proxy_ids') or [])}/3)",
                            "warn",
                        )
                    else:
                        attempt_i = self._reserve_email_creation()
                        if not attempt_i:
                            return
                        email_slot_reserved = True
                        if use_domain_pool:
                            domain_lease = self.domain_pool.acquire(
                                f"protocol-email-{attempt_i}"
                            )
                            if domain_lease is None:
                                self.resource_exhausted_reason = "DOMAIN_EXHAUSTED"
                                self.error_message = "没有可用的 Cloudflare Temp 域名，任务需要人工处理"
                                self.log(self.error_message, "error")
                                return
                        try:
                            if domain_lease is not None:
                                jwt, email = email_service.create_email_for_domain(
                                    domain_lease.domain
                                )
                            else:
                                jwt, email = email_service.create_email()
                            current_email = email
                        except Exception as e:
                            self._finish_email_creation(success=False)
                            email_slot_reserved = False
                            self._fail_account(
                                email_service, None, f"邮箱服务异常: {e}"
                            )
                            # 邮箱服务抖动：稍等再试，不整任务退出
                            if self._sleep(2):
                                return
                            continue

                        if not email:
                            self._finish_email_creation(success=False)
                            email_slot_reserved = False
                            self._fail_account(email_service, None, "创建邮箱失败")
                            if self._sleep(1):
                                return
                            continue
                        self._finish_email_creation(success=True)
                        email_slot_reserved = False
                        if domain_lease is not None:
                            self.domain_pool.release(domain_lease)
                            domain_lease = None

                    if self.stop_event.is_set():
                        email_service.delete_email(email)
                        current_email = None
                        return

                    email_meta = (
                        dict(protocol_retry.get("email_meta") or {})
                        if protocol_retry is not None
                        else email_service.get_email_metadata(email)
                    )
                    self.log(
                        f"开始注册: {email} · {email_meta.get('email_provider') or '?'} / "
                        f"{email_meta.get('email_domain') or '?'}",
                        "info",
                    )

                    # 架构：发码/验码/注册 = 纯协议；Turnstile = Camoufox 无头 Solver
                    # Castle 产线 G6 尚未纯协议还原，默认 Camoufox 无头 mint（CASTLE_MODE=skip 可关）
                    castle_token = None
                    if castle_service.mode not in ("skip", "none", "off", "0", "false"):
                        self.log(
                            f"{email} Castle mint（Camoufox 无头，mode={castle_service.mode}）…",
                            "info",
                        )
                        try:
                            castle_token = castle_service.mint(stop_event=self.stop_event)
                        except Exception as ce:
                            self.log(f"{email} Castle mint 异常: {ce}", "warn")
                            castle_token = None
                        if castle_token:
                            self.log(
                                f"{email} Castle OK len={len(castle_token)} head={castle_token[:28]}…",
                                "info",
                            )
                        else:
                            self.log(
                                f"{email} Castle 未拿到（{castle_service.last_error or 'empty'}），"
                                f"发码/注册将不带或空带 castle",
                                "warn",
                            )
                    if self.stop_event.is_set():
                        try:
                            email_service.delete_email(email)
                        except Exception:
                            pass
                        current_email = None
                        return

                    if not self.send_email_code_grpc(
                        session, email, castle_request_token=castle_token
                    ):
                        self._fail_account(
                            email_service, email, f"{email} 发送邮箱验证码失败"
                        )
                        current_email = None
                        continue

                    self.log(f"{email} 已请求邮箱验证码，等待收件…", "info")
                    verify_code = email_service.fetch_verification_code(
                        email, stop_event=self.stop_event
                    )
                    if self.stop_event.is_set():
                        try:
                            email_service.delete_email(email)
                        except Exception:
                            pass
                        current_email = None
                        return
                    if not verify_code:
                        self._fail_account(
                            email_service, email, f"{email} 未收到邮箱验证码"
                        )
                        current_email = None
                        continue

                    self.log(f"{email} 邮箱验证码: {verify_code}，提交校验…", "info")
                    if not self.verify_email_code_grpc(session, email, verify_code):
                        self._fail_account(
                            email_service,
                            email,
                            f"{email} 邮箱验证码校验失败（码={verify_code}）",
                        )
                        current_email = None
                        continue

                    self.log(f"{email} 邮箱已通过（码={verify_code}），开始解 Turnstile…", "info")
                    signup_ok = False
                    last_turnstile_err = ""
                    # 邮箱验证码在「成功创建账号」后即失效；Turnstile 仅允许在未拿到 SSO 前重试
                    for attempt in range(1, 4):
                        if self.stop_event.is_set():
                            email_service.delete_email(email)
                            current_email = None
                            return

                        try:
                            self.log(
                                f"{email} Turnstile 第 {attempt}/3 次（Solver: {turnstile_service.solver_url}）",
                                "info",
                            )
                            task_id = turnstile_service.create_task(
                                self.site_url,
                                self.config["site_key"],
                                stop_event=self.stop_event,
                            )
                            self.log(f"{email} Turnstile 任务已创建: {str(task_id)[:18]}…", "info")
                            token = turnstile_service.get_response(
                                task_id, stop_event=self.stop_event
                            )
                        except RuntimeError as te:
                            if str(te) == "stopped" or self.stop_event.is_set():
                                try:
                                    email_service.delete_email(email)
                                except Exception:
                                    pass
                                current_email = None
                                return
                            last_turnstile_err = str(te)
                            self.log(f"{email} Turnstile 创建/查询失败: {te}", "error")
                            if self._sleep(1):
                                return
                            continue
                        except Exception as te:
                            if self.stop_event.is_set():
                                try:
                                    email_service.delete_email(email)
                                except Exception:
                                    pass
                                current_email = None
                                return
                            last_turnstile_err = str(te)
                            self.log(f"{email} Turnstile 创建/查询失败: {te}", "error")
                            if self._sleep(1):
                                return
                            continue

                        if self.stop_event.is_set() or (
                            not token and turnstile_service.last_error == "已停止"
                        ):
                            try:
                                email_service.delete_email(email)
                            except Exception:
                                pass
                            current_email = None
                            return

                        if not token or token == "CAPTCHA_FAIL":
                            err = turnstile_service.last_error or "无 token / CAPTCHA_FAIL"
                            last_turnstile_err = err
                            self.log(f"{email} Turnstile 失败: {err}", "warn")
                            if self._sleep(1):
                                return
                            continue

                        # 终态前尽量刷新 castle（token 有时效）；失败则复用发码时的
                        signup_castle = castle_token
                        if castle_service.mode not in ("skip", "none", "off", "0", "false"):
                            try:
                                fresh = castle_service.mint(stop_event=self.stop_event)
                                if fresh:
                                    signup_castle = fresh
                                    self.log(
                                        f"{email} 终态 Castle 刷新 OK len={len(fresh)}",
                                        "info",
                                    )
                            except Exception as ce:
                                self.log(
                                    f"{email} 终态 Castle 刷新失败，复用旧 token: {ce}",
                                    "warn",
                                )

                        self.log(f"{email} Turnstile 成功，提交注册（协议）…", "info")
                        headers = {
                            "user-agent": account_user_agent,
                            "accept": "text/x-component",
                            "content-type": "text/plain;charset=UTF-8",
                            "origin": self.site_url,
                            "referer": f"{self.site_url}/sign-up",
                            "cookie": f"__cf_bm={session.cookies.get('__cf_bm', '')}",
                            "next-router-state-tree": self.config["state_tree"],
                            "next-action": final_action_id,
                        }
                        body_obj = {
                            "emailValidationCode": verify_code,
                            "createUserAndSessionRequest": {
                                "email": email,
                                "givenName": generate_random_name(),
                                "familyName": generate_random_name(),
                                "clearTextPassword": password,
                                "tosAcceptedVersion": "$undefined",
                            },
                            "turnstileToken": token,
                            "conversionId": str(uuid.uuid4()),
                            "promptOnDuplicateEmail": True,
                        }
                        if signup_castle:
                            body_obj["castleRequestToken"] = signup_castle
                        payload = [body_obj]

                        try:
                            # 仅起步节流，HTTP 本身并行，避免 8 线程全卡在一把锁上
                            self._throttle_signup_post()
                            res = session.post(
                                f"{self.site_url}/sign-up",
                                json=payload,
                                headers=headers,
                                timeout=15,
                            )
                        except Exception as pe:
                            if self.stop_event.is_set():
                                return
                            last_turnstile_err = f"提交注册异常: {pe}"
                            self.log(f"{email} 提交注册异常: {pe}", "error")
                            if self._sleep(1):
                                return
                            continue

                        if res.status_code != 200:
                            last_turnstile_err = f"注册 HTTP {res.status_code}: {res.text[:120]}"
                            self.log(f"{email} {last_turnstile_err}", "warn")
                            if self._sleep(1):
                                return
                            continue

                        body_text = res.text or ""
                        # 邮箱验证码已用尽 / 失效：再解 Turnstile 也没用，立刻结束本账号
                        if (
                            "invalid-validation" in body_text
                            or "Email validation code is invalid" in body_text
                            or "email:invalid" in body_text
                        ):
                            last_turnstile_err = "邮箱验证码已失效（不可重复注册）"
                            self.log(
                                f"{email} 邮箱验证码已失效，停止对本邮箱重试（避免空转）",
                                "error",
                            )
                            break

                        match = re.search(
                            r'(https://[^" \s]+set-cookie\?q=[^:" \s]+)1:', body_text
                        )
                        if not match:
                            last_turnstile_err = (
                                f"注册响应无 set-cookie: {body_text[:160]}"
                            )
                            self.log(f"{email} {last_turnstile_err}", "warn")
                            if self._sleep(1):
                                return
                            continue

                        verify_url = match.group(1)
                        try:
                            session.get(verify_url, allow_redirects=True, timeout=12)
                        except Exception:
                            if self.stop_event.is_set():
                                # 可能已有 cookie，尽量抢救
                                sso_try = session.cookies.get("sso")
                                if sso_try:
                                    self._emergency_save_sso(
                                        email, sso_try, "停止时抢救"
                                    )
                                return
                        sso = session.cookies.get("sso")
                        sso_rw = session.cookies.get("sso-rw")
                        if not sso:
                            last_turnstile_err = "未拿到 sso cookie"
                            self.log(f"{email} 未拿到 sso cookie，重试 Turnstile", "warn")
                            if self._sleep(1):
                                return
                            continue

                        # ========== 邮箱保护硬规则 ==========
                        # 1) 拿到 SSO = xAI 账号已创建，验证码已消耗
                        # 2) 立刻落盘，后续任何失败都不得丢号、不得重注册
                        # 3) device flow / 协议 / NSFW 全部是「锦上添花」
                        sso_saved = self._emergency_save_sso(
                            email, sso, "注册完成立即落盘"
                        )
                        if not sso_saved:
                            self.log(
                                f"{email} 落盘失败，将在记成功时再写一次",
                                "error",
                            )

                        # protocol 始终是 UNCHECKED：不进行 OAuth/BFS，仅后台处理协议/NSFW。
                        self.log(
                            f"{email} 已拿到 SSO（{'已落盘' if sso_saved else '落盘失败'}），"
                            f"立即记为 UNCHECKED，协议/NSFW 后台处理…",
                            "info",
                        )
                        sid = self._record_success(
                            email=email,
                            sso=sso,
                            unhinged_ok=False,
                            email_service=email_service,
                            note="enrich=pending",
                            already_written=sso_saved,
                            auth_token=None,
                            proxy_audit=self.proxy_pool.lease_audit(proxy_lease),
                        )
                        if sid:
                            self._schedule_enrich(
                                email=email,
                                sso=sso,
                                sso_rw=sso_rw or "",
                                success_id=sid,
                                impersonate=impersonate_fingerprint,
                                user_agent=account_user_agent,
                                skip_token=True,
                                risk_gated=False,
                                proxy_lease=proxy_lease,
                            )
                            proxy_handed_off = True
                        # SSO 已在盘上：无论是否计入目标，都算本邮箱完成
                        current_email = None
                        signup_ok = True
                        proxy_outcome = "success"
                        protocol_retry = None
                        break

                    if not signup_ok:
                        if self.stop_event.is_set():
                            if current_email:
                                try:
                                    email_service.delete_email(current_email)
                                except Exception:
                                    pass
                                current_email = None
                            return
                        detail = last_turnstile_err or "Turnstile/注册失败"
                        if _is_proxy_network_error(detail):
                            proxy_outcome = "network"
                        attempted_ids = set((protocol_retry or {}).get("attempted_proxy_ids") or set())
                        if not proxy_lease.direct:
                            attempted_ids.add(proxy_lease.proxy_id)
                        if (
                            not proxy_lease.direct
                            and len(attempted_ids) < 3
                            and _protocol_safe_to_retry_with_new_proxy(detail)
                        ):
                            protocol_retry = {
                                "email": email,
                                "jwt": jwt,
                                "password": password,
                                "email_meta": email_meta,
                                "attempted_proxy_ids": attempted_ids,
                            }
                            current_email = email
                            self.log(
                                f"{email} 代理网络故障（signup 尚未提交）· "
                                "保留邮箱并换代理重新发码",
                                "warn",
                            )
                            continue
                        self._fail_account(
                            email_service,
                            email,
                            f"{email} 重试 3 次后仍失败（{detail}）",
                        )
                        protocol_retry = None
                        current_email = None
                        # 本账号失败，继续下一封新邮箱，不结束整任务
                        continue

                    # 成功且未达目标：继续下一封邮箱
                    continue

            except Exception as e:
                if _is_proxy_network_error(e):
                    proxy_outcome = "network"
                if self.stop_event.is_set():
                    if current_email:
                        try:
                            email_service.delete_email(current_email)
                        except Exception:
                            pass
                    return
                self._fail_account(
                    email_service,
                    current_email,
                    f"异常: {str(e)[:120]}",
                )
                current_email = None
                if self._sleep(1):
                    return
                continue
            finally:
                if email_slot_reserved:
                    self._finish_email_creation(success=False)
                if domain_lease is not None:
                    self.domain_pool.release(domain_lease)
                if proxy_lease is not None and not proxy_handed_off:
                    self.proxy_pool.release(proxy_lease, proxy_outcome)

        if protocol_retry is not None and current_email:
            try:
                email_service.delete_email(current_email)
            except Exception:
                pass

    def _run_workers(self, workers: int):
        try:
            if not self.initialize():
                return
            if self.stop_event.is_set():
                self.status = "done"
                self.log("任务已取消（初始化后停止）", "warn")
                return
            self.status = "running"
            mode = resolve_register_mode(getattr(self, "register_mode", None))
            self.register_mode = mode
            worker_fn = (
                self.register_single_thread_same_session
                if mode == "same_session"
                else self.register_single_thread
            )
            self.log(
                f"启动 {workers} 个线程 · 创邮目标 {self.target_count} · 路径={mode}",
                "info",
            )
            self.log(f"输出: {self.output_file}", "info")

            def _worker_entry() -> None:
                try:
                    worker_fn()
                finally:
                    # Playwright Sync/greenlet 必须由创建它的 worker 线程关闭。
                    # 协调线程在 executor 退出后再关会触发跨线程切换错误。
                    if mode == "same_session":
                        try:
                            from g.same_session_register import _drop_thread_pool

                            _drop_thread_pool(self.log, reason="worker 退出清理")
                        except Exception as cleanup_err:
                            self.log(f"worker camoufox 清理异常: {cleanup_err}", "warn")

            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                self._executor = executor
                futures = [executor.submit(_worker_entry) for _ in range(workers)]
                # 周期检查 stop，避免 wait 一直挂到所有线程自然结束才有反馈
                while True:
                    done, _not_done = concurrent.futures.wait(
                        futures, timeout=0.5, return_when=concurrent.futures.ALL_COMPLETED
                    )
                    if len(done) == len(futures):
                        break
                    if self.stop_event.is_set() and self.status == "stopping":
                        # 再等一小会儿让线程看到 stop_event 退出；最长约 6s
                        concurrent.futures.wait(futures, timeout=6)
                        break
            self._executor = None
            # 等后台 NSFW/协议收尾（最多 ~45s）
            try:
                deadline = time.time() + 45.0
                while time.time() < deadline:
                    with self._enrich_lock:
                        pending = self._enrich_pending
                    if pending <= 0:
                        break
                    time.sleep(0.5)
                with self._enrich_lock:
                    left = self._enrich_pending
                # 统计时：有可用 token 或已导入都算「票已就绪」（导入后会清内存 token）
                token_ready = 0
                imported_n = 0
                for it in list(self.recent_success):
                    if it.get("imported"):
                        imported_n += 1
                        token_ready += 1
                    elif is_auth_token_usable(it.get("auth_token")):
                        token_ready += 1
                if left > 0:
                    self.log(
                        f"仍有 {left} 个后台 NSFW/协议未完成；token 就绪 "
                        f"{token_ready}/{self.success_count}"
                        f"（不自动入库，页面手动导入）",
                        "warn",
                    )
                else:
                    self.log(
                        f"流水线收尾：token 就绪 {token_ready}/{self.success_count}"
                        f"（不自动入库 · 点「导入」手动入库）",
                        "success" if token_ready else "warn",
                    )
            except Exception:
                pass
            # 主流程不自动入库：账号/token 只落盘 + recent_success，
            # 若 Web 运行时启用了目标，则只排队，不阻塞注册线程。
            callback = getattr(self, "auto_import_callback", None)
            if callable(callback):
                try:
                    callback([
                        {
                            "id": it.get("id"),
                            "email": it.get("email"),
                            "sso": it.get("sso"),
                            "auth_token": it.get("auth_token"),
                            "clean": it.get("clean"),
                        }
                        for it in list(self.recent_success)
                        if it.get("sso") and it.get("clean") is True and not it.get("auto_queued")
                    ])
                except Exception as auto_exc:
                    self.log(f"自动导入排队失败: {auto_exc}", "warn")
            if self.status == "error":
                pass
            elif self.resource_exhausted_reason:
                self.status = "resource_exhausted"
                self.log(
                    f"任务结束：资源耗尽 {self.resource_exhausted_reason} · {self.error_message}",
                    "error",
                )
            else:
                self.status = "done"
                attempts = int(getattr(self, "attempt_count", 0) or 0)
                created = int(getattr(self, "email_create_count", 0) or 0)
                self.log(
                    f"任务结束：创邮 {created}/{self.target_count}"
                    f" · 邮箱API尝试 {attempts}"
                    f" · 成功 {self.success_count}"
                    f" · CLEAN {getattr(self, 'clean_count', 0)}"
                    f" · UNCHECKED {getattr(self, 'unchecked_count', 0)}"
                    f" · 过程失败 {self.fail_count}"
                    f" · MARKED {getattr(self, 'marked_count', 0)}"
                    f" · 连续MARKED {getattr(self, '_ss_consecutive_deny', 0)}",
                    "success" if created >= self.target_count else "warn",
                )
        except Exception as e:
            self.error_message = str(e)
            self.status = "error"
            self.log(f"运行失败: {e}", "error")
        finally:
            self.stop_event.set()
            # 账号级租约应已逐一释放；这里是批次异常/中断的最后兜底。
            try:
                from g.socks5_http_bridge import shutdown_all_bridges

                shutdown_all_bridges()
            except Exception:
                pass
            if self.status not in ("done", "error", "resource_exhausted"):
                self.status = "done"
            # 钉死耗时：结束后前端轮询不再让「已用时间」空转
            self._freeze_elapsed()
            # 任务结束即停看门狗，避免空闲时反复拉起已崩溃的 Solver
            try:
                import solver_manager

                solver_manager.stop_watchdog()
            except Exception:
                pass
            callback = getattr(self, "on_run_complete", None)
            if callable(callback):
                try:
                    callback()
                except Exception as callback_err:
                    self.log(f"批次收尾回调异常: {callback_err}", "warn")

    def _auto_import_clean_accounts(self) -> None:
        """
        任务收尾自动入库：
        1) 优先 recent_success 里未导入且有缓存 token 的 CLEAN 号（直写）
        2) 若内存已全部 imported，跳过（避免再读 clean 文件走 sso-to-oauth 二次导入）
        3) 仅当内存空/缺票时，才回落 _clean.txt
        """
        from g.auto_import import auto_import_enabled

        if not auto_import_enabled():
            self.log("自动入库已关闭（AUTO_IMPORT=0）", "info")
            return

        pending = [
            it
            for it in list(self.recent_success)
            if it.get("sso")
            and not it.get("imported")
            and it.get("clean") is True
        ]
        already = sum(1 for it in list(self.recent_success) if it.get("imported"))
        if not pending and already > 0:
            self.log(
                f"自动入库跳过：{already} 条已在任务内直写导入，无需再读 clean 文件",
                "success",
            )
            return

        if pending:
            try:
                from app import import_sso_to_upstream
            except Exception as e:
                self.log(f"自动入库失败：无法加载导入模块 · {e}", "error")
                return
            accounts = []
            seen = set()
            for it in pending:
                sso = (it.get("sso") or "").strip()
                if not sso or sso in seen:
                    continue
                seen.add(sso)
                tok = it.get("auth_token")
                accounts.append(
                    {
                        "email": (it.get("email") or "").strip(),
                        "sso": sso,
                        "auth_token": tok if isinstance(tok, dict) else None,
                    }
                )
            if not accounts:
                self.log("自动入库跳过：无可提交账号", "warn")
                return
            cached_n = sum(
                1 for a in accounts if is_auth_token_usable(a.get("auth_token"))
            )
            self.log(
                f"自动入库开始 · recent_success {len(accounts)} 条"
                f"（缓存 token {cached_n}）",
                "info",
            )
            result = import_sso_to_upstream(
                accounts=accounts, merge=True, max_workers=1
            )
            # 标记已导入，清内存 token（与 app._mark_recent_imported 对齐）
            ok_emails = set()
            for row in result.get("results") or []:
                if row.get("status") == "ok" and row.get("email"):
                    ok_emails.add(str(row["email"]).lower())
            if result.get("ok") or (result.get("success") or 0) > 0:
                for it in self.recent_success:
                    em = (it.get("email") or "").lower()
                    if em and em in ok_emails:
                        it["imported"] = True
                        it["auth_token"] = None
                    elif result.get("ok") and it in pending:
                        it["imported"] = True
                        it["auth_token"] = None
            success = int(result.get("success") or 0)
            fail = int(result.get("fail") or 0)
            msg = result.get("message") or ""
            level = (
                "success"
                if success > 0 and fail == 0
                else ("warn" if success > 0 else "error")
            )
            self.log(
                f"自动入库完成 · 成功 {success}/{len(accounts)} · 失败 {fail} · {msg}",
                level,
            )
            return

        # 回落：内存无账号时读 clean 文件（例如仅 CLI 跑完、或 recent 被清）
        if not self.output_file:
            self.log("自动入库跳过：无 output 与 recent", "warn")
            return
        try:
            from g.auto_import import import_clean_file

            clean_file = Path(self.output_file).with_name(
                Path(self.output_file).stem + "_clean.txt"
            )
            if clean_file.is_file() and clean_file.stat().st_size > 0:
                import_clean_file(
                    clean_file,
                    log=lambda msg, level="info": self.log(msg, level),
                )
            else:
                self.log("无 CLEAN 文件，跳过自动入库", "warn")
        except Exception as ie:
            self.log(f"自动入库（文件回落）异常: {ie}", "warn")

    def stop(self) -> dict:
        if not self.is_running():
            return {"ok": False, "message": "当前没有运行中的任务", **self.get_status()}
        self.status = "stopping"
        self.stop_event.set()
        self.log("正在停止任务（等待当前网络请求结束，最多约数秒）…", "warn")
        return {"ok": True, "message": "已发送停止信号", **self.get_status()}

    def start(
        self,
        workers: int = 8,
        target: int = 100,
        blocking: bool = False,
        mode: Optional[str] = None,
        risk_check_enabled: bool = True,
    ) -> dict:
        with self._run_lock:
            # 线程还没跑到 initialize 时 status 也要立刻占位，防止重复启动
            if self.is_running() or (
                self._worker_thread is not None and self._worker_thread.is_alive()
            ) or self._enrich_pending > 0:
                return {"ok": False, "message": "任务已在运行中", **self.get_status()}

            workers = max(1, min(int(workers), 64))
            target = max(1, int(target))
            # same_session 吃浏览器资源，默认压并发上限
            reg_mode = resolve_register_mode(
                mode if mode is not None else os.environ.get("GROK_REGISTER_MODE")
            )
            if reg_mode == "same_session":
                max_ss = int(os.environ.get("GROK_SS_MAX_WORKERS") or "4")
                max_ss = max(1, min(max_ss, 16))
                if workers > max_ss:
                    self.log(
                        f"same_session 并发 {workers}→{max_ss}（GROK_SS_MAX_WORKERS，防浏览器打爆）",
                        "warn",
                    )
                    workers = max_ss

            self.stop_event.clear()
            self.success_count = 0
            self.fail_count = 0
            self.clean_count = 0
            self.marked_count = 0
            self.review_count = 0
            self.infra_retry_count = 0
            self.unchecked_count = 0
            self.pending_bfs_count = 0
            self.oauth_infra_streak = 0
            self.attempt_count = 0
            self.email_create_count = 0
            self._email_create_reserved = 0
            self.bot_retry_count = 0
            self._ss_consecutive_deny = 0
            self.target_count = target
            self.workers = workers
            self.register_mode = reg_mode
            # protocol 路径没有同会话 Risk 门禁，始终按 UNCHECKED 处理。
            self.risk_check_enabled = bool(risk_check_enabled) and reg_mode == "same_session"
            self._ss_idx = 0
            self.start_time = time.time()
            self.end_time = None  # 新一轮重新计时
            self.error_message = ""
            self.resource_exhausted_reason = ""
            self.recent_success.clear()
            # 先标 initializing，避免并发 /api/start 重复拉起
            self.status = "initializing"
            # 不清空缓存的 action_id；initialize 会优先用缓存
            if not self.config.get("action_id") and self._action_cache.get("action_id"):
                self._apply_action_cache()

            os.makedirs("keys", exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            prefix = "grok_ss" if reg_mode == "same_session" else "grok"
            self.output_file = f"keys/{prefix}_{timestamp}_{target}.txt"
            self._classification_store = ClassificationStore(_BASE_DIR / self.output_file)
            self.log(
                "账号 Risk 检测: "
                + ("已启用" if self.risk_check_enabled else "已关闭（成功号记为 UNCHECKED）"),
                "info" if self.risk_check_enabled else "warn",
            )

            # Web runtime uses this synchronous hook to mark proxies as
            # `testing` before any worker can acquire one.
            callback = getattr(self, "on_run_start", None)
            if callable(callback):
                try:
                    callback()
                except Exception as callback_err:
                    self.log(f"批次启动回调异常: {callback_err}", "warn")

            if blocking:
                self._run_workers(workers)
                return {"ok": True, "message": "任务完成", **self.get_status()}

            self._worker_thread = threading.Thread(
                target=self._run_workers,
                args=(workers,),
                daemon=True,
                name="RegisterEngine",
            )
            self._worker_thread.start()
            return {
                "ok": True,
                "message": f"任务已启动（路径={reg_mode}）",
                **self.get_status(),
            }


# 兼容旧 CLI 全局入口
_cli_logs = LogBuffer()
engine = RegisterEngine(log_fn=lambda msg, level="info": _cli_logs.emit(msg, level))


def main():
    print("=" * 60 + "\nGrok 注册机\n" + "=" * 60)
    default_mode = resolve_register_mode()
    print(f"注册路径: same_session=同会话CLEAN（默认） / protocol=旧混合协议")
    print(f"当前默认: {default_mode}（可用环境变量 GROK_REGISTER_MODE 覆盖）")
    mode_in = input(f"\n路径 (默认 {default_mode}): ").strip() or default_mode
    mode = resolve_register_mode(mode_in)
    try:
        t = int(input("\n并发数 (默认4): ").strip() or 4)
    except Exception:
        t = 4
    try:
        total = int(input("创建邮箱目标 (默认10): ").strip() or 10)
    except Exception:
        total = 10
    engine.start(workers=t, target=total, blocking=True, mode=mode)


if __name__ == "__main__":
    main()
