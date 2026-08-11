# -*- coding: utf-8 -*-
"""
同会话 CLEAN 注册（edu.valenastra.com）

根因对齐 grokzhuce1 已验证路径:
  拆会话 Camoufox mint → curl signup  = BOT_FLAG_SOURCE_CASTLE deny
  同页 fiber mint + 页内 fetch 发码/验码/signup = 可 CLEAN

- 邮箱域名默认 edu.valenastra.com
- Turnstile: 本地 Camoufox Solver（并行预解）
- Castle: 同页 createRequestToken（禁止拷到外层 curl）
"""
from __future__ import annotations

import json
import os
import random
import re
import string
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

BASE = Path(__file__).resolve().parent
os.chdir(BASE)
sys.path.insert(0, str(BASE))

# Windows 控制台/管道默认 GBK，中文会变成 ��；强制 UTF-8 输出
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
os.environ.setdefault("PYTHONUTF8", "1")
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
try:
    # 尽量把控制台代码页切到 UTF-8（失败忽略）
    import ctypes

    ctypes.windll.kernel32.SetConsoleOutputCP(65001)
    ctypes.windll.kernel32.SetConsoleCP(65001)
except Exception:
    pass

from dotenv import load_dotenv

load_dotenv(BASE / ".env", override=False)

# standalone 默认自动入库 CLEAN；环境变量/命令行显式 AUTO_IMPORT=0 可关
if (os.environ.get("AUTO_IMPORT") or "").strip() == "":
    os.environ["AUTO_IMPORT"] = "1"

# 实时日志文件（UTF-8）：STANDALONE_LIVE_LOG=路径 或默认 logs/standalone_live.log
_LIVE_LOG_PATH = (os.environ.get("STANDALONE_LIVE_LOG") or "").strip()
if not _LIVE_LOG_PATH:
    _LIVE_LOG_PATH = str(BASE / "logs" / "standalone_live.log")
try:
    Path(_LIVE_LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
except Exception:
    pass

MAIL_DOMAIN = (os.environ.get("STANDALONE_MAIL_DOMAIN") or "").strip()
# Empty means: use the same global provider configuration as the Web app.
# The legacy override remains available for one-off compatibility runs.
if MAIL_DOMAIN:
    os.environ["FREEMAIL_DOMAIN"] = MAIL_DOMAIN
os.environ["GROK_SAME_SESSION_PROTOCOL"] = "1"
os.environ["GROK_SAME_SESSION_HEADLESS"] = "camoufox"
os.environ["GROK_SAME_SESSION_BROWSER"] = "camoufox"
os.environ["GROK_SAME_SESSION_TS_PARALLEL"] = "1"
for k in ("GROK_PROXY", "XAI_PROXY", "SAME_SESSION_PROXY"):
    os.environ.pop(k, None)

from g import EmailService, TurnstileService, same_session_register
from g.auto_import import auto_import_enabled, import_clean_file
from g.clean_fp_ledger import record_clean_success, record_marked, summarize as fp_ledger_summarize
from g.same_session_register import parse_proxy_spec, shutdown_camoufox_pool

# 本批 id（main 里赋值，供账本关联）
_BATCH_ID = ""
try:
    from g.socks5_http_bridge import shutdown_all_bridges
except Exception:  # pragma: no cover
    def shutdown_all_bridges() -> None:  # type: ignore
        return None
import solver_manager

try:
    from g import AntibotService
except Exception:
    AntibotService = None  # type: ignore

COUNT = int(os.environ.get("STANDALONE_COUNT") or "1")
# 连续 policy=deny / MARKED 熔断：默认 3 次即停批，避免同 IP 连打空烧
# 覆盖：STANDALONE_DENY_BREAK=3（0/off 关闭）
def _deny_break_n() -> int:
    raw = (os.environ.get("STANDALONE_DENY_BREAK") or "3").strip().lower()
    if raw in ("0", "off", "false", "no", "none"):
        return 0
    try:
        return max(0, int(raw))
    except Exception:
        return 3


DENY_BREAK_N = _deny_break_n()


def _inter_account_delay_s(consecutive_deny: int = 0) -> float:
    """
    号间抖动：压同出口短时 $registration 密度（Castle deny 簇）。
    主流程 grok.py 默认 900-3200ms；standalone 以前只有 0.15-0.4s，密度过高。
    环境：STANDALONE_SS_JITTER_MS / GROK_SS_JITTER_MS = 1500-4000 或 0 关闭。
    连续 deny 时自动加长冷却。
    """
    raw = (
        os.environ.get("STANDALONE_SS_JITTER_MS")
        or os.environ.get("GROK_SS_JITTER_MS")
        or "1500-4500"
    ).strip().lower()
    if raw in ("0", "off", "no", "false", "none"):
        base = random.uniform(0.15, 0.4)
    else:
        try:
            if "-" in raw:
                a, b = raw.split("-", 1)
                lo, hi = int(a.strip()), int(b.strip())
            else:
                lo = hi = int(raw)
        except ValueError:
            lo, hi = 1500, 4500
        if hi < lo:
            lo, hi = hi, lo
        lo = max(0, lo)
        hi = max(lo, hi)
        base = random.randint(lo, hi) / 1000.0
    # 连续 deny：指数加冷（1→+4s, 2→+8s），熔断前先降密度
    if consecutive_deny > 0:
        base += min(20.0, 4.0 * (2 ** (consecutive_deny - 1)))
    return max(0.0, base)


SITE_URL = "https://accounts.x.ai"
SITE_KEY = "0x4AAAAAAAhr9JGVDZbrZOo0"

# 默认【电脑代理 127.0.0.1:7897】—— 就是你本机 Clash mixed 口，不是 1024。
# 覆盖：STANDALONE_LOCAL_PROXY / LOCAL_PROXY
# 远程池要显式开：
#   STANDALONE_USE_1024=1           → 内置 1024 SOCKS5
#   STANDALONE_PROXY_POOL / FILE    → 自定义池
#   STANDALONE_USE_CLIPROXY=1       → 旧 cliproxy
#   STANDALONE_NO_PROXY=1           → 不塞任何 app 代理（纯跟系统，一般不用）
_LOCAL_PROXY_RAW = (
    os.environ.get("STANDALONE_LOCAL_PROXY")
    or os.environ.get("LOCAL_PROXY")
    or "127.0.0.1:7897"
).strip()
_USE_CLIPROXY = (os.environ.get("STANDALONE_USE_CLIPROXY") or "").strip().lower() in (
    "1",
    "true",
    "yes",
)
_NO_PROXY = (os.environ.get("STANDALONE_NO_PROXY") or "").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
_HAS_PROXY_POOL_ENV = bool(
    (os.environ.get("STANDALONE_PROXY_POOL") or "").strip()
    or (os.environ.get("STANDALONE_PROXY_FILE") or "").strip()
)
_USE_1024 = (os.environ.get("STANDALONE_USE_1024") or "").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
) or _HAS_PROXY_POOL_ENV
# 默认本机 7897（电脑代理）；1024/cliproxy/NO_PROXY 才改
_USE_LOCAL = not (_USE_1024 or _USE_CLIPROXY or _NO_PROXY)
_USE_SYSTEM = _NO_PROXY and not (_USE_LOCAL or _USE_1024 or _USE_CLIPROXY)
_USE_DIRECT = _USE_SYSTEM
# 每号是否给 1024/带鉴权代理追加 -session-xxx（换出口 IP）；0=关
_PROXY_SESSION_ROTATE = (
    os.environ.get("STANDALONE_PROXY_SESSION") or "1"
).strip().lower() not in ("0", "off", "false", "no", "none")

# 指纹地区池：与出口区对齐 + 多区轮换，压连号撞同一 locale/OS/时区
FP_REGIONS = [
    {
        "tag": "JP-TKY",
        "locale": "ja-JP",
        "timezone": "Asia/Tokyo",
        "fp_os": "windows",
    },
    {
        "tag": "JP-OSK",
        "locale": "ja-JP",
        "timezone": "Asia/Tokyo",
        "fp_os": "macos",
    },
    {
        "tag": "US-W",
        "locale": "en-US",
        "timezone": "America/Los_Angeles",
        "fp_os": "windows",
    },
    {
        "tag": "US-E",
        "locale": "en-US",
        "timezone": "America/New_York",
        "fp_os": "macos",
    },
    {
        "tag": "AU-SYD",
        "locale": "en-AU",
        "timezone": "Australia/Sydney",
        "fp_os": "windows",
    },
    {
        "tag": "AU-MEL",
        "locale": "en-AU",
        "timezone": "Australia/Melbourne",
        "fp_os": "macos",
    },
    {
        "tag": "KR",
        "locale": "ko-KR",
        "timezone": "Asia/Seoul",
        "fp_os": "windows",
    },
    {
        "tag": "SG",
        "locale": "en-SG",
        "timezone": "Asia/Singapore",
        "fp_os": "macos",
    },
    {
        "tag": "TW",
        "locale": "zh-TW",
        "timezone": "Asia/Taipei",
        "fp_os": "windows",
    },
    {
        "tag": "TW-MAC",
        "locale": "zh-TW",
        "timezone": "Asia/Taipei",
        "fp_os": "macos",
    },
    {
        "tag": "MY",
        "locale": "en-MY",
        "timezone": "Asia/Kuala_Lumpur",
        "fp_os": "windows",
    },
    {
        "tag": "MY-MAC",
        "locale": "en-MY",
        "timezone": "Asia/Kuala_Lumpur",
        "fp_os": "macos",
    },
    {
        "tag": "HK",
        "locale": "zh-HK",
        "timezone": "Asia/Hong_Kong",
        "fp_os": "windows",
    },
    {
        "tag": "HK-MAC",
        "locale": "zh-HK",
        "timezone": "Asia/Hong_Kong",
        "fp_os": "macos",
    },
    {
        "tag": "GB",
        "locale": "en-GB",
        "timezone": "Europe/London",
        "fp_os": "macos",
    },
]

# 代理凭据不内置到源码；通过 STANDALONE_PROXY_POOL 传入。
_DEFAULT_1024_POOL: list[str] = []

# 仅 STANDALONE_USE_CLIPROXY=1 时启用（历史兼容）
CLIPROXY_BASES: list[dict[str, Any]] = []


def _guess_region_meta(user: str, host: str = "") -> dict[str, str]:
    """从 user/host 里猜 locale/timezone/tag（region-JP / Tokyo 等）。"""
    blob = f"{user} {host}".lower()
    if "region-jp" in blob or "-jp-" in blob or "tokyo" in blob or "osaka" in blob:
        return {
            "tag": "JP-1024",
            "locale": "ja-JP",
            "timezone": "Asia/Tokyo",
            "fp_os": "windows",
        }
    if "region-au" in blob or "sydney" in blob or "melbourne" in blob:
        return {
            "tag": "AU-1024",
            "locale": "en-AU",
            "timezone": "Australia/Sydney",
            "fp_os": "windows",
        }
    if "region-us" in blob or "losangeles" in blob or "newyork" in blob:
        return {
            "tag": "US-1024",
            "locale": "en-US",
            "timezone": "America/Los_Angeles",
            "fp_os": "windows",
        }
    if "region-kr" in blob or "seoul" in blob:
        return {
            "tag": "KR-1024",
            "locale": "ko-KR",
            "timezone": "Asia/Seoul",
            "fp_os": "windows",
        }
    if "region-sg" in blob or "singapore" in blob:
        return {
            "tag": "SG-1024",
            "locale": "en-SG",
            "timezone": "Asia/Singapore",
            "fp_os": "windows",
        }
    return {
        "tag": "PX",
        "locale": "en-US",
        "timezone": "America/Los_Angeles",
        "fp_os": "windows",
    }


def _default_pool_scheme(host: str = "", explicit: str = "") -> str:
    """
    池条目协议：
      1) 行内显式 socks5h/http
      2) STANDALONE_PROXY_SCHEME / GROK_PROXY_SCHEME
      3) 1024proxy 主机 → socks5h（本机 HTTP 不通）
      4) 其它 → http
    """
    ex = (explicit or "").strip().lower()
    if ex in ("socks5", "socks5h"):
        return "socks5h"
    if ex in ("http", "https"):
        return "http"
    env = (
        os.environ.get("STANDALONE_PROXY_SCHEME")
        or os.environ.get("GROK_PROXY_SCHEME")
        or ""
    ).strip().lower()
    if env in ("socks5", "socks5h"):
        return "socks5h"
    if env in ("http", "https"):
        return "http"
    if "1024proxy" in (host or "").lower():
        return "socks5h"
    return "http"


def _parse_proxy_line(line: str, idx: int = 0) -> Optional[dict[str, Any]]:
    """
    解析一条代理：
      host:port:user:pass
      socks5h://user:pass@host:port
      http://user:pass@host:port
      user:pass@host:port
    """
    s = (line or "").strip()
    if not s or s.startswith("#"):
        return None
    host = port = user = pw = ""
    scheme_raw = ""
    if "://" in s:
        m = re.match(
            r"^(?P<sch>[a-zA-Z][a-zA-Z0-9+.-]*)://"
            r"(?:(?P<user>[^:@/]+):(?P<pw>[^@/]*)@)?"
            r"(?P<host>[^:/]+):(?P<port>\d+)\s*$",
            s,
        )
        if not m:
            return None
        scheme_raw = (m.group("sch") or "").lower()
        host = m.group("host") or ""
        port = m.group("port") or ""
        user = m.group("user") or ""
        pw = m.group("pw") or ""
    elif "@" in s and s.rfind("@") > 0:
        cred, hp = s.rsplit("@", 1)
        if ":" in cred:
            user, pw = cred.split(":", 1)
        if ":" in hp:
            host, port = hp.rsplit(":", 1)
    else:
        parts = s.split(":")
        # host:port:user:pass  （user 里可能含 -region-XX，不含额外冒号）
        if len(parts) >= 4 and parts[1].isdigit():
            host, port = parts[0], parts[1]
            user = parts[2]
            pw = ":".join(parts[3:])
        elif len(parts) == 2 and parts[1].isdigit():
            host, port = parts[0], parts[1]
        else:
            return None
    if not host or not port:
        return None
    scheme = _default_pool_scheme(host, scheme_raw)
    meta = _guess_region_meta(user, host)
    tag = meta["tag"]
    if "1024" in host.lower():
        if "1024" not in tag:
            tag = f"{tag}-1024"
    return {
        "tag": f"{tag}#{idx + 1}" if idx else tag,
        "host": host,
        "port": str(port),
        "user": user,
        "pass": pw,
        "locale": meta["locale"],
        "timezone": meta["timezone"],
        "fp_os": meta["fp_os"],
        "scheme": scheme,
        "session_rotate": bool(user) and _PROXY_SESSION_ROTATE,
        "raw": s,
    }


def _fp_only_bases(mode_tag: str = "system") -> tuple[list[dict[str, Any]], str]:
    """只轮指纹区；出口交给系统代理 / 本机显式口。"""
    ents: list[dict[str, Any]] = []
    for fr in FP_REGIONS:
        ent = dict(fr)
        ent["session_rotate"] = False
        ents.append(ent)
    if mode_tag == "local":
        return ents, f"local({_LOCAL_PROXY_RAW})"
    return ents, "system"


def _load_proxy_pool_lines() -> list[str]:
    """
    远程代理池（仅 STANDALONE_USE_1024=1 或显式 POOL/FILE 时用）：
      1) STANDALONE_PROXY_POOL
      2) STANDALONE_PROXY_FILE
      3) 内置 _DEFAULT_1024_POOL
    """
    raw = (os.environ.get("STANDALONE_PROXY_POOL") or "").strip()
    if raw:
        parts = re.split(r"[\n\r|;]+", raw)
        return [p.strip() for p in parts if p.strip() and not p.strip().startswith("#")]
    fpath = (os.environ.get("STANDALONE_PROXY_FILE") or "").strip()
    if fpath:
        p = Path(fpath)
        if not p.is_absolute():
            p = BASE / p
        if p.is_file():
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
                return [
                    ln.strip()
                    for ln in text.splitlines()
                    if ln.strip() and not ln.strip().startswith("#")
                ]
            except Exception:
                pass
    return list(_DEFAULT_1024_POOL)


def _build_base_proxies() -> tuple[list[dict[str, Any]], str]:
    # 优先级：cliproxy > 1024池 > NO_PROXY > 默认本机 7897（电脑代理）
    if _USE_CLIPROXY:
        return list(CLIPROXY_BASES), "cliproxy"
    if _USE_1024:
        lines = _load_proxy_pool_lines()
        ents: list[dict[str, Any]] = []
        for i, ln in enumerate(lines):
            ent = _parse_proxy_line(ln, i)
            if ent:
                ents.append(ent)
        if ents:
            tags = ",".join(e.get("tag") or "?" for e in ents[:4])
            extra = f"+{len(ents) - 4}" if len(ents) > 4 else ""
            return ents, f"pool({len(ents)}:{tags}{extra})"
        return _fp_only_bases("local")
    if _NO_PROXY:
        return _fp_only_bases("system")
    return _fp_only_bases("local")


BASE_PROXIES, _PROXY_MODE = _build_base_proxies()

FP_OS_POOL = ["windows", "macos"]
# 默认 rotate 打散时序（压工厂感）；STANDALONE_TIMING=turbo 可回极限
_TIMING_ENV = (os.environ.get("STANDALONE_TIMING") or "rotate").strip().lower()
if _TIMING_ENV in ("rotate", "random", "rand", "mix", ""):
    # 加权：略抬 fast/normal，少纯 turbo 连发
    TIMING_POOL = ["turbo", "fast", "normal", "human"]
    TIMING_WEIGHTS = [28, 38, 24, 10]
elif _TIMING_ENV in ("turbo", "fast", "normal", "human", "slow"):
    TIMING_POOL = [_TIMING_ENV]
    TIMING_WEIGHTS = [1]
else:
    TIMING_POOL = ["turbo", "fast", "normal"]
    TIMING_WEIGHTS = [30, 40, 30]

# 近期指纹签名去重，避免同批连号撞同一 locale/OS/时区/时序
_RECENT_FP_LOCK = threading.Lock()
_RECENT_FP_SIGS: list[str] = []
_RECENT_FP_MAX = 24


def log(msg: str, level: str = "info") -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] [{level}] {msg}"
    # 控制台：优先 binary UTF-8，避免 PS5 Tee-Object / 管道按系统 ANSI 二次解码花字
    try:
        sys.stdout.buffer.write((line + "\n").encode("utf-8", errors="replace"))
        sys.stdout.buffer.flush()
    except Exception:
        try:
            print(line, flush=True)
        except Exception:
            pass
    # 双写 UTF-8 文件（无 BOM）——以这个为准读日志
    # 读法：python -c "print(open(r'logs/standalone_live.log',encoding='utf-8').read())"
    #      或 Get-Content -Encoding utf8 logs\standalone_live.log
    # 注意：别用 Tee-Object 接管道（PS5 会把 stderr/警告当 NativeCommandError 再乱码）
    try:
        with open(_LIVE_LOG_PATH, "a", encoding="utf-8", errors="replace", newline="\n") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _normalize_local_proxy(raw: str) -> str:
    """本机代理统一成 host:port 或 http://host:port（无 user）。"""
    s = (raw or "").strip()
    if not s:
        return "127.0.0.1:7897"
    if "://" in s:
        return s
    # host:port
    return s


def _with_session_user(user: str, idx: int) -> str:
    """
    1024 / cliproxy 类：user-session-xxx 换粘性出口。
    已带 -session- 则不重复追加。
    """
    u = (user or "").strip()
    if not u:
        return u
    if re.search(r"-session-", u, re.I):
        return u
    sess = f"s{idx:02d}{uuid.uuid4().hex[:10]}"
    return f"{u}-session-{sess}"


def proxy_spec(base: dict[str, Any], idx: int) -> str:
    """
    拼代理 spec。
      默认：127.0.0.1:7897（电脑 Clash mixed）
      1024/池：socks5h://user:pass@host:port
      NO_PROXY："" 
    """
    if base.get("host") and base.get("user"):
        user = str(base.get("user") or "")
        do_sess = bool(base.get("session_rotate", _PROXY_SESSION_ROTATE))
        if do_sess:
            user = _with_session_user(user, idx)
        pw = str(base.get("pass") or "")
        host = str(base.get("host") or "")
        port = str(base.get("port") or "")
        scheme = _default_pool_scheme(host, str(base.get("scheme") or ""))
        return f"{scheme}://{user}:{pw}@{host}:{port}"
    if _NO_PROXY:
        return ""
    # 默认电脑代理口 7897
    return _normalize_local_proxy(_LOCAL_PROXY_RAW)


def proxy_url(spec: str) -> str:
    """给 curl_cffi / 环境变量用的完整代理 URL；空 spec → 空串（直连）。"""
    if not (spec or "").strip():
        return ""
    p = parse_proxy_spec(spec) or {}
    if p.get("server_url"):
        su = p["server_url"]
        if "://:@" in su:
            su = su.replace("://:@", "://", 1)
        return su
    server = p.get("server") or ""
    user = p.get("username") or ""
    pw = p.get("password") or ""
    scheme = (p.get("scheme") or "http").lower()
    if "://" in server:
        scheme = server.split("://", 1)[0].lower() or scheme
        hostport = server.split("://", 1)[-1]
    else:
        hostport = server
    if user:
        return f"{scheme}://{quote(user, safe='')}:{quote(pw, safe='')}@{hostport}"
    return f"{scheme}://{hostport}" if hostport and "://" not in hostport else server


def _fp_sig(fp: dict[str, Any], region_tag: str = "") -> str:
    scr = fp.get("screen") or {}
    return "|".join(
        [
            str(region_tag or ""),
            str(fp.get("fp_os") or ""),
            str(fp.get("timezone") or ""),
            str(fp.get("locale") or ""),
            str(fp.get("timing") or ""),
            str(fp.get("webgl_renderer") or "")[:40],
            f"{scr.get('width')}x{scr.get('height')}",
            str(fp.get("hardware_concurrency") or ""),
            str(fp.get("device_pixel_ratio") or ""),
        ]
    )


def _region_family(tag_or_user: str) -> str:
    """粗分国家簇，避免 JP 出口配 AU locale（IP/时区错配）。"""
    b = (tag_or_user or "").lower().replace("_", " ").replace("-", " ")
    if "jp" in b or "tokyo" in b or "osaka" in b or "japan" in b:
        return "jp"
    if "au" in b or "sydney" in b or "melbourne" in b or "australia" in b:
        return "au"
    if (
        " us" in f" {b}"
        or b.startswith("us")
        or "los angeles" in b
        or "new york" in b
        or "america/" in b
        or "united states" in b
    ):
        return "us"
    if "kr" in b or "seoul" in b or "korea" in b:
        return "kr"
    if "sg" in b or "singapore" in b:
        return "sg"
    if "tw" in b or "taipei" in b or "taiwan" in b:
        return "tw"
    if "my" in b or "kuala" in b or "malaysia" in b:
        return "my"
    if "hk" in b or "hong kong" in b or "hongkong" in b:
        return "hk"
    if "gb" in b or "london" in b or "uk" in b or "britain" in b:
        return "gb"
    return ""


# ISO / 常见时区 → 国家簇（local 出口探测用）
_CC_FAMILY: dict[str, str] = {
    "JP": "jp",
    "AU": "au",
    "US": "us",
    "KR": "kr",
    "SG": "sg",
    "TW": "tw",
    "MY": "my",
    "HK": "hk",
    "GB": "gb",
    "UK": "gb",
}
_TZ_FAMILY: dict[str, str] = {
    "asia/tokyo": "jp",
    "asia/osaka": "jp",
    "australia/sydney": "au",
    "australia/melbourne": "au",
    "america/los_angeles": "us",
    "america/new_york": "us",
    "america/chicago": "us",
    "america/denver": "us",
    "asia/seoul": "kr",
    "asia/singapore": "sg",
    "asia/taipei": "tw",
    "asia/kuala_lumpur": "my",
    "asia/hong_kong": "hk",
    "europe/london": "gb",
}
# 探测不到池内条目时的兜底 locale/tz（按簇）
_FAMILY_DEFAULTS: dict[str, dict[str, str]] = {
    "jp": {"tag": "JP-LOCAL", "locale": "ja-JP", "timezone": "Asia/Tokyo"},
    "au": {"tag": "AU-LOCAL", "locale": "en-AU", "timezone": "Australia/Sydney"},
    "us": {"tag": "US-LOCAL", "locale": "en-US", "timezone": "America/Los_Angeles"},
    "kr": {"tag": "KR-LOCAL", "locale": "ko-KR", "timezone": "Asia/Seoul"},
    "sg": {"tag": "SG-LOCAL", "locale": "en-SG", "timezone": "Asia/Singapore"},
    "tw": {"tag": "TW-LOCAL", "locale": "zh-TW", "timezone": "Asia/Taipei"},
    "my": {"tag": "MY-LOCAL", "locale": "en-MY", "timezone": "Asia/Kuala_Lumpur"},
    "hk": {"tag": "HK-LOCAL", "locale": "zh-HK", "timezone": "Asia/Hong_Kong"},
    "gb": {"tag": "GB-LOCAL", "locale": "en-GB", "timezone": "Europe/London"},
}

# local 出口探测缓存（批内复用；Clash 切节点后可 STANDALONE_EGRESS_REFRESH=1 强刷）
_LOCAL_EGRESS_LOCK = threading.Lock()
_LOCAL_EGRESS: Optional[dict[str, Any]] = None


def _proxy_url_for_probe(raw: str = "") -> str:
    """本机/系统探测用的 http(s) 代理 URL。"""
    s = _normalize_local_proxy(raw or _LOCAL_PROXY_RAW)
    if not s:
        return ""
    if "://" not in s:
        s = f"http://{s}"
    return s


def _family_from_egress(cc: str = "", tz: str = "", city: str = "") -> str:
    cc_u = (cc or "").strip().upper()
    if cc_u in _CC_FAMILY:
        return _CC_FAMILY[cc_u]
    tz_l = (tz or "").strip().lower()
    if tz_l in _TZ_FAMILY:
        return _TZ_FAMILY[tz_l]
    # 模糊：时区前缀 / 城市名
    fam = _region_family(f"{cc} {tz} {city}")
    return fam


def detect_local_egress(force: bool = False, log_fn: Any = None) -> dict[str, Any]:
    """
    经本机代理（默认 7897）探测真实出口 IP/国家/时区。
    结果缓存批内复用；local 指纹只在同国家簇内轮，不再全球乱跳。
    覆盖：STANDALONE_EGRESS_CC / STANDALONE_EGRESS_TZ 可手填跳过探测。
    """
    global _LOCAL_EGRESS
    with _LOCAL_EGRESS_LOCK:
        if _LOCAL_EGRESS is not None and not force:
            return dict(_LOCAL_EGRESS)

    # 环境强制（调试/已知节点）
    env_cc = (os.environ.get("STANDALONE_EGRESS_CC") or "").strip().upper()
    env_tz = (os.environ.get("STANDALONE_EGRESS_TZ") or "").strip()
    env_ip = (os.environ.get("STANDALONE_EGRESS_IP") or "").strip()
    if env_cc or env_tz:
        fam = _family_from_egress(env_cc, env_tz, "")
        info = {
            "ok": True,
            "source": "env",
            "ip": env_ip or "?",
            "cc": env_cc,
            "country": env_cc,
            "city": "",
            "timezone": env_tz
            or (_FAMILY_DEFAULTS.get(fam) or {}).get("timezone", ""),
            "family": fam,
            "proxy": _LOCAL_PROXY_RAW,
        }
        with _LOCAL_EGRESS_LOCK:
            _LOCAL_EGRESS = dict(info)
        return info

    proxy = _proxy_url_for_probe()
    proxies = {"http": proxy, "https": proxy} if proxy and not _NO_PROXY else None
    info: dict[str, Any] = {
        "ok": False,
        "source": "",
        "ip": "",
        "cc": "",
        "country": "",
        "city": "",
        "timezone": "",
        "family": "",
        "proxy": _LOCAL_PROXY_RAW if not _NO_PROXY else "(system/direct)",
        "error": "",
    }

    # 多源兜底：ip-api → ipapi.co → Cloudflare trace
    try:
        import urllib.request

        def _get(url: str, timeout: float = 8.0) -> str:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; egress-probe/1.0)"},
            )
            # 走代理：用 ProxyHandler
            if proxies:
                handler = urllib.request.ProxyHandler(proxies)
                opener = urllib.request.build_opener(handler)
            else:
                opener = urllib.request.build_opener()
            with opener.open(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")

        # 1) ip-api.com（免费，字段全）
        try:
            raw = _get("http://ip-api.com/json/?fields=status,message,country,countryCode,city,timezone,query")
            data = json.loads(raw)
            if str(data.get("status") or "").lower() == "success":
                info.update(
                    {
                        "ok": True,
                        "source": "ip-api",
                        "ip": str(data.get("query") or ""),
                        "cc": str(data.get("countryCode") or "").upper(),
                        "country": str(data.get("country") or ""),
                        "city": str(data.get("city") or ""),
                        "timezone": str(data.get("timezone") or ""),
                    }
                )
        except Exception as e1:
            info["error"] = f"ip-api:{e1}"[:120]

        # 2) ipapi.co
        if not info["ok"]:
            try:
                raw = _get("https://ipapi.co/json/")
                data = json.loads(raw)
                if data.get("ip") and not data.get("error"):
                    info.update(
                        {
                            "ok": True,
                            "source": "ipapi.co",
                            "ip": str(data.get("ip") or ""),
                            "cc": str(data.get("country_code") or data.get("country") or "").upper(),
                            "country": str(data.get("country_name") or ""),
                            "city": str(data.get("city") or ""),
                            "timezone": str(data.get("timezone") or ""),
                            "error": "",
                        }
                    )
            except Exception as e2:
                info["error"] = (info.get("error") or "") + f"|ipapi:{e2}"[:100]

        # 3) Cloudflare trace（至少拿到 IP；国家从 loc=）
        if not info["ok"]:
            try:
                raw = _get("https://www.cloudflare.com/cdn-cgi/trace")
                kv = {}
                for ln in raw.splitlines():
                    if "=" in ln:
                        k, v = ln.split("=", 1)
                        kv[k.strip()] = v.strip()
                if kv.get("ip") or kv.get("loc"):
                    info.update(
                        {
                            "ok": True,
                            "source": "cf-trace",
                            "ip": str(kv.get("ip") or ""),
                            "cc": str(kv.get("loc") or "").upper(),
                            "country": str(kv.get("loc") or ""),
                            "city": "",
                            "timezone": "",
                            "error": "",
                        }
                    )
            except Exception as e3:
                info["error"] = (info.get("error") or "") + f"|cf:{e3}"[:100]
    except Exception as e:
        info["error"] = str(e)[:160]

    if info.get("ok"):
        fam = _family_from_egress(
            str(info.get("cc") or ""),
            str(info.get("timezone") or ""),
            str(info.get("city") or ""),
        )
        # 有 cc 但池里没有：仍标 family 空，后面用探测 tz 合成
        info["family"] = fam
        # 探测到 tz 为空时，用族默认
        if not info.get("timezone") and fam and fam in _FAMILY_DEFAULTS:
            info["timezone"] = _FAMILY_DEFAULTS[fam]["timezone"]

    # 强刷探测失败时不要覆盖上一份成功缓存。否则会出现：
    #   启动探到 HK/TW → pick 阶段复探偶发失败 → eg.ok=False →
    #   local 指纹回退全球池，最终 HK 出口 mint JP/AU 画像。
    # 这会把 IP/locale/timezone 一致性打穿，增加 MARKED/deny。
    with _LOCAL_EGRESS_LOCK:
        prev_ok = dict(_LOCAL_EGRESS) if isinstance(_LOCAL_EGRESS, dict) and _LOCAL_EGRESS.get("ok") else None
        refresh_error = str(info.get("error") or "")
        if info.get("ok") or not prev_ok:
            _LOCAL_EGRESS = dict(info)
        else:
            info = dict(prev_ok)
            info["stale"] = True
            info["refresh_error"] = refresh_error

    if log_fn:
        try:
            if info.get("ok"):
                log_fn(
                    f"local出口 · {info.get('ip') or '?'} · "
                    f"{info.get('cc') or '?'} {info.get('city') or ''} · "
                    f"tz={info.get('timezone') or '?'} · "
                    f"family={info.get('family') or 'unknown'} · "
                    f"via {info.get('source')}",
                    "info",
                )
            else:
                log_fn(
                    f"local出口探测失败 · {info.get('error') or '?'} · "
                    "指纹将全球轮（可设 STANDALONE_EGRESS_CC/TZ）",
                    "warn",
                )
        except Exception:
            pass
    return info


def _fp_pool_for_family(fam: str, egress: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
    """同国家簇指纹池；无匹配则用探测 tz/locale 合成 win+mac 两条。"""
    fam = (fam or "").strip().lower()
    if fam:
        same = [
            fr
            for fr in FP_REGIONS
            if _region_family(f"{fr.get('tag') or ''} {fr.get('timezone') or ''}") == fam
        ]
        if same:
            return same
    # 合成：优先探测 tz + 族默认 locale
    eg = egress or {}
    base = dict(_FAMILY_DEFAULTS.get(fam) or {})
    tz = (eg.get("timezone") or base.get("timezone") or "America/Los_Angeles").strip()
    loc = (base.get("locale") or "en-US").strip()
    tag = base.get("tag") or f"EG-{(eg.get('cc') or 'XX')}"
    # 若有探测 tz 且能反推族，校正 locale
    if not fam and eg.get("timezone"):
        fam2 = _family_from_egress(str(eg.get("cc") or ""), str(eg.get("timezone") or ""), "")
        if fam2 and fam2 in _FAMILY_DEFAULTS:
            loc = _FAMILY_DEFAULTS[fam2]["locale"]
            tag = _FAMILY_DEFAULTS[fam2]["tag"]
    return [
        {"tag": tag, "locale": loc, "timezone": tz, "fp_os": "windows"},
        {"tag": f"{tag}-MAC", "locale": loc, "timezone": tz, "fp_os": "macos"},
    ]


def pick_rotating_proxy(idx: int) -> tuple[dict[str, Any], str]:
    """
    从 BASE_PROXIES 轮换：
      - 多条池：按序号取模
      - 单条 1024：同一账号模板，每号 -session- 换出口
      - 本机：出口固定 → 指纹只在同国家簇内轮（探测 7897 真实出口）
    有区域出口时：locale/tz 锁在同国家簇内轮（防 IP↔时区错配）。
    """
    n = len(BASE_PROXIES) or 1
    ent = dict(BASE_PROXIES[(idx - 1) % n])
    jump_p = 0.55
    try:
        jump_p = float(
            (
                os.environ.get("STANDALONE_FP_JUMP")
                or os.environ.get("GROK_SS_FP_JUMP_PROB")
                or "0.55"
            ).strip()
            or "0.55"
        )
    except ValueError:
        jump_p = 0.55
    jump_p = max(0.0, min(0.95, jump_p))

    if ent.get("host") and ent.get("user") and FP_REGIONS:
        # 区域代理：只在同国家簇内轮 OS/次要 tag，不跳到别国时区
        fam = _region_family(
            f"{ent.get('tag') or ''} {ent.get('user') or ''} {ent.get('locale') or ''}"
        )
        same = [
            fr
            for fr in FP_REGIONS
            if _region_family(f"{fr.get('tag') or ''} {fr.get('timezone') or ''}") == fam
        ] if fam else []
        pool = same or [
            {
                "tag": ent.get("tag"),
                "locale": ent.get("locale"),
                "timezone": ent.get("timezone"),
                "fp_os": ent.get("fp_os") or "windows",
            },
            {
                "tag": ent.get("tag"),
                "locale": ent.get("locale"),
                "timezone": ent.get("timezone"),
                "fp_os": "macos" if (ent.get("fp_os") or "") != "macos" else "windows",
            },
        ]
        if random.random() < jump_p:
            fr = random.choice(pool)
        else:
            fr = pool[(idx - 1) % len(pool)]
        ent = dict(ent)
        ent["locale"] = fr.get("locale") or ent.get("locale")
        ent["timezone"] = fr.get("timezone") or ent.get("timezone")
        ent["fp_os"] = fr.get("fp_os") or ent.get("fp_os")
        ent["fp_tag"] = fr.get("tag") or ent.get("tag")
    elif not ent.get("host"):
        # 本机 / 系统：探真实出口，指纹只在同簇内轮（禁止 JP 出口配 AU locale）
        # STANDALONE_EGRESS_EVERY=N：每 N 号强制复探（默认 3，防 Clash 负载均衡漂移）
        #   1=每号都探；0=仅缓存/首号；STANDALONE_EGRESS_REFRESH=1 等同每号强刷
        force_env = (os.environ.get("STANDALONE_EGRESS_REFRESH") or "").strip().lower() in (
            "1",
            "true",
            "yes",
            "on",
        )
        try:
            every_n = int(
                (os.environ.get("STANDALONE_EGRESS_EVERY") or "3").strip() or "3"
            )
        except ValueError:
            every_n = 3
        every_n = max(0, every_n)
        prev = dict(_LOCAL_EGRESS) if _LOCAL_EGRESS else {}
        do_force = bool(force_env) or (
            every_n > 0 and (idx <= 1 or (idx - 1) % every_n == 0)
        )
        # 漂移探测：复探时静默；变了再打日志
        eg = detect_local_egress(force=do_force, log_fn=None)
        if do_force and eg.get("ok") and prev.get("ok"):
            old_ip = str(prev.get("ip") or "")
            new_ip = str(eg.get("ip") or "")
            old_fam = str(prev.get("family") or "")
            new_fam = str(eg.get("family") or "")
            if old_ip and new_ip and old_ip != new_ip:
                log(
                    f"出口漂移 · {old_ip}({old_fam or '?'}) → {new_ip}({new_fam or '?'}) · "
                    f"指纹簇重锁 · idx={idx}",
                    "warn" if old_fam and new_fam and old_fam != new_fam else "info",
                )
            elif old_fam and new_fam and old_fam != new_fam:
                log(
                    f"出口国家簇变 · {old_fam} → {new_fam} · 指纹重锁 · idx={idx}",
                    "warn",
                )
        fam = str(eg.get("family") or "")
        # STANDALONE_LOCAL_ALIGN=0 可关对齐（回退全球轮，仅调试）
        align_off = (os.environ.get("STANDALONE_LOCAL_ALIGN") or "1").strip().lower() in (
            "0",
            "off",
            "false",
            "no",
        )
        if align_off or not eg.get("ok"):
            pool = list(FP_REGIONS)
        else:
            pool = _fp_pool_for_family(fam, eg)
        if not pool:
            pool = list(FP_REGIONS)
        if random.random() < jump_p:
            fr = random.choice(pool)
        else:
            fr = pool[(max(0, idx - 1)) % len(pool)]
        ent = dict(ent)
        # tag 带出口信息，方便账本/日志对照
        base_tag = fr.get("tag") or ent.get("tag") or "LOCAL"
        cc = str(eg.get("cc") or "").upper()
        if eg.get("ok") and cc and cc not in str(base_tag).upper():
            ent["tag"] = f"{base_tag}@{cc}"
        else:
            ent["tag"] = base_tag
        ent["locale"] = fr.get("locale")
        ent["timezone"] = fr.get("timezone")
        ent["fp_os"] = fr.get("fp_os")
        ent["fp_tag"] = fr.get("tag") or base_tag
        ent["egress_ip"] = eg.get("ip") or ""
        ent["egress_cc"] = eg.get("cc") or ""
        ent["egress_family"] = fam
        ent["egress_city"] = eg.get("city") or ""
        ent["egress_tz"] = eg.get("timezone") or ""
    pspec = proxy_spec(ent, idx)
    return ent, pspec


def pick_fp(region: dict[str, Any], idx: int) -> dict[str, Any]:
    """
    打散 OS / 时序 / 分辨率 / humanize / 设备上下文（WebGL·屏幕·CPU…）；
    近期签名去重。
    STANDALONE_FP_OS=windows|macos 可锁 OS；STANDALONE_HUMANIZE=0/1 可强制。
    """
    from g.same_session_register import build_device_fingerprint

    os_env = (
        os.environ.get("STANDALONE_FP_OS") or os.environ.get("GROK_SS_FP_OS") or ""
    ).strip().lower()
    hum_raw = (
        os.environ.get("STANDALONE_HUMANIZE")
        or os.environ.get("GROK_SAME_SESSION_HUMANIZE")
        or ""
    ).strip().lower()

    def _one() -> dict[str, Any]:
        if os_env in ("win", "windows"):
            fp_os = "windows"
        elif os_env in ("mac", "macos", "osx"):
            fp_os = "macos"
        else:
            pref = str(region.get("fp_os") or "windows").lower()
            if pref not in FP_OS_POOL:
                pref = "windows"
            # 60% 池内随机，打散 OS
            fp_os = random.choice(FP_OS_POOL) if random.random() < 0.60 else pref

        if len(TIMING_POOL) == 1:
            timing = TIMING_POOL[0]
        else:
            timing = random.choices(TIMING_POOL, weights=TIMING_WEIGHTS, k=1)[0]

        if hum_raw in ("1", "true", "yes", "on"):
            humanize = True
        elif hum_raw in ("0", "false", "no", "off"):
            humanize = False
        else:
            # 默认：turbo/fast 少开轨迹，normal/human 多开
            if timing in ("turbo", "fast"):
                humanize = random.random() < 0.30
            elif timing == "human":
                humanize = True
            else:
                humanize = random.random() < 0.70

        # 富设备上下文：screen / webgl / hw / media / dpr（一号一套）
        device = build_device_fingerprint(fp_os)
        return {
            "fp_os": fp_os,
            "locale": region.get("locale") or "en-US",
            "timezone": region.get("timezone") or "America/Los_Angeles",
            "timing": timing,
            "viewport": dict(device.get("viewport") or {"width": 1440, "height": 900}),
            "humanize": humanize,
            # 下面整包塞进 same_session_register(device_fp=…)
            "device_fp": device,
            "screen": device.get("screen"),
            "webgl_vendor": device.get("webgl_vendor"),
            "webgl_renderer": device.get("webgl_renderer"),
            "hardware_concurrency": device.get("hardware_concurrency"),
            "device_memory_gb": device.get("device_memory_gb"),
            "device_pixel_ratio": device.get("device_pixel_ratio"),
        }

    region_tag = str(
        region.get("fp_tag") or region.get("tag") or region.get("region") or ""
    )
    fp: dict[str, Any] = {}
    for _try in range(8):
        fp = _one()
        sig = _fp_sig(fp, region_tag)
        with _RECENT_FP_LOCK:
            if sig not in _RECENT_FP_SIGS or _try >= 6:
                _RECENT_FP_SIGS.append(sig)
                if len(_RECENT_FP_SIGS) > _RECENT_FP_MAX:
                    del _RECENT_FP_SIGS[: len(_RECENT_FP_SIGS) - _RECENT_FP_MAX]
                break
    return fp


def rand_name() -> str:
    return random.choice(
        ["James", "Emma", "Liam", "Olivia", "Noah", "Ava", "Lucas", "Mia", "Ethan", "Sophia"]
    )


def rand_password(n: int = 14) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%"
    return "".join(random.choice(chars) for _ in range(n))


def ensure_solver() -> None:
    st = solver_manager.status(force=True)
    if st.get("ready"):
        log(f"Solver 在线 pid={st.get('pid')}", "success")
        return
    log("Solver 未就绪，启动中…", "info")
    r = solver_manager.ensure_ready(timeout=120.0)
    if not r.get("ok") or not r.get("ready"):
        raise RuntimeError(f"Solver 失败: {r.get('message')}")
    log(f"Solver 就绪 pid={r.get('pid')}", "success")


def probe_risk(sso: str, sso_rw: str, proxy_spec_str: str, impersonate: str = "chrome131") -> dict[str, Any]:
    if AntibotService is None:
        return {"clean": None, "error": "AntibotService missing", "summary": "NO_PROBE"}
    url = proxy_url(proxy_spec_str)
    # 只清业务代理键；系统 HTTP_PROXY（Clash 等）保留，跟电脑出口
    for k in ("GROK_PROXY", "XAI_PROXY", "SAME_SESSION_PROXY"):
        os.environ.pop(k, None)
    if url:
        # 显式池/本机：risk 跟同一出口
        os.environ["GROK_PROXY"] = url
        os.environ["XAI_PROXY"] = url
    ab = AntibotService()
    risk = ab.probe_account_risk(sso, sso_rw=sso_rw or sso, impersonate=impersonate, timeout=20)
    # 可换 token 口径：无 deny、无 botFlag 坏信号（HIGH 无 botFlag 也算 clean）
    clean = AntibotService.is_risk_clean(risk)
    summary = AntibotService.risk_mark_summary(risk)
    return {
        "clean": clean,
        "importable": clean,
        "denied": bool(risk.get("denied")),
        "false_clean": bool(risk.get("false_clean")),
        "cli_usable": risk.get("cli_usable"),
        "risk_score": risk.get("risk_score"),
        "risk_level": risk.get("risk_level"),
        "bot_flag_source": risk.get("bot_flag_source"),
        "bot_flag_details": risk.get("bot_flag_details"),
        "policy": risk.get("policy"),
        "event": risk.get("event"),
        "user_id": risk.get("user_id"),
        "error": risk.get("error"),
        "summary": summary,
        "acl_strings": risk.get("acl_strings"),
        "signals": risk.get("signals"),
    }


def finalize_risk_row(row: dict[str, Any], out_file: Path, wait_s: float = 25.0) -> dict[str, Any]:
    """
    收齐异步 risk，落盘 CLEAN/MARKED。
    主路径 elapsed_s 保持为注册耗时；另记 elapsed_with_risk_s。
    """
    if not row.get("risk_pending"):
        return row
    holder = row.get("_risk_holder") or {}
    done_ev = holder.get("done")
    t_wait0 = time.time()
    if done_ev is not None and not done_ev.is_set():
        done_ev.wait(timeout=max(1.0, float(wait_s)))
    risk = holder.get("risk")
    if risk is None:
        risk = {
            "clean": False,
            "importable": False,
            "summary": "RISK_TIMEOUT",
            "error": "risk async timeout",
        }
    row["risk_wait_s"] = round(time.time() - t_wait0, 2)
    row["risk"] = risk
    row["clean"] = bool(risk.get("clean"))
    row["importable"] = bool(risk.get("importable", risk.get("clean")))
    row["risk_pending"] = False
    email = row.get("email") or ""
    sso = row.get("sso_token") or ""
    summary = risk.get("summary") or "?"
    log(
        f"risk · {summary}",
        "success" if risk.get("clean") else "warn",
    )
    if row["clean"] and email and sso:
        clean_path = out_file.with_name(out_file.stem + "_clean.txt")
        with open(clean_path, "a", encoding="utf-8") as f:
            f.write(f"{email}----{sso}\n")
        row["ok"] = True
        log("CLEAN 落盘", "success")
        try:
            record_clean_success(
                row,
                mail_domain=MAIL_DOMAIN,
                proxy_mode=_PROXY_MODE,
                batch_id=_BATCH_ID or out_file.stem,
                log=log,
            )
        except Exception:
            pass
    elif email and sso:
        row["ok"] = False
        row["error"] = risk.get("summary") or "MARKED"
        marked_path = out_file.with_name(out_file.stem + "_marked.txt")
        with open(marked_path, "a", encoding="utf-8") as f:
            f.write(f"{email}----{sso}\n")
        meta_path = out_file.with_name(out_file.stem + "_marked_meta.txt")
        with open(meta_path, "a", encoding="utf-8") as f:
            f.write(f"{email}\t{risk.get('summary')}\n")
        log("MARKED · deny/botFlag，不计入 CLEAN", "warn")
        try:
            record_marked(
                row,
                mail_domain=MAIL_DOMAIN,
                proxy_mode=_PROXY_MODE,
                batch_id=_BATCH_ID or out_file.stem,
                log=log,
            )
        except Exception:
            pass
    # 清理不可序列化字段
    row.pop("_risk_holder", None)
    reg = float(row.get("elapsed_reg_s") or row.get("elapsed_s") or 0)
    row["elapsed_with_risk_s"] = round(reg + float(row.get("risk_wait_s") or 0), 2)
    # 默认报告用注册耗时
    row["elapsed_s"] = reg
    detail = row.get("_detail_path")
    if detail:
        try:
            p = Path(detail)
            if p.is_file():
                data = json.loads(p.read_text(encoding="utf-8"))
                data["risk"] = risk
                data["risk_pending"] = False
                data["clean"] = row.get("clean")
                data["elapsed_with_risk_s"] = row.get("elapsed_with_risk_s")
                p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass
    row.pop("_detail_path", None)
    return row


def _is_same_email_retryable(err: str) -> bool:
    """
    同邮箱可再跑整段注册的瞬时失败（默认最多再试 2 次）。
    命中：signup 500 / 无 set-cookie / RSC digest / 网络断流。
    不命中：验证码废、邮箱重复、camoufox 启动、建邮失败等。
    """
    e = (err or "").strip().lower()
    if not e:
        return False
    # 硬业务：别用同邮空转
    hard = (
        "duplicate",
        "email already",
        "already registered",
        "already exists",
        "email validation code invalid",
        "invalid-validation",
        "create_email",
        "禁止 xyz",
        "no webgl data",  # 配置问题，重跑也炸
    )
    if any(h in e for h in hard):
        return False
    soft = (
        "signup 500",
        "无 set-cookie",
        "no set-cookie",
        "digest=",
        '"digest"',
        "failed to fetch",
        "networkerror",
        "signup fetch err",
        "net::",
        "timeout",
        "target closed",
        "targetclosed",
        "browser has been closed",
        "signup:500",
    )
    return any(s in e for s in soft)


def _same_email_retry_n() -> int:
    """
    同邮箱额外重试次数（不含首次）。
    默认 2 → 总共最多 3 次整段 same_session。
    STANDALONE_SAME_EMAIL_RETRY=0 关闭；最大 5。
    """
    raw = (os.environ.get("STANDALONE_SAME_EMAIL_RETRY") or "2").strip().lower()
    if raw in ("0", "off", "false", "no", "none"):
        return 0
    try:
        return max(0, min(5, int(raw)))
    except ValueError:
        return 2


def run_one(idx: int, email_svc: EmailService, ts_svc: TurnstileService, out_file: Path) -> dict[str, Any]:
    region, pspec = pick_rotating_proxy(idx)
    fp = pick_fp(region, idx)
    # 仅当显式锁 OS 时覆盖（pick_fp 已处理 STANDALONE_FP_OS）
    password = rand_password()
    given, family = rand_name(), rand_name()
    proxy_tag = region.get("fp_tag") or region.get("tag") or region.get("region") or "?"
    # 日志：空 = NO_PROXY；默认应是 127.0.0.1:7897
    pspec_show = (pspec or "").strip() or "no-proxy"
    try:
        if "://" in pspec_show and "@" in pspec_show:
            sch, rest = pspec_show.split("://", 1)
            cred, hp = rest.rsplit("@", 1)
            u = cred.split(":", 1)[0]
            u_show = u if len(u) <= 40 else (u[:18] + "…" + u[-14:])
            pspec_show = f"{sch}://{u_show}:***@{hp}"
        elif pspec_show.count(":") >= 3:
            parts = pspec_show.split(":")
            if len(parts) >= 4 and parts[1].isdigit():
                u = parts[2]
                u_show = u if len(u) <= 36 else (u[:20] + "…" + u[-12:])
                pspec_show = f"{parts[0]}:{parts[1]}:{u_show}:***"
    except Exception:
        pass
    _gpu = str(fp.get("webgl_renderer") or "")[:32]
    _scr = fp.get("screen") or {}
    _vp = fp.get("viewport") or {}
    _eg = ""
    if region.get("egress_ip") or region.get("egress_cc"):
        _eg = (
            f" · egress={region.get('egress_ip') or '?'}:"
            f"{region.get('egress_cc') or '?'}"
            f"/{region.get('egress_family') or '?'}"
        )
    log(
        f"[{idx}/{COUNT}] {proxy_tag} · {fp.get('locale')}/{fp.get('timezone')} · "
        f"{fp.get('fp_os')} · {fp.get('timing')} · "
        f"hum={1 if fp.get('humanize') else 0} · "
        f"vp={_vp.get('width')}x{_vp.get('height')} · "
        f"scr={_scr.get('width')}x{_scr.get('height')} · "
        f"dpr={fp.get('device_pixel_ratio')} · hw={fp.get('hardware_concurrency')} · "
        f"gpu={_gpu}{_eg} · {pspec_show}",
        "info",
    )

    row: dict[str, Any] = {
        "idx": idx,
        "region": region.get("tag") or region.get("region") or "?",
        "email": "",
        "fp": fp,
        "ok": False,
        "sso": False,
        "clean": False,
        "elapsed_s": 0.0,
        "elapsed_reg_s": 0.0,
        "error": "",
        "castle_len": 0,
        "castle_method": "",
        "risk": None,
        "risk_pending": False,
        # 出口快照 → 账本按 egress IP 算 CLEAN 率
        "egress_ip": region.get("egress_ip") or "",
        "egress_cc": region.get("egress_cc") or "",
        "egress_family": region.get("egress_family") or "",
        "proxy_spec": pspec or "",
    }
    # fp 里也挂一份，ledger 兜底能读到
    if isinstance(row.get("fp"), dict):
        row["fp"] = dict(row["fp"])
        row["fp"]["egress_ip"] = row["egress_ip"]
        row["fp"]["egress_cc"] = row["egress_cc"]
        row["fp"]["egress_family"] = row["egress_family"]
    t0 = time.time()
    email = ""
    try:
        if not (ts_svc.yescaptcha_key or "").strip():
            ts_svc._ensure_local_solver()

        # Turnstile 超早并行：与建邮 + camoufox 启动 + 页面/castle/发码全重叠
        # sitekey 固定已知，不必等页面解析
        ts_pre: dict[str, Any] = {
            "token": None,
            "error": None,
            "t0": time.time(),
            "done": threading.Event(),
            "used": False,
        }

        def _ts_prewarm() -> None:
            try:
                task_id = ts_svc.create_task(SITE_URL, SITE_KEY)
                tok = ts_svc.get_response(task_id)
                ts_pre["token"] = tok
                if not tok or tok == "CAPTCHA_FAIL":
                    ts_pre["error"] = ts_svc.last_error or "empty/CAPTCHA_FAIL"
            except Exception as e:
                ts_pre["error"] = str(e)
            finally:
                ts_pre["done"].set()

        threading.Thread(
            target=_ts_prewarm, daemon=True, name=f"ts-prewarm-{idx}"
        ).start()
        log("Turnstile 预解启动（与建邮/浏览器重叠）", "info")

        jwt, email = email_svc.create_email()
        row["email"] = email or ""
        if not email:
            row["error"] = "create_email failed"
            row["elapsed_s"] = round(time.time() - t0, 2)
            return row
        if "xyz" in email.lower():
            raise RuntimeError(f"禁止 xyz: {email}")
        email_meta = email_svc.get_email_metadata(email)
        row["email_provider"] = email_meta.get("email_provider") or email_svc.provider_name
        row["domain"] = email_meta.get("email_domain") or email.rsplit("@", 1)[-1]
        if MAIL_DOMAIN and not email.endswith("@" + MAIL_DOMAIN):
            log(f"邮箱后缀非预期: {email}（期望 @{MAIL_DOMAIN}）", "warn")
        log(f"注册 {email}", "info")

        def fetch_code(em: str):
            return email_svc.fetch_verification_code(em)

        def solve_ts(site_key: str):
            # 优先吃预解结果（与浏览器启动重叠后通常已好或只差几秒）
            if not ts_pre["done"].is_set():
                remain = max(1.0, 90.0 - (time.time() - float(ts_pre["t0"])))
                ts_pre["done"].wait(timeout=remain)
            tok = ts_pre.get("token")
            if tok and tok != "CAPTCHA_FAIL" and not ts_pre["used"]:
                ts_pre["used"] = True
                elapsed = round(time.time() - float(ts_pre["t0"]), 1)
                log(f"Turnstile 预解命中 · 墙钟 {elapsed}s", "success")
                return tok
            # 预解失败或已被用：同步补解
            sk = site_key or SITE_KEY
            task_id = ts_svc.create_task(SITE_URL, sk)
            return ts_svc.get_response(task_id)

        # 空 pspec = 系统出口；显式 None 避免 same_session 再去读 GROK_PROXY
        _proxy_arg: Optional[str] = (pspec or "").strip() or None
        # 同邮箱整段重试：signup 500 / 无 set-cookie 等瞬时错，不换邮再跑
        # 默认额外 2 次（共 3 次）；STANDALONE_SAME_EMAIL_RETRY 可调
        max_extra = _same_email_retry_n()
        max_attempts = 1 + max_extra
        ss: dict[str, Any] = {}
        attempt_errors: list[str] = []
        for attempt in range(1, max_attempts + 1):
            # 首次可用预解 token；重试必须重新解（旧 token 已消耗/过期）
            pre_token = None
            if attempt == 1 and ts_pre["done"].is_set():
                t = ts_pre.get("token")
                if t and t != "CAPTCHA_FAIL" and not ts_pre["used"]:
                    pre_token = t
                    ts_pre["used"] = True
                    log(
                        f"Turnstile 预解已就绪 · "
                        f"{round(time.time()-float(ts_pre['t0']),1)}s",
                        "success",
                    )
            if attempt > 1:
                # 丢弃预解，强制 solve_ts 同步新解
                ts_pre["used"] = True
                ts_pre["token"] = None
                try:
                    # 冷启浏览器池，避免上一轮 TargetClosed / 脏 context
                    shutdown_camoufox_pool()
                except Exception:
                    pass
                gap = 1.2 + (attempt - 1) * 0.8
                log(
                    f"同邮箱重试 {attempt - 1}/{max_extra} · {email} · "
                    f"原因: {(attempt_errors[-1] if attempt_errors else '?')[:100]} · "
                    f"冷却 {gap:.1f}s",
                    "warn",
                )
                time.sleep(gap)

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
                proxy=_proxy_arg,
                locale=fp["locale"],
                timezone_id=fp["timezone"],
                fp_os=fp["fp_os"],
                timing=fp["timing"],
                viewport=fp["viewport"],
                humanize=fp.get("humanize", True),
                device_fp=fp.get("device_fp") or fp,
                log=log,
            )
            if ss.get("ok") and ss.get("sso"):
                if attempt > 1:
                    log(
                        f"同邮箱重试成功 · 第 {attempt}/{max_attempts} 次 · {email}",
                        "success",
                    )
                break
            err_s = str(ss.get("error") or "same_session failed")
            attempt_errors.append(err_s)
            can_retry = (
                attempt < max_attempts
                and _is_same_email_retryable(err_s)
            )
            if can_retry:
                log(
                    f"瞬时失败可同邮重试 · {email} · try {attempt}/{max_attempts} · "
                    f"{err_s[:140]}",
                    "warn",
                )
                continue
            # 不可重试或次数用尽
            break

        row["castle_len"] = ss.get("castle_len") or 0
        row["castle_method"] = ss.get("castle_method") or ""
        row["steps"] = ss.get("steps")
        row["reg_attempts"] = len(attempt_errors) + (1 if ss.get("ok") else 0)
        if attempt_errors:
            row["reg_attempt_errors"] = attempt_errors[:6]
        # 注册回写的真实设备指纹（与 Camoufox 启动一致）
        if ss.get("device_fp"):
            row["device_fp"] = ss.get("device_fp")
            # 同步进 fp，账本/报告一份齐全
            if isinstance(row.get("fp"), dict):
                row["fp"] = dict(row["fp"])
                row["fp"]["device_fp"] = ss.get("device_fp")
                for _k in (
                    "webgl_vendor",
                    "webgl_renderer",
                    "hardware_concurrency",
                    "device_memory_gb",
                    "device_pixel_ratio",
                    "screen",
                    "viewport",
                ):
                    if ss["device_fp"].get(_k) is not None:
                        row["fp"][_k] = ss["device_fp"].get(_k)
        if ss.get("viewport"):
            row.setdefault("fp", {})
            if isinstance(row["fp"], dict):
                row["fp"]["viewport"] = ss.get("viewport")
        if not ss.get("ok"):
            row["error"] = ss.get("error") or "same_session failed"
            if attempt_errors and len(attempt_errors) > 1:
                row["error"] = (
                    f"{row['error']} · 同邮已重试{len(attempt_errors)-1}次仍失败"
                )
            log(f"失败 {email} · {row['error']}", "error")
            try:
                email_svc.delete_email(email)
            except Exception:
                pass
            row["elapsed_s"] = round(time.time() - t0, 2)
            return row

        sso = ss.get("sso") or ""
        sso_rw = ss.get("sso_rw") or sso
        row["sso"] = True
        row["sso_token"] = sso
        row["sso_rw"] = sso_rw
        row["proxy_spec"] = pspec
        # 注册主路径计时：不含 risk（risk 后置，可与下一号重叠）
        row["elapsed_reg_s"] = round(time.time() - t0, 2)
        row["browser_from_pool"] = bool(ss.get("browser_from_pool"))
        row["browser_launch_s"] = ss.get("browser_launch_s")
        log(
            f"SSO ok · castle={row['castle_len']} · {row['castle_method']} · "
            f"reg={row['elapsed_reg_s']}s"
            + (f" · pool" if row["browser_from_pool"] else ""),
            "success",
        )

        keys = BASE / "keys"
        keys.mkdir(exist_ok=True)
        with open(keys / "emergency_sso.txt", "a", encoding="utf-8") as f:
            f.write(f"{email}----{sso}\n")
        with open(out_file, "a", encoding="utf-8") as f:
            f.write(sso + "\n")

        # risk 默认同步：同一线程里做完再下一号，避免异步 risk 与 Camoufox/Playwright
        # 抢 asyncio loop（曾出现 ProactorEventLoop is not the running loop）。
        # 若确需异步重叠：GROK_RISK_ASYNC=1
        risk_async = (os.environ.get("GROK_RISK_ASYNC") or "").strip().lower() in (
            "1",
            "true",
            "yes",
            "on",
        )
        # 兼容旧开关：GROK_RISK_SYNC=0 也可开异步
        _sync_env = (os.environ.get("GROK_RISK_SYNC") or "").strip().lower()
        if _sync_env in ("0", "false", "no", "off"):
            risk_async = True
        risk_sync = not risk_async

        def _apply_risk(risk: dict[str, Any]) -> None:
            row["risk"] = risk
            row["clean"] = bool(risk.get("clean"))
            row["importable"] = bool(risk.get("importable", risk.get("clean")))
            summary = risk.get("summary") or "?"
            log(
                f"risk · {summary}",
                "success" if risk.get("clean") else "warn",
            )
            if row["clean"]:
                clean_path = out_file.with_name(out_file.stem + "_clean.txt")
                with open(clean_path, "a", encoding="utf-8") as f:
                    f.write(f"{email}----{sso}\n")
                row["ok"] = True
                lvl = str(risk.get("risk_level") or "")
                if "HIGH" in lvl.upper():
                    log("CLEAN 落盘 · HIGH 无 botFlag，可换 token", "success")
                else:
                    log("CLEAN 落盘", "success")
                try:
                    # same_session 回写的 device 细节并入 row
                    if isinstance(risk, dict) and not row.get("device_fp"):
                        pass
                    record_clean_success(
                        row,
                        mail_domain=MAIL_DOMAIN,
                        proxy_mode=_PROXY_MODE,
                        batch_id=_BATCH_ID or out_file.stem,
                        log=log,
                    )
                except Exception:
                    pass
            else:
                row["ok"] = False
                row["error"] = risk.get("summary") or "MARKED"
                marked_path = out_file.with_name(out_file.stem + "_marked.txt")
                with open(marked_path, "a", encoding="utf-8") as f:
                    f.write(f"{email}----{sso}\n")
                meta_path = out_file.with_name(out_file.stem + "_marked_meta.txt")
                with open(meta_path, "a", encoding="utf-8") as f:
                    f.write(f"{email}\t{risk.get('summary')}\n")
                log("MARKED · deny/botFlag，不计入 CLEAN", "warn")
                try:
                    record_marked(
                        row,
                        mail_domain=MAIL_DOMAIN,
                        proxy_mode=_PROXY_MODE,
                        batch_id=_BATCH_ID or out_file.stem,
                        log=log,
                    )
                except Exception:
                    pass

        if risk_sync:
            risk = probe_risk(sso, sso_rw, pspec)
            _apply_risk(risk)
        else:
            # 异步 risk（显式 GROK_RISK_ASYNC=1）：主路径先记 pending
            row["risk_pending"] = True
            row["_risk_holder"] = {"done": threading.Event(), "risk": None}

            def _risk_worker() -> None:
                try:
                    r = probe_risk(sso, sso_rw, pspec)
                except Exception as e:
                    r = {
                        "clean": False,
                        "importable": False,
                        "summary": f"RISK_ERR:{e}",
                        "error": str(e),
                    }
                row["_risk_holder"]["risk"] = r
                row["_risk_holder"]["done"].set()

            threading.Thread(
                target=_risk_worker, daemon=True, name=f"risk-{idx}"
            ).start()
            log("risk 异步探测中（不堵下一号）", "info")

        try:
            email_svc.delete_email(email)
        except Exception:
            pass
        # elapsed_s 默认 = 注册路径（不含 risk 等待）
        row["elapsed_s"] = row["elapsed_reg_s"]

        # per-account json（risk 可能仍 pending，finalize 再补）
        _tag = str(region.get("tag") or region.get("region") or "x").lower()
        _tag = re.sub(r"[^a-z0-9_-]+", "_", _tag)[:24]
        detail = keys / f"ss_{_tag}_{idx:02d}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        row["_detail_path"] = str(detail)
        detail.write_text(
            json.dumps(
                {
                    "email": email,
                    "password": password,
                    "region": region["tag"],
                    "fp": fp,
                    "sso": sso,
                    "risk": row.get("risk"),
                    "risk_pending": bool(row.get("risk_pending")),
                    "castle_len": row["castle_len"],
                    "castle_method": row["castle_method"],
                    "elapsed_s": row["elapsed_s"],
                    "elapsed_reg_s": row.get("elapsed_reg_s"),
                    "browser_from_pool": row.get("browser_from_pool"),
                    "domain": row.get("domain") or "",
                    "email_provider": row.get("email_provider") or "",
                    "steps": ss.get("steps"),
                    "at": datetime.now().isoformat(timespec="seconds"),
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        return row
    except Exception as e:
        row["error"] = str(e)[:200]
        row["elapsed_s"] = round(time.time() - t0, 2)
        log(f"异常: {e}", "error")
        if email:
            try:
                email_svc.delete_email(email)
            except Exception:
                pass
        return row


def main() -> int:
    proxy_mode = _PROXY_MODE
    _risk_mode = (
        "async"
        if (os.environ.get("GROK_RISK_ASYNC") or "").strip().lower()
        in ("1", "true", "yes", "on")
        or (os.environ.get("GROK_RISK_SYNC") or "").strip().lower()
        in ("0", "false", "no", "off")
        else "sync"
    )
    _jit = (
        os.environ.get("STANDALONE_SS_JITTER_MS")
        or os.environ.get("GROK_SS_JITTER_MS")
        or "1500-4500"
    ).strip()
    _sess = "on" if _PROXY_SESSION_ROTATE else "off"
    log(
        f"same-session x{COUNT} · {MAIL_DOMAIN} · camoufox · {proxy_mode} · "
        f"session轮换={_sess} · timing={_TIMING_ENV} · "
        f"risk={_risk_mode} · deny熔断={DENY_BREAK_N or 'off'} · "
        f"jitter={_jit}ms · auto_import={'on' if auto_import_enabled() else 'off'}",
        "info",
    )
    log(
        f"代理池 {len(BASE_PROXIES)} 条 · 指纹区 {len(FP_REGIONS)} · "
        f"时序池 {TIMING_POOL}",
        "info",
    )
    # local / system：启动时探真实出口，后续 pick 只在同国家簇内轮指纹
    if not _USE_1024 and not _USE_CLIPROXY:
        force_eg = (os.environ.get("STANDALONE_EGRESS_REFRESH") or "").strip().lower() in (
            "1",
            "true",
            "yes",
            "on",
        )
        eg = detect_local_egress(force=force_eg, log_fn=log)
        try:
            every_n = int(
                (os.environ.get("STANDALONE_EGRESS_EVERY") or "3").strip() or "3"
            )
        except ValueError:
            every_n = 3
        if eg.get("ok") and eg.get("family"):
            pool_n = len(_fp_pool_for_family(str(eg.get("family") or ""), eg))
            log(
                f"local指纹对齐 · family={eg.get('family')} · "
                f"池内 {pool_n} 条（仅同簇 locale/tz，禁全球乱跳） · "
                f"复探每{every_n or '关'}号",
                "success",
            )
        elif eg.get("ok"):
            log(
                f"local出口已识别 cc={eg.get('cc')} tz={eg.get('timezone')} · "
                "池无精确簇，将按探测 tz 合成 locale",
                "warn",
            )
    ensure_solver()

    email_svc = EmailService(log_fn=log)
    ts_svc = TurnstileService()

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = BASE / "keys" / f"standalone_ss_{stamp}_{COUNT}.txt"
    out_file.parent.mkdir(exist_ok=True)
    global _BATCH_ID
    _BATCH_ID = out_file.stem
    log(f"输出 {out_file.name}", "info")
    log(
        "指纹账本 on · CLEAN→keys/clean_fp_success.jsonl · "
        "全量→keys/fp_outcome.jsonl（CLEAN_FP_LEDGER=0 可关）",
        "info",
    )

    rows = []
    consecutive_deny = 0
    fused = False
    fuse_reason = ""
    for i in range(1, COUNT + 1):
        row = run_one(i, email_svc, ts_svc, out_file)
        rows.append(row)

        # 同步 risk 已落盘；异步 pending 先跳过，finalize 后再计
        # 口径：有 SSO 且 clean=True 清零；有 SSO 且 clean=False 叠连续 deny
        if not row.get("risk_pending"):
            if row.get("sso") and row.get("clean") is True:
                consecutive_deny = 0
            elif row.get("sso") and row.get("clean") is False:
                consecutive_deny += 1
                # deny×1 即提示换节点（比等 deny×3 更省；废号已实锤换不出 token）
                eg_ip = row.get("egress_ip") or "?"
                eg_cc = row.get("egress_cc") or "?"
                log(
                    f"连续 MARKED/deny {consecutive_deny}"
                    + (f"/{DENY_BREAK_N}" if DENY_BREAK_N else "")
                    + f" · egress={eg_ip}/{eg_cc}",
                    "warn",
                )
                if consecutive_deny == 1:
                    log(
                        "⚠ 建议立刻换 Clash 节点（同出口短窗 $registration 易连 deny；"
                        "policy=deny 换不出 token）· "
                        f"当前 {eg_ip} ({eg_cc}) · "
                        "切完可设 STANDALONE_EGRESS_REFRESH=1 或等下号自动复探",
                        "warn",
                    )
                # STANDALONE_DENY_HINT_BREAK=1：deny×1 直接停批（默认关，只提示）
                hint_break = (
                    os.environ.get("STANDALONE_DENY_HINT_BREAK") or ""
                ).strip().lower() in ("1", "true", "yes", "on")
                if hint_break and consecutive_deny >= 1:
                    fused = True
                    fuse_reason = (
                        f"deny×1 提示熔断（STANDALONE_DENY_HINT_BREAK=1）· "
                        f"请换节点后再跑 · egress={eg_ip}"
                    )
                    log(fuse_reason, "error")
                    try:
                        shutdown_camoufox_pool()
                    except Exception:
                        pass
                    break
                if DENY_BREAK_N > 0 and consecutive_deny >= DENY_BREAK_N:
                    fused = True
                    fuse_reason = (
                        f"连续 {consecutive_deny} 次 MARKED/deny，"
                        f"熔断停批（阈值={DENY_BREAK_N}）· 请换节点 · egress={eg_ip}"
                    )
                    log(fuse_reason, "error")
                    try:
                        shutdown_camoufox_pool()
                    except Exception:
                        pass
                    break

        if i < COUNT and not fused:
            gap = _inter_account_delay_s(consecutive_deny)
            if gap >= 1.0:
                log(f"号间冷却 {gap:.1f}s（连续deny={consecutive_deny}）", "info")
            time.sleep(gap)

    # 收齐异步 risk（与上一号重叠后通常已完成）
    for r in rows:
        if r.get("risk_pending"):
            finalize_risk_row(r, out_file)

    # 去掉不可序列化字段再落盘
    for r in rows:
        r.pop("_risk_holder", None)
        r.pop("_detail_path", None)

    report = BASE / "keys" / f"standalone_ss_report_{stamp}.json"
    report.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")

    log("—— 结果 ——", "info")
    for r in rows:
        status = "CLEAN" if r.get("clean") else ("SSO" if r.get("sso") else "FAIL")
        detail = (r.get("risk") or {}).get("summary") or r.get("error") or "OK"
        log(
            f"#{r['idx']} {status} · {r.get('email') or '-'} · "
            f"castle={r.get('castle_len') or 0} · reg={r.get('elapsed_reg_s') or r.get('elapsed_s')}s · {detail}",
            "success" if r.get("clean") else ("warn" if r.get("sso") else "error"),
        )
    clean_n = sum(1 for x in rows if x.get("clean"))
    marked_n = sum(
        1 for x in rows if x.get("sso") and x.get("clean") is False
    )
    regs = [float(x.get("elapsed_reg_s") or x.get("elapsed_s") or 0) for x in rows if x.get("sso")]
    avg_reg = round(sum(regs) / len(regs), 1) if regs else 0
    log(
        f"汇总 CLEAN={clean_n}/{len(rows)} · MARKED={marked_n} · "
        f"均reg={avg_reg}s"
        + (f" · 熔断={fuse_reason}" if fused else "")
        + f" · {report.name}",
        "success" if clean_n and not fused else "warn",
    )

    # 指纹账本小结：哪类环境 CLEAN 更多（含 egress IP）
    try:
        stats = fp_ledger_summarize(top=5)
        if stats.get("total_clean"):
            top_loc = stats.get("by_locale") or []
            top_tz = stats.get("by_timezone") or []
            top_gpu = stats.get("by_gpu") or []
            top_eg = stats.get("by_egress_ip") or []
            log(
                f"指纹账本累计 CLEAN={stats.get('total_clean')} · "
                f"locale热门={top_loc[:3]} · tz热门={top_tz[:3]} · "
                f"gpu热门={[(g[:28], n) for g, n in top_gpu[:2]]}",
                "info",
            )
            if top_eg:
                log(
                    f"egress IP CLEAN数 · "
                    + ", ".join(f"{ip}×{n}" for ip, n in top_eg[:4]),
                    "info",
                )
            rates = (stats.get("clean_rate_by") or {}).get("locale") or []
            if rates:
                tip = ", ".join(
                    f"{x['key']} {x['clean_rate']}%({x['clean']}/{x['total']})"
                    for x in rates[:4]
                )
                log(f"locale CLEAN率 · {tip}", "info")
            eg_rates = (stats.get("clean_rate_by") or {}).get("egress_ip") or []
            if eg_rates:
                tip = ", ".join(
                    f"{x['key']} {x['clean_rate']}%({x['clean']}/{x['total']})"
                    for x in eg_rates[:4]
                )
                log(f"egress IP CLEAN率 · {tip}", "info")
    except Exception:
        pass

    # 批次结束后自动入库 CLEAN
    clean_file = out_file.with_name(out_file.stem + "_clean.txt")
    if clean_n > 0:
        import_clean_file(clean_file, log=log)
    else:
        log("无 CLEAN，跳过自动入库", "warn")
    try:
        shutdown_camoufox_pool()
    except Exception:
        pass
    try:
        shutdown_all_bridges()
    except Exception:
        pass
    return 0 if clean_n else 1


if __name__ == "__main__":
    raise SystemExit(main())
