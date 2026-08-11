"""
Turnstile 纯协议客户端（accounts.x.ai / Cloudflare）— HAR 对齐版。

已用日常 Chrome HAR 验证的完整链路：
1) GET accounts.x.ai/sign-up（暖 cookie）
2) GET challenges.cloudflare.com/turnstile/v0/api.js → build
3) GET .../turnstile/f/av0/rch/{widgetId}/{sitekey}/light/fbE/new/flexible?lang=auto
4) 解析 window._cf_chl_opt：
     iuvE7=widgetId, wMrJ8=sitekey, DZCCV4=ray,
     XWlU0=cf-chl(=FO path tail), gswH5=ts, mbRD3=branch
5) 从 challenge 脚本抠 /fo/{session}:{ts}:{sig}/
6) POST FO1  text/plain 加密 body（~4KB）→ 大响应（~500KB）+ cf-chl-gen
7) GET  /pat/... （常 401） /ci/... （图）
8) POST FO2  大加密 body（~80KB+）→ 小响应 + cf-chl-out / cf-chl-out-s
9) 浏览器侧 postMessage 得到 token：1.<payload>.<mid>.<hex64>
   业务侧字段名 turnstileToken

当前：
- 1~5 可纯协议稳定跑通（暖站/api.js/rch/parse_opt/拼 FO URL）
- 6~8 的 HTTP 形状/头已对齐 HAR
- FO body 必须与当次 rch 会话绑定；HAR 样本仅作形状/字符集对照，不可对 live fo_url 盲放
- 默认不注入、不跑 jsdom/VM（注入会被 CF 判 fail）
- Node VM 仅实验开关，默认关闭
- 已从 har1 静态还原：F7 自定义 b64 + F8 RSA-1024 头（g/turnstile_fo_codec.py）
- 已还原 FA/XXTEA 流水线（g/turnstile_fa_encoder.py）：FJ→Fh→pad→RSA(FC)→XXTEA→b64
- 已还原 gDRqi3：runProgram 注入 XOR，k[i]^=s.charCodeAt(i%s.length)；har1 s=xpGnbLPmChEjwmse
- 已还原 FO1 明文 44 字段语义 + builder（g/turnstile_fo1_plain.py）
  live 成功样本 key order：含 oBcej5，无 dplu8/BDws8/seXW0/flGw8/JUitv6
- 离线 har1 链已打通：FO1 POST → PAT/CI → FO2 POST(88439) → token 1.*
  （Node harness: logs/har1/_node_vm_extract.js；FORCE_HAR_FO2 默认开）
- 离线 har2 链已打通：FO1 4140 → FO2 88460 → token 1.IVotu…；F7 pad=V；gDRqi3 s 同 har1
  （Node harness: logs/har2/_node_vm_extract.js）
- live FO1：✅ 200 + ~500KB + F5 ~374KB + cf-chl-gen（seed Ismh9/qmsd2/oBcej5/计数器）
- live FO2 plain：仍须同 session 浏览器 VM（37 sensor + ~50 named；schema 会旋转）
- F6：✅ 原版 Node F6 已接入 g/turnstile_f6.py（bit-identical 黄金 FO2 body）
  logs/har1/work/_f6_cli.js + F6.js；zlib 近似会压过狠导致 hybrid 体型偏小
- hybrid：✅ FA wire decrypt → exact F6 re-encode 同 FC；CDP: logs/hybrid_fo2_solve.py
  build_fo2_plain_hybrid() 在 schema_drift 时 passthrough 完整 live plain
"""
from __future__ import annotations

import json
import os
import re
import secrets
import string
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from g.turnstile_fo_codec import FoCodec, extract_fo_keys_from_rch
from g.turnstile_fa_encoder import FaEncoder
from g.turnstile_fo1_plain import build_fo1_plain, fo1_fill_report
from g.turnstile_fo2_plain import build_fo2_plain_hybrid, build_fo2_plain_replay
from g.turnstile_f5 import f5_decode, verify_har1_f5, verify_har2_f5

DEFAULT_SITEKEY = "0x4AAAAAAAhr9JGVDZbrZOo0"
DEFAULT_SITE_URL = "https://accounts.x.ai"
CF_HOST = "https://challenges.cloudflare.com"
IMPERSONATE = "chrome131"

# HAR 对照目录（Reqable 成功链优先 har1，其次 har2）
DEFAULT_HAR_BODY_DIRS = (
    Path(__file__).resolve().parents[1] / "logs" / "har1" / "extracted",
    Path(__file__).resolve().parents[1] / "logs" / "har2" / "extracted",
    Path(__file__).resolve().parents[1] / "logs" / "har" / "extracted",
)

# HAR 实测 size 是 flexible，不是 normal
DEFAULT_SIZE = "flexible"
DEFAULT_THEME = "light"
DEFAULT_FEEDBACK = "fbE"
DEFAULT_TRIGGER = "new"


def _new_widget_id(n: int = 5) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _session():
    try:
        from curl_cffi import requests as crequests

        s = crequests.Session(impersonate=IMPERSONATE)
        return s, "curl_cffi"
    except Exception:
        import requests

        s = requests.Session()
        return s, "requests"


@dataclass
class ProtocolStageResult:
    stage: str
    ok: bool
    detail: str = ""
    data: dict = field(default_factory=dict)


@dataclass
class TurnstileProtocolResult:
    ok: bool
    token: str = ""
    error: str = ""
    sitekey: str = ""
    site_url: str = ""
    widget_id: str = ""
    rch_url: str = ""
    build_id: str = ""
    ray_id: str = ""
    chl_token: str = ""
    fo_session: str = ""
    fo_url: str = ""
    fo_path_prefix: str = ""
    stages: list[dict] = field(default_factory=list)
    opt: dict = field(default_factory=dict)
    elapsed_ms: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


class TurnstileProtocolSolver:
    """
    纯协议 Turnstile 求解器。

    能力：
    - 暖站 / api.js / rch / 解析 opt / 拼完整 FO URL+头
    - 可选 Node 挑战 VM 尝试生成 FO body
    - 可选用 HAR 样本 body 做结构回放诊断
    """

    def __init__(
        self,
        site_url: str = DEFAULT_SITE_URL,
        sitekey: str = DEFAULT_SITEKEY,
        theme: str = DEFAULT_THEME,
        size: str = DEFAULT_SIZE,
        language: str = "auto",
        timeout: float = 25.0,
        dump_dir: str | Path | None = None,
        try_node_vm: bool = False,
        har_body_dir: str | Path | None = None,
        allow_har_body_replay: bool = False,
    ):
        self.site_url = (site_url or DEFAULT_SITE_URL).rstrip("/")
        self.sitekey = sitekey or DEFAULT_SITEKEY
        self.theme = theme or DEFAULT_THEME
        self.size = size or DEFAULT_SIZE
        self.language = language or "auto"
        self.timeout = timeout
        self.dump_dir = Path(dump_dir) if dump_dir else None
        # 默认 False：jsdom/注入会触发 CF fail(300010)，不要当主路
        self.try_node_vm = try_node_vm
        self.har_body_dir = Path(har_body_dir) if har_body_dir else None
        # 默认 False：HAR FO body 绑定旧 session，对 live fo_url 盲放必废
        self.allow_har_body_replay = allow_har_body_replay
        self.last_error = ""
        self._sess = None
        self._backend = ""

    # ---------- HTTP helpers ----------

    def _headers_nav(self, *, dest: str = "document", referer: str | None = None) -> dict:
        return {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            ),
            "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": dest,
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "cross-site" if dest == "iframe" else "none",
            "Sec-Fetch-User": "?1",
            "Referer": referer or f"{self.site_url}/sign-up",
        }

    def _headers_fo(self, *, rch_url: str, chl_token: str) -> dict:
        return {
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "text/plain;charset=UTF-8",
            "Origin": CF_HOST,
            "Referer": rch_url,
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            ),
            "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "cf-chl": chl_token,
            "cf-chl-ra": "0",
        }

    def _ensure_session(self):
        if self._sess is None:
            self._sess, self._backend = _session()
        return self._sess

    def _dump(self, name: str, content: str | bytes) -> None:
        if not self.dump_dir:
            return
        self.dump_dir.mkdir(parents=True, exist_ok=True)
        path = self.dump_dir / name
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")

    # ---------- URL / parse ----------

    @staticmethod
    def build_rch_url(
        widget_id: str,
        sitekey: str,
        *,
        theme: str = DEFAULT_THEME,
        size: str = DEFAULT_SIZE,
        language: str = "auto",
        branch: str = "b",
        trigger: str = DEFAULT_TRIGGER,
        feedback: str = DEFAULT_FEEDBACK,
        rc_v: str = "",
    ) -> str:
        """
        HAR 实测：
        /cdn-cgi/challenge-platform/h/b/turnstile/f/av0/rch/{widgetId}/{sitekey}/light/fbE/new/flexible?lang=auto
        """
        g = f"h/{branch}/" if branch else ""
        i = rc_v or ""
        return (
            f"{CF_HOST}/cdn-cgi/challenge-platform/{g}turnstile/f/av0/rch"
            f"{i}/{widget_id}/{sitekey}/{theme}/{feedback}/{trigger}/{size}"
            f"?lang={language}"
        )

    @staticmethod
    def parse_chl_opt(html: str) -> dict[str, Any]:
        m = re.search(r"window\._cf_chl_opt\s*=\s*(\{.*?\});", html, re.S)
        raw = m.group(1) if m else ""
        out: dict[str, Any] = {"_raw_len": len(raw)}
        if not raw:
            return out

        for k, v in re.findall(r"([A-Za-z0-9_]+)\s*:\s*'([^']*)'", raw):
            out[k] = v
        for k, v in re.findall(r"([A-Za-z0-9_]+)\s*:\s*(\d+)", raw):
            out.setdefault(k, int(v))
        for k, v in re.findall(r"([A-Za-z0-9_]+)\s*:\s*(true|false)", raw):
            out.setdefault(k, v == "true")

        # HAR 对齐语义（当前 build；key 混淆会变，失败时仍保留原始键）
        semantic = {}
        for sk, candidates in {
            "widget_id": ("iuvE7", "widgetId"),
            "sitekey": ("wMrJ8",),
            "mode": ("RttsH8",),
            "size": ("DQGo5",),
            "theme": ("ADntd0",),
            "trigger": ("GgTlY6",),
            "ray_id": ("DZCCV4",),
            "branch": ("mbRD3",),
            "host": ("xMQQ7",),
            "chl_type": ("nKLah0",),
            "chl_token": ("XWlU0",),  # = cf-chl header / FO path tail
            "ts": ("gswH5",),
            "next_rcv": ("zhsyu0", "nextRcV"),
            "c_ray_alt": ("ukhgR5",),
            "source": ("source",),
        }.items():
            for c in candidates:
                if c in out and out[c] not in ("", None):
                    semantic[sk] = out[c]
                    break
        out["_semantic"] = semantic
        out["_raw_head"] = raw[:800]
        return out

    @staticmethod
    def extract_fo_session(html_or_js: str) -> str:
        """返回 session:ts:sig，例如 3780930219:1784268015:EicPjn9..."""
        m = re.search(r"/fo/([0-9]+:[0-9]+:[A-Za-z0-9_\-]+)/", html_or_js)
        return m.group(1) if m else ""

    @staticmethod
    def extract_fo_prefix(html_or_js: str) -> str:
        m = re.search(r"/fo/([0-9]+:[0-9]+:[A-Za-z0-9_\-]+)/", html_or_js)
        return m.group(0) if m else ""

    @staticmethod
    def build_fo_url(
        *,
        branch: str,
        fo_session: str,
        ray_id: str,
        chl_token: str,
    ) -> str:
        return (
            f"{CF_HOST}/cdn-cgi/challenge-platform/h/{branch}/fo/"
            f"{fo_session}/{ray_id}/{chl_token}"
        )

    @staticmethod
    def extract_token_from_text(text: str) -> str:
        if not text:
            return ""
        # HAR 实测 token 以 1. 开头（非 0.）
        m = re.search(r"\b([01]\.[A-Za-z0-9_\-\.]{100,})\b", text)
        return m.group(1) if m else ""

    # ---------- optional Node VM ----------

    def _run_node_vm(self, rch_html: str, rch_url: str) -> dict:
        """
        用 Node + jsdom 跑 rch 页，拦截 XHR/fetch 到 /fo/ 的 body。
        需要 logs/har/node_modules/jsdom；没有则返回 skip。
        """
        runner = Path(__file__).resolve().parents[1] / "logs" / "har" / "_chl_vm_runner.js"
        if not runner.exists():
            return {"ok": False, "error": "runner missing", "skip": True}
        jsdom_dir = runner.parent / "node_modules" / "jsdom"
        if not jsdom_dir.exists():
            return {"ok": False, "error": "jsdom not installed", "skip": True}

        html_path = (self.dump_dir or runner.parent) / "_vm_rch.html"
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(rch_html, encoding="utf-8")
        out_path = html_path.with_suffix(".vm.json")

        try:
            proc = subprocess.run(
                [
                    "node",
                    str(runner),
                    str(html_path),
                    rch_url,
                    str(out_path),
                ],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=str(runner.parent),
            )
        except Exception as e:
            return {"ok": False, "error": f"node spawn: {e}"}

        if out_path.exists():
            try:
                return json.loads(out_path.read_text(encoding="utf-8"))
            except Exception as e:
                return {
                    "ok": False,
                    "error": f"parse vm out: {e}",
                    "stdout": (proc.stdout or "")[-500],
                    "stderr": (proc.stderr or "")[-500],
                }
        return {
            "ok": False,
            "error": f"node exit {proc.returncode}",
            "stdout": (proc.stdout or "")[-800],
            "stderr": (proc.stderr or "")[-800],
        }

    def _load_har_bodies(self) -> dict[str, str]:
        """从 HAR 提取目录读 fo_01 / fo_02 body，仅用于诊断对照（不默认 POST）。"""
        dirs: list[Path] = []
        if self.har_body_dir and Path(self.har_body_dir).exists():
            dirs.append(Path(self.har_body_dir))
        for cand in DEFAULT_HAR_BODY_DIRS:
            if cand.exists() and cand not in dirs:
                dirs.append(cand)
        if not dirs:
            return {}

        # 兼容 har1 (fo_01_e8) 与 旧 har (fo_01_e38) 命名
        fo1_names = ("fo_01_e8_req.txt", "fo_01_e38_req.txt")
        fo2_names = ("fo_02_e20_req.txt", "fo_02_e45_req.txt")
        out: dict[str, str] = {}
        for d in dirs:
            if "fo1" not in out:
                for name in fo1_names:
                    p = d / name
                    if p.exists():
                        out["fo1"] = p.read_text(encoding="utf-8", errors="replace").strip()
                        out["fo1_path"] = str(p)
                        break
            if "fo2" not in out:
                for name in fo2_names:
                    p = d / name
                    if p.exists():
                        out["fo2"] = p.read_text(encoding="utf-8", errors="replace").strip()
                        out["fo2_path"] = str(p)
                        break
            if "token" not in out:
                p = d / "token_turnstile.txt"
                if p.exists():
                    out["token"] = p.read_text(encoding="utf-8", errors="replace").strip()
            if "fo1" in out and "fo2" in out and "token" in out:
                out["sample_dir"] = str(d)
                break
        return out

    @staticmethod
    def verify_offline_har1_chain() -> dict[str, Any]:
        """
        离线验证 har1 全链形状（不发 live 请求）:
          FO1 body ↔ FO2 body 同 RSA header
          F5(FO1/FO2 resp) 可解
          token 1.* 存在
        """
        root = Path(__file__).resolve().parents[1] / "logs" / "har1" / "extracted"
        codec = FoCodec.har1_sample()
        out: dict[str, Any] = {"ok": True, "steps": []}

        def step(name: str, ok: bool, **data):
            out["steps"].append({"name": name, "ok": ok, **data})
            if not ok:
                out["ok"] = False

        fo1 = (root / "fo_01_e8_req.txt").read_text(encoding="utf-8").strip()
        fo2 = (root / "fo_02_e20_req.txt").read_text(encoding="utf-8").strip()
        tok = (root / "token_turnstile.txt").read_text(encoding="utf-8").strip()
        p1 = codec.parse_body(fo1)
        p2 = codec.parse_body(fo2)
        step(
            "fo_bodies",
            bool(p1.get("ok") and p2.get("ok")),
            fo1_len=len(fo1),
            fo2_len=len(fo2),
            same_rsa_header=p1.get("header_hex") == p2.get("header_hex"),
            fo1_pad=p1.get("pad_byte"),
            fo2_pad=p2.get("pad_byte"),
        )
        f5 = verify_har1_f5()
        step("f5_decode", bool(f5.get("ok")), checks=f5.get("checks"))
        tok_ok = bool(tok.startswith("1.") and len(tok) > 100 and not tok.startswith("1.2.1."))
        step("token", tok_ok, token_head=tok[:48], token_len=len(tok))
        # Node harness offline artifact (if previously run)
        vm_tok = Path(__file__).resolve().parents[1] / "logs" / "har1" / "work" / "vm_token.txt"
        if vm_tok.exists():
            vt = vm_tok.read_text(encoding="utf-8").strip()
            step(
                "vm_token_artifact",
                vt.startswith("1.") and len(vt) > 100,
                token_head=vt[:48],
            )
        out["token"] = tok if tok_ok else ""
        return out

    def run_har1_node_harness(
        self,
        *,
        use_har_fo1: bool = True,
        force_har_fo2: bool = True,
        timeout: float = 60.0,
    ) -> dict[str, Any]:
        """跑 logs/har1/_node_vm_extract.js 离线链。"""
        return self._run_node_harness(
            "har1",
            use_har_fo1=use_har_fo1,
            force_har_fo2=force_har_fo2,
            timeout=timeout,
        )

    def run_har2_node_harness(
        self,
        *,
        use_har_fo1: bool = True,
        force_har_fo2: bool = True,
        timeout: float = 60.0,
    ) -> dict[str, Any]:
        """跑 logs/har2/_node_vm_extract.js 离线链。"""
        return self._run_node_harness(
            "har2",
            use_har_fo1=use_har_fo1,
            force_har_fo2=force_har_fo2,
            timeout=timeout,
        )

    def _run_node_harness(
        self,
        har_name: str,
        *,
        use_har_fo1: bool = True,
        force_har_fo2: bool = True,
        timeout: float = 60.0,
    ) -> dict[str, Any]:
        """
        跑 logs/{har}/_node_vm_extract.js 离线链。
        成功时 posts>=2 且 token 1.*（FO2 可由 FORCE_HAR_FO2 补齐）。
        """
        harness = (
            Path(__file__).resolve().parents[1]
            / "logs"
            / har_name
            / "_node_vm_extract.js"
        )
        if not harness.exists():
            return {"ok": False, "error": "harness missing", "path": str(harness), "har": har_name}
        env = os.environ.copy()
        env["USE_HAR_FO1"] = "1" if use_har_fo1 else "0"
        env["FORCE_HAR_FO2"] = "1" if force_har_fo2 else "0"
        try:
            proc = subprocess.run(
                ["node", str(harness)],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(harness.parent),
                env=env,
            )
        except Exception as e:
            return {"ok": False, "error": f"node spawn: {e}", "har": har_name}
        extract = harness.parent / "work" / "vm_extract.json"
        token_p = harness.parent / "work" / "vm_token.txt"
        s_p = harness.parent / "work" / "vm_gdrqi3_s.txt"
        info: dict[str, Any] = {
            "ok": False,
            "har": har_name,
            "exit": proc.returncode,
            "stdout_tail": (proc.stdout or "")[-600],
            "stderr_tail": (proc.stderr or "")[-400],
        }
        if s_p.exists():
            info["gdrqi3_s"] = s_p.read_text(encoding="utf-8").strip()
        if extract.exists():
            try:
                data = json.loads(extract.read_text(encoding="utf-8"))
                posts = data.get("fo_posts") or []
                tok = data.get("token") or ""
                if token_p.exists() and not tok:
                    tok = token_p.read_text(encoding="utf-8").strip()
                info.update(
                    {
                        "posts": len(posts),
                        "body_lens": [p.get("bodyLen") for p in posts if isinstance(p, dict)],
                        "token": tok,
                        "g_calls": len(data.get("g_calls") or []),
                        "errors": len(data.get("errors") or []),
                        "has_gDRqi3": data.get("has_gDRqi3"),
                    }
                )
                info["ok"] = (
                    len(posts) >= 2
                    and isinstance(tok, str)
                    and tok.startswith("1.")
                    and len(tok) > 100
                    and not tok.startswith("1.2.1.")
                )
            except Exception as e:
                info["error"] = f"parse extract: {e}"
        else:
            info["error"] = "vm_extract.json missing"
        return info

    @staticmethod
    def verify_offline_har2_chain() -> dict[str, Any]:
        """
        离线验证 har2 全链形状（不发 live 请求）:
          FO1 body ↔ FO2 body 同 RSA header
          F5(FO1/FO2 resp) 可解（head cyhNem…）
          token 1.* 存在
          gDRqi3 s 已恢复
        """
        root = Path(__file__).resolve().parents[1] / "logs" / "har2" / "extracted"
        work = Path(__file__).resolve().parents[1] / "logs" / "har2" / "work"
        codec = FoCodec.har2_sample()
        out: dict[str, Any] = {"ok": True, "har": "har2", "steps": []}

        def step(name: str, ok: bool, **data):
            out["steps"].append({"name": name, "ok": ok, **data})
            if not ok:
                out["ok"] = False

        fo1 = (root / "fo_01_e8_req.txt").read_text(encoding="utf-8").strip()
        fo2 = (root / "fo_02_e20_req.txt").read_text(encoding="utf-8").strip()
        tok = (root / "token_turnstile.txt").read_text(encoding="utf-8").strip()
        p1 = codec.parse_body(fo1)
        p2 = codec.parse_body(fo2)
        step(
            "fo_bodies",
            bool(p1.get("ok") and p2.get("ok")),
            fo1_len=len(fo1),
            fo2_len=len(fo2),
            same_rsa_header=p1.get("header_hex") == p2.get("header_hex"),
            fo1_pad=p1.get("pad_byte"),
            fo2_pad=p2.get("pad_byte"),
        )
        f5 = verify_har2_f5()
        step("f5_decode", bool(f5.get("ok")), checks=f5.get("checks"))
        tok_ok = bool(tok.startswith("1.") and len(tok) > 100 and not tok.startswith("1.2.1."))
        step("token", tok_ok, token_head=tok[:48], token_len=len(tok))
        s_p = work / "vm_gdrqi3_s.txt"
        if s_p.exists():
            s = s_p.read_text(encoding="utf-8").strip()
            step("gdrqi3_s", s == "xpGnbLPmChEjwmse", s=s)
        else:
            step("gdrqi3_s", False, error="missing vm_gdrqi3_s.txt")
        vm_tok = work / "vm_token.txt"
        if vm_tok.exists():
            vt = vm_tok.read_text(encoding="utf-8").strip()
            step(
                "vm_token_artifact",
                vt.startswith("1.") and len(vt) > 100,
                token_head=vt[:48],
            )
        # compare F7 vs har1
        har1_f7 = FoCodec.har1_sample().keys.f7_raw
        step(
            "f7_differs_from_har1",
            codec.keys.f7_raw != har1_f7,
            har2_f7=codec.keys.f7_raw,
            har1_f7=har1_f7,
        )
        out["token"] = tok if tok_ok else ""
        return out

    # ---------- main ----------

    def solve(self, stop_event=None) -> TurnstileProtocolResult:
        t0 = time.time()
        stages: list[ProtocolStageResult] = []
        widget_id = _new_widget_id(5)
        result = TurnstileProtocolResult(
            ok=False,
            sitekey=self.sitekey,
            site_url=self.site_url,
            widget_id=widget_id,
        )

        def stopped() -> bool:
            return bool(stop_event is not None and stop_event.is_set())

        def add(stage: str, ok: bool, detail: str = "", **data):
            st = ProtocolStageResult(stage=stage, ok=ok, detail=detail, data=data)
            stages.append(st)
            return st

        try:
            s = self._ensure_session()
            if stopped():
                result.error = "stopped"
                return result

            # --- stage 0: warm site ---
            page_url = f"{self.site_url}/sign-up"
            pr = s.get(
                page_url, timeout=self.timeout, headers=self._headers_nav(dest="document")
            )
            try:
                cookie_names = list(s.cookies.keys())
            except Exception:
                cookie_names = []
            add(
                "warm_site",
                pr.status_code == 200,
                f"HTTP {pr.status_code}",
                cookies=cookie_names,
                backend=self._backend,
            )
            if pr.status_code != 200:
                result.error = f"打开站点失败 HTTP {pr.status_code}"
                result.stages = [asdict(x) for x in stages]
                result.elapsed_ms = int((time.time() - t0) * 1000)
                return result

            m = re.search(r'sitekey"\s*:\s*"(0x4[A-Za-z0-9_-]+)"', pr.text or "")
            if m:
                self.sitekey = m.group(1)
                result.sitekey = self.sitekey

            if stopped():
                result.error = "stopped"
                return result

            # --- stage 1: api.js ---
            api_url = f"{CF_HOST}/turnstile/v0/api.js"
            ar = s.get(
                api_url,
                timeout=self.timeout,
                headers={
                    **self._headers_nav(dest="script", referer=page_url),
                    "Sec-Fetch-Dest": "script",
                    "Sec-Fetch-Mode": "no-cors",
                    "Accept": "*/*",
                },
                allow_redirects=True,
            )
            build_id = ""
            final_api = str(getattr(ar, "url", api_url) or api_url)
            bm = re.search(r"/turnstile/v0/b/([a-f0-9]+)/api\.js", final_api)
            if not bm:
                bm = re.search(r"/turnstile/v0/b/([a-f0-9]+)/api\.js", ar.text or "")
            if bm:
                build_id = bm.group(1)
            result.build_id = build_id
            add(
                "api_js",
                ar.status_code == 200,
                f"HTTP {ar.status_code} build={build_id or '?'}",
                final_url=final_api,
                build_id=build_id,
            )

            if stopped():
                result.error = "stopped"
                return result

            # --- stage 2: rch (HAR: flexible) ---
            rch_url = self.build_rch_url(
                widget_id,
                self.sitekey,
                theme=self.theme,
                size=self.size,
                language=self.language,
            )
            result.rch_url = rch_url
            rr = s.get(
                rch_url,
                timeout=self.timeout,
                headers=self._headers_nav(dest="iframe", referer=page_url),
            )
            body = rr.text or ""
            self._dump(f"rch_{widget_id}.html", body)
            ok_rch = (
                rr.status_code == 200
                and len(body) > 5000
                and "errCode" not in body[:800]
            )
            add(
                "rch",
                ok_rch,
                f"HTTP {rr.status_code} len={len(body)} size={self.size}",
                url=rch_url,
                status=rr.status_code,
                len=len(body),
                cf_ray=rr.headers.get("cf-ray"),
            )
            if not ok_rch:
                em = re.search(r"errCode\s*=\s*(\d+)", body)
                result.error = (
                    f"rch 失败 HTTP {rr.status_code}"
                    + (f" errCode={em.group(1)}" if em else "")
                    + f" url={rch_url}"
                )
                result.stages = [asdict(x) for x in stages]
                result.elapsed_ms = int((time.time() - t0) * 1000)
                self.last_error = result.error
                return result

            # --- stage 3: parse opt + fo session ---
            opt = self.parse_chl_opt(body)
            sem = opt.get("_semantic") or {}
            fo_session = self.extract_fo_session(body)
            fo_prefix = self.extract_fo_prefix(body)
            ray_id = str(sem.get("ray_id") or "")
            if not ray_id:
                ray_id = (rr.headers.get("cf-ray") or "").split("-")[0]
            chl_token = str(sem.get("chl_token") or "")
            branch = str(sem.get("branch") or "b")
            if sem.get("widget_id"):
                result.widget_id = str(sem["widget_id"])
                widget_id = result.widget_id

            result.ray_id = ray_id
            result.chl_token = chl_token
            result.fo_session = fo_session
            result.fo_path_prefix = fo_prefix
            result.opt = {
                "semantic": sem,
                "keys": sorted([k for k in opt.keys() if not k.startswith("_")])[:50],
                "raw_head": opt.get("_raw_head") or "",
            }

            fo_url = ""
            if fo_session and ray_id and chl_token:
                fo_url = self.build_fo_url(
                    branch=branch,
                    fo_session=fo_session,
                    ray_id=ray_id,
                    chl_token=chl_token,
                )
            result.fo_url = fo_url

            parse_ok = bool(fo_session and ray_id and chl_token)
            add(
                "parse_opt",
                parse_ok,
                f"ray={ray_id} session={fo_session[:32]} chl={chl_token[:24]}...",
                semantic=sem,
                fo_session=fo_session,
                fo_url=fo_url,
            )
            if not parse_ok:
                result.error = "rch 已通，但未解析到 fo_session/ray/chl_token"
                result.stages = [asdict(x) for x in stages]
                result.elapsed_ms = int((time.time() - t0) * 1000)
                self.last_error = result.error
                return result

            self._dump(
                "fo_plan.json",
                json.dumps(
                    {
                        "rch_url": rch_url,
                        "fo_url": fo_url,
                        "headers": self._headers_fo(rch_url=rch_url, chl_token=chl_token),
                        "semantic": sem,
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
            )

            # --- stage 4a: 从当次 rch 抠 F7/F8（自定义 b64 + RSA n）---
            fo_codec: FoCodec | None = None
            try:
                fo_keys = extract_fo_keys_from_rch(body)
                if fo_keys:
                    fo_codec = FoCodec(fo_keys)
                    self._dump(
                        "fo_keys.json",
                        json.dumps(fo_keys.to_dict(), ensure_ascii=False, indent=2),
                    )
                    add(
                        "fo_keys",
                        True,
                        f"F7 alph={len(fo_keys.alphabet)} pad={fo_keys.pad_char!r} "
                        f"n_bits={fo_keys.n.bit_length()} e={fo_keys.e}",
                        alphabet_head=fo_keys.alphabet[:16],
                        pad_char=fo_keys.pad_char,
                        n_bits=fo_keys.n.bit_length(),
                    )
                else:
                    add(
                        "fo_keys",
                        False,
                        "rch 中未抠到 F7/F8（变量名可能换了）",
                    )
            except Exception as e:
                add("fo_keys", False, f"extract err: {e}")

            # --- stage 4b: HAR 样本对照 + 离线编解码自检（主证据，不注入）---
            fo1_body = ""
            fo2_body = ""
            har: dict[str, str] = {}
            try:
                har = self._load_har_bodies()
                if har:
                    fo1s = har.get("fo1") or ""
                    fo2s = har.get("fo2") or ""
                    toks = har.get("token") or ""
                    # 用 har1 固定 codec 验证样本 roundtrip；live codec 另存
                    har_codec = FoCodec.har1_sample()
                    parse1 = har_codec.parse_body(fo1s) if fo1s else {}
                    parse2 = har_codec.parse_body(fo2s) if fo2s else {}
                    add(
                        "har_sample",
                        True,
                        f"fo1={len(fo1s)} fo2={len(fo2s)} token={len(toks)} "
                        f"dec1={parse1.get('payload_len')} dec2={parse2.get('payload_len')}",
                        fo1_charset="".join(sorted(set(fo1s[:2000]))) if fo1s else "",
                        token_head=toks[:40] if toks else "",
                        fo1_pad=parse1.get("pad_byte"),
                        fo2_pad=parse2.get("pad_byte"),
                        same_rsa_header=(
                            parse1.get("header_hex") == parse2.get("header_hex")
                            if parse1.get("ok") and parse2.get("ok")
                            else None
                        ),
                        note="HAR 成功链；body 绑定旧 session，默认不 POST 到 live fo_url",
                    )
                    if self.allow_har_body_replay:
                        # 仅诊断：会几乎必然失败，用来对照状态码/头
                        fo1_body = fo1s
                        fo2_body = fo2s
                        add(
                            "har_replay_mode",
                            True,
                            "allow_har_body_replay=ON（诊断用，非生产）",
                        )
                    # 离线形状自检：F5 + 同 RSA header + token 1.*
                    try:
                        offline = self.verify_offline_har1_chain()
                        add(
                            "offline_har1_chain",
                            bool(offline.get("ok")),
                            f"ok={offline.get('ok')} steps={len(offline.get('steps') or [])}",
                            steps=offline.get("steps"),
                            token_head=(offline.get("token") or "")[:40],
                        )
                        # 诊断模式：若 live 无 token，可把 har token 挂到结果仅作形状对照
                        if (
                            offline.get("ok")
                            and offline.get("token")
                            and self.allow_har_body_replay
                            and not result.token
                        ):
                            # 不直接当 live 成功；只写 dump
                            self._dump("har_token_shape.txt", offline["token"])
                    except Exception as e:
                        add("offline_har1_chain", False, f"offline verify err: {e}")
            except Exception as e:
                add("har_sample", False, f"har load err: {e}")

            # --- stage 4c: FO1 plain builder + FA encode → 自建 body 供 live POST ---
            # FO1/FO2 必须共用同一 session_fc（RSA 头共享）；fa_enc 整链复用
            fa_enc: FaEncoder | None = None
            session_fc: bytes | None = None
            fo1_plain: dict | None = None
            if fo_codec:
                try:
                    from g.turnstile_fa_encoder import HAR1_GDRQI3_S, load_fc

                    fa_enc = FaEncoder(fo_codec.keys, gdrqi3_s=HAR1_GDRQI3_S)
                    # 可选：环境变量 / dump 注入浏览器 FO1 捕获的 FC（给 FO2 复用）
                    # TURNSTILE_SESSION_FC = hex 或路径(fc0_raw.bin / fc.hex)
                    fc_env = os.environ.get("TURNSTILE_SESSION_FC") or ""
                    if fc_env.strip():
                        try:
                            fa_enc.bind_fc(load_fc(fc_env.strip()))
                            add(
                                "session_fc_bind",
                                True,
                                f"bound FC from TURNSTILE_SESSION_FC ({fc_env[:80]})",
                                fc_head=fa_enc.session_fc.hex()[:32] if fa_enc.session_fc else "",
                            )
                        except Exception as e:
                            add("session_fc_bind", False, f"load FC failed: {e}")
                    # 用 rch opt + 页面 URL 拼 FO1 明文
                    # live 成功样本：44 keys + Ismh9/qmsd2/oBcej5 形状；无 dplu8/BDws8
                    page_url = f"{self.site_url}/sign-up"
                    api_js = (
                        f"{CF_HOST}/turnstile/v0/b/{build_id}/api.js"
                        if build_id
                        else f"{CF_HOST}/turnstile/v0/api.js"
                    )
                    fo1_plain = build_fo1_plain(
                        opt,
                        page_url=page_url,
                        origin=self.site_url,
                        build_id=build_id or "",
                        api_url=api_js,
                        rch_url=rch_url,
                        seed_collectors=True,
                    )
                    fill = fo1_fill_report(fo1_plain)
                    fa_res = fa_enc.encode(fo1_plain)  # 首次 encode 绑定 session_fc
                    session_fc = fa_res.fc
                    self._dump("session_fc.bin", session_fc)
                    self._dump("session_fc.hex", session_fc.hex())
                    self._dump(
                        "fo1_plain_probe.json",
                        json.dumps(
                            {
                                "plain": fo1_plain,
                                "fill": fill,
                                "encode": fa_res.to_dict(),
                                "gdrqi3_s": HAR1_GDRQI3_S,
                                "session_fc_hex": session_fc.hex(),
                                "note": "FO1 binds session_fc; FO2 must reuse same FC/RSA header",
                            },
                            ensure_ascii=False,
                            indent=2,
                            default=str,
                        ),
                    )
                    add(
                        "fo1_plain",
                        fill["filled"] >= 40,
                        f"filled={fill['filled']}/{fill['total']} missing={fill['missing']} "
                        f"json={fill['json_len']} body={len(fa_res.body)}",
                        filled=fill["filled"],
                        total=fill["total"],
                        missing=fill["missing"],
                        body_len=len(fa_res.body),
                    )
                    add(
                        "fa_encoder",
                        True,
                        f"FO1 body={len(fa_res.body)} raw={fa_res.raw and len(fa_res.raw)} "
                        f"pad={fa_res.pad} gDRqi3=XOR s={HAR1_GDRQI3_S!r} "
                        f"fc={session_fc.hex()[:16]}…",
                        body_len=len(fa_res.body),
                        pad=fa_res.pad,
                        gdrqi3_s=HAR1_GDRQI3_S,
                        fc_head=session_fc.hex()[:32],
                        header_head=fa_res.header.hex()[:32],
                    )
                    # live 默认：当次 F7/F8 + FA 自建 body（不再绑 allow_har_body_replay）
                    if fa_res.body:
                        fo1_body = fa_res.body
                        add(
                            "fo1_body_source",
                            True,
                            "FA-encoded FO1 plain (live session F7/F8 + opt; FC bound)",
                            body_len=len(fo1_body),
                            filled=fill["filled"],
                            total=fill["total"],
                            gdrqi3_s=HAR1_GDRQI3_S,
                            fc_head=session_fc.hex()[:32],
                        )
                except Exception as e:
                    add("fa_encoder", False, f"FA/FO1 encode err: {e}")
            else:
                add("fa_encoder", False, "skip: no fo_keys")

            # --- stage 4d: 可选 Node VM（默认关；注入/jsdom 易被 CF 判 fail）---
            if self.try_node_vm:
                try:
                    vm_info = self._run_node_vm(body, rch_url) or {}
                    self._dump(
                        "vm_result.json",
                        json.dumps(vm_info, ensure_ascii=False, indent=2, default=str),
                    )
                    posts = vm_info.get("fo_posts") or []
                    if not isinstance(posts, list):
                        posts = []
                    if posts and not fo1_body:
                        fo1_body = str((posts[0] or {}).get("body") or "")
                    if len(posts) >= 2 and not fo2_body:
                        fo2_body = str((posts[1] or {}).get("body") or "")
                    tok_vm = str(vm_info.get("token") or "")
                    # 过滤假 token（frMd / 1.2.1.1- 路径碎片）
                    if (
                        tok_vm
                        and len(tok_vm) > 100
                        and tok_vm.startswith(("0.", "1."))
                        and not tok_vm.startswith("1.2.1.")
                    ):
                        result.token = tok_vm
                    add(
                        "node_vm",
                        bool(vm_info.get("ok") and fo1_body),
                        str(
                            vm_info.get("error")
                            or f"posts={len(posts)} token={bool(result.token)}"
                        )[:300],
                        skip=bool(vm_info.get("skip")),
                        posts=len(posts),
                        warn="实验路径；勿当主路",
                    )
                except Exception as e:
                    add("node_vm", False, f"vm exception: {e}")
            else:
                add(
                    "node_vm",
                    False,
                    "disabled（默认关闭，避免注入/jsdom 触发 CF fail）",
                    skip=True,
                )

            # --- stage 5a: PAT/CI 形状（HAR 链 FO1 之后、FO2 之前）---
            if ray_id and fo_url:
                try:
                    ts = str(sem.get("ts") or int(time.time() * 1000))
                    pat_url = (
                        f"{CF_HOST}/cdn-cgi/challenge-platform/h/{branch}/pat/"
                        f"{ray_id}/{ts}/offline-probe/yaPhNCKUKIMGL4O"
                    )
                    # 不强制 live 成功；只记形状。live 路径由 FO1-stage 自己拼 URL。
                    add(
                        "pat_ci_shape",
                        True,
                        "HAR: FO1→PAT(401)→CI→FO2；live URL 由 FO1-stage 生成",
                        ray_id=ray_id,
                        note="harness firePatCi 已对齐",
                    )
                except Exception as e:
                    add("pat_ci_shape", False, str(e))

            # --- stage 5: FO1 POST（仅当有当次 body 或显式 HAR 回放诊断）---
            fo1_resp_f5_len = 0
            if fo1_body and fo_url:
                fr = s.post(
                    fo_url,
                    data=fo1_body.encode("utf-8"),
                    timeout=self.timeout,
                    headers=self._headers_fo(rch_url=rch_url, chl_token=chl_token),
                )
                resp_text = fr.text or ""
                self._dump("fo1_req.txt", fo1_body)
                self._dump("fo1_resp.txt", resp_text)
                # try F5 decode on live FO1 resp (shape check)
                try:
                    if resp_text and ray_id and len(resp_text) > 100:
                        rb = f5_decode(resp_text, ray_id)
                        fo1_resp_f5_len = len(rb)
                        self._dump("fo1_resp_f5_head.txt", rb[:2000])
                except Exception:
                    pass
                tok = self.extract_token_from_text(resp_text)
                if tok and not tok.startswith("1.2.1."):
                    result.token = tok
                # 成功形态：HTTP 200 + 大响应(~100KB+) + 可 F5；小/空响应多半 session/s/指纹拒
                fo1_accept = (
                    fr.status_code == 200
                    and len(resp_text) > 10000
                )
                add(
                    "fo1",
                    fo1_accept,
                    f"HTTP {fr.status_code} post={len(fo1_body)} resp={len(resp_text)} "
                    f"f5={fo1_resp_f5_len}"
                    + (f" gen={(fr.headers.get('cf-chl-gen') or '')[:40]}" if fr.headers.get("cf-chl-gen") else ""),
                    status=fr.status_code,
                    cf_chl_gen=(fr.headers.get("cf-chl-gen") or "")[:80],
                    token=bool(tok),
                    f5_len=fo1_resp_f5_len,
                    resp_len=len(resp_text),
                    body_source="fa_live",
                )
            else:
                add(
                    "fo1",
                    False,
                    "无 FO1 body（需 fo_codec + FA encode 成功）",
                    fo_url=fo_url,
                    har_fo1_len=len(har.get("fo1") or ""),
                    fo_keys_ok=bool(fo_codec),
                    need="F7/F8 + FO1 plain + gDRqi3 s → FA.encode → POST",
                )

            # --- stage 6: FO2 ---
            # 硬规则：FO2 必须与 FO1 共用 session_fc（同一 RSA header）。
            # 优先级：
            #   1) TURNSTILE_FO2_PLAIN = 同 session 浏览器 FA plain（hybrid 首选）
            #   2) capture fo2_plain 会话补丁回放（探针，live 会 400）
            # HAR 旧 fo2 body 与 live FO1 FC 不一致，默认不 POST。
            fo1_ok = any(
                st.stage == "fo1" and st.ok for st in stages
            )
            if (
                not fo2_body
                and fa_enc is not None
                and session_fc is not None
                and not result.token
                and fo1_ok
            ):
                fo2_plain_path = (
                    os.environ.get("TURNSTILE_FO2_PLAIN")
                    or ""
                ).strip()
                fo2_plain_obj: dict | None = None
                fo2_src = ""
                try:
                    if fo2_plain_path:
                        p_fo2 = Path(fo2_plain_path)
                        raw_obj = json.loads(
                            p_fo2.read_text(encoding="utf-8")
                        )
                        if isinstance(raw_obj, dict) and "plain" in raw_obj:
                            raw_obj = raw_obj["plain"]
                        # Prefer hybrid assembly so stable keys can be
                        # filled from opt/template while sensors+volatile
                        # stay browser-live.
                        n_live_sensors = len(
                            [k for k in (raw_obj or {}) if str(k).isdigit()]
                        )
                        if isinstance(raw_obj, dict) and n_live_sensors >= 30:
                            cap_tpl = (
                                Path(__file__).resolve().parents[1]
                                / "logs"
                                / "fc_captures"
                                / "20260721_175819"
                                / "fo2_plain.json"
                            )
                            tpl = None
                            if cap_tpl.exists():
                                tpl = json.loads(
                                    cap_tpl.read_text(encoding="utf-8")
                                )
                            api_js2 = (
                                f"{CF_HOST}/turnstile/v0/b/{build_id}/api.js"
                                if build_id
                                else f"{CF_HOST}/turnstile/v0/api.js"
                            )
                            fo2_plain_obj = build_fo2_plain_hybrid(
                                raw_obj,
                                template=tpl if isinstance(tpl, dict) else None,
                                opt={
                                    **opt,
                                    "wMrJ8": opt.get("wMrJ8") or self.sitekey,
                                    "ybxU8": build_id or opt.get("ybxU8") or "",
                                    "JDHe4": api_js2,
                                },
                                page_url=f"{self.site_url}/sign-up",
                                origin=self.site_url,
                            )
                            fo2_src = "env_TURNSTILE_FO2_PLAIN_hybrid"
                        else:
                            fo2_plain_obj = raw_obj if isinstance(raw_obj, dict) else None
                            fo2_src = "env_TURNSTILE_FO2_PLAIN"
                    else:
                        # 默认探针：capture FO2 plain + live session 字段
                        # （sensor/volatile 仍是旧 session → live POST 400）
                        cap_fo2 = (
                            Path(__file__).resolve().parents[1]
                            / "logs"
                            / "fc_captures"
                            / "20260721_175819"
                            / "fo2_plain.json"
                        )
                        if cap_fo2.exists():
                            sample = json.loads(
                                cap_fo2.read_text(encoding="utf-8")
                            )
                            fo1_for_fo2 = fo1_plain if isinstance(fo1_plain, dict) else None
                            api_js2 = (
                                f"{CF_HOST}/turnstile/v0/b/{build_id}/api.js"
                                if build_id
                                else f"{CF_HOST}/turnstile/v0/api.js"
                            )
                            fo2_plain_obj = build_fo2_plain_replay(
                                {
                                    **opt,
                                    "ybxU8": build_id or "",
                                    "JDHe4": api_js2,
                                    "DZCCV4": ray_id,
                                },
                                sample,
                                page_url=f"{self.site_url}/sign-up",
                                origin=self.site_url,
                            )
                            if isinstance(fo1_for_fo2, dict):
                                for k in (
                                    "gswH5",
                                    "rhnWp3",
                                    "zhsyu0",
                                    "GDopw2",
                                    "wMrJ8",
                                    "AbRO4",
                                    "GgTlY6",
                                    "Ismh9",
                                    "qmsd2",
                                    "ybxU8",
                                    "JDHe4",
                                    "WfbmX7",
                                    "JoSC2",
                                    "hpQq4",
                                    "VBSM7",
                                    "oBcej5",
                                    "QpuXD2",
                                    "CjbkT0",
                                    "DqobB9",
                                ):
                                    if fo1_for_fo2.get(k) is not None:
                                        fo2_plain_obj[k] = fo1_for_fo2[k]
                            fo2_plain_obj["DZCCV4"] = ray_id
                            fo2_plain_obj["ybxU8"] = build_id or fo2_plain_obj.get(
                                "ybxU8", ""
                            )
                            fo2_plain_obj["JDHe4"] = api_js2
                            n_sensors = len(
                                [k for k in fo2_plain_obj if str(k).isdigit()]
                            )
                            fo2_plain_obj["cbYg3"] = n_sensors
                            fo2_src = "capture_fo2_replay_stale"
                    if isinstance(fo2_plain_obj, dict):
                        fa2 = fa_enc.encode(fo2_plain_obj)  # reuses session_fc
                        fo2_body = fa2.body
                        same = fa2.fc == session_fc
                        n_sensors = len(
                            [k for k in fo2_plain_obj if str(k).isdigit()]
                        )
                        live_ready = (
                            fo2_src.startswith("env_TURNSTILE_FO2_PLAIN")
                            and n_sensors >= 30
                        )
                        self._dump(
                            "fo2_plain_probe.json",
                            json.dumps(
                                {
                                    "source": fo2_src,
                                    "keys": len(fo2_plain_obj),
                                    "sensors": n_sensors,
                                    "encode": fa2.to_dict(),
                                    "same_fc_as_fo1": same,
                                    "header_head": fa2.header.hex()[:32],
                                    "live_ready": live_ready,
                                    "note": (
                                        "hybrid: 28 stable template-ok; "
                                        "22 volatile + 37 sensors must be "
                                        "same-session browser VM (TURNSTILE_FO2_PLAIN)"
                                        if live_ready
                                        else (
                                            "STALE probe: capture sensor/hash will 400; "
                                            "set TURNSTILE_FO2_PLAIN=live fo2 plain "
                                            "from logs/hybrid_fo2_solve.py or cdp_fa_plain_hook"
                                        )
                                    ),
                                },
                                ensure_ascii=False,
                                indent=2,
                                default=str,
                            ),
                        )
                        add(
                            "fo2_body_source",
                            same and (live_ready or fo2_src == "env_TURNSTILE_FO2_PLAIN"),
                            f"FA FO2 src={fo2_src} body={len(fo2_body)} "
                            f"sensors={n_sensors} same_fc={same} live_ready={live_ready}",
                            body_len=len(fo2_body),
                            source=fo2_src,
                            sensors=n_sensors,
                            live_ready=live_ready,
                            fc_head=fa2.fc.hex()[:32],
                            header_head=fa2.header.hex()[:32],
                        )
                except Exception as e:
                    add("fo2_body_source", False, f"FO2 plain encode err: {e}")

            if fo2_body and fo_url and not result.token:
                # 拒 HAR fo2：与 live FO1 头不一致时（除非 allow_har_body_replay）
                if (
                    not self.allow_har_body_replay
                    and har.get("fo2")
                    and fo2_body == har.get("fo2")
                    and session_fc is not None
                ):
                    add(
                        "fo2",
                        False,
                        "拒绝 POST HAR fo2：与 live FO1 session_fc/RSA 头必然不一致",
                        har_fo2_len=len(fo2_body),
                    )
                    fo2_body = ""
            if fo2_body and fo_url and not result.token:
                fr2 = s.post(
                    fo_url,
                    data=fo2_body.encode("utf-8"),
                    timeout=self.timeout,
                    headers=self._headers_fo(rch_url=rch_url, chl_token=chl_token),
                )
                resp2 = fr2.text or ""
                self._dump("fo2_req.txt", fo2_body)
                self._dump("fo2_resp.txt", resp2)
                try:
                    if resp2 and ray_id:
                        rb2 = f5_decode(resp2, ray_id)
                        self._dump("fo2_resp_f5_head.txt", rb2[:2000])
                except Exception:
                    pass
                tok = self.extract_token_from_text(resp2)
                if tok and not tok.startswith("1.2.1."):
                    result.token = tok
                # FO2 success surface: cf-chl-out headers (token via parent postMessage)
                chl_out = fr2.headers.get("cf-chl-out") or ""
                chl_out_s = fr2.headers.get("cf-chl-out-s") or ""
                add(
                    "fo2",
                    fr2.status_code == 200,
                    f"HTTP {fr2.status_code} post={len(fo2_body)} resp={len(resp2)} "
                    f"out={bool(chl_out)} out_s={len(chl_out_s)}"
                    + (" [HAR-replay]" if self.allow_har_body_replay else ""),
                    status=fr2.status_code,
                    cf_chl_out=chl_out[:80],
                    cf_chl_out_s_len=len(chl_out_s),
                    token=bool(tok),
                    session_fc_head=(session_fc.hex()[:32] if session_fc else ""),
                )
            elif not result.token:
                add(
                    "fo2",
                    False,
                    "无当次 FO2 body（须与 FO1 同 session_fc；"
                    "TURNSTILE_FO2_PLAIN=plain.json 可探针；或 Node runProgram 出 plain）",
                    har_fo2_len=len(har.get("fo2") or ""),
                    fo_keys_ok=bool(fo_codec),
                    session_fc_bound=bool(session_fc),
                    offline_hint="bind browser FO1 FC: TURNSTILE_SESSION_FC=fc0_raw.bin",
                )

            if result.token:
                result.ok = True
                result.error = ""
                self._dump("token.txt", result.token)
            else:
                result.ok = False
                fo1_pass = any(st.stage == "fo1" and st.ok for st in stages)
                if fo1_pass:
                    result.error = (
                        "live FO1 已通（200 + ~500KB + F5 + cf-chl-gen）。"
                        " FO2 仍缺：runProgram 执行 FO1-F5 bytecode 产出当次 FO2 plain"
                        "（capture sensor/hash 回放会 400）。"
                        " FO1/FO2 必须同 session_fc。探针: logs/_probe_fo2_after_fo1.py"
                        " 或 TURNSTILE_FO2_PLAIN=live_fo2_plain.json。"
                    )
                else:
                    result.error = (
                        "live FO1 未通过。检查 fo1_plain 44键/Ismh9/qmsd2/oBcej5；"
                        " 离线链: TurnstileProtocolSolver.verify_offline_har1_chain()。"
                    )
                self.last_error = result.error

            result.stages = [asdict(x) for x in stages]
            result.elapsed_ms = int((time.time() - t0) * 1000)
            return result

        except Exception as e:
            self.last_error = str(e)
            result.error = f"protocol solver 异常: {e}"
            result.stages = [asdict(x) for x in stages]
            result.elapsed_ms = int((time.time() - t0) * 1000)
            return result


def solve_turnstile_protocol(
    site_url: str = DEFAULT_SITE_URL,
    sitekey: str = DEFAULT_SITEKEY,
    **kwargs,
) -> dict:
    solver = TurnstileProtocolSolver(site_url=site_url, sitekey=sitekey, **kwargs)
    return solver.solve().to_dict()


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] in ("offline", "verify", "har1"):
        print(json.dumps(TurnstileProtocolSolver.verify_offline_har1_chain(), ensure_ascii=False, indent=2))
        if len(sys.argv) > 2 and sys.argv[2] == "vm":
            print(json.dumps(TurnstileProtocolSolver().run_har1_node_harness(), ensure_ascii=False, indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] in ("har2", "offline2"):
        print(json.dumps(TurnstileProtocolSolver.verify_offline_har2_chain(), ensure_ascii=False, indent=2))
        if len(sys.argv) > 2 and sys.argv[2] == "vm":
            print(json.dumps(TurnstileProtocolSolver().run_har2_node_harness(), ensure_ascii=False, indent=2))
    else:
        print(json.dumps(solve_turnstile_protocol(), ensure_ascii=False, indent=2)[:4000])
