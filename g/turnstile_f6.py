# -*- coding: utf-8 -*-
"""
F6 compressor used by FA/Fh when plain framed size >= 128.

Recovered from har1 F6.js:
  - DEFLATE-style fixed Huffman (length/distance tables match RFC1951)
  - LZ77: min match 3, max 258, lookback window 32768
  - Output: raw deflate-like bytes (no zlib CMF/FLG)

Exact path (default when Node available):
  logs/har1/work/F6.js + string_table_fixed.json via _f6_cli.js
  → bit-identical to browser FO2 compressed blob (verified 2026-07-24
    on logs/fc_captures/20260721_175819).

Fallback: zlib raw deflate (wbits=-15). Size is smaller / different match
picker — live FO2 may still 400 if server is picky about Fh payload shape.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import zlib
from pathlib import Path
from typing import Optional

_ROOT = Path(__file__).resolve().parents[1]
_F6_WORK = _ROOT / "logs" / "har1" / "work"
_F6_CLI = _F6_WORK / "_f6_cli.js"
_F6_JS = _F6_WORK / "F6.js"
_F6_TABLE = _F6_WORK / "string_table_fixed.json"

# Prefer exact Node F6 unless explicitly disabled.
_ENV_FORCE_ZLIB = os.environ.get("TURNSTILE_F6_ZLIB", "").strip() in (
    "1",
    "true",
    "yes",
)
_ENV_NODE = os.environ.get("TURNSTILE_NODE") or os.environ.get("NODE") or "node"

_node_ok: Optional[bool] = None
_exact_available: Optional[bool] = None


def _node_bin() -> str:
    return _ENV_NODE


def exact_f6_available() -> bool:
    """True when Node + recovered F6 artifacts can run."""
    global _exact_available, _node_ok
    if _ENV_FORCE_ZLIB:
        return False
    if _exact_available is not None:
        return _exact_available
    if not (_F6_CLI.is_file() and _F6_JS.is_file() and _F6_TABLE.is_file()):
        _exact_available = False
        return False
    if _node_ok is None:
        try:
            r = subprocess.run(
                [_node_bin(), "-e", "process.exit(0)"],
                capture_output=True,
                timeout=5,
            )
            _node_ok = r.returncode == 0
        except Exception:
            _node_ok = False
    _exact_available = bool(_node_ok)
    return _exact_available


def f6_compress_zlib(data: bytes, *, level: int = 9) -> bytes:
    """Approx F6 via zlib raw DEFLATE — NOT bit-identical to CF."""
    co = zlib.compressobj(level=level, method=zlib.DEFLATED, wbits=-15, memLevel=9)
    return co.compress(data) + co.flush()


def f6_compress_exact(data: bytes, *, timeout: float = 60.0) -> bytes:
    """
    Bit-identical F6 via Node harness (logs/har1/work/_f6_cli.js).
    Raises on missing Node/artifacts or non-zero exit.
    """
    if not exact_f6_available():
        raise RuntimeError(
            "exact F6 unavailable (need Node + logs/har1/work/{_f6_cli.js,F6.js,"
            "string_table_fixed.json}); set TURNSTILE_F6_ZLIB=1 to force zlib approx"
        )
    # Temp files avoid binary stdin/stdout issues on Windows PowerShell wrappers.
    with tempfile.TemporaryDirectory(prefix="f6_") as td:
        tin = Path(td) / "in.bin"
        tout = Path(td) / "out.bin"
        tin.write_bytes(data)
        proc = subprocess.run(
            [_node_bin(), str(_F6_CLI), str(tin), str(tout)],
            capture_output=True,
            timeout=timeout,
            cwd=str(_ROOT),
        )
        if proc.returncode != 0 or not tout.is_file():
            err = (proc.stderr or b"").decode("utf-8", "replace")[:500]
            raise RuntimeError(
                f"F6 node failed rc={proc.returncode}: {err or 'no stderr'}"
            )
        out = tout.read_bytes()
        if not out:
            raise RuntimeError("F6 node returned empty output")
        return out


def f6_compress(data: bytes, *, level: int = 9, exact: Optional[bool] = None) -> bytes:
    """
    Compress with F6 semantics.

    exact=None (default): prefer Node exact F6, fall back to zlib.
    exact=True: require Node exact (raise if unavailable).
    exact=False: zlib approx only.
    """
    if exact is False or _ENV_FORCE_ZLIB:
        return f6_compress_zlib(data, level=level)
    if exact is True or exact_f6_available():
        try:
            return f6_compress_exact(data)
        except Exception:
            if exact is True:
                raise
            return f6_compress_zlib(data, level=level)
    return f6_compress_zlib(data, level=level)


def f6_decompress(data: bytes) -> bytes:
    """Inflate F6 / raw DEFLATE payload (browser + our exact F6 both zlib-compatible)."""
    return zlib.decompress(data, -15)


def fh_maybe_compress(framed: bytes, *, exact: Optional[bool] = None) -> tuple[bytes, int]:
    """
    Fh: [253,1,flag] + body
    flag=1 if F6(framed) smaller than framed (and typically len>=128).
    Returns (wrapped, flag).
    """
    if len(framed) < 128:
        return bytes([253, 1, 0]) + framed, 0
    try:
        c = f6_compress(framed, exact=exact)
    except Exception:
        return bytes([253, 1, 0]) + framed, 0
    if len(c) < len(framed):
        return bytes([253, 1, 1]) + c, 1
    return bytes([253, 1, 0]) + framed, 0


def self_check() -> dict:
    raw = b"hello " * 200 + b"world"
    c_zlib = f6_compress_zlib(raw)
    d_zlib = f6_decompress(c_zlib)
    wrapped, flag = fh_maybe_compress(b" " + raw + b" ", exact=False)
    out: dict = {
        "zlib_ok": d_zlib == raw and wrapped[:2] == b"\xfd\x01",
        "raw_len": len(raw),
        "zlib_comp_len": len(c_zlib),
        "flag": flag,
        "wrapped_len": len(wrapped),
        "exact_available": exact_f6_available(),
        "node": _node_bin(),
        "cli": str(_F6_CLI),
    }
    # Golden FO2 framed blob (if present): must match browser F6 bit-identical.
    golden_framed = (
        _ROOT
        / "logs"
        / "fc_captures"
        / "20260721_175819"
        / "fo2_browser_framed.bin"
    )
    golden_comp = (
        _ROOT
        / "logs"
        / "fc_captures"
        / "20260721_175819"
        / "fo2_browser_comp.bin"
    )
    if exact_f6_available() and golden_framed.is_file() and golden_comp.is_file():
        try:
            framed = golden_framed.read_bytes()
            want = golden_comp.read_bytes()
            got = f6_compress_exact(framed)
            out["exact_golden_ok"] = got == want
            out["exact_golden_len"] = len(got)
            out["exact_golden_want"] = len(want)
        except Exception as e:
            out["exact_golden_ok"] = False
            out["exact_golden_err"] = str(e)
    out["ok"] = bool(out["zlib_ok"]) and (
        not out.get("exact_available") or out.get("exact_golden_ok", True)
    )
    return out


if __name__ == "__main__":
    import json as _json

    print(_json.dumps(self_check(), indent=2))
