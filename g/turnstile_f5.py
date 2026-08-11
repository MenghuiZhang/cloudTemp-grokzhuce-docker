# -*- coding: utf-8 -*-
"""
Turnstile F5 response decoder — recovered from har1 rch_big_script.js.

F5(responseText):
  1. key stream seed x=32, then x ^= each char of (ray_id + '_0')
  2. atob(responseText) → binary string
  3. out[i] = ((byte[i] - x - (i % 65535) + 65535) % 255)

Used on FO1 (~500KB → ~374KB bytecode) and FO2 (~4KB → ~3KB bytecode) responses.
"""
from __future__ import annotations

import base64
from pathlib import Path
from typing import Optional


def f5_decode(data: str | bytes, ray_id: str) -> str:
    """Decode FO response body with F5 XOR stream keyed by ray_id+'_0'."""
    if isinstance(data, bytes):
        data = data.decode("latin-1", errors="replace")
    data = str(data).strip()
    x = 32
    rV = str(ray_id) + "_0"
    for ch in rV:
        x ^= ord(ch)
    raw = base64.b64decode(data)
    out = bytearray(len(raw))
    for j, rX in enumerate(raw):
        out[j] = ((rX & 255) - x - (j % 65535) + 65535) % 255
    return out.decode("latin-1")


def verify_har1_f5() -> dict:
    """Offline check against har1 FO1/FO2 response fixtures."""
    return _verify_har_f5(
        "har1",
        ray="a1c7bf683f25795b",
        pairs=[
            ("extracted/fo_01_e8_resp.txt", "work/fo1_resp_f5_full.txt", 373872, "dqEpxAslJBojCyax"),
            ("extracted/fo_02_e20_resp.txt", "work/fo2_resp_f5_full.txt", 3224, "dqEpxAslJBojCyax"),
        ],
    )


def verify_har2_f5() -> dict:
    """Offline check against har2 FO1/FO2 response fixtures."""
    return _verify_har_f5(
        "har2",
        ray="a1e80167d910e170",
        pairs=[
            ("extracted/fo_01_e8_resp.txt", "work/fo1_resp_f5_full.txt", 373808, "cyhNemFzeG55YXjl"),
            ("extracted/fo_02_e20_resp.txt", "work/fo2_resp_f5_full.txt", 3224, "cyhNemFzeG55YXjl"),
        ],
    )


def _verify_har_f5(
    name: str,
    *,
    ray: str,
    pairs: list[tuple[str, str, int, str]],
) -> dict:
    root = Path(__file__).resolve().parents[1] / "logs" / name
    out: dict = {"ok": True, "har": name, "ray": ray, "checks": []}
    for resp_rel, ref_rel, expect_len, head_prefix in pairs:
        resp_p = root / resp_rel
        ref_p = root / ref_rel
        if not resp_p.exists():
            out["checks"].append({"file": resp_rel, "ok": False, "error": "missing"})
            out["ok"] = False
            continue
        rb = f5_decode(resp_p.read_text(encoding="utf-8", errors="replace").strip(), ray)
        ok_len = len(rb) == expect_len or abs(len(rb) - expect_len) < 8
        head_ok = rb.startswith(head_prefix)
        match_ref = True
        if ref_p.exists():
            ref = ref_p.read_text(encoding="latin-1", errors="replace")
            match_ref = rb[:200] == ref[:200]
        item = {
            "file": resp_rel,
            "ok": ok_len and head_ok and match_ref,
            "decoded_len": len(rb),
            "expect_len": expect_len,
            "head_ok": head_ok,
            "match_ref_head": match_ref,
            "head": rb[:32],
        }
        out["checks"].append(item)
        if not item["ok"]:
            out["ok"] = False
    return out


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) > 1 and sys.argv[1] in ("har2", "2"):
        print(json.dumps(verify_har2_f5(), ensure_ascii=False, indent=2))
    else:
        print(json.dumps(verify_har1_f5(), ensure_ascii=False, indent=2))
