# -*- coding: utf-8 -*-
"""
FO1 plain object builder — recovered from har1 + live capture FO1 decrypt.

Confirmed live FO1 key order (fc_captures/20260721_175819 fo_req_1 decrypt):
  44 keys, Fh flag=1 (F6), includes oBcej5, NO dplu8/BDws8/seXW0/flGw8/JUitv6.

  e = {
    jZKxl9: opt.nKLah0,           # "chl_api_m"
    xZCnB3: opt.xZCnB3,           # "3"
    cbYg3: 0, XGxfH0: 0,
    uFPDh8: "iZuB9",
    QpuXD2: opt.ySGK7 - opt.Sodnh1,          # perf delta
    CjbkT0: opt.HVApE7 - opt.nRgJ6,          # Date.now elapsed
    DqobB9: opt.HVApE7 - opt.nRgJ6,          # same
    yqLu1: 1,
    gswH5: opt.gswH5, rhnWp3: opt.rhnWp3,
    BfeHe8: opt.NleD9 === 1,
    Ismh9: h.Ismh9,                # runtime counters (often all 0 on pass)
    EKkJ7: "rqeeD8", HRvWe3: "",
    QMxgC3: JSON.stringify(h.QMxgC3),  # live success: "[]"
    qmsd2: h.qmsd2,                # live success: "KfWr3"
    bxzf5: 0,
    tFoTC6: "Gnsb5",
    hpQq4: (opt.RbLR5||{}).cuBq9,
    AbRO4, wMrJ8, qgwGD7, ybxU8, JDHe4,
    WfbmX7: page URL, JoSC2: origin,
    zhsyu0, GgTlY6, JtEld1..IcWcN5 counters,
    ywHt7: opt.GAcJ0 - opt.BAKSL5,
    yVUVD6, GDopw2: ukhgR5-like token,
    VBSM7: h.rdjEA3(),
    oBcej5: resource timing entries,
    TBOT2: timing delta (ms)
  }
  Then G(fo_url, e) => FA(e) => XHR text/plain

Note: older FO1_KEY_ORDER (48 keys with dplu8/BDws8/seXW0/flGw8/JUitv6) was a
schema guess; live success FO1 omits those keys entirely.
"""
from __future__ import annotations

import json
import time
from typing import Any, Optional

# Live FO1 key order from decrypted capture fo_req_1 (2026-07-21)
FO1_KEY_ORDER = [
    "jZKxl9",
    "xZCnB3",
    "cbYg3",
    "XGxfH0",
    "uFPDh8",
    "QpuXD2",
    "CjbkT0",
    "DqobB9",
    "yqLu1",
    "gswH5",
    "rhnWp3",
    "BfeHe8",
    "Ismh9",
    "EKkJ7",
    "HRvWe3",
    "QMxgC3",
    "qmsd2",
    "bxzf5",
    "tFoTC6",
    "hpQq4",
    "AbRO4",
    "wMrJ8",
    "qgwGD7",
    "ybxU8",
    "JDHe4",
    "WfbmX7",
    "JoSC2",
    "zhsyu0",
    "GgTlY6",
    "JtEld1",
    "qFtL8",
    "TsXv7",
    "QgSdk3",
    "ibCj2",
    "AyFy7",
    "SEiW6",
    "ouToE8",
    "IcWcN5",
    "ywHt7",
    "yVUVD6",
    "GDopw2",
    "VBSM7",
    "oBcej5",
    "TBOT2",
]

# Constants recovered from O helper object (ep map)
CONST_EEKJ7 = "rqeeD8"  # O.PVeMc
CONST_TFOTC6 = "Gnsb5"  # O.qAEum
CONST_UFPDH8 = "iZuB9"
CONST_QMSD2 = "KfWr3"  # live FO1 success constant (capture)

# Ismh9 shape from live FO1 success (all counters 0 still accepted)
DEFAULT_ISMH9 = {
    "qSoN6": 0,
    "bXETW1": 0,
    "dGzf0": 0,
    "CyYS8": 0,
    "UrDT3": 0,
    "RXfM8": 0,
    "rdBj2": 0,
    "vcvp7": 0,
}


def _num(v: Any, default: float = 0) -> float:
    try:
        return float(v)
    except Exception:
        return default


def _default_vbsm7(api_url: str = "") -> list[dict]:
    """Minimal stack-shaped VBSM7 observed on live success FO1."""
    api = api_url or "https://challenges.cloudflare.com/turnstile/v0/api.js"
    return [
        {
            "m": "h",
            "t": 1,
            "s": (
                f"Aa@{api}:1:13039\n"
                f"Ee@{api}:1:13170\n"
                f"ae@{api}:1:55852\n"
                f"Si@{api}:1:69283\n"
                f"fa@{api}:1:38317\n"
            ),
            "c": 1,
        }
    ]


def _default_obcej5(
    *,
    rch_url: str = "",
    api_url: str = "",
    jte: int = 0,
) -> list[dict]:
    """
    Resource timing-ish entries (oBcej5) from live FO1 success.
    Shape: SvsR4 URL + aRmoL0/khKn8 durations; zeros for unused slots.
    """
    base = max(int(jte), 1800)
    api = api_url or "https://challenges.cloudflare.com/turnstile/v0/api.js"
    entries: list[dict] = []
    if rch_url:
        entries.append(
            {
                "SvsR4": rch_url,
                "aRmoL0": base - 40,
                "yhypx7": 0,
                "khKn8": base - 20,
                "jvcFG4": 0,
                "KraC6": 0,
            }
        )
    entries.append(
        {
            "SvsR4": f"{api}?onload=onload",
            "aRmoL0": base + 1800,
            "yhypx7": 0,
            "khKn8": base + 300,
            "jvcFG4": 0,
            "KraC6": 0,
        }
    )
    return entries


def _seed_timing_counters(opt: dict, cj: int) -> dict[str, int]:
    """
    Fill performance counters when opt lacks them (pure HTTP path).
    Magnitudes match live success FO1 (~2s challenge load window).
    """
    base = int(opt.get("JtEld1") or 0)
    if base <= 0:
        # synthetic but realistic window; cj is wall-clock FO build delta
        base = max(cj * 12, 1800) if cj else 2200
    return {
        "JtEld1": int(opt.get("JtEld1") or base),
        "qFtL8": int(opt.get("qFtL8") or max(base - 1, 0)),
        "TsXv7": int(opt.get("TsXv7") or 0),
        "QgSdk3": int(opt.get("QgSdk3") or 0),
        "ibCj2": int(opt.get("ibCj2") or 0),
        "AyFy7": int(opt.get("AyFy7") or 0),
        "SEiW6": int(opt.get("SEiW6") or max(base - 40, 0)),
        "ouToE8": int(opt.get("ouToE8") or 3),
        "IcWcN5": int(opt.get("IcWcN5") or 37),
        "yVUVD6": int(opt.get("yVUVD6") or 2),
    }


def build_fo1_plain(
    opt: dict,
    *,
    runtime: Optional[dict] = None,
    page_url: Optional[str] = None,
    origin: Optional[str] = None,
    now_ms: Optional[int] = None,
    build_id: Optional[str] = None,
    api_url: Optional[str] = None,
    rch_url: Optional[str] = None,
    seed_collectors: bool = True,
) -> dict:
    """
    Build FO1 plain dict from _cf_chl_opt + optional runtime collectors.

    runtime keys (optional):
      Ismh9, QMxgC3 (object or pre-stringified), qmsd2,
      VBSM7, oBcej5, NleD9, HVApE7, nRgJ6, GAcJ0, ySGK7, Sodnh1, BAKSL5,
      ybxU8, JDHe4, TBOT2
    """
    rt = runtime or {}
    now = int(now_ms if now_ms is not None else time.time() * 1000)

    ySGK7 = rt.get("ySGK7", opt.get("ySGK7"))
    Sodnh1 = rt.get("Sodnh1", opt.get("Sodnh1"))
    BAKSL5 = rt.get("BAKSL5", opt.get("BAKSL5"))
    GAcJ0 = rt.get("GAcJ0", opt.get("GAcJ0", ySGK7))
    nRgJ6 = rt.get("nRgJ6", opt.get("nRgJ6"))
    HVApE7 = rt.get("HVApE7", opt.get("HVApE7"))
    NleD9 = rt.get("NleD9", opt.get("NleD9", 0))

    # Date.now marks: early init + FO send
    if nRgJ6 is None:
        gsw = opt.get("gswH5")
        nRgJ6 = int(gsw) * 1000 if str(gsw).isdigit() else now - 100
    if HVApE7 is None:
        HVApE7 = now

    qpu = 0
    if ySGK7 is not None and Sodnh1 is not None:
        qpu = int(_num(ySGK7) - _num(Sodnh1))
    elif seed_collectors:
        qpu = int(rt.get("QpuXD2", 2))
    cj = int(_num(HVApE7) - _num(nRgJ6))
    # pure HTTP: wall clock from gswH5 often huge; clamp to FO build window
    if seed_collectors and cj > 5000:
        cj = int(rt.get("CjbkT0", 80 + (now % 120)))
    yw = 0
    if GAcJ0 is not None and BAKSL5 is not None:
        yw = int(_num(GAcJ0) - _num(BAKSL5))
    elif seed_collectors:
        yw = int(rt.get("ywHt7", 47))

    rb = opt.get("RbLR5") or {}
    if not isinstance(rb, dict):
        rb = {}

    # QMxgC3: live success is string "[]", not "{}"
    qmx = rt.get("QMxgC3", opt.get("QMxgC3"))
    if qmx is None and seed_collectors:
        qmx = []
    if not isinstance(qmx, str):
        try:
            qmx = json.dumps(
                qmx if qmx is not None else [],
                separators=(",", ":"),
                ensure_ascii=False,
            )
        except Exception:
            qmx = "[]"

    ismh = rt.get("Ismh9", opt.get("Ismh9"))
    if ismh is None and seed_collectors:
        ismh = dict(DEFAULT_ISMH9)

    qmsd = rt.get("qmsd2", opt.get("qmsd2"))
    if qmsd is None and seed_collectors:
        qmsd = CONST_QMSD2

    bid = (
        rt.get("ybxU8")
        or build_id
        or opt.get("ybxU8")
        or ""
    )
    api = (
        rt.get("JDHe4")
        or api_url
        or opt.get("JDHe4")
        or "https://challenges.cloudflare.com/turnstile/v0/api.js"
    )
    if bid and "api.js" in str(api) and "/b/" not in str(api):
        api = f"https://challenges.cloudflare.com/turnstile/v0/b/{bid}/api.js"

    vbsm = rt.get("VBSM7", opt.get("VBSM7"))
    if (vbsm is None or vbsm == []) and seed_collectors:
        vbsm = _default_vbsm7(str(api))

    counters = _seed_timing_counters(opt, cj) if seed_collectors else {
        "JtEld1": opt.get("JtEld1", 0),
        "qFtL8": opt.get("qFtL8", 0),
        "TsXv7": opt.get("TsXv7", 0),
        "QgSdk3": opt.get("QgSdk3", 0),
        "ibCj2": opt.get("ibCj2", 0),
        "AyFy7": opt.get("AyFy7", 0),
        "SEiW6": opt.get("SEiW6", 0),
        "ouToE8": opt.get("ouToE8", 0),
        "IcWcN5": opt.get("IcWcN5", 0),
        "yVUVD6": opt.get("yVUVD6", 0),
    }
    # runtime overrides win
    for ck in counters:
        if ck in rt and rt[ck] is not None:
            counters[ck] = int(rt[ck])

    obc = rt.get("oBcej5", opt.get("oBcej5"))
    if obc is None and seed_collectors:
        obc = _default_obcej5(
            rch_url=rch_url or str(opt.get("rch_url") or ""),
            api_url=str(api),
            jte=int(counters.get("JtEld1") or 0),
        )

    plain = {
        "jZKxl9": opt.get("nKLah0", "chl_api_m"),
        "xZCnB3": opt.get("xZCnB3", "3"),
        "cbYg3": 0,
        "XGxfH0": 0,
        "uFPDh8": CONST_UFPDH8,
        "QpuXD2": qpu,
        "CjbkT0": cj,
        "DqobB9": cj,
        "yqLu1": 1,
        "gswH5": opt.get("gswH5"),
        "rhnWp3": opt.get("rhnWp3"),
        "BfeHe8": bool(NleD9 == 1),
        "Ismh9": ismh,
        "EKkJ7": CONST_EEKJ7,
        "HRvWe3": "",
        "QMxgC3": qmx,
        "qmsd2": qmsd,
        "bxzf5": 0,
        "tFoTC6": CONST_TFOTC6,
        "hpQq4": rb.get("cuBq9") or opt.get("HHgeD5") or "en-us",
        "AbRO4": opt.get("AbRO4"),
        "wMrJ8": opt.get("wMrJ8"),
        "qgwGD7": opt.get("qgwGD7", 0),
        "ybxU8": bid,
        "JDHe4": api,
        "WfbmX7": page_url or opt.get("WfbmX7") or "",
        "JoSC2": origin or opt.get("JoSC2") or "",
        "zhsyu0": opt.get("zhsyu0"),
        "GgTlY6": opt.get("GgTlY6"),
        "JtEld1": counters["JtEld1"],
        "qFtL8": counters["qFtL8"],
        "TsXv7": counters["TsXv7"],
        "QgSdk3": counters["QgSdk3"],
        "ibCj2": counters["ibCj2"],
        "AyFy7": counters["AyFy7"],
        "SEiW6": counters["SEiW6"],
        "ouToE8": counters["ouToE8"],
        "IcWcN5": counters["IcWcN5"],
        "ywHt7": yw,
        "yVUVD6": counters["yVUVD6"],
        "GDopw2": opt.get("GDopw2") or opt.get("ukhgR5"),
        "VBSM7": vbsm if vbsm is not None else [],
        "oBcej5": obc if obc is not None else [],
        "TBOT2": rt.get(
            "TBOT2",
            opt.get("TBOT2", cj if cj else int(_num(HVApE7) - _num(nRgJ6))),
        ),
    }
    return {k: plain.get(k) for k in FO1_KEY_ORDER}


def fo1_fill_report(plain: dict) -> dict:
    missing = [k for k in FO1_KEY_ORDER if plain.get(k) is None]
    empty_str = [
        k
        for k in ("ybxU8", "JDHe4", "WfbmX7", "JoSC2", "rhnWp3", "gswH5")
        if plain.get(k) in (None, "")
    ]
    return {
        "total": len(FO1_KEY_ORDER),
        "filled": len(FO1_KEY_ORDER) - len(missing),
        "missing": missing,
        "empty_critical": empty_str,
        "json_len": len(json.dumps(plain, separators=(",", ":"), ensure_ascii=False)),
        "has_Ismh9": plain.get("Ismh9") is not None,
        "has_oBcej5": bool(plain.get("oBcej5")),
        "qmsd2": plain.get("qmsd2"),
    }
