# -*- coding: utf-8 -*-
"""
FO2 plain assembler — live dump recovered 2026-07-21.

Status (2026-07-21 — FO2 plain DUMPED):
  - FO1 plain: 44 keys (FO1_KEY_ORDER)
  - FO2 plain: 87 keys total:
      * 37 numeric sensor entries (1-37): each is a dict with core fields
        (XsAVh8, qlAo5, oHTRn9, qPgf1, ucpv9, wZHkQ5, kExc4, GqRg5, OwbxU6, eOLK2)
        + optional extra sensor-specific keys (canvas/webgl/audio/fonts probes)
      * 50 named keys: 42 shared with FO1 + 8 FO2-only
  - fe_expand bug FIXED (bi=0 short-circuit removed)

FA local-wrap breakthrough + browser FO capture:
  - G closes over local FA; patching rebinds → dumps plains + FC
  - page.route() injects FC capture + gDRqi3 key capture
  - Live session s = "xpGnbLPmChEjwmse" (same as HAR1)

FO2 sample: logs/fc_captures/20260721_175819/fo2_plain.json
FO1 sample: logs/fc_captures/20260721_175819/fo1_plain.json

End-to-end: self-build FO1 + replay FO2 (sensor data is browser-specific)
→ token verified via HAR offline path.
"""
from __future__ import annotations

import json
import time
from typing import Any, Optional

from g.turnstile_fo1_plain import FO1_KEY_ORDER, build_fo1_plain

# FO2 named key order (recovered from live dump 2026-07-21)
# Differs from FO1: drops BfeHe8/bxzf5, inserts FO2-only keys, reorders later keys
FO2_KEY_ORDER: list[str] = [
    # ── 37 numeric sensor entries (keys "1".."37") ──
    # These come FIRST in the FO2 object and each is a dict.
    # They are NOT listed here — they are injected dynamically.
    # ── 50 named keys ──
    "jZKxl9",    # "chl_api_m"  [shared with FO1]
    "DZCCV4",    # "a1e9590a58f5d4e6"  [FO2-only]
    "xZCnB3",    # "3"  [shared]
    "cbYg3",     # 37 (sensor count)  [shared, value differs]
    "XGxfH0",    # 0  [shared]
    "uFPDh8",    # "iZuB9"  [shared]
    "QpuXD2",    # perf delta  [shared]
    "CjbkT0",    # Date.now elapsed  [shared]
    "DqobB9",    # same  [shared]
    "gswH5",     # timestamp  [shared]
    "rhnWp3",    # chl token  [shared]
    "Ismh9",     # runtime collector  [shared]
    "yqLu1",     # 1  [shared, moved in FO2]
    "AbRO4",     # "0"  [shared]
    "wMrJ8",     # sitekey  [shared]
    "qgwGD7",    # 0  [shared]
    "ybxU8",     # session id prefix  [shared]
    "JDHe4",     # api.js URL  [shared]
    "WfbmX7",    # page URL  [shared]
    "JoSC2",     # origin  [shared]
    "zhsyu0",    # token  [shared]
    "GgTlY6",    # "new"  [shared]
    "JtEld1",    # counter  [shared]
    "qFtL8",     # counter  [shared]
    "TsXv7",     # 0  [shared]
    "QgSdk3",    # 0  [shared]
    "ibCj2",     # 0  [shared]
    "AyFy7",     # 0  [shared]
    "SEiW6",     # counter  [shared]
    "ouToE8",    # 3  [shared]
    "IcWcN5",    # 37  [shared, value differs]
    "ywHt7",     # perf delta  [shared]
    "yVUVD6",    # 2  [shared]
    "GDopw2",    # token  [shared]
    "VBSM7",     # history stack  [shared]
    "oBcej5",    # challenge URLs  [shared, value differs]
    "EKkJ7",     # "rqeeD8"  [shared, moved in FO2]
    "HRvWe3",    # runtime data  [shared, value differs]
    "YdaRE8",    # 28  [FO2-only]
    "xapzC9",    # []  [FO2-only]
    "pPRUE3",    # token  [FO2-only, was EB-only]
    "kNzT1",     # hash  [FO2-only]
    "kWdjZ4",    # hash  [FO2-only]
    "gYaa9",     # 0  [FO2-only]
    "QMxgC3",    # collector results  [shared, value differs, moved in FO2]
    "qmsd2",     # "KfWr3"  [shared, moved in FO2]
    "tFoTC6",    # 0 (was "Gnsb5" in FO1)  [shared, value differs, moved in FO2]
    "hpQq4",     # locale  [shared, moved in FO2]
    "Vcjvh8",    # 1465  [FO2-only]
    "TBOT2",     # timing delta  [shared, value differs]
]

# Dropped from FO1: BfeHe8, bxzf5

# Sensor entry core fields (always present)
SENSOR_CORE_FIELDS = [
    "XsAVh8",   # challenge token (str)
    "qlAo5",    # short token/hash (str)
    "oHTRn9",   # chl token with timestamp (str)
    "qPgf1",    # integer counter (int)
    "ucpv9",    # empty or short string (str)
    "wZHkQ5",   # 0 (int)
    "kExc4",    # navigator/env info dict (dict)
    "GqRg5",    # timestamp ms (int)
    "OwbxU6",   # timestamp ms (int)
    "eOLK2",    # small int counter (int)
]

# Intermediate /eb/ body keys (captured via FA local-wrap 2026-07-21)
# These are stage failure telemetry, NOT the FO2 challenge payload.
EB_KEY_ORDER: list[str] = [
    "pPRUE3",  # long chl-like token string
    "vUzt2",  # error object {QhFT4 message, lDVU2 stack JSON}
    "xJSLL0",  # fingerprint / challenge sub-object
    "UuHa3",  # short type id (e.g. "WvZMt8")
    "YGLxp3",  # context: sitekey, page url, flags
    "PJEn6",  # zrgWB7-style chain string (joined probe results)
]

# Runtime fields known to grow between FO1 and FO2 stages
FO2_RUNTIME_HINTS = [
    "Ismh9",
    "dplu8",
    "BDws8",
    "QMxgC3",
    "qmsd2",
    "VBSM7",
    "TBOT2",
    "HRvWe3",  # grows from "" to complex data
    "cbYg3",   # grows from 0 to sensor count
    "tFoTC6",  # changes from "Gnsb5" to 0
    "IcWcN5",  # sensor count mirror
    # large sensor blobs: entries 1..N with canvas/webgl/audio/fonts probes
]

# FO2-only named keys (not in FO1)
FO2_ONLY_KEYS = {"DZCCV4", "YdaRE8", "xapzC9", "pPRUE3", "kNzT1", "kWdjZ4", "gYaa9", "Vcjvh8"}

# Dropped from FO1 in FO2
FO2_DROPPED_KEYS = {"BfeHe8", "bxzf5", "dplu8", "BDws8", "flGw8", "JUitv6", "seXW0"}

# ── Cross-session key classes (live dumps 2026-07-21..22) ──────────────
# 50 named keys total.  Practical hybrid split:
#   * STABLE (~28): literal constants + same-site fillable fields.  Can live
#     in a template / FO1-derived opt without re-running sensor VM.
#   * VOLATILE (~22): session tokens / hashes / runtime counters / collector
#     blobs.  MUST come from the same browser session that ran FO1 F5 VM.
#   * SENSORS (37 numeric entries "1".."37"): pure VM bytecode output.
#     Real browser only — Node sandbox stubs cannot produce valid values.
#
# Evidence (ja-jp pair 175819 vs 161812): 26 named equal, 24 differ.
# Soft-stable extras that are constant-or-site most of the time push the
# "reusable template" set to ~28.  Treat soft keys as template-ok only when
# live browser did not supply them.

FO2_STABLE_NAMED: frozenset[str] = frozenset(
    {
        # literal / constant across successful FO2 plains
        "jZKxl9",
        "xZCnB3",
        "XGxfH0",
        "uFPDh8",
        "yqLu1",
        "AbRO4",
        "qgwGD7",
        "GgTlY6",
        "TsXv7",
        "QgSdk3",
        "ibCj2",
        "AyFy7",
        "EKkJ7",
        "qmsd2",
        "tFoTC6",
        "xapzC9",
        "Ismh9",
        # site / build / sensor-count mirrors (fillable without sensor VM)
        "wMrJ8",
        "WfbmX7",
        "JoSC2",
        "JDHe4",
        "ybxU8",
        "hpQq4",
        "cbYg3",
        # soft-stable (often constant across same site/locale; still prefer live)
        "YdaRE8",
        "yVUVD6",
        "gYaa9",  # soft — can flip 0/1
        "ouToE8",  # soft — can be 3/9
    }
)

# Keys that look stable but sometimes drift — if absent from live dump,
# hybrid may fill from template, but full FA-hook plains always include them.
FO2_SOFT_STABLE_NAMED: frozenset[str] = frozenset({"YdaRE8", "yVUVD6", "gYaa9", "ouToE8"})

FO2_VOLATILE_NAMED: frozenset[str] = frozenset(
    {
        # session / challenge tokens + hashes
        "DZCCV4",
        "gswH5",
        "rhnWp3",
        "zhsyu0",
        "GDopw2",
        "pPRUE3",
        "kNzT1",
        "kWdjZ4",
        # timing / counters
        "QpuXD2",
        "CjbkT0",
        "DqobB9",
        "JtEld1",
        "qFtL8",
        "SEiW6",
        "TBOT2",
        "ywHt7",
        "Vcjvh8",
        "IcWcN5",
        # collector / history / resource blobs (VM or runtime)
        "HRvWe3",
        "QMxgC3",
        "VBSM7",
        "oBcej5",
    }
)

# Sanity: 28 + 22 = 50 named keys in FO2_KEY_ORDER
assert len(FO2_STABLE_NAMED) == 28, len(FO2_STABLE_NAMED)
assert len(FO2_VOLATILE_NAMED) == 22, len(FO2_VOLATILE_NAMED)
assert FO2_SOFT_STABLE_NAMED <= FO2_STABLE_NAMED
assert FO2_STABLE_NAMED.isdisjoint(FO2_VOLATILE_NAMED)
assert FO2_STABLE_NAMED | FO2_VOLATILE_NAMED == set(FO2_KEY_ORDER)


def classify_fa_plain(plain: dict) -> str:
    """
    Classify a captured FA plain object.
    Returns: 'fo1' | 'eb' | 'fo2' | 'unknown'
    """
    if not isinstance(plain, dict) or not plain:
        return "unknown"
    keys = list(plain.keys())
    keyset = set(keys)
    if keyset >= set(FO1_KEY_ORDER[:20]) and len(keys) >= 40:
        return "fo1"
    if keyset >= set(EB_KEY_ORDER) or set(EB_KEY_ORDER).issubset(keyset):
        return "eb"
    # FO2 heuristic: has numeric sensor keys + named keys
    num_keys = [k for k in keys if k.isdigit()]
    if len(num_keys) > 10 and len(keys) > 60:
        return "fo2"
    try:
        n = len(json.dumps(plain, separators=(",", ":"), ensure_ascii=False))
    except Exception:
        n = 0
    if len(keys) > 50 or n > 8000:
        return "fo2"
    return "unknown"


def get_fo2_sensor_count(plain: dict) -> int:
    """Count how many numeric sensor entries are in a FO2 plain."""
    return len([k for k in plain.keys() if k.isdigit()])


def build_sensor_entry(
    *,
    XsAVh8: str = "",
    qlAo5: str = "",
    oHTRn9: str = "",
    qPgf1: int = 0,
    ucpv9: str = "",
    wZHkQ5: int = 0,
    kExc4: Optional[dict] = None,
    GqRg5: int = 0,
    OwbxU6: int = 0,
    eOLK2: int = 0,
    **extra: Any,
) -> dict:
    """Build a single FO2 sensor entry dict."""
    entry = {
        "XsAVh8": XsAVh8,
        "qlAo5": qlAo5,
        "oHTRn9": oHTRn9,
        "qPgf1": qPgf1,
        "ucpv9": ucpv9,
        "wZHkQ5": wZHkQ5,
        "kExc4": kExc4 or {},
        "GqRg5": GqRg5,
        "OwbxU6": OwbxU6,
        "eOLK2": eOLK2,
    }
    entry.update(extra)
    return entry


def build_fo2_plain(
    opt: dict,
    *,
    runtime: Optional[dict] = None,
    fo1_plain: Optional[dict] = None,
    sensor_entries: Optional[list[dict]] = None,
    page_url: Optional[str] = None,
    origin: Optional[str] = None,
    now_ms: Optional[int] = None,
) -> dict:
    """
    Build FO2 plain dict for FA encode.

    Strategy:
      - Build FO1 base → derive FO2 named keys from it
      - Inject sensor entries (1..N) at the front
      - Fill FO2-only keys + update values that change between stages

    sensor_entries: list of sensor entry dicts (keys "1".."N").
      If None, FO2 will have no sensor data (protocol-minimal mode).
    """
    rt = dict(runtime or {})
    now = int(now_ms if now_ms is not None else time.time() * 1000)

    # Build FO1 base first
    base = fo1_plain or build_fo1_plain(
        opt, runtime=rt, page_url=page_url, origin=origin, now_ms=now
    )

    # ── Compute FO2-specific overrides ──
    sensor_count = len(sensor_entries) if sensor_entries else rt.get("sensor_count", 0)

    # Keys that change values between FO1 and FO2
    hr = rt.get("HRvWe3", opt.get("HRvWe3", ""))
    qmx = rt.get("QMxgC3", base.get("QMxgC3", ""))
    if not isinstance(qmx, str):
        try:
            qmx = json.dumps(qmx, separators=(",", ":"), ensure_ascii=False)
        except Exception:
            qmx = str(qmx)

    # ── Build FO2 named keys ──
    out = {}
    for k in FO2_KEY_ORDER:
        if k == "DZCCV4":
            out[k] = rt.get("DZCCV4", opt.get("DZCCV4", ""))
        elif k == "cbYg3":
            out[k] = sensor_count  # grows from 0 to sensor count
        elif k == "icWcN5":  # note: FO2 has both cbYg3 and IcWcN5 = sensor count
            pass  # skip
        elif k == "IcWcN5":
            out[k] = sensor_count
        elif k == "HRvWe3":
            out[k] = hr
        elif k == "QMxgC3":
            out[k] = qmx
        elif k == "tFoTC6":
            out[k] = rt.get("tFoTC6", 0)  # changes from "Gnsb5" to 0
        elif k == "TBOT2":
            out[k] = rt.get("TBOT2", now - int(opt.get("nRgJ6", now - 100)))
        elif k == "oBcej5":
            out[k] = rt.get("oBcej5", base.get("oBcej5", []))
        elif k in base:
            out[k] = base[k]
        else:
            # FO2-only keys with defaults
            defaults = {
                "YdaRE8": sensor_count - 9 if sensor_count > 9 else 0,
                "xapzC9": [],
                "pPRUE3": "",
                "kNzT1": "",
                "kWdjZ4": "",
                "gYaa9": 0,
                "Vcjvh8": 0,
            }
            out[k] = rt.get(k, defaults.get(k))

    # ── Inject sensor entries at the front ──
    if sensor_entries:
        ordered = {}
        for i, entry in enumerate(sensor_entries):
            ordered[str(i + 1)] = entry
        ordered.update(out)
        return ordered
    return out


def build_fo2_plain_replay(
    opt: dict,
    fo2_sample: dict,
    *,
    page_url: Optional[str] = None,
    origin: Optional[str] = None,
    now_ms: Optional[int] = None,
) -> dict:
    """
    Replay a captured FO2 plain with updated opt values.

    Reuses sensor entries from the sample but updates timing/navigation keys.
    This is the practical path for end-to-end token generation since
    sensor data is browser-fingerprint-specific and hard to reproduce.

    WARNING: stale sensor + volatile named keys cause FO2 HTTP 400 on live
    sessions. Prefer build_fo2_plain_hybrid() with a same-session browser dump.
    """
    now = int(now_ms if now_ms is not None else time.time() * 1000)

    out = dict(fo2_sample)  # start with full copy

    # Update keys that must match current session
    out["wMrJ8"] = opt.get("wMrJ8", out.get("wMrJ8"))
    out["WfbmX7"] = page_url or opt.get("WfbmX7", out.get("WfbmX7"))
    out["JoSC2"] = origin or opt.get("JoSC2", out.get("JoSC2"))
    out["JDHe4"] = opt.get("JDHe4", out.get("JDHe4"))
    out["ybxU8"] = opt.get("ybxU8", out.get("ybxU8", ""))
    out["hpQq4"] = (opt.get("RbLR5") or {}).get("cuBq9") or opt.get("HHgeD5", out.get("hpQq4"))
    out["TBOT2"] = int(now - (int(opt.get("nRgJ6", now - 100))))

    # Do not recompute IcWcN5 from the visible numeric sensor count.
    # Live captures show cbYg3 == number of numeric sensor entries, while
    # IcWcN5 is a separate runtime counter and can diverge
    # (e.g. 37 sensors but IcWcN5 == 40).  Recomputing it poisons replay.
    out["cbYg3"] = len([k for k in out if str(k).isdigit()])

    return out


def sensor_keys(plain: dict) -> list[str]:
    return sorted((k for k in plain if str(k).isdigit()), key=lambda x: int(x))


def classify_fo2_plain(plain: dict) -> dict[str, Any]:
    """Split a FO2 plain into stable / volatile / sensor partitions.

    Named keys rotate across CF builds.  When the live dump's names do not
    intersect the HAR1 catalog, treat the dump as a full schema-drift plain:
    readiness is structural (sensor count + named count), not fixed names.
    """
    if not isinstance(plain, dict):
        return {"ok": False, "error": "not_dict"}
    sensors = sensor_keys(plain)
    named = [k for k in plain if not str(k).isdigit()]
    named_set = set(named)
    stable_present = sorted(k for k in named if k in FO2_STABLE_NAMED)
    volatile_present = sorted(k for k in named if k in FO2_VOLATILE_NAMED)
    unknown = sorted(k for k in named if k not in FO2_STABLE_NAMED and k not in FO2_VOLATILE_NAMED)
    schema_match = len(stable_present) + len(volatile_present) >= 20
    # Full live FO2 from FA hook: ~37 sensors + ~50 named regardless of rotation.
    structural_ready = len(sensors) >= 30 and len(named) >= 40 and len(plain) >= 70
    catalog_ready = len(sensors) >= 30 and len(volatile_present) >= 18
    return {
        "ok": True,
        "total_keys": len(plain),
        "sensor_count": len(sensors),
        "named_count": len(named),
        "stable_named": stable_present,
        "volatile_named": volatile_present,
        "unknown_named": unknown,
        "missing_stable": sorted(FO2_STABLE_NAMED - named_set),
        "missing_volatile": sorted(FO2_VOLATILE_NAMED - named_set),
        "schema_match": schema_match,
        "schema_drift": not schema_match and len(named) >= 40,
        "cbYg3": plain.get("cbYg3"),
        "IcWcN5": plain.get("IcWcN5"),
        "is_live_ready": structural_ready or catalog_ready,
    }


def order_fo2_plain(plain: dict) -> dict:
    """Canonical FO2 key order: sensors 1..N then FO2_KEY_ORDER named keys."""
    ordered: dict[str, Any] = {}
    for sk in sensor_keys(plain):
        ordered[sk] = plain[sk]
    for k in FO2_KEY_ORDER:
        if k in plain:
            ordered[k] = plain[k]
    for k, v in plain.items():
        if k not in ordered:
            ordered[k] = v
    return ordered


def build_fo2_plain_hybrid(
    live: dict,
    *,
    template: Optional[dict] = None,
    opt: Optional[dict] = None,
    page_url: Optional[str] = None,
    origin: Optional[str] = None,
    require_sensors: int = 30,
    allow_template_volatile: bool = False,
) -> dict:
    """
    Assemble FO2 plain for live FO2 POST.

    Rules (hard):
      1. All numeric sensor entries MUST come from `live` (browser VM).
      2. When live uses the HAR1 named-key catalog: FO2_VOLATILE_NAMED MUST
         come from `live` unless allow_template_volatile=True.
      3. When live names have fully rotated (schema drift) but the dump is a
         complete FO2 (~37 sensors + ~50 named), PASSTHROUGH the live object
         as the hybrid body — template merge by fixed names is impossible.
      4. FO2_STABLE_NAMED may be filled from live first, else template, else opt
         (catalog-match path only).
      5. Never recompute IcWcN5 from sensor count.
      6. Sensor-count mirror keys are only rewritten when the catalog name
         `cbYg3` is present (do not invent rotated aliases).

    `live` can be a full FO2 plain (preferred) or a partial dump that at least
    contains sensors + volatile named keys.
    """
    if not isinstance(live, dict) or not live:
        raise ValueError("live FO2 material is required (browser VM output)")

    opt = dict(opt or {})
    tpl = dict(template or {})
    sensors = sensor_keys(live)
    if len(sensors) < require_sensors:
        raise ValueError(
            f"live FO2 has only {len(sensors)} sensor entries "
            f"(need >={require_sensors}); browser VM did not finish"
        )

    cls = classify_fo2_plain(live)
    named = [k for k in live if not str(k).isdigit()]

    # Schema-drift full dump: CF rotated every named key.  Browser already
    # produced a complete FO2 plain — re-encode it as-is (optionally pin
    # sitekey / page URL if those values are identifiable by content, not name).
    if cls.get("schema_drift") or (
        len(named) >= 40
        and len(set(named) & FO2_VOLATILE_NAMED) == 0
        and len(set(named) & FO2_STABLE_NAMED) == 0
    ):
        out = dict(live)
        # Best-effort site pin by value shape (sitekey / page URL), no rename.
        sitekey = opt.get("wMrJ8")
        if sitekey:
            for k, v in list(out.items()):
                if isinstance(v, str) and v.startswith("0x4") and len(v) >= 20:
                    out[k] = sitekey
        if page_url:
            for k, v in list(out.items()):
                if isinstance(v, str) and v.startswith("http") and "accounts.x.ai" in v and "/turnstile" not in v:
                    # page URL vs origin: prefer longer path match
                    if "/sign-up" in v or v.rstrip("/").count("/") >= 3:
                        out[k] = page_url
                    elif origin and v.rstrip("/") == v.split("/")[0] + "//" + v.split("/")[2]:
                        out[k] = origin
        return order_fo2_plain(out)

    out: dict[str, Any] = {}

    # 1) sensors — browser only
    for sk in sensors:
        out[sk] = live[sk]

    # 2) volatile named — browser only (default)
    missing_vol: list[str] = []
    for k in FO2_VOLATILE_NAMED:
        if k in live:
            out[k] = live[k]
        elif allow_template_volatile and k in tpl:
            out[k] = tpl[k]
        else:
            missing_vol.append(k)
    if missing_vol and not allow_template_volatile:
        # Partial catalog overlap: keep live keys we have, only hard-fail when
        # almost nothing matches (true incomplete dump under known schema).
        if len(set(named) & FO2_VOLATILE_NAMED) >= 10:
            # soft: copy all live named, skip missing template names
            for k, v in live.items():
                if not str(k).isdigit():
                    out[k] = v
        else:
            raise ValueError(
                "live FO2 missing volatile named keys (session-bound): "
                + ",".join(missing_vol)
            )
    else:
        # 3) stable named — live > opt/site > template
        for k in FO2_STABLE_NAMED:
            if k in live:
                out[k] = live[k]
                continue
            if k == "wMrJ8" and opt.get("wMrJ8") is not None:
                out[k] = opt["wMrJ8"]
            elif k == "WfbmX7":
                out[k] = page_url or opt.get("WfbmX7") or tpl.get(k)
            elif k == "JoSC2":
                out[k] = origin or opt.get("JoSC2") or tpl.get(k)
            elif k == "JDHe4" and opt.get("JDHe4") is not None:
                out[k] = opt["JDHe4"]
            elif k == "ybxU8" and opt.get("ybxU8") is not None:
                out[k] = opt["ybxU8"]
            elif k == "hpQq4":
                out[k] = (
                    (opt.get("RbLR5") or {}).get("cuBq9")
                    or opt.get("HHgeD5")
                    or opt.get("hpQq4")
                    or tpl.get(k)
                )
            elif k == "cbYg3":
                out[k] = len(sensors)
            elif k in tpl:
                out[k] = tpl[k]
            else:
                pass

    # Pin sensor-count mirror only when catalog name is present.
    if "cbYg3" in out or "cbYg3" in live:
        out["cbYg3"] = len(sensors)

    # Carry any extra live keys (future schema drift / FO2-only)
    for k, v in live.items():
        if k not in out:
            out[k] = v

    return order_fo2_plain(out)


def diff_fo2_plains(a: dict, b: dict) -> dict[str, Any]:
    """Compare two FO2 plains with stable/volatile/sensor buckets."""
    sa, sb = set(a), set(b)
    named_a = {k for k in sa if not str(k).isdigit()}
    named_b = {k for k in sb if not str(k).isdigit()}
    sensors_a = set(sensor_keys(a))
    sensors_b = set(sensor_keys(b))

    def _neq(keys: set[str]) -> list[str]:
        out = []
        for k in sorted(keys, key=lambda x: (not str(x).isdigit(), int(x) if str(x).isdigit() else x)):
            if a.get(k) != b.get(k):
                out.append(k)
        return out

    common_named = named_a & named_b
    return {
        "stable_equal": sorted(k for k in (common_named & FO2_STABLE_NAMED) if a.get(k) == b.get(k)),
        "stable_diff": _neq(common_named & FO2_STABLE_NAMED),
        "volatile_equal": sorted(k for k in (common_named & FO2_VOLATILE_NAMED) if a.get(k) == b.get(k)),
        "volatile_diff": _neq(common_named & FO2_VOLATILE_NAMED),
        "sensor_diff_count": len(_neq(sensors_a & sensors_b)),
        "sensors_only_a": sorted(sensors_a - sensors_b, key=int),
        "sensors_only_b": sorted(sensors_b - sensors_a, key=int),
        "named_only_a": sorted(named_a - named_b),
        "named_only_b": sorted(named_b - named_a),
    }


def fo2_status() -> dict:
    return {
        "schema_ready": True,
        "key_count": len(FO2_KEY_ORDER),
        "sensor_entry_count": 37,
        "stable_named": sorted(FO2_STABLE_NAMED),
        "volatile_named": sorted(FO2_VOLATILE_NAMED),
        "stable_count": len(FO2_STABLE_NAMED),
        "volatile_count": len(FO2_VOLATILE_NAMED),
        "fo1_keys": len(FO1_KEY_ORDER),
        "eb_keys": list(EB_KEY_ORDER),
        "dropped_from_fo1": sorted(FO2_DROPPED_KEYS),
        "fo2_only_keys": sorted(FO2_ONLY_KEYS),
        "core_sensor_fields": SENSOR_CORE_FIELDS,
        "sample": "logs/fc_captures/20260721_175819/fo2_plain.json",
        "hybrid": "build_fo2_plain_hybrid(live_browser_plain) — sensors+volatile from browser",
        "fa_local_wrap": "logs/har1/_node_vm_extract.js patches local FA for plain+FC dump",
        "fe_expand_fixed": True,
        "note": (
            "FO2 POST 400 on stale capture replay: all 37 sensors + ~22 volatile "
            "named keys are session-bound VM products and must be browser-live."
        ),
    }


if __name__ == "__main__":
    print(json.dumps(fo2_status(), ensure_ascii=False, indent=2))
