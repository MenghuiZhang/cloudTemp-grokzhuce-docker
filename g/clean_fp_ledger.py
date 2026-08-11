# -*- coding: utf-8 -*-
"""
CLEAN 成功指纹账本：每次 CLEAN 落盘时追加一条环境快照，方便事后比对
「哪类 locale/时区/WebGL/屏幕/出口」命中率更高。

文件（UTF-8 JSONL，一行一条）:
  keys/clean_fp_success.jsonl   — 仅 CLEAN
  keys/fp_outcome.jsonl         — CLEAN + MARKED（可选，便于算标记率）

读法:
  python -c "from g.clean_fp_ledger import summarize; print(summarize())"
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

_LOCK = threading.Lock()

_BASE = Path(__file__).resolve().parents[1]
_KEYS = _BASE / "keys"
_SUCCESS_FILE = _KEYS / "clean_fp_success.jsonl"
_OUTCOME_FILE = _KEYS / "fp_outcome.jsonl"


def _ledger_enabled() -> bool:
    raw = (os.environ.get("CLEAN_FP_LEDGER") or "1").strip().lower()
    return raw not in ("0", "false", "off", "no")


def _outcome_enabled() -> bool:
    """是否同时记 MARKED 到 fp_outcome.jsonl（默认开，方便对比）。"""
    raw = (os.environ.get("FP_OUTCOME_LEDGER") or "1").strip().lower()
    return raw not in ("0", "false", "off", "no")


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _proxy_host(proxy_spec: str) -> str:
    s = (proxy_spec or "").strip()
    if not s:
        return "direct"
    try:
        if "://" in s:
            rest = s.split("://", 1)[1]
            if "@" in rest:
                rest = rest.rsplit("@", 1)[-1]
            return rest.split("/", 1)[0]
        parts = s.split(":")
        if len(parts) >= 2 and parts[1].isdigit():
            return f"{parts[0]}:{parts[1]}"
    except Exception:
        pass
    return s[:48]


def _slim_device(fp: Optional[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(fp, dict):
        return {}
    device = fp.get("device_fp") if isinstance(fp.get("device_fp"), dict) else fp
    scr = device.get("screen") if isinstance(device.get("screen"), dict) else {}
    vp = device.get("viewport") if isinstance(device.get("viewport"), dict) else (
        fp.get("viewport") if isinstance(fp.get("viewport"), dict) else {}
    )
    return {
        "fp_os": device.get("fp_os") or fp.get("fp_os"),
        "locale": fp.get("locale") or device.get("locale"),
        "timezone": fp.get("timezone") or device.get("timezone"),
        "timing": fp.get("timing"),
        "humanize": bool(fp.get("humanize")) if "humanize" in fp else None,
        "viewport": {
            "width": vp.get("width"),
            "height": vp.get("height"),
        }
        if vp
        else None,
        "screen": {
            "width": scr.get("width"),
            "height": scr.get("height"),
        }
        if scr
        else None,
        "device_pixel_ratio": device.get("device_pixel_ratio") or fp.get("device_pixel_ratio"),
        "hardware_concurrency": device.get("hardware_concurrency")
        or fp.get("hardware_concurrency"),
        "device_memory_gb": device.get("device_memory_gb") or fp.get("device_memory_gb"),
        "webgl_vendor": device.get("webgl_vendor") or fp.get("webgl_vendor"),
        "webgl_renderer": device.get("webgl_renderer") or fp.get("webgl_renderer"),
        "color_depth": device.get("color_depth"),
        "max_touch_points": device.get("max_touch_points"),
        "media_micros": device.get("media_micros"),
        "media_speakers": device.get("media_speakers"),
        "media_webcams": device.get("media_webcams"),
        "audio_sample_rate": device.get("audio_sample_rate"),
    }


def build_outcome_record(
    row: dict[str, Any],
    *,
    outcome: str,
    mail_domain: str = "",
    proxy_mode: str = "",
    batch_id: str = "",
) -> dict[str, Any]:
    """从 run_one 的 row 抽可比对字段。"""
    fp = row.get("fp") if isinstance(row.get("fp"), dict) else {}
    risk = row.get("risk") if isinstance(row.get("risk"), dict) else {}
    ss_dev = row.get("device_fp") if isinstance(row.get("device_fp"), dict) else None
    # same_session 回写的 device_fp 优先
    if ss_dev:
        merged_fp = dict(fp)
        merged_fp["device_fp"] = ss_dev
        for k in (
            "webgl_vendor",
            "webgl_renderer",
            "hardware_concurrency",
            "device_memory_gb",
            "device_pixel_ratio",
            "screen",
            "viewport",
        ):
            if ss_dev.get(k) is not None and not merged_fp.get(k):
                merged_fp[k] = ss_dev.get(k)
        fp = merged_fp

    email = str(row.get("email") or "")
    domain = mail_domain
    if not domain and "@" in email:
        domain = email.split("@", 1)[-1]

    device = _slim_device(fp)
    proxy_spec = str(row.get("proxy_spec") or "")
    # 出口：row 顶层优先，其次 fp / region 元数据
    egress_ip = str(
        row.get("egress_ip")
        or fp.get("egress_ip")
        or row.get("egress")
        or ""
    ).strip()
    egress_cc = str(
        row.get("egress_cc") or fp.get("egress_cc") or ""
    ).strip().upper()
    egress_family = str(
        row.get("egress_family") or fp.get("egress_family") or ""
    ).strip().lower()
    egress_key = egress_ip or (
        f"{egress_cc}/{egress_family}" if (egress_cc or egress_family) else ""
    )
    rec: dict[str, Any] = {
        "ts": _now_iso(),
        "outcome": outcome,  # CLEAN | MARKED | FAIL
        "email": email,
        "domain": domain,
        "batch_id": batch_id or None,
        "idx": row.get("idx"),
        "region": row.get("region") or fp.get("region"),
        "egress_ip": egress_ip or None,
        "egress_cc": egress_cc or None,
        "egress_family": egress_family or None,
        "egress_key": egress_key or None,
        "proxy_mode": proxy_mode or None,
        "proxy_host": _proxy_host(proxy_spec),
        "proxy_spec": proxy_spec[:120] if proxy_spec else "",
        "device": device,
        "castle_len": row.get("castle_len"),
        "castle_method": row.get("castle_method"),
        "browser_from_pool": row.get("browser_from_pool"),
        "browser_launch_s": row.get("browser_launch_s"),
        "elapsed_reg_s": row.get("elapsed_reg_s") or row.get("elapsed_s"),
        "risk_summary": risk.get("summary") or row.get("error") or None,
        "risk_score": risk.get("risk_score"),
        "bot_flag_source": risk.get("bot_flag_source"),
        "policy": risk.get("policy"),
        "impersonate": risk.get("impersonate"),
    }
    # 紧凑签名：人工扫一眼 / 聚合用
    d = device
    scr = d.get("screen") or {}
    vp = d.get("viewport") or {}
    rec["sig"] = "|".join(
        [
            str(d.get("fp_os") or ""),
            str(d.get("locale") or ""),
            str(d.get("timezone") or ""),
            str(d.get("timing") or ""),
            f"scr={scr.get('width')}x{scr.get('height')}",
            f"vp={vp.get('width')}x{vp.get('height')}",
            f"dpr={d.get('device_pixel_ratio')}",
            f"hw={d.get('hardware_concurrency')}",
            f"mem={d.get('device_memory_gb')}",
            str(d.get("webgl_renderer") or "")[:48],
            str(rec.get("region") or ""),
            str(egress_ip or egress_cc or ""),
            str(domain or ""),
        ]
    )
    return rec


def _append_jsonl(path: Path, rec: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(rec, ensure_ascii=False, default=str)
    with _LOCK:
        with open(path, "a", encoding="utf-8", newline="\n") as f:
            f.write(line + "\n")


def record_outcome(
    row: dict[str, Any],
    *,
    outcome: str,
    mail_domain: str = "",
    proxy_mode: str = "",
    batch_id: str = "",
    log: Optional[Any] = None,
) -> Optional[dict[str, Any]]:
    """
    记一笔结果。CLEAN 必写 success 账本；CLEAN/MARKED 都写 outcome（可关）。
    """
    if not _ledger_enabled():
        return None
    try:
        rec = build_outcome_record(
            row,
            outcome=outcome,
            mail_domain=mail_domain,
            proxy_mode=proxy_mode,
            batch_id=batch_id,
        )
    except Exception as e:
        if log:
            try:
                log(f"指纹账本构建失败 · {e}", "warn")
            except Exception:
                pass
        return None

    try:
        if outcome == "CLEAN":
            _append_jsonl(_SUCCESS_FILE, rec)
        if _outcome_enabled() and outcome in ("CLEAN", "MARKED"):
            _append_jsonl(_OUTCOME_FILE, rec)
        if log and outcome == "CLEAN":
            try:
                d = rec.get("device") or {}
                log(
                    f"指纹账本 · CLEAN · {d.get('fp_os')}/{d.get('locale')}/"
                    f"{d.get('timezone')} · hw={d.get('hardware_concurrency')} · "
                    f"gpu={str(d.get('webgl_renderer') or '')[:28]} · "
                    f"→ {_SUCCESS_FILE.name}",
                    "info",
                )
            except Exception:
                pass
        return rec
    except Exception as e:
        if log:
            try:
                log(f"指纹账本写入失败 · {e}", "warn")
            except Exception:
                pass
        return None


def record_clean_success(
    row: dict[str, Any],
    *,
    mail_domain: str = "",
    proxy_mode: str = "",
    batch_id: str = "",
    log: Optional[Any] = None,
) -> Optional[dict[str, Any]]:
    return record_outcome(
        row,
        outcome="CLEAN",
        mail_domain=mail_domain,
        proxy_mode=proxy_mode,
        batch_id=batch_id,
        log=log,
    )


def record_marked(
    row: dict[str, Any],
    *,
    mail_domain: str = "",
    proxy_mode: str = "",
    batch_id: str = "",
    log: Optional[Any] = None,
) -> Optional[dict[str, Any]]:
    return record_outcome(
        row,
        outcome="MARKED",
        mail_domain=mail_domain,
        proxy_mode=proxy_mode,
        batch_id=batch_id,
        log=log,
    )


def iter_records(path: Optional[Path] = None) -> list[dict[str, Any]]:
    p = path or _SUCCESS_FILE
    if not p.is_file():
        return []
    out: list[dict[str, Any]] = []
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def summarize(path: Optional[Path] = None, top: int = 12) -> dict[str, Any]:
    """
    聚合成功账本：按 locale / tz / os / gpu / region / domain 统计次数。
    若给 outcome 文件，顺带算 CLEAN 率。
    """
    from collections import Counter

    recs = iter_records(path or _SUCCESS_FILE)
    by_locale: Counter = Counter()
    by_tz: Counter = Counter()
    by_os: Counter = Counter()
    by_gpu: Counter = Counter()
    by_region: Counter = Counter()
    by_domain: Counter = Counter()
    by_timing: Counter = Counter()
    by_hw: Counter = Counter()
    by_scr: Counter = Counter()
    by_egress_ip: Counter = Counter()
    by_egress_cc: Counter = Counter()

    def _egress_label(r: dict[str, Any]) -> str:
        ip = str(r.get("egress_ip") or "").strip()
        if ip:
            return ip
        key = str(r.get("egress_key") or "").strip()
        if key:
            return key
        cc = str(r.get("egress_cc") or "").strip()
        fam = str(r.get("egress_family") or "").strip()
        if cc or fam:
            return f"{cc or '?'}/{fam or '?'}"
        return ""

    for r in recs:
        d = r.get("device") or {}
        by_locale[str(d.get("locale") or "?")] += 1
        by_tz[str(d.get("timezone") or "?")] += 1
        by_os[str(d.get("fp_os") or "?")] += 1
        gpu = str(d.get("webgl_renderer") or "?")[:48]
        by_gpu[gpu] += 1
        by_region[str(r.get("region") or "?")] += 1
        by_domain[str(r.get("domain") or "?")] += 1
        by_timing[str(d.get("timing") or "?")] += 1
        by_hw[str(d.get("hardware_concurrency") or "?")] += 1
        scr = d.get("screen") or {}
        by_scr[f"{scr.get('width')}x{scr.get('height')}"] += 1
        eg = _egress_label(r)
        if eg:
            by_egress_ip[eg] += 1
        cc = str(r.get("egress_cc") or "").strip().upper()
        if cc:
            by_egress_cc[cc] += 1

    def _top(c: Counter) -> list[tuple[str, int]]:
        return c.most_common(top)

    result: dict[str, Any] = {
        "file": str(path or _SUCCESS_FILE),
        "total_clean": len(recs),
        "by_locale": _top(by_locale),
        "by_timezone": _top(by_tz),
        "by_os": _top(by_os),
        "by_gpu": _top(by_gpu),
        "by_region": _top(by_region),
        "by_domain": _top(by_domain),
        "by_timing": _top(by_timing),
        "by_hw": _top(by_hw),
        "by_screen": _top(by_scr),
        "by_egress_ip": _top(by_egress_ip),
        "by_egress_cc": _top(by_egress_cc),
    }

    # 若有 outcome 全量，算各维 CLEAN 率
    if _OUTCOME_FILE.is_file():
        all_recs = iter_records(_OUTCOME_FILE)
        dim_stats: dict[str, dict[str, list[int]]] = {
            "locale": {},
            "timezone": {},
            "region": {},
            "domain": {},
            "fp_os": {},
            "gpu": {},
            "egress_ip": {},
            "egress_cc": {},
        }
        for r in all_recs:
            d = r.get("device") or {}
            eg_lab = _egress_label(r) or "?"
            pairs = {
                "locale": str(d.get("locale") or "?"),
                "timezone": str(d.get("timezone") or "?"),
                "region": str(r.get("region") or "?"),
                "domain": str(r.get("domain") or "?"),
                "fp_os": str(d.get("fp_os") or "?"),
                "gpu": str(d.get("webgl_renderer") or "?")[:40],
                "egress_ip": eg_lab,
                "egress_cc": str(r.get("egress_cc") or "?") or "?",
            }
            is_clean = 1 if r.get("outcome") == "CLEAN" else 0
            is_mark = 1 if r.get("outcome") == "MARKED" else 0
            for dim, key in pairs.items():
                bucket = dim_stats[dim].setdefault(key, [0, 0])  # clean, marked
                bucket[0] += is_clean
                bucket[1] += is_mark

        rates: dict[str, list[dict[str, Any]]] = {}
        for dim, mp in dim_stats.items():
            rows = []
            for key, (c, m) in mp.items():
                tot = c + m
                if tot <= 0:
                    continue
                rows.append(
                    {
                        "key": key,
                        "clean": c,
                        "marked": m,
                        "total": tot,
                        "clean_rate": round(c / tot * 100, 1),
                    }
                )
            rows.sort(key=lambda x: (-x["total"], -x["clean_rate"]))
            rates[dim] = rows[:top]
        result["outcome_file"] = str(_OUTCOME_FILE)
        result["outcome_total"] = len(all_recs)
        result["clean_rate_by"] = rates

    return result


def success_file() -> Path:
    return _SUCCESS_FILE


def outcome_file() -> Path:
    return _OUTCOME_FILE
