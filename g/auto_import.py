# -*- coding: utf-8 -*-
"""跑完 CLEAN 后自动入库 sub2api。"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable, Optional


def auto_import_enabled() -> bool:
    """
    CLEAN 成功号自动入库 sub2api。
    开启：AUTO_IMPORT=1 / true / on / yes（.env 默认 1）
    关闭：AUTO_IMPORT=0 / false / off / no
    """
    raw = (os.environ.get("AUTO_IMPORT") or "1").strip().lower()
    return raw in ("1", "true", "on", "yes", "y")


def import_clean_file(
    clean_path: Path | str,
    *,
    log: Optional[Callable[[str, str], None]] = None,
    merge: bool = True,
    max_workers: int = 1,
) -> dict[str, Any]:
    """
    把 email----sso / 纯 sso 的 CLEAN 文件导入 sub2api。
    返回 import_sso_to_upstream 结果；文件不存在/空则 ok=False。
    """
    def _log(msg: str, level: str = "info") -> None:
        if log:
            try:
                log(msg, level)
                return
            except Exception:
                pass
        print(f"[{level}] {msg}", flush=True)

    if not auto_import_enabled():
        _log("自动入库已关闭（AUTO_IMPORT=0）", "info")
        return {"ok": False, "skipped": True, "message": "AUTO_IMPORT disabled"}

    path = Path(clean_path)
    if not path.is_file():
        _log(f"自动入库跳过：CLEAN 文件不存在 {path}", "warn")
        return {"ok": False, "skipped": True, "message": f"missing: {path}"}

    try:
        # 延迟导入，避免 standalone 冷启动拖 Flask
        from app import import_sso_to_upstream, _read_sso_file_lines
    except Exception as e:
        _log(f"自动入库失败：无法加载 app 导入模块 · {e}", "error")
        return {"ok": False, "error": str(e)}

    try:
        lines = _read_sso_file_lines(path)
    except Exception as e:
        _log(f"自动入库失败：读 CLEAN 文件 · {e}", "error")
        return {"ok": False, "error": str(e)}

    if not lines:
        _log("自动入库跳过：CLEAN 文件为空", "warn")
        return {"ok": False, "skipped": True, "message": "empty clean file", "total": 0}

    _log(f"自动入库开始 · {path.name} · {len(lines)} 条", "info")
    try:
        result = import_sso_to_upstream(
            sso_lines=lines,
            merge=merge,
            max_workers=max(1, int(max_workers)),
        )
    except Exception as e:
        _log(f"自动入库异常 · {e}", "error")
        return {"ok": False, "error": str(e), "total": len(lines)}

    success = int(result.get("success") or 0)
    fail = int(result.get("fail") or 0)
    total = int(result.get("total") or len(lines))
    msg = result.get("message") or f"{success}/{total} 成功"
    level = "success" if success > 0 and fail == 0 else ("warn" if success > 0 else "error")
    _log(f"自动入库完成 · 成功 {success}/{total} · 失败 {fail} · {msg}", level)
    if fail:
        for r in (result.get("results") or [])[:10]:
            if r.get("status") != "ok":
                _log(
                    f"  失败 · {r.get('email') or r.get('sso_hint') or '?'}: {r.get('error')}",
                    "warn",
                )
    return result
