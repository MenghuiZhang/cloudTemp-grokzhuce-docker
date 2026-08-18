"""Two-phase BFS scan/apply operations for historical auth files."""
from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from g.bfs_service import (
    apply_bfs_metadata,
    atomic_write_json,
    inspect_record_bfs,
    token_fingerprint,
)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _records(data: Any) -> list[tuple[str | None, dict[str, Any]]]:
    if not isinstance(data, dict):
        return []
    fields = ("access_token", "key", "sso", "id_token", "refresh_token")
    if any(data.get(field) for field in fields):
        return [(None, data)]
    return [
        (str(key), value)
        for key, value in data.items()
        if isinstance(value, dict) and any(value.get(field) for field in fields)
    ]


def preview_scan(paths: Iterable[str | Path], report_dir: str | Path) -> dict[str, Any]:
    roots = [Path(path).expanduser().resolve() for path in paths]
    report: dict[str, Any] = {
        "version": 1,
        "scan_id": secrets.token_hex(12),
        "created_at": _now(),
        "applied_at": "",
        "roots": [str(path) for path in roots],
        "counts": {"total": 0, "flagged": 0, "clean": 0, "unknown": 0, "error": 0},
        "items": [],
    }
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:
                report["counts"]["error"] += 1
                report["items"].append({
                    "path": str(path), "record_key": None, "status": "error", "error": str(exc)[:160]
                })
                continue
            for key, record in _records(data):
                info = inspect_record_bfs(record)
                status = "flagged" if info.get("has_bfs") else ("clean" if info.get("ok") else "unknown")
                report["counts"]["total"] += 1
                report["counts"][status] += 1
                report["items"].append({
                    "path": str(path),
                    "record_key": key,
                    "email": str(record.get("email") or ""),
                    "status": status,
                    "bfs_value": info.get("bfs"),
                    "source": info.get("source") or "",
                })
    folder = Path(report_dir).expanduser().resolve()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = folder / f"bfs-scan-{stamp}-{report['scan_id'][:8]}.json"
    atomic_write_json(report_path, report)
    return {**report, "report_path": str(report_path)}


def _inside(path: Path, roots: list[Path]) -> bool:
    return any(path == root or root in path.parents for root in roots)


def apply_scan_report(report_path: str | Path) -> dict[str, Any]:
    path = Path(report_path).expanduser().resolve()
    report = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(report, dict) or report.get("version") != 1:
        raise ValueError("不支持的 BFS 扫描报告")
    if report.get("applied_at"):
        raise ValueError("该报告已经 apply")
    roots = [Path(root).resolve() for root in report.get("roots") or []]
    changed = 0
    skipped = 0
    for item in report.get("items") or []:
        if item.get("status") == "error":
            skipped += 1
            continue
        target = Path(str(item.get("path") or "")).resolve()
        if not _inside(target, roots):
            raise ValueError("报告包含超出扫描目录的路径")
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
            key = item.get("record_key")
            record = data if key is None else data.get(str(key))
            if not isinstance(record, dict):
                skipped += 1
                continue
            info = inspect_record_bfs(record)
            apply_bfs_metadata(record, info)
            atomic_write_json(target, data)
            changed += 1
        except (OSError, json.JSONDecodeError):
            skipped += 1
    report["applied_at"] = _now()
    report["apply_result"] = {"changed": changed, "skipped": skipped}
    atomic_write_json(path, report)
    return {"ok": True, "report_path": str(path), "changed": changed, "skipped": skipped}


def set_token_bound_override(auth_path: str | Path, *, reason: str) -> dict[str, Any]:
    path = Path(auth_path).expanduser().resolve()
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("认证文件必须是 JSON 对象")
    if data.get("risk_status") == "risk_marked" or data.get("classification_source") == "risk":
        raise ValueError("Risk MARKED 不允许手动放行")
    info = inspect_record_bfs(data)
    status = "flagged" if info.get("has_bfs") else ("clean" if info.get("ok") else "unknown")
    if status not in ("flagged", "unknown"):
        raise ValueError("只允许放行 BFS flagged/unknown")
    token = str(data.get("access_token") or data.get("key") or "")
    fingerprint = token_fingerprint(token)
    if not fingerprint:
        raise ValueError("缺少可绑定的 access token")
    data["bfs_override"] = {
        "token_fingerprint": fingerprint,
        "created_at": _now(),
        "reason": str(reason or "manual override")[:240],
    }
    data["disabled"] = False
    atomic_write_json(path, data)
    return {"ok": True, "path": str(path), "status": status, "token_fingerprint": fingerprint}
