"""Local JWT ``bfs`` inspection and CPA auth scanning.

The payload is decoded only for classification.  This module intentionally
does not treat decoding as signature verification or authentication.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterable


TOKEN_FIELDS = ("access_token", "sso", "id_token", "refresh_token")


def _decode_payload(token: str) -> tuple[bool, dict[str, Any]]:
    try:
        parts = str(token or "").strip().split(".")
        if len(parts) < 2:
            return False, {}
        segment = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(segment.encode("ascii")))
        return (True, payload) if isinstance(payload, dict) else (False, {})
    except Exception:
        return False, {}


def inspect_jwt_bfs(token: str) -> dict[str, Any]:
    """Classify one JWT by ``bfs`` key presence, including ``bfs: 0``."""
    raw = str(token or "").strip()
    if raw.startswith("sso="):
        raw = raw[4:].strip()
    if raw.startswith("{"):
        try:
            nested = json.loads(raw)
        except Exception:
            nested = None
        if isinstance(nested, dict):
            for key in ("access_token", "token", "sso", "id_token", "key"):
                candidate = str(nested.get(key) or "").strip()
                if candidate.count(".") >= 2:
                    raw = candidate
                    break
    ok, claims = _decode_payload(raw) if raw.count(".") >= 2 else (False, {})
    has_bfs = bool(ok and "bfs" in claims)
    return {
        "ok": ok,
        "has_bfs": has_bfs,
        "bfs": claims.get("bfs") if has_bfs else None,
        "tier": claims.get("tier"),
        "sub": str(claims.get("sub") or claims.get("principal_id") or "")[:48],
        "exp": claims.get("exp"),
        "referrer": claims.get("referrer"),
        "claim_keys": sorted(str(key) for key in claims) if claims else [],
    }


def inspect_token_bundle_bfs(
    *,
    access_token: str = "",
    sso: str = "",
    id_token: str = "",
    refresh_token: str = "",
) -> dict[str, Any]:
    """Inspect all JWT-shaped values; any source containing ``bfs`` wins."""
    issued_sources = (
        ("access_token", access_token),
        ("id_token", id_token),
        ("refresh_token", refresh_token),
    )
    # Once OAuth returned token material, an entirely undecodable token bundle
    # is UNKNOWN even if the older SSO JWT itself is readable.
    has_issued_material = any(str(value or "").strip() for _, value in issued_sources)
    sources = issued_sources + (("sso", sso),)
    result: dict[str, Any] = {
        "ok": False,
        "has_bfs": False,
        "bfs": None,
        "source": "",
        "tier": None,
        "sub": "",
        "exp": None,
        "referrer": None,
        "claim_keys": [],
        "checked": [],
    }
    for name, value in sources:
        raw = str(value or "").strip()
        if raw.count(".") < 2:
            continue
        info = inspect_jwt_bfs(raw)
        result["checked"].append(name)
        if not info.get("ok"):
            continue
        if not result["ok"]:
            result.update(
                ok=True,
                has_bfs=bool(info.get("has_bfs")),
                bfs=info.get("bfs"),
                source=name,
                tier=info.get("tier"),
                sub=info.get("sub") or "",
                exp=info.get("exp"),
                referrer=info.get("referrer"),
                claim_keys=list(info.get("claim_keys") or []),
            )
        if info.get("has_bfs"):
            result.update(
                ok=True,
                has_bfs=True,
                bfs=info.get("bfs"),
                source=name,
                tier=info.get("tier"),
                sub=info.get("sub") or result.get("sub") or "",
                exp=info.get("exp") or result.get("exp"),
                referrer=info.get("referrer") or result.get("referrer"),
                claim_keys=list(info.get("claim_keys") or []),
            )
            break
    if has_issued_material and not any(
        inspect_jwt_bfs(str(value or "").strip()).get("ok")
        for _, value in issued_sources
        if str(value or "").strip().count(".") >= 2
    ):
        result.update(ok=False, has_bfs=False, bfs=None, source="")
    return result


def inspect_record_bfs(record: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(record, dict):
        return {"ok": False, "has_bfs": False, "bfs": None, "source": "", "error": "invalid record"}
    info = inspect_token_bundle_bfs(
        access_token=str(record.get("access_token") or record.get("key") or ""),
        sso=str(record.get("sso") or ""),
        id_token=str(record.get("id_token") or ""),
        refresh_token=str(record.get("refresh_token") or ""),
    )
    info["email"] = str(record.get("email") or "").strip()
    return info


def apply_bfs_metadata(
    record: dict[str, Any],
    info: dict[str, Any] | None = None,
    *,
    disable_flagged: bool = True,
    disable_unknown: bool = True,
) -> dict[str, Any]:
    """Annotate a CPA record and enforce the agreed disabled policy."""
    result = info or inspect_record_bfs(record)
    if not result.get("ok"):
        record.update(bfs=None, bfs_checked=False, bfs_status="unknown")
        record.pop("bfs_value", None)
        record.pop("bfs_source", None)
        if disable_unknown:
            record["disabled"] = True
        return record
    flagged = bool(result.get("has_bfs"))
    record.update(
        bfs=flagged,
        bfs_checked=True,
        bfs_status="flagged" if flagged else "clean",
    )
    if flagged:
        record["bfs_value"] = result.get("bfs")
        record["bfs_source"] = str(result.get("source") or "")
        if disable_flagged:
            record["disabled"] = True
    else:
        record.pop("bfs_value", None)
        record.pop("bfs_source", None)
    return record


def token_fingerprint(token: str) -> str:
    raw = str(token or "").strip().encode("utf-8")
    return hashlib.sha256(raw).hexdigest() if raw else ""


def _record_rows(data: Any, filename: str) -> Iterable[tuple[str, dict[str, Any]]]:
    if not isinstance(data, dict):
        return []
    if any(data.get(key) for key in ("access_token", "key", "sso", "id_token", "refresh_token")):
        return [(filename, data)]
    rows: list[tuple[str, dict[str, Any]]] = []
    for key, value in data.items():
        if isinstance(value, dict) and any(
            value.get(field) for field in ("access_token", "key", "sso", "id_token", "refresh_token")
        ):
            rows.append((f"{filename}#{str(key)[:80]}", value))
    return rows


def scan_auth_dirs(paths: Iterable[str | Path], *, include_clean: bool = True) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "ok": True,
        "total": 0,
        "bfs_count": 0,
        "clean_count": 0,
        "unknown_count": 0,
        "error_count": 0,
        "bfs_rate": 0.0,
        "bfs_value_dist": {},
        "items": [],
    }
    values: dict[str, int] = {}
    for raw_path in paths:
        root = Path(raw_path)
        if not root.is_dir():
            continue
        for path in sorted(root.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:
                summary["total"] += 1
                summary["error_count"] += 1
                summary["items"].append({"file": path.name, "status": "error", "error": str(exc)[:160]})
                continue
            rows = list(_record_rows(data, path.name))
            if not rows:
                continue
            for label, record in rows:
                summary["total"] += 1
                info = inspect_record_bfs(record)
                status = "flagged" if info.get("has_bfs") else ("clean" if info.get("ok") else "unknown")
                item = {
                    "file": label,
                    "path": str(path),
                    "email": str(record.get("email") or ""),
                    "status": status,
                    "has_bfs": bool(info.get("has_bfs")),
                    "bfs": info.get("bfs"),
                    "source": info.get("source") or "",
                }
                if status == "flagged":
                    summary["bfs_count"] += 1
                    key = str(info.get("bfs"))
                    values[key] = values.get(key, 0) + 1
                elif status == "clean":
                    summary["clean_count"] += 1
                else:
                    summary["unknown_count"] += 1
                if include_clean or status != "clean":
                    summary["items"].append(item)
    decoded = summary["bfs_count"] + summary["clean_count"]
    summary["bfs_rate"] = round(100.0 * summary["bfs_count"] / decoded, 2) if decoded else 0.0
    summary["bfs_value_dist"] = values
    return summary


def atomic_write_json(path: str | Path, payload: Any, *, mode: int = 0o600) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}-", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temp_name, mode)
        except OSError:
            pass
        os.replace(temp_name, target)
        temp_name = ""
    finally:
        if temp_name:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
