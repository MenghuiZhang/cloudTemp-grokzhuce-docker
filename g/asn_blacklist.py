"""Persistent manual and evidence-based ASN blacklist."""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import time
from pathlib import Path
from typing import Any


WINDOW_SECONDS = 24 * 60 * 60
AUTO_TTL_SECONDS = 24 * 60 * 60
AUTO_DISTINCT_IP_THRESHOLD = 5


def normalize_asn(value: Any) -> int:
    match = re.search(r"(?:AS)?(\d+)", str(value or "").strip(), re.I)
    if not match:
        raise ValueError("ASN 格式无效")
    asn = int(match.group(1))
    if not 1 <= asn <= 4_294_967_295:
        raise ValueError("ASN 超出范围")
    return asn


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temp_name, 0o600)
        except OSError:
            pass
        os.replace(temp_name, path)
        temp_name = ""
    finally:
        if temp_name:
            try:
                os.unlink(temp_name)
            except OSError:
                pass


class AsnBlacklistStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.RLock()

    @staticmethod
    def _default() -> dict[str, Any]:
        return {"version": 1, "manual": [], "auto": [], "samples": []}

    def _load(self) -> dict[str, Any]:
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            loaded = {}
        doc = self._default()
        if isinstance(loaded, dict):
            for key in ("manual", "auto", "samples"):
                if isinstance(loaded.get(key), list):
                    doc[key] = loaded[key]
        return doc

    @staticmethod
    def _purge(doc: dict[str, Any], now: float) -> None:
        doc["auto"] = [row for row in doc["auto"] if float(row.get("expires_at") or 0) > now]
        doc["samples"] = [row for row in doc["samples"] if float(row.get("at") or 0) >= now - WINDOW_SECONDS]

    def _save(self, doc: dict[str, Any]) -> None:
        _atomic_json(self.path, doc)

    def add_manual(self, asn: Any, note: str = "", *, now: float | None = None) -> dict[str, Any]:
        normalized = normalize_asn(asn)
        current = float(now if now is not None else time.time())
        with self._lock:
            doc = self._load()
            self._purge(doc, current)
            doc["manual"] = [row for row in doc["manual"] if int(row.get("asn") or 0) != normalized]
            doc["manual"].append({"asn": normalized, "note": str(note or "")[:160], "created_at": current})
            self._save(doc)
        return {"asn": normalized, "source": "manual", "note": str(note or "")[:160]}

    def remove(self, asn: Any) -> bool:
        normalized = normalize_asn(asn)
        with self._lock:
            doc = self._load()
            before = len(doc["manual"]) + len(doc["auto"])
            doc["manual"] = [row for row in doc["manual"] if int(row.get("asn") or 0) != normalized]
            doc["auto"] = [row for row in doc["auto"] if int(row.get("asn") or 0) != normalized]
            self._save(doc)
            return before != len(doc["manual"]) + len(doc["auto"])

    def record_risk_marked(
        self,
        *,
        asn: Any,
        ip: str,
        now: float | None = None,
    ) -> dict[str, Any]:
        normalized = normalize_asn(asn)
        address = str(ip or "").strip()
        if not address:
            raise ValueError("缺少出口 IP")
        current = float(now if now is not None else time.time())
        with self._lock:
            doc = self._load()
            self._purge(doc, current)
            if not any(
                int(row.get("asn") or 0) == normalized and str(row.get("ip") or "") == address
                for row in doc["samples"]
            ):
                doc["samples"].append({"asn": normalized, "ip": address, "at": current})
            distinct = {
                str(row.get("ip") or "")
                for row in doc["samples"]
                if int(row.get("asn") or 0) == normalized and str(row.get("ip") or "")
            }
            learned = len(distinct) >= AUTO_DISTINCT_IP_THRESHOLD
            if learned and not any(int(row.get("asn") or 0) == normalized for row in doc["auto"]):
                doc["auto"].append(
                    {
                        "asn": normalized,
                        "created_at": current,
                        "expires_at": current + AUTO_TTL_SECONDS,
                        "evidence_count": len(distinct),
                    }
                )
            self._save(doc)
            return {"asn": normalized, "distinct_ips": len(distinct), "learned": learned}

    def is_blocked(self, asn: Any, *, now: float | None = None) -> tuple[bool, dict[str, Any]]:
        normalized = normalize_asn(asn)
        current = float(now if now is not None else time.time())
        with self._lock:
            doc = self._load()
            before = len(doc["auto"]) + len(doc["samples"])
            self._purge(doc, current)
            if before != len(doc["auto"]) + len(doc["samples"]):
                self._save(doc)
            for row in doc["manual"]:
                if int(row.get("asn") or 0) == normalized:
                    return True, {"asn": normalized, "source": "manual", "note": row.get("note") or ""}
            for row in doc["auto"]:
                if int(row.get("asn") or 0) == normalized:
                    return True, {
                        "asn": normalized,
                        "source": "auto",
                        "expires_at": float(row.get("expires_at") or 0),
                        "evidence_count": int(row.get("evidence_count") or 0),
                    }
            return False, {"asn": normalized, "source": ""}

    def public(self, *, now: float | None = None) -> dict[str, Any]:
        current = float(now if now is not None else time.time())
        with self._lock:
            doc = self._load()
            self._purge(doc, current)
            sample_counts: dict[int, set[str]] = {}
            for row in doc["samples"]:
                try:
                    sample_counts.setdefault(normalize_asn(row.get("asn")), set()).add(str(row.get("ip") or ""))
                except ValueError:
                    continue
            items = [
                {"asn": int(row["asn"]), "label": f"AS{int(row['asn'])}", "source": "manual", "note": row.get("note") or "", "expires_at": None}
                for row in doc["manual"]
                if row.get("asn")
            ]
            items.extend(
                {
                    "asn": int(row["asn"]),
                    "label": f"AS{int(row['asn'])}",
                    "source": "auto",
                    "note": "",
                    "expires_at": float(row.get("expires_at") or 0),
                    "evidence_count": int(row.get("evidence_count") or len(sample_counts.get(int(row["asn"]), set()))),
                }
                for row in doc["auto"]
                if row.get("asn")
            )
            return {
                "items": sorted(items, key=lambda row: (int(row["asn"]), row["source"])),
                "threshold": AUTO_DISTINCT_IP_THRESHOLD,
                "window_seconds": WINDOW_SECONDS,
                "auto_ttl_seconds": AUTO_TTL_SECONDS,
            }

