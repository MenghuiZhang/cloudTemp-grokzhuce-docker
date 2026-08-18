"""Atomic, mutually-exclusive account classification files."""
from __future__ import annotations

import json
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


FINAL_STATES = ("clean", "marked", "unchecked", "infra_retry")


def _private_atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
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


class ClassificationStore:
    def __init__(self, output_file: str | Path):
        self.output_file = Path(output_file)
        self._lock = threading.RLock()

    def path_for(self, state: str) -> Path:
        if state not in FINAL_STATES:
            raise ValueError(f"invalid classification: {state}")
        return self.output_file.with_name(f"{self.output_file.stem}_{state}.txt")

    @property
    def marked_meta_path(self) -> Path:
        return self.output_file.with_name(f"{self.output_file.stem}_marked_meta.jsonl")

    @property
    def pending_path(self) -> Path:
        return self.output_file.with_name(f"{self.output_file.stem}_pending_bfs.json")

    @staticmethod
    def _line(email: str, sso: str) -> str:
        clean_email = str(email or "").replace("\r", " ").replace("\n", " ").strip()
        clean_sso = str(sso or "").replace("\r", "").replace("\n", "").strip()
        return f"{clean_email}----{clean_sso}"

    @staticmethod
    def _without(lines: list[str], *, email: str, sso: str) -> list[str]:
        wanted = ClassificationStore._line(email, sso)
        return [line for line in lines if line.strip() != wanted]

    def finalize(
        self,
        *,
        email: str,
        sso: str,
        state: str,
        reason: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> Path:
        target = self.path_for(state)
        line = self._line(email, sso)
        with self._lock:
            for candidate_state in FINAL_STATES:
                path = self.path_for(candidate_state)
                try:
                    rows = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
                except OSError:
                    rows = []
                rows = self._without(rows, email=email, sso=sso)
                if candidate_state == state:
                    rows.append(line)
                if rows or path.exists() or candidate_state == state:
                    _private_atomic_text(path, "\n".join(rows) + ("\n" if rows else ""))
            if state == "marked":
                event = {
                    "at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                    "email": str(email or "").strip(),
                    "reason": str(reason or "MARKED")[:160],
                    **dict(metadata or {}),
                }
                previous = self.marked_meta_path.read_text(encoding="utf-8") if self.marked_meta_path.is_file() else ""
                _private_atomic_text(
                    self.marked_meta_path,
                    previous + json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n",
                )
            self.remove_pending(email=email, sso=sso)
        return target

    def _read_pending(self) -> list[dict[str, Any]]:
        try:
            value = json.loads(self.pending_path.read_text(encoding="utf-8"))
            return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    def add_pending(self, *, email: str, sso: str, data: dict[str, Any] | None = None) -> None:
        with self._lock:
            rows = self._read_pending()
            rows = [row for row in rows if row.get("sso") != sso]
            rows.append({"email": email, "sso": sso, **dict(data or {})})
            _private_atomic_text(self.pending_path, json.dumps(rows, ensure_ascii=False, indent=2) + "\n")

    def remove_pending(self, *, email: str, sso: str) -> None:
        with self._lock:
            if not self.pending_path.exists():
                return
            rows = [row for row in self._read_pending() if row.get("sso") != sso]
            _private_atomic_text(self.pending_path, json.dumps(rows, ensure_ascii=False, indent=2) + "\n")

    def pending(self) -> list[dict[str, Any]]:
        with self._lock:
            return self._read_pending()

