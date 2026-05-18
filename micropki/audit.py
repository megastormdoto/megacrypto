from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

_ZERO_HASH = "0" * 64


class AuditLogger:

    def __init__(self, audit_dir: str | Path = "./pki/audit"):
        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.audit_dir / "audit.log"
        self.chain_path = self.audit_dir / "chain.dat"
        self._lock = threading.Lock()
        self._prev_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        if self.chain_path.is_file():
            text = self.chain_path.read_text(encoding="utf-8").strip()
            lines = text.splitlines()
            if lines:
                return lines[-1].strip()
        return _ZERO_HASH

    def _compute_hash(self, entry: dict) -> str:
        entry_copy = json.loads(json.dumps(entry, sort_keys=True, ensure_ascii=False))
        if "integrity" in entry_copy:
            entry_copy["integrity"].pop("hash", None)
        canonical = json.dumps(entry_copy, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def log_event(
            self,
            operation: str,
            status: str,
            message: str,
            metadata: dict | None = None,
            level: str = "AUDIT",
    ) -> dict:
        with self._lock:
            now = datetime.now(timezone.utc)
            entry = {
                "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond:06d}Z",
                "level": level,
                "operation": operation,
                "status": status,
                "message": message,
                "system": "megacrypto",  # <--- ВАША МЕТКА
                "metadata": metadata or {},
                "integrity": {
                    "prev_hash": self._prev_hash,
                    "hash": "",
                },
            }
            current_hash = self._compute_hash(entry)
            entry["integrity"]["hash"] = current_hash

            line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

            with open(self.chain_path, "a", encoding="utf-8") as f:
                f.write(current_hash + "\n")

            self._prev_hash = current_hash
            return entry


def verify_log(
        log_path: str | Path = "./pki/audit/audit.log",
        chain_path: str | Path = "./pki/audit/chain.dat",
) -> tuple[bool, int | None]:
    log_path = Path(log_path)
    chain_path = Path(chain_path)

    if not log_path.is_file():
        return True, None

    entries: list[dict] = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                return False, len(entries)

    if not entries:
        return True, None

    stored_hashes: list[str] = []
    if chain_path.is_file():
        with open(chain_path, "r", encoding="utf-8") as f:
            for line in f:
                h = line.strip()
                if h:
                    stored_hashes.append(h)

    prev_hash = _ZERO_HASH
    for i, entry in enumerate(entries):
        integrity = entry.get("integrity", {})
        recorded_prev = integrity.get("prev_hash", "")
        recorded_hash = integrity.get("hash", "")

        if recorded_prev != prev_hash:
            return False, i

        entry_copy = json.loads(json.dumps(entry, sort_keys=True, ensure_ascii=False))
        if "integrity" in entry_copy:
            entry_copy["integrity"].pop("hash", None)
        canonical = json.dumps(entry_copy, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        computed_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        if computed_hash != recorded_hash:
            return False, i

        if stored_hashes and i < len(stored_hashes):
            if stored_hashes[i] != recorded_hash:
                return False, i

        prev_hash = recorded_hash

    return True, None


def query_log(
        log_path: str | Path = "./pki/audit/audit.log",
        from_ts: str | None = None,
        to_ts: str | None = None,
        level: str | None = None,
        operation: str | None = None,
        serial: str | None = None,
) -> list[dict]:
    log_path = Path(log_path)
    if not log_path.is_file():
        return []

    results: list[dict] = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            if level and entry.get("level", "").upper() != level.upper():
                continue
            if operation and entry.get("operation", "") != operation:
                continue
            if serial:
                meta_serial = entry.get("metadata", {}).get("serial", "")
                if serial.upper() not in meta_serial.upper():
                    continue
            if from_ts:
                entry_ts = entry.get("timestamp", "")
                if entry_ts < from_ts:
                    continue
            if to_ts:
                entry_ts = entry.get("timestamp", "")
                if entry_ts > to_ts:
                    continue

            results.append(entry)

    return results


_default_logger: AuditLogger | None = None
_default_lock = threading.Lock()


def get_audit_logger(audit_dir: str | Path = "./pki/audit") -> AuditLogger:
    global _default_logger
    with _default_lock:
        if _default_logger is None or str(_default_logger.audit_dir) != str(Path(audit_dir)):
            _default_logger = AuditLogger(audit_dir)
        return _default_logger


def reset_audit_logger() -> None:
    global _default_logger
    with _default_lock:
        _default_logger = None