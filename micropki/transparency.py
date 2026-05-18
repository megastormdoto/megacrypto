from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization


def _fingerprint(cert: x509.Certificate) -> str:
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def log_certificate(
    cert: x509.Certificate,
    audit_dir: str | Path = "./pki/audit",
) -> None:
    audit_dir = Path(audit_dir)
    audit_dir.mkdir(parents=True, exist_ok=True)
    ct_path = audit_dir / "ct.log"

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    serial_hex = f"{cert.serial_number:X}"
    subject_dn = cert.subject.rfc4514_string()
    issuer_dn = cert.issuer.rfc4514_string()
    fp = _fingerprint(cert)

    line = f"{ts} | {serial_hex} | {subject_dn} | {fp} | {issuer_dn}\n"

    with open(ct_path, "a", encoding="utf-8") as f:
        f.write(line)
    try:
        ct_path.chmod(0o644)
    except OSError:
        pass


def verify_inclusion(
    serial_hex: str,
    ct_log_path: str | Path = "./pki/audit/ct.log",
) -> bool:
    ct_log_path = Path(ct_log_path)
    if not ct_log_path.is_file():
        return False

    serial_upper = serial_hex.upper()
    with open(ct_log_path, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.split("|")
            if len(parts) >= 2 and parts[1].strip().upper() == serial_upper:
                return True
    return False
