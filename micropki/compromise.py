from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import database
from . import crl as crl_module
from . import crypto_utils
from .audit import get_audit_logger
from .revocation import revoke


def _public_key_hash(public_key) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def public_key_hash_from_cert(cert: x509.Certificate) -> str:
    return _public_key_hash(cert.public_key())


def mark_compromised(
    db_path: str | Path,
    cert_path: str | Path,
    reason: str = "keyCompromise",
    audit_dir: str | Path = "./pki/audit",
    ca_cert_path: str | None = None,
    ca_key_path: str | None = None,
    ca_pass_file: str | None = None,
    out_dir: str | None = None,
) -> dict:
    audit = get_audit_logger(audit_dir)
    cert = crypto_utils.load_certificate_pem(str(cert_path))
    serial_hex = f"{cert.serial_number:X}"
    pk_hash = public_key_hash_from_cert(cert)
    now = datetime.now(timezone.utc).isoformat()
    database.insert_compromised_key(db_path, pk_hash, serial_hex, now, reason)
    revoked = False
    try:
        revoked = revoke(db_path, serial_hex, reason)
    except ValueError:
        pass
    audit.log_event(
        operation="key_compromise",
        status="success",
        message=f"Private key compromise simulated for serial {serial_hex}",
        metadata={
            "serial": serial_hex,
            "subject": cert.subject.rfc4514_string(),
            "public_key_hash": pk_hash,
            "reason": reason,
        },
        level="AUDIT",
    )
    if ca_cert_path and ca_key_path and ca_pass_file and out_dir:
        try:
            ca_pass = crypto_utils.load_passphrase(ca_pass_file)
            crl_module.generate_crl(
                ca_cert_path=ca_cert_path,
                ca_key_path=ca_key_path,
                ca_passphrase=ca_pass,
                out_dir=out_dir,
                db_path=db_path,
                next_update_days=1,
            )
            audit.log_event(
                operation="emergency_crl",
                status="success",
                message=f"Emergency CRL generated after key compromise of {serial_hex}",
                metadata={"serial": serial_hex},
                level="AUDIT",
            )
        except Exception as e:
            audit.log_event(
                operation="emergency_crl",
                status="failure",
                message=f"Emergency CRL generation failed: {e}",
                metadata={"serial": serial_hex},
                level="ERROR",
            )

    return {
        "serial": serial_hex,
        "public_key_hash": pk_hash,
        "revoked": revoked,
    }


def is_key_compromised(db_path: str | Path, public_key) -> bool:
    pk_hash = _public_key_hash(public_key)
    return database.is_key_hash_compromised(db_path, pk_hash)
