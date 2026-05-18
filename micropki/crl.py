from __future__ import annotations
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from . import database
from .logger import setup_logging
from .revocation import REASON_MAPPING
def generate_crl(
    ca_cert_path: str | Path,
    ca_key_path: str | Path,
    ca_passphrase: bytes | None,
    out_dir: str | Path,
    db_path: str | Path = "./pki/micropki.db",
    next_update_days: int = 7,
    out_file: str | Path | None = None,
    log_file: str | None = None,
) -> Path:
    log = setup_logging(log_file)
    from . import crypto_utils
    ca_cert = crypto_utils.load_certificate_pem(ca_cert_path)
    ca_key = crypto_utils.load_private_key_encrypted(ca_key_path, ca_passphrase)
    ca_subject_str = getattr(ca_cert.subject, "rfc4514_string", lambda: ca_cert.subject.public_bytes(serialization.Encoding.DER).hex())()
    try:
        ca_subject_str = ca_cert.subject.rfc4514_string()
    except AttributeError:
        pass 
    metadata = database.get_crl_metadata(db_path, ca_subject_str)
    crl_number = 1 if not metadata else metadata["crl_number"] + 1
    out_dir_path = Path(out_dir) / "crl"
    out_dir_path.mkdir(parents=True, exist_ok=True)
    if out_file:
        final_out_path = Path(out_file)
    else:
        fname = "root.crl.pem" if "Root" in ca_subject_str else "intermediate.crl.pem"
        final_out_path = out_dir_path / fname
    this_update = datetime.now(timezone.utc)
    next_update = this_update + timedelta(days=next_update_days)
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(this_update)
    builder = builder.next_update(next_update)
    builder = builder.add_extension(
        x509.CRLNumber(crl_number),
        critical=False,
    )
    try:
        ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski.value),
            critical=False,
        )
    except x509.ExtensionNotFound:
        pass 
    revoked_list = database.get_revoked_certificates_by_issuer(db_path, ca_subject_str)
    count = 0
    for rev in revoked_list:
        try:
            rev_date = datetime.fromisoformat(rev["revocation_date"])
        except (ValueError, TypeError):
            rev_date = this_update 
        try:
            rev_serial = int(rev["serial_number"], 16)
        except (ValueError, TypeError):
            rev_serial = int(rev["serial_number"])
        rev_builder = x509.RevokedCertificateBuilder()
        rev_builder = rev_builder.serial_number(rev_serial)
        rev_builder = rev_builder.revocation_date(rev_date)
        reason_str = rev["revocation_reason"]
        if reason_str and reason_str in REASON_MAPPING:
            rev_builder = rev_builder.add_extension(
                x509.CRLReason(REASON_MAPPING[reason_str]),
                critical=False,
            )
        builder = builder.add_revoked_certificate(rev_builder.build())
        count += 1
    hash_alg = ca_cert.signature_hash_algorithm or hashes.SHA256()
    crl = builder.sign(
        private_key=ca_key,
        algorithm=hash_alg,
    )
    final_out_path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    log.info("Generated CRL with %d revoked certs for %s at %s", count, ca_subject_str, final_out_path)
    database.update_crl_metadata(
        db_path,
        ca_subject_str,
        crl_number,
        this_update.isoformat(),
        next_update.isoformat(),
        str(final_out_path)
    )

    # Audit logging (best-effort)
    try:
        from .audit import get_audit_logger
        pki_root = Path(out_dir)
        audit = get_audit_logger(str(pki_root / "audit"))
        audit.log_event("generate_crl", "success",
                        f"CRL generated with {count} revoked certs for {ca_subject_str}",
                        {"crl_number": crl_number, "revoked_count": count,
                         "ca_subject": ca_subject_str}, "AUDIT")
    except Exception:
        pass

    return final_out_path
