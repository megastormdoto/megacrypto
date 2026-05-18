from __future__ import annotations
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from . import certificates
from . import database
from . import crypto_utils
from . import csr as csr_module
from . import logger as log_module
from . import repository
from . import serial as serial_module
from . import templates as tmpl
from .audit import get_audit_logger
from .policy import (
    PolicyViolationError, check_key_size, check_validity_period,
    check_san_policy, check_csr_key_size, check_csr_algorithm,
    check_path_length, check_public_key_size,
)
from . import transparency
from . import compromise as compromise_module


def _audit_dir_from_out(out_dir: str) -> str:
    out = Path(out_dir)
    return str(out / "audit")


def resolve_local_ca_for_issuer(
    out_dir: str,
    issuer_rfc4514: str,
) -> tuple[x509.Certificate, Path, str] | None:
    out = Path(out_dir)
    root_cert_p = out / "certs" / "ca.cert.pem"
    if not root_cert_p.is_file():
        return None
    root_c = crypto_utils.load_certificate_pem(str(root_cert_p))
    inter_cert_p = out / "certs" / "intermediate.cert.pem"
    if inter_cert_p.is_file():
        inter_c = crypto_utils.load_certificate_pem(str(inter_cert_p))
        if inter_c.subject.rfc4514_string() == issuer_rfc4514:
            return inter_c, out / "private" / "intermediate.key.pem", "intermediate.crl.pem"
    if root_c.subject.rfc4514_string() == issuer_rfc4514:
        return root_c, out / "private" / "ca.key.pem", "root.crl.pem"
    return None
def _gen_key(key_type: str, key_size: int, logger, label: str = ""):
    logger.info("Starting key generation%s (type=%s, size=%s)",
                f" for {label}" if label else "", key_type, key_size)
    key = crypto_utils.generate_key(key_type, key_size)
    logger.info("Key generation completed successfully")
    return key
def init_root_ca(
    subject: str, key_type: str, key_size: int,
    passphrase: bytes, out_dir: str, validity_days: int,
    db_path: str | None = None, log_file: str | None = None, force: bool = False,
) -> None:
    logger = log_module.setup_logging(log_file)
    audit = get_audit_logger(_audit_dir_from_out(out_dir))
    audit.log_event("ca_init", "started", f"Root CA initialisation requested: {subject}",
                    {"subject": subject, "key_type": key_type, "key_size": key_size}, "AUDIT")
    try:
        check_key_size(key_type, key_size, "root")
        check_validity_period(validity_days, "root")
    except PolicyViolationError as e:
        audit.log_event("ca_init", "failure", f"Policy violation: {e}",
                        {"subject": subject, "error": str(e)}, "AUDIT")
        raise

    out = Path(out_dir)
    (out / "crl").mkdir(parents=True, exist_ok=True)
    key_path = out / "private" / "ca.key.pem"
    cert_path = out / "certs" / "ca.cert.pem"
    policy_path = out / "policy.txt"
    _check_overwrite([key_path, cert_path], force, logger)
    key = _gen_key(key_type, key_size, logger)
    logger.info("Starting certificate signing")
    db_path = db_path or str(out / "micropki.db")
    cert = certificates.build_self_signed_root_ca(
        subject_dn=subject, private_key=key,
        validity_days=validity_days, key_type=key_type, key_size=key_size,
        serial_number=serial_module.generate_serial(),
    )
    logger.info("Certificate signing completed successfully")
    _save_ca_artifacts(out, key_path, cert_path, key, passphrase, cert, logger)
    try:
        repository.insert_certificate(
            serial_number=cert.serial_number,
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            not_before=cert.not_valid_before_utc.isoformat(),
            not_after=cert.not_valid_after_utc.isoformat(),
            cert_pem=cert_path.read_text(encoding="utf-8"),
            status="valid",
            db_path=out / "micropki.db",
            log_file=log_file
        )
    except Exception as e:
        logger.warning("Could not insert Root CA into DB: %s", e)
    transparency.log_certificate(cert, _audit_dir_from_out(out_dir))
    audit.log_event("ca_init", "success",
                    f"Root CA initialised: CN={_extract_cn(subject)}, serial={cert.serial_number:X}",
                    {"serial": f"{cert.serial_number:X}", "subject": cert.subject.rfc4514_string()}, "AUDIT")

    algo_desc = f"RSA-{key_size}" if key_type == "rsa" else "ECC-P384"
    policy_path.write_text(_build_root_policy(
        subject, f"{cert.serial_number:x}",
        cert.not_valid_before_utc, cert.not_valid_after_utc, algo_desc,
    ), encoding="utf-8")
    logger.info("Generated policy document at %s", str(policy_path.resolve()))
def issue_intermediate_ca(
    root_cert_path: str, root_key_path: str, root_passphrase: bytes,
    subject: str, key_type: str, key_size: int,
    passphrase: bytes, out_dir: str, validity_days: int,
    pathlen: int = 0, db_path: str | None = None, log_file: str | None = None, force: bool = False,
) -> None:
    logger = log_module.setup_logging(log_file)
    audit = get_audit_logger(_audit_dir_from_out(out_dir))
    audit.log_event("issue_intermediate", "started",
                    f"Intermediate CA issuance requested: {subject}",
                    {"subject": subject, "key_type": key_type, "key_size": key_size}, "AUDIT")
    try:
        check_key_size(key_type, key_size, "intermediate")
        check_validity_period(validity_days, "intermediate")
        check_path_length(pathlen, "intermediate")
    except PolicyViolationError as e:
        audit.log_event("issue_intermediate", "failure", f"Policy violation: {e}",
                        {"subject": subject, "error": str(e)}, "AUDIT")
        raise

    out = Path(out_dir)
    (out / "crl").mkdir(parents=True, exist_ok=True)
    key_path = out / "private" / "intermediate.key.pem"
    cert_path = out / "certs" / "intermediate.cert.pem"
    policy_path = out / "policy.txt"
    _check_overwrite([key_path, cert_path], force, logger)
    root_cert = crypto_utils.load_certificate_pem(root_cert_path)
    root_key = crypto_utils.load_private_key_encrypted(root_key_path, root_passphrase)
    inter_key = _gen_key(key_type, key_size, logger, "Intermediate CA")
    logger.info("Generating Intermediate CA CSR")
    inter_csr = csr_module.generate_intermediate_csr(subject, inter_key, pathlen)
    logger.info("Intermediate CA CSR generated")
    db_path = db_path or str(out / "micropki.db")
    database.init_db(db_path)
    logger.info("Signing Intermediate CA certificate with Root CA")
    inter_cert = csr_module.sign_intermediate_csr(
        inter_csr, root_cert, root_key, validity_days, pathlen,
        serial_number=serial_module.generate_serial(),
    )
    logger.info("Intermediate CA certificate signed (serial=%x)", inter_cert.serial_number)
    _insert_cert_record(db_path, inter_cert)
    logger.info("Certificate insertion successful: serial=%x, subject=%s", inter_cert.serial_number, subject)
    _save_ca_artifacts(out, key_path, cert_path, inter_key, passphrase, inter_cert, logger)
    try:
        repository.insert_certificate(
            serial_number=inter_cert.serial_number,
            subject=inter_cert.subject.rfc4514_string(),
            issuer=inter_cert.issuer.rfc4514_string(),
            not_before=inter_cert.not_valid_before_utc.isoformat(),
            not_after=inter_cert.not_valid_after_utc.isoformat(),
            cert_pem=cert_path.read_text(encoding="utf-8"),
            status="valid",
            db_path=out / "micropki.db",
            log_file=log_file
        )
    except Exception as e:
        logger.warning("Could not insert Intermediate CA into DB: %s", e)
    transparency.log_certificate(inter_cert, _audit_dir_from_out(out_dir))
    audit.log_event("issue_intermediate", "success",
                    f"Intermediate CA issued: serial={inter_cert.serial_number:X}",
                    {"serial": f"{inter_cert.serial_number:X}",
                     "subject": inter_cert.subject.rfc4514_string()}, "AUDIT")

    algo_desc = f"RSA-{key_size}" if key_type == "rsa" else "ECC-P384"
    _append_intermediate_policy(
        policy_path, subject, f"{inter_cert.serial_number:x}",
        inter_cert.not_valid_before_utc, inter_cert.not_valid_after_utc,
        algo_desc, pathlen, root_cert.subject.rfc4514_string(),
    )
    logger.info("Updated policy document at %s", str(policy_path.resolve()))
def issue_end_entity(
    ca_cert_path: str, ca_key_path: str, ca_passphrase: bytes,
    template: str, subject: str, san_strings: list[str],
    out_dir: str, validity_days: int,
    csr_path: str | None = None, csr_pem: str | None = None,
    db_path: str | None = None, log_file: str | None = None,
) -> str | None:
    logger = log_module.setup_logging(log_file)
    ca_cert = crypto_utils.load_certificate_pem(ca_cert_path)
    ca_key = crypto_utils.load_private_key_encrypted(ca_key_path, ca_passphrase)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    pki_root = out.parent if out.name == "certs" else out
    (pki_root / "crl").mkdir(parents=True, exist_ok=True)
    db_path = db_path or str(pki_root / "micropki.db")
    database.init_database(db_path)

    audit = get_audit_logger(str(pki_root / "audit"))
    try:
        check_validity_period(validity_days, "end_entity")
    except PolicyViolationError as e:
        audit.log_event("issue_certificate", "failure", f"Policy violation: {e}",
                        {"subject": subject, "template": template, "error": str(e)}, "AUDIT")
        raise

    ext_csr = None
    if csr_pem:
        ext_csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8") if isinstance(csr_pem, str) else csr_pem)
    elif csr_path:
        ext_csr = crypto_utils.load_csr_pem(csr_path)
    if ext_csr is not None:
        if not ext_csr.is_signature_valid:
            raise ValueError("CSR signature verification failed")
        try:
            check_csr_key_size(ext_csr, "end_entity")
            check_csr_algorithm(ext_csr)
        except PolicyViolationError as e:
            audit.log_event("issue_certificate", "failure", f"Policy violation (CSR): {e}",
                            {"subject": subject, "template": template, "error": str(e)}, "AUDIT")
            raise

        pub = ext_csr.public_key()
        from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod, ec as ec_mod
        if isinstance(pub, rsa_mod.RSAPublicKey) and pub.key_size < 2048:
            raise ValueError(f"CSR key too small: {pub.key_size} bits (minimum 2048)")
        if compromise_module.is_key_compromised(db_path, pub):
            err = "CSR uses a compromised public key — issuance blocked"
            audit.log_event("issue_certificate", "failure", err,
                            {"subject": subject, "template": template}, "AUDIT")
            raise PolicyViolationError(err)

        try:
            bc_req = ext_csr.extensions.get_extension_for_class(x509.BasicConstraints)
            if bc_req.value.ca:
                raise ValueError("CSR requests CA=true, rejected for end-entity issuance")
        except x509.ExtensionNotFound:
            pass
        _OID_TO_SHORT = {
            NameOID.COMMON_NAME: "CN",
            NameOID.ORGANIZATION_NAME: "O",
            NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
            NameOID.COUNTRY_NAME: "C",
            NameOID.LOCALITY_NAME: "L",
            NameOID.STATE_OR_PROVINCE_NAME: "ST",
            NameOID.STREET_ADDRESS: "STREET",
            NameOID.DOMAIN_COMPONENT: "DC",
            NameOID.EMAIL_ADDRESS: "EMAIL",
        }
        dn_parts = []
        for attr in ext_csr.subject:
            short = _OID_TO_SHORT.get(attr.oid, attr.oid.dotted_string)
            dn_parts.append(f"{short}={attr.value}")
        subject = "/" + "/".join(dn_parts)
        try:
            san_ext = ext_csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_names = list(san_ext.value)
        except x509.ExtensionNotFound:
            san_names = []
        if not san_strings:
            san_strings = []
            for name in san_names:
                if isinstance(name, x509.DNSName):
                    san_strings.append(f"dns:{name.value}")
                elif isinstance(name, x509.IPAddress):
                    san_strings.append(f"ip:{str(name.value)}")
                elif isinstance(name, x509.RFC822Name):
                    san_strings.append(f"email:{name.value}")
                elif isinstance(name, x509.UniformResourceIdentifier):
                    san_strings.append(f"uri:{name.value}")
        public_key = ext_csr.public_key()
        leaf_key = None
        logger.info("Using public key from CSR")
    else:
        logger.info("Generating key pair for end-entity certificate")
        is_rsa_ca = crypto_utils.is_rsa_key(ca_key)
        leaf_key = crypto_utils.generate_key("rsa", 2048) if is_rsa_ca else crypto_utils.generate_key("ecc", 256)
        public_key = leaf_key.public_key()
        logger.info("Key pair generated for %s", subject)
    san_names = tmpl.parse_san_list(san_strings) if san_strings else []
    try:
        check_san_policy(template, san_names)
    except PolicyViolationError as e:
        audit.log_event("issue_certificate", "failure", f"Policy violation (SAN): {e}",
                        {"subject": subject, "template": template, "error": str(e)}, "AUDIT")
        raise

    tmpl.validate_san_for_template(template, san_names)
    base_name = _safe_filename(_extract_cn(subject))
    ext = tmpl.get_template_extensions(template, san_names, is_rsa=crypto_utils.is_rsa_key(public_key))
    audit.log_event("issue_certificate", "started",
                    f"Certificate issuance started for {subject} (template={template})",
                    {"subject": subject, "template": template}, "AUDIT")

    logger.info("Issuing %s certificate for %s", template, subject)
    cert = csr_module.issue_end_entity_cert(
        subject_dn=subject, public_key=public_key,
        ca_cert=ca_cert, ca_key=ca_key,
        validity_days=validity_days, template_ext=ext,
        serial_number=serial_module.generate_serial(),
    )
    san_desc = ", ".join(san_strings) if san_strings else "none"
    logger.info(
        "Certificate issued: serial=%x, subject=%s, template=%s, SANs=[%s], issued=%s",
        cert.serial_number, subject, template, san_desc,
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    _insert_cert_record(db_path, cert)
    logger.info("Certificate insertion successful: serial=%x, subject=%s", cert.serial_number, subject)
    cert_pem_bytes = crypto_utils.cert_to_pem(cert)
    cert_file = out / f"{base_name}.cert.pem"
    cert_file.write_bytes(cert_pem_bytes)
    logger.info("Saved certificate to %s", str(cert_file.resolve()))
    if leaf_key is not None:
        key_file = out / f"{base_name}.key.pem"
        crypto_utils.write_private_key_unencrypted(str(key_file), leaf_key, logger=logger)
    transparency.log_certificate(cert, str(pki_root / "audit"))
    audit.log_event("issue_certificate", "success",
                    f"Issued {template} certificate for {subject}",
                    {"serial": f"{cert.serial_number:X}", "subject": subject,
                     "template": template}, "AUDIT")

    return cert_pem_bytes.decode("utf-8")
def verify_certificate(cert_path: str, log_file: str | None = None) -> bool:
    logger = log_module.setup_logging(log_file)
    cert = crypto_utils.load_certificate_pem(cert_path)
    try:
        crypto_utils.verify_cert_signature(cert, cert)
    except Exception as e:
        logger.error("Certificate signature verification failed: %s", e)
        raise
    logger.info("Certificate verification succeeded: %s", cert_path)
    return True
def _check_overwrite(paths: list[Path], force: bool, logger) -> None:
    if force:
        return
    for p in paths:
        if p.exists():
            logger.error("Refusing to overwrite: %s (use --force)", p)
            raise FileExistsError(f"File exists: {p}")
def _save_ca_artifacts(out: Path, key_path: Path, cert_path: Path,
                       key, passphrase: bytes, cert, logger) -> None:
    crypto_utils.ensure_private_dir_permissions(str(key_path.parent), logger=logger)
    crypto_utils.write_private_key_pem(str(key_path), key, passphrase, logger=logger)
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_bytes(crypto_utils.cert_to_pem(cert))
    logger.info("Saved certificate to %s", str(cert_path.resolve()))
def _extract_cn(subject_dn: str) -> str:
    name = certificates.parse_subject_dn(subject_dn)
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else "cert"
def _safe_filename(name: str) -> str:
    safe = re.sub(r'[^\w.\-]', '_', name).strip('_')
    return safe or "cert"
def _build_root_policy(subject, serial_hex, not_before, not_after, key_algo) -> str:
    created = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return f"""MicroPKI Root CA Policy
-----------------------
Subject: {subject}
Serial:  {serial_hex}
Created: {created}
Valid:   {not_before} to {not_after}
Key:     {key_algo}
"""

def _append_intermediate_policy(policy_path, subject, serial_hex,
                                not_before, not_after, key_algo, pathlen, issuer_dn) -> None:
    section = f"""
Intermediate CA Policy
----------------------
Subject: {subject}
Issuer:  {issuer_dn}
Serial:  {serial_hex}
Valid:   {not_before} to {not_after}
Key:     {key_algo}
Path Length Constraint: {pathlen}
"""
    with open(policy_path, "a", encoding="utf-8") as f:
        f.write(section)
def _insert_cert_record(db_path: str, cert) -> None:
    repository.insert_certificate(
        serial_number=cert.serial_number,
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        not_before=cert.not_valid_before_utc.isoformat().replace("+00:00", "Z"),
        not_after=cert.not_valid_after_utc.isoformat().replace("+00:00", "Z"),
        cert_pem=crypto_utils.cert_to_pem(cert).decode("utf-8"),
        status="valid",
        db_path=db_path
    )
