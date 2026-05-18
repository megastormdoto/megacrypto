from __future__ import annotations
from datetime import datetime, timezone
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization
from . import database
from . import repository
def process_ocsp_request(
    request_der: bytes,
    responder_cert: x509.Certificate,
    responder_key,
    issuer_cert: x509.Certificate,
    db_path: str,
    logger,
) -> bytes:
    try:
        req = ocsp.load_der_ocsp_request(request_der)
    except Exception as e:
        logger.error("Failed to parse OCSP request: %s", e)
        return ocsp.OCSPResponseBuilder.build_unsuccessful(ocsp.OCSPResponseStatus.MALFORMED_REQUEST).public_bytes(serialization.Encoding.DER)
    
    builder = ocsp.OCSPResponseBuilder()
    try:
        nonce_ext = req.extensions.get_extension_for_class(x509.OCSPNonce)
        builder = builder.add_extension(nonce_ext.value, critical=nonce_ext.critical)
    except x509.ExtensionNotFound:
        pass
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    status_enum = ocsp.OCSPCertStatus.UNKNOWN
    revocation_time = None
    revocation_reason = None
    serial_hex = f"{req.serial_number:X}"
    cert_data = repository.get_certificate_by_serial(req.serial_number, db_path=db_path)
    if cert_data:
        db_status = cert_data["status"]
        if db_status == "valid":
            status_enum = ocsp.OCSPCertStatus.GOOD
        elif db_status == "revoked":
            status_enum = ocsp.OCSPCertStatus.REVOKED
            if cert_data.get("revocation_date"):
                try:
                    revocation_time = datetime.fromisoformat(cert_data["revocation_date"]).replace(tzinfo=None)
                except Exception:
                    revocation_time = now
            else:
                revocation_time = now
            from .revocation import parse_reason
            try:
                reason_str = cert_data.get("revocation_reason", "unspecified")
                revocation_reason = parse_reason(reason_str)
            except Exception:
                revocation_reason = x509.ReasonFlags.unspecified
    builder = builder.add_response_by_hash(
        issuer_name_hash=req.issuer_name_hash,
        issuer_key_hash=req.issuer_key_hash,
        serial_number=req.serial_number,
        algorithm=req.hash_algorithm,
        cert_status=status_enum,
        this_update=now,
        next_update=None,
        revocation_time=revocation_time,
        revocation_reason=revocation_reason
    )
    builder = builder.responder_id(ocsp.OCSPResponderEncoding.HASH, responder_cert)
    builder = builder.certificates([responder_cert])
    try:
        response = builder.sign(
            private_key=responder_key,
            algorithm=hashes.SHA256(),
        )
        return response.public_bytes(serialization.Encoding.DER)
    except Exception as e:
        logger.error("Failed to sign OCSP response: %s", e)
        return ocsp.OCSPResponseBuilder.build_unsuccessful(ocsp.OCSPResponseStatus.INTERNAL_ERROR).public_bytes(serialization.Encoding.DER)
