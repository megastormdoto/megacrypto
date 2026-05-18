from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from . import crypto_utils


@dataclass
class RevocationStatus:
    status: str
    source: str = ""
    reason: str | None = None
    revocation_time: str | None = None
    detail: str = ""


def extract_ocsp_url(cert: x509.Certificate) -> str | None:
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        for desc in aia.value:
            if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                return desc.access_location.value
    except x509.ExtensionNotFound:
        pass
    return None


def extract_cdp_urls(cert: x509.Certificate) -> list[str]:
    urls = []
    try:
        cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        for dp in cdp.value:
            if dp.full_name:
                for name in dp.full_name:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        urls.append(name.value)
    except x509.ExtensionNotFound:
        pass
    return urls


def check_ocsp(
    cert: x509.Certificate,
    issuer_cert: x509.Certificate,
    ocsp_url: str | None = None,
    logger=None,
) -> RevocationStatus:
    import requests as http_requests
    url = ocsp_url or extract_ocsp_url(cert)
    if not url:
        return RevocationStatus(status="unknown", source="ocsp", detail="No OCSP URL available")
    try:
        builder = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer_cert, hashes.SHA256())
        try:
            builder = builder.add_extension(x509.OCSPNonce(b"\x00" * 16), critical=False)
        except Exception:
            pass
        ocsp_req = builder.build()
        req_data = ocsp_req.public_bytes(serialization.Encoding.DER)
        resp = http_requests.post(
            url,
            data=req_data,
            headers={"Content-Type": "application/ocsp-request"},
            timeout=10,
        )
        if resp.status_code != 200:
            return RevocationStatus(
                status="unknown", source="ocsp",
                detail=f"OCSP responder returned HTTP {resp.status_code}",
            )
        ocsp_resp = ocsp.load_der_ocsp_response(resp.content)
        if ocsp_resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            return RevocationStatus(
                status="unknown", source="ocsp",
                detail=f"OCSP response status: {ocsp_resp.response_status.name}",
            )
        cert_status = ocsp_resp.certificate_status
        if cert_status == ocsp.OCSPCertStatus.GOOD:
            if logger:
                logger.info("OCSP check: certificate is GOOD (url=%s)", url)
            return RevocationStatus(status="good", source="ocsp")
        elif cert_status == ocsp.OCSPCertStatus.REVOKED:
            rev_time = getattr(ocsp_resp, 'revocation_time_utc', None) or ocsp_resp.revocation_time
            rev_reason = ocsp_resp.revocation_reason
            if logger:
                logger.info("OCSP check: certificate is REVOKED (url=%s)", url)
            return RevocationStatus(
                status="revoked", source="ocsp",
                reason=rev_reason.name if rev_reason else None,
                revocation_time=rev_time.isoformat() if rev_time else None,
            )
        else:
            return RevocationStatus(status="unknown", source="ocsp", detail="OCSP status: unknown")
    except Exception as e:
        if logger:
            logger.warning("OCSP check failed: %s", e)
        return RevocationStatus(status="unknown", source="ocsp", detail=f"OCSP error: {e}")


def check_crl(
    cert: x509.Certificate,
    issuer_cert: x509.Certificate,
    crl_source: str | None = None,
    logger=None,
) -> RevocationStatus:
    import requests as http_requests
    crl_data = None
    source_desc = crl_source or "CDP"
    if crl_source:
        if crl_source.startswith("http://") or crl_source.startswith("https://"):
            try:
                resp = http_requests.get(crl_source, timeout=10)
                if resp.status_code == 200:
                    crl_data = resp.content
                else:
                    return RevocationStatus(
                        status="unknown", source="crl",
                        detail=f"CRL fetch returned HTTP {resp.status_code}",
                    )
            except Exception as e:
                return RevocationStatus(status="unknown", source="crl", detail=f"CRL fetch error: {e}")
        else:
            try:
                crl_data = Path(crl_source).read_bytes()
            except Exception as e:
                return RevocationStatus(status="unknown", source="crl", detail=f"CRL file error: {e}")
    else:
        cdp_urls = extract_cdp_urls(cert)
        for url in cdp_urls:
            try:
                resp = http_requests.get(url, timeout=10)
                if resp.status_code == 200:
                    crl_data = resp.content
                    source_desc = url
                    break
            except Exception:
                continue
    if crl_data is None:
        return RevocationStatus(status="unknown", source="crl", detail="No CRL available")
    try:
        if crl_data.startswith(b"-----BEGIN"):
            crl = x509.load_pem_x509_crl(crl_data)
        else:
            crl = x509.load_der_x509_crl(crl_data)
    except Exception as e:
        return RevocationStatus(status="unknown", source="crl", detail=f"CRL parse error: {e}")
    try:
        pub = issuer_cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(crl.signature, crl.tbs_certlist_bytes, padding.PKCS1v15(), crl.signature_hash_algorithm)
        else:
            pub.verify(crl.signature, crl.tbs_certlist_bytes, ec.ECDSA(crl.signature_hash_algorithm))
    except Exception as e:
        if logger:
            logger.warning("CRL signature verification failed: %s", e)
        return RevocationStatus(status="unknown", source="crl", detail=f"CRL signature invalid: {e}")
    now = datetime.now(timezone.utc)
    if hasattr(crl, 'next_update_utc') and crl.next_update_utc and now > crl.next_update_utc:
        if logger:
            logger.warning("CRL is expired (nextUpdate=%s)", crl.next_update_utc)
    revoked_cert = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    if revoked_cert is not None:
        rev_time = None
        rev_reason = None
        if hasattr(revoked_cert, 'revocation_date_utc'):
            rev_time = revoked_cert.revocation_date_utc
        elif hasattr(revoked_cert, 'revocation_date'):
            rev_time = revoked_cert.revocation_date
        try:
            reason_ext = revoked_cert.extensions.get_extension_for_class(x509.CRLReason)
            rev_reason = reason_ext.value.reason.name
        except (x509.ExtensionNotFound, Exception):
            rev_reason = None
        if logger:
            logger.info("CRL check: certificate is REVOKED (source=%s)", source_desc)
        return RevocationStatus(
            status="revoked", source="crl",
            reason=rev_reason,
            revocation_time=rev_time.isoformat() if rev_time else None,
        )
    if logger:
        logger.info("CRL check: certificate is GOOD (source=%s)", source_desc)
    return RevocationStatus(status="good", source="crl")


def check_revocation_status(
    cert: x509.Certificate,
    issuer_cert: x509.Certificate,
    ocsp_url: str | None = None,
    crl_source: str | None = None,
    logger=None,
) -> RevocationStatus:
    ocsp_result = check_ocsp(cert, issuer_cert, ocsp_url=ocsp_url, logger=logger)
    if ocsp_result.status in ("good", "revoked"):
        return ocsp_result
    if logger:
        logger.info("OCSP inconclusive (%s), falling back to CRL", ocsp_result.detail)
    crl_result = check_crl(cert, issuer_cert, crl_source=crl_source, logger=logger)
    if crl_result.status in ("good", "revoked"):
        return crl_result
    if logger:
        logger.warning("Both OCSP and CRL checks inconclusive")
    return RevocationStatus(
        status="unknown", source="both",
        detail=f"OCSP: {ocsp_result.detail}; CRL: {crl_result.detail}",
    )
