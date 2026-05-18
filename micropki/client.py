from __future__ import annotations
import json
import sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from . import crypto_utils
from . import validation
from . import revocation_check
from .certificates import parse_subject_dn
from .templates import parse_san_list
from .logger import setup_logging


def generate_csr(
    subject: str,
    key_type: str = "rsa",
    key_size: int = 2048,
    san_strings: list[str] | None = None,
    out_key: str = "./key.pem",
    out_csr: str = "./request.csr.pem",
    log_file: str | None = None,
) -> None:
    logger = setup_logging(log_file)
    logger.info("Generating %s-%d key pair for CSR", key_type, key_size)
    key = crypto_utils.generate_key(key_type, key_size)
    builder = x509.CertificateSigningRequestBuilder().subject_name(parse_subject_dn(subject))
    if san_strings:
        san_names = parse_san_list(san_strings)
        builder = builder.add_extension(x509.SubjectAlternativeName(san_names), critical=False)
    csr = builder.sign(key, crypto_utils.signing_algorithm(key))
    key_path = Path(out_key)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    crypto_utils.write_private_key_unencrypted(str(key_path), key, logger=logger)
    csr_path = Path(out_csr)
    csr_path.parent.mkdir(parents=True, exist_ok=True)
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    csr_path.write_bytes(csr_pem)
    logger.info("CSR saved to %s", str(csr_path.resolve()))
    logger.info("CSR subject: %s", csr.subject.rfc4514_string())
    if san_strings:
        logger.info("CSR SANs: %s", ", ".join(san_strings))


def request_certificate(
    csr_path: str,
    template: str,
    ca_url: str,
    out_cert: str = "./cert.pem",
    log_file: str | None = None,
) -> None:
    import requests as http_requests
    logger = setup_logging(log_file)
    csr_pem = Path(csr_path).read_text(encoding="utf-8")
    url = ca_url.rstrip("/") + "/request-cert"
    logger.info("Submitting CSR to %s (template=%s)", url, template)
    try:
        resp = http_requests.post(
            url,
            json={"csr_pem": csr_pem, "template": template},
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
    except Exception as e:
        logger.error("Failed to connect to CA: %s", e)
        raise ConnectionError(f"Cannot connect to CA at {url}: {e}")
    if resp.status_code == 201:
        cert_pem = resp.text
        cert_path = Path(out_cert)
        cert_path.parent.mkdir(parents=True, exist_ok=True)
        cert_path.write_text(cert_pem, encoding="utf-8")
        logger.info("Certificate received and saved to %s", str(cert_path.resolve()))
    else:
        detail = resp.text
        try:
            detail = resp.json().get("detail", resp.text)
        except Exception:
            pass
        logger.error("Certificate request failed: HTTP %d — %s", resp.status_code, detail)
        raise RuntimeError(f"Certificate request failed: HTTP {resp.status_code} — {detail}")


def validate_certificate(
    cert_path: str,
    untrusted_paths: list[str] | None = None,
    trusted_path: str = "./pki/certs/ca.cert.pem",
    crl_source: str | None = None,
    use_ocsp: bool = False,
    ocsp_url: str | None = None,
    mode: str = "full",
    validation_time: str | None = None,
    output_format: str = "table",
    log_file: str | None = None,
) -> validation.ValidationResult:
    logger = setup_logging(log_file)
    leaf = crypto_utils.load_certificate_pem(cert_path)
    untrusted = []
    if untrusted_paths:
        for p in untrusted_paths:
            untrusted.append(crypto_utils.load_certificate_pem(p))
    trusted = [crypto_utils.load_certificate_pem(trusted_path)]
    now = None
    if validation_time:
        from datetime import datetime as dt
        now = dt.fromisoformat(validation_time).replace(tzinfo=None)
        from datetime import timezone as tz
        now = now.replace(tzinfo=tz.utc)
    logger.info("Building certificate chain...")
    try:
        chain = validation.build_chain(leaf, untrusted, trusted)
    except ValueError as e:
        logger.error("Chain building failed: %s", e)
        result = validation.ValidationResult(passed=False, error=str(e))
        _print_validation_result(result, output_format)
        return result
    logger.info("Chain built: %s", " → ".join(c.subject.rfc4514_string() for c in chain))
    result = validation.validate_path(chain, now=now)
    if result.passed and mode == "full":
        logger.info("Path validation passed, checking revocation...")
        for cert in chain[:-1]:
            issuer_idx = chain.index(cert) + 1
            issuer = chain[issuer_idx]
            rev_ocsp_url = ocsp_url if use_ocsp else None
            rev_crl = crl_source
            if use_ocsp and not rev_ocsp_url:
                rev_ocsp_url = revocation_check.extract_ocsp_url(cert)
            if not rev_crl:
                cdp_urls = revocation_check.extract_cdp_urls(cert)
                rev_crl = cdp_urls[0] if cdp_urls else None
            if rev_ocsp_url or rev_crl:
                rev_status = revocation_check.check_revocation_status(
                    cert, issuer,
                    ocsp_url=rev_ocsp_url if use_ocsp else None,
                    crl_source=rev_crl,
                    logger=logger,
                )
                if rev_status.status == "revoked":
                    result.passed = False
                    subj = cert.subject.rfc4514_string()
                    result.error = (
                        f"{subj}: REVOKED via {rev_status.source}"
                        f" (reason={rev_status.reason}, time={rev_status.revocation_time})"
                    )
                    for cv in result.certs:
                        if cv.subject == subj:
                            cv.steps.append(validation.StepResult(
                                "revocation", False, result.error,
                            ))
                    logger.error("Revocation detected: %s", result.error)
                    break
                else:
                    for cv in result.certs:
                        if cv.subject == cert.subject.rfc4514_string():
                            cv.steps.append(validation.StepResult(
                                "revocation", True,
                                f"{rev_status.status} via {rev_status.source}",
                            ))
    _print_validation_result(result, output_format)
    return result


def check_status(
    cert_path: str,
    ca_cert_path: str,
    crl_source: str | None = None,
    ocsp_url: str | None = None,
    log_file: str | None = None,
) -> revocation_check.RevocationStatus:
    logger = setup_logging(log_file)
    cert = crypto_utils.load_certificate_pem(cert_path)
    issuer = crypto_utils.load_certificate_pem(ca_cert_path)
    logger.info("Checking revocation status for serial=%X", cert.serial_number)
    result = revocation_check.check_revocation_status(
        cert, issuer,
        ocsp_url=ocsp_url,
        crl_source=crl_source,
        logger=logger,
    )
    _print_revocation_status(result, cert)
    return result


def _print_validation_result(result: validation.ValidationResult, fmt: str = "table") -> None:
    if fmt == "json":
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        return
    status_str = "PASS" if result.passed else "FAIL"
    print(f"\nChain validation: {status_str}")
    if result.chain:
        print(f"Chain: {' -> '.join(result.chain)}")
    print()
    for cv in result.certs:
        cert_status = "OK" if cv.passed else "FAIL"
        print(f"  [{cert_status}] {cv.subject}")
        for step in cv.steps:
            mark = "  [+]" if step.passed else "  [-]"
            print(f"      {mark} {step.name}: {step.detail}")
    if result.error:
        print(f"\nError: {result.error}")
    print()


def _print_revocation_status(result: revocation_check.RevocationStatus, cert: x509.Certificate) -> None:
    serial = f"{cert.serial_number:X}"
    subject = cert.subject.rfc4514_string()
    print(f"\nCertificate: {subject}")
    print(f"Serial: {serial}")
    print(f"Status: {result.status}")
    print(f"Source: {result.source}")
    if result.reason:
        print(f"Reason: {result.reason}")
    if result.revocation_time:
        print(f"Revocation time: {result.revocation_time}")
    if result.detail:
        print(f"Detail: {result.detail}")
    print()
