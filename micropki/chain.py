from __future__ import annotations
from datetime import datetime, timezone
from cryptography import x509
from .crypto_utils import verify_cert_signature
def check_validity(cert: x509.Certificate, now: datetime | None = None) -> None:
    now = now or datetime.now(timezone.utc)
    nb = cert.not_valid_before_utc
    na = cert.not_valid_after_utc
    if now < nb:
        raise ValueError(f"Certificate not yet valid (notBefore={nb})")
    if now > na:
        raise ValueError(f"Certificate expired (notAfter={na})")
def check_basic_constraints_ca(cert: x509.Certificate, expect_ca: bool) -> None:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        if expect_ca:
            raise ValueError("Missing BasicConstraints extension on CA certificate")
        return
    if bc.value.ca != expect_ca:
        raise ValueError(f"BasicConstraints CA={bc.value.ca}, expected {expect_ca}")
def check_path_length(ca_certs: list[x509.Certificate]) -> None:
    for i, cert in enumerate(ca_certs):
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        except x509.ExtensionNotFound:
            continue
        if bc.value.path_length is not None and i > bc.value.path_length:
            raise ValueError(
                f"Path length constraint violated: {cert.subject} allows "
                f"{bc.value.path_length} but {i} CA certs below"
            )
def validate_chain(
    leaf: x509.Certificate,
    intermediates: list[x509.Certificate],
    root: x509.Certificate,
    now: datetime | None = None,
) -> list[x509.Certificate]:
    chain = [leaf] + intermediates + [root]
    for cert in chain:
        check_validity(cert, now)
    check_basic_constraints_ca(leaf, expect_ca=False)
    for inter in intermediates:
        check_basic_constraints_ca(inter, expect_ca=True)
    check_basic_constraints_ca(root, expect_ca=True)
    issuers = intermediates + [root] if intermediates else [root]
    subjects = [leaf] + intermediates
    for subject_cert, issuer_cert in zip(subjects, issuers):
        verify_cert_signature(subject_cert, issuer_cert)
    verify_cert_signature(root, root)
    check_path_length(intermediates + [root])
    return chain
