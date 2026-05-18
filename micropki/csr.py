from __future__ import annotations
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from .certificates import parse_subject_dn, subject_key_identifier_from_public_key
from .crypto_utils import make_serial, signing_algorithm
from .templates import TemplateExtensions
def generate_intermediate_csr(
    subject_dn: str,
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    path_length: int = 0,
) -> x509.CertificateSigningRequest:
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(parse_subject_dn(subject_dn))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
    )
    return builder.sign(private_key, signing_algorithm(private_key))
def _build_aki_from_issuer(issuer_cert: x509.Certificate) -> x509.AuthorityKeyIdentifier:
    ski_ext = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    return x509.AuthorityKeyIdentifier(
        key_identifier=ski_ext.value.digest,
        authority_cert_issuer=None,
        authority_cert_serial_number=None,
    )
def sign_intermediate_csr(
    csr: x509.CertificateSigningRequest,
    root_cert: x509.Certificate,
    root_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    validity_days: int,
    path_length: int = 0,
    serial_number: int | None = None,
) -> x509.Certificate:
    not_before = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(root_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial_number or make_serial())
        .not_valid_before(not_before)
        .not_valid_after(not_before + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=False,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(subject_key_identifier_from_public_key(csr.public_key()), critical=False)
        .add_extension(_build_aki_from_issuer(root_cert), critical=False)
    )
    return builder.sign(root_key, signing_algorithm(root_key))
def issue_end_entity_cert(
    subject_dn: str,
    public_key,
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    validity_days: int,
    template_ext: TemplateExtensions,
    serial_number: int | None = None,
) -> x509.Certificate:
    not_before = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(parse_subject_dn(subject_dn))
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(serial_number or make_serial())
        .not_valid_before(not_before)
        .not_valid_after(not_before + timedelta(days=validity_days))
        .add_extension(template_ext.basic_constraints, critical=template_ext.basic_constraints_critical)
        .add_extension(template_ext.key_usage, critical=template_ext.key_usage_critical)
        .add_extension(template_ext.extended_key_usage, critical=template_ext.eku_critical)
        .add_extension(subject_key_identifier_from_public_key(public_key), critical=False)
        .add_extension(_build_aki_from_issuer(ca_cert), critical=False)
    )
    if template_ext.san is not None:
        builder = builder.add_extension(template_ext.san, critical=template_ext.san_critical)
    return builder.sign(ca_key, signing_algorithm(ca_key))
