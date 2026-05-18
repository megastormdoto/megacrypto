from __future__ import annotations
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from .crypto_utils import make_serial, signing_algorithm
_DN_OID_MAP = {
    "C": NameOID.COUNTRY_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "CN": NameOID.COMMON_NAME,
    "L": NameOID.LOCALITY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "STREET": NameOID.STREET_ADDRESS,
    "DC": NameOID.DOMAIN_COMPONENT,
    "EMAIL": NameOID.EMAIL_ADDRESS,
}
def parse_subject_dn(dn_string: str) -> x509.Name:
    s = (dn_string or "").strip()
    if not s:
        raise ValueError("Subject DN is empty")
    normalized = s.replace("/", ",").strip(",")
    parts = [p.strip() for p in normalized.split(",") if p.strip()]
    if not parts:
        raise ValueError("Subject DN has no components")
    attrs = []
    for part in parts:
        if "=" not in part:
            raise ValueError(f"Invalid DN component (missing =): {part}")
        key, _, value = part.partition("=")
        key, value = key.strip().upper(), value.strip()
        if not key or not value:
            raise ValueError(f"Invalid DN component: {part}")
        oid = _DN_OID_MAP.get(key)
        if oid is None:
            raise ValueError(f"Unsupported DN attribute: {key}")
        attrs.append(x509.NameAttribute(oid, value))
    return x509.Name(attrs)
def subject_key_identifier_from_public_key(public_key) -> x509.SubjectKeyIdentifier:
    return x509.SubjectKeyIdentifier.from_public_key(public_key)
def build_self_signed_root_ca(
    subject_dn: str,
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    validity_days: int,
    key_type: str,
    key_size: int,
    serial_number: int | None = None,
) -> x509.Certificate:
    name = parse_subject_dn(subject_dn)
    public_key = private_key.public_key()
    not_before = datetime.now(timezone.utc)
    not_after = not_before + timedelta(days=validity_days)
    ski = subject_key_identifier_from_public_key(public_key)
    aki = x509.AuthorityKeyIdentifier(
        key_identifier=ski.digest,
        authority_cert_issuer=None,
        authority_cert_serial_number=None,
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(serial_number or make_serial())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=False,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ski, critical=False)
        .add_extension(aki, critical=False)
    )
    return builder.sign(private_key=private_key, algorithm=signing_algorithm(private_key))
