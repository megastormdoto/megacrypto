import pytest
from cryptography import x509

from micropki import certificates
from micropki import crypto_utils


def test_parse_subject_dn_slash_notation():
    name = certificates.parse_subject_dn("/CN=My Root CA")
    assert name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME) == [
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "My Root CA")
    ]


def test_parse_subject_dn_comma_notation():
    name = certificates.parse_subject_dn("CN=ECC Root CA,O=MicroPKI,C=US")
    assert name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "ECC Root CA"
    assert name.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value == "MicroPKI"
    assert name.get_attributes_for_oid(x509.oid.NameOID.COUNTRY_NAME)[0].value == "US"


def test_parse_subject_dn_empty_fails():
    with pytest.raises(ValueError, match="empty"):
        certificates.parse_subject_dn("")
    with pytest.raises(ValueError, match="empty"):
        certificates.parse_subject_dn("   ")


def test_parse_subject_dn_invalid_component_fails():
    with pytest.raises(ValueError, match="missing ="):
        certificates.parse_subject_dn("CN=OK,Invalid")


def test_cert_to_pem_roundtrip():
    key = crypto_utils.generate_rsa_key(4096)
    cert = certificates.build_self_signed_root_ca(
        subject_dn="/CN=Test",
        private_key=key,
        validity_days=365,
        key_type="rsa",
        key_size=4096,
    )
    pem = crypto_utils.cert_to_pem(cert)
    assert b"-----BEGIN CERTIFICATE-----" in pem
    loaded = x509.load_pem_x509_certificate(pem)
    assert loaded.serial_number == cert.serial_number


def test_certificate_extensions_and_fields():
    key = crypto_utils.generate_rsa_key(4096)
    cert = certificates.build_self_signed_root_ca(
        subject_dn="CN=Root Test,O=MicroPKI,C=US",
        private_key=key,
        validity_days=3650,
        key_type="rsa",
        key_size=4096,
    )
    assert cert.subject == cert.issuer
    assert cert.serial_number > 0

    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.critical is True
    assert bc.value.ca is True
    assert bc.value.path_length is None

    ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert ku.critical is True
    assert ku.value.key_cert_sign is True
    assert ku.value.crl_sign is True
    assert ku.value.digital_signature is True

    ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    assert ski.value.digest is not None and len(ski.value.digest) == 20

    aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    assert aki.value.key_identifier == ski.value.digest
