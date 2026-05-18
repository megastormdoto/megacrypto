import pytest
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from micropki import validation
from micropki import crypto_utils
from micropki import revocation_check
from micropki import client

@pytest.fixture
def keys_and_chain():
    root_key = crypto_utils.generate_key("rsa", 2048)
    root_subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test Root CA")])
    root_cert = x509.CertificateBuilder().subject_name(
        root_subject
    ).issuer_name(
        root_subject
    ).public_key(
        root_key.public_key()
    ).serial_number(
        1
    ).not_valid_before(
        datetime.now(timezone.utc) - timedelta(days=10)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=10)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).add_extension(
        x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False),
        critical=True
    ).sign(root_key, hashes.SHA256())

    inter_key = crypto_utils.generate_key("rsa", 2048)
    inter_subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test Inter CA")])
    inter_cert = x509.CertificateBuilder().subject_name(
        inter_subject
    ).issuer_name(
        root_subject
    ).public_key(
        inter_key.public_key()
    ).serial_number(
        2
    ).not_valid_before(
        datetime.now(timezone.utc) - timedelta(days=9)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=9)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=0), critical=True
    ).add_extension(
        x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False),
        critical=True
    ).sign(root_key, hashes.SHA256())

    leaf_key = crypto_utils.generate_key("rsa", 2048)
    leaf_subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test Leaf")])
    leaf_cert = x509.CertificateBuilder().subject_name(
        leaf_subject
    ).issuer_name(
        inter_subject
    ).public_key(
        leaf_key.public_key()
    ).serial_number(
        3
    ).not_valid_before(
        datetime.now(timezone.utc) - timedelta(days=8)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=8)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).add_extension(
        x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False),
        critical=True
    ).add_extension(
        x509.AuthorityInformationAccess([
            x509.AccessDescription(x509.AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier("http://ocsp.test"))
        ]), critical=False
    ).add_extension(
        x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier("http://crl.test/crl.pem")],
                relative_name=None, reasons=None, crl_issuer=None
            )
        ]), critical=False
    ).sign(inter_key, hashes.SHA256())

    return {
        "root_key": root_key,
        "root_cert": root_cert,
        "inter_key": inter_key,
        "inter_cert": inter_cert,
        "leaf_key": leaf_key,
        "leaf_cert": leaf_cert,
    }


def test_validation_build_chain_and_validate(keys_and_chain):
    chain = validation.build_chain(
        keys_and_chain["leaf_cert"],
        [keys_and_chain["inter_cert"]],
        [keys_and_chain["root_cert"]]
    )
    assert len(chain) == 3
    assert chain[0] == keys_and_chain["leaf_cert"]
    assert chain[1] == keys_and_chain["inter_cert"]
    assert chain[2] == keys_and_chain["root_cert"]

    res = validation.validate_path(chain)
    assert res.passed is True

def test_extract_urls(keys_and_chain):
    leaf = keys_and_chain["leaf_cert"]
    ocsp_url = revocation_check.extract_ocsp_url(leaf)
    assert ocsp_url == "http://ocsp.test"
    crl_urls = revocation_check.extract_cdp_urls(leaf)
    assert crl_urls == ["http://crl.test/crl.pem"]

@patch("requests.post")
def test_check_ocsp(mock_post, keys_and_chain):
    from cryptography.x509 import ocsp
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    builder = ocsp.OCSPResponseBuilder()
    resp_der = builder.build_unsuccessful(ocsp.OCSPResponseStatus.INTERNAL_ERROR).public_bytes(serialization.Encoding.DER)
    mock_resp.content = resp_der
    mock_post.return_value = mock_resp

    status = revocation_check.check_ocsp(keys_and_chain["leaf_cert"], keys_and_chain["inter_cert"])
    assert status.source == "ocsp"
    assert status.status == "unknown"

@patch("requests.get")
@patch("pathlib.Path.read_bytes")
def test_check_crl(mock_read_bytes, mock_get, keys_and_chain):
    # Mock CRL logic failure parse
    status = revocation_check.check_crl(keys_and_chain["leaf_cert"], keys_and_chain["inter_cert"], crl_source="test.crl")
    assert status.source == "crl"
    assert status.status == "unknown"


def test_generate_csr():
    with tempfile.TemporaryDirectory() as d:
        key_p = Path(d) / "key.pem"
        csr_p = Path(d) / "req.csr"
        client.generate_csr("CN=Tester", "rsa", 2048, ["DNS:test.local"], str(key_p), str(csr_p))
        assert key_p.exists()
        assert csr_p.exists()
