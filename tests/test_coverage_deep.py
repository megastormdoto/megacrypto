import pytest
import sqlite3
import json
import sys
from unittest.mock import MagicMock, patch
from pathlib import Path
from micropki import repository, ca, revocation_check, audit, client, crypto_utils, validation, serial
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, timezone

def create_fake_cert(subject_name="CN=Test", issuer_name="CN=Test"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name.from_rfc4514_string(subject_name)
    issuer = x509.Name.from_rfc4514_string(issuer_name)
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc) - timedelta(days=1)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=1)
    ).sign(key, hashes.SHA256())
    return cert

# 1. Target: micropki/repository.py (DB error handling)
def test_repo_db_errors(tmp_path):
    db_path = str(tmp_path / "error.db")
    with patch("sqlite3.connect") as mock_connect:
        mock_conn = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.execute.side_effect = sqlite3.Error("DB Failure")
        res = repository.get_certificate_by_serial(12345, db_path)
        assert res is None
        with pytest.raises(sqlite3.Error):
            repository.update_certificate_status(12345, "revoked", db_path=db_path)

# 2. Target: micropki/ca.py (Init edge cases)
def test_ca_init_missing_files(tmp_path):
    with pytest.raises(Exception):
        ca.verify_certificate(str(tmp_path / "nonexistent.pem"))
    res = ca.resolve_local_ca_for_issuer(str(tmp_path), "CN=None")
    assert res is None

# 3. Target: micropki/revocation_check.py (In-depth)
@patch("requests.get")
@patch("requests.post")
def test_revocation_check_all_paths(mock_post, mock_get, tmp_path):
    cert = create_fake_cert()
    issuer = create_fake_cert()
    mock_post.return_value = MagicMock(status_code=404)
    res = revocation_check.check_ocsp(cert, issuer, ocsp_url="http://ocsp.com")
    assert res.status == "unknown"
    assert "HTTP 404" in res.detail
    mock_get.return_value = MagicMock(status_code=200, content=b"not-a-crl")
    res = revocation_check.check_crl(cert, issuer, crl_source="http://crl.com")
    assert res.status == "unknown"
    assert "parse error" in res.detail

# 4. Target: micropki/audit.py (Tamper detection)
def test_audit_tamper_details(tmp_path):
    log_dir = tmp_path / "audit"
    log_dir.mkdir()
    logger = audit.AuditLogger(str(log_dir))
    logger.log_event("test", "success", "message")
    log_file = log_dir / "audit.log"
    with open(log_file, "a", encoding="utf-8") as f:
        f.write("NOT_JSON\n")
    passed, index = audit.verify_log(log_path=str(log_file), chain_path=str(log_dir / "chain.dat"))
    assert passed is False
    assert index == 1

# 5. Target: micropki/validation.py (Constraints)
def test_validation_constraints():
    cert = create_fake_cert("CN=Inter", "CN=Root")
    with pytest.raises(ValueError, match="Cannot build chain"):
        validation.build_chain(cert, [], [])

# 6. Target: micropki/cli.py (Help and Groups)
def test_cli_coverage():
    from micropki import cli
    with patch("sys.exit"), patch("sys.argv", ["micropki", "ca", "--help"]):
        cli.main()
    with patch("sys.exit"), patch("sys.argv", ["micropki", "client", "--help"]):
        cli.main()

# 7. Target: micropki/repo.py & repo server
def test_repo_server_details(tmp_path):
    from fastapi.testclient import TestClient
    from micropki import repo
    with TestClient(repo.app) as c:
        assert c.get("/certificate/NOT_HEX").status_code == 400
        assert c.get("/certificate/FFFFFFFF").status_code == 404

# 8. Target: micropki/client.py (CSR Errors & validate_cert)
def test_client_extra_paths(tmp_path):
    with pytest.raises(Exception):
        client.gen_csr("INVALID", str(tmp_path / "k"), str(tmp_path / "c"))
    
    # Test validate_cert function
    cert = create_fake_cert("CN=Leaf", "CN=Root")
    root = create_fake_cert("CN=Root", "CN=Root")
    
    # Mock validation.build_chain and validation.validate_path
    with patch("micropki.validation.build_chain", return_value=[cert, root]), \
         patch("micropki.validation.validate_path", return_value=validation.ValidationResult(passed=True, chain=[], certs=[])), \
         patch("micropki.crypto_utils.load_certificate_pem", return_value=cert):
        res = client.validate_certificate(cert_path="dummy", untrusted_paths=[], trusted_path="dummy")

def test_extreme_revocation_check_details():
    from micropki import revocation_check
    from cryptography import x509
    from unittest.mock import MagicMock
    cert = MagicMock(spec=x509.Certificate)
    cert.extensions = MagicMock()
    cert.extensions.get_extension_for_class.side_effect = x509.ExtensionNotFound("No CRL", x509.ExtensionOID.CRL_DISTRIBUTION_POINTS)
    res = revocation_check.check_revocation_status(cert, cert)
    assert res.status == "unknown"
