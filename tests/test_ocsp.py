import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization
from micropki import ocsp as micro_ocsp
from micropki import ocsp_responder
from micropki import crypto_utils

@pytest.fixture
def keys_and_certs():
    issuer_key = crypto_utils.generate_key("rsa", 2048)
    issuer_subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test Root CA")])
    issuer_cert = x509.CertificateBuilder().subject_name(
        issuer_subject
    ).issuer_name(
        issuer_subject
    ).public_key(
        issuer_key.public_key()
    ).serial_number(
        1
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc)
    ).sign(issuer_key, hashes.SHA256())

    responder_key = crypto_utils.generate_key("rsa", 2048)
    responder_cert = x509.CertificateBuilder().subject_name(
        x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test OCSP Responder")])
    ).issuer_name(
        issuer_subject
    ).public_key(
        responder_key.public_key()
    ).serial_number(
        1000
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc)
    ).sign(issuer_key, hashes.SHA256())

    client_cert = x509.CertificateBuilder().subject_name(
        x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test Client")])
    ).issuer_name(
        issuer_subject
    ).public_key(
        crypto_utils.generate_key("rsa", 2048).public_key()
    ).serial_number(
        2000
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc)
    ).sign(issuer_key, hashes.SHA256())

    return {
        "issuer_key": issuer_key,
        "issuer_cert": issuer_cert,
        "responder_key": responder_key,
        "responder_cert": responder_cert,
        "client_cert": client_cert,
    }

def test_process_ocsp_request_good(keys_and_certs):
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(
        keys_and_certs["client_cert"],
        keys_and_certs["issuer_cert"],
        hashes.SHA256()
    )
    req = builder.build()
    req_der = req.public_bytes(serialization.Encoding.DER)

    with patch("micropki.repository.get_certificate_by_serial") as mock_get:
        mock_get.return_value = {"status": "valid"}
        logger = MagicMock()
        
        resp_der = micro_ocsp.process_ocsp_request(
            req_der,
            keys_and_certs["responder_cert"],
            keys_and_certs["responder_key"],
            keys_and_certs["issuer_cert"],
            "db.sqlite",
            logger
        )
        
        ocsp_resp = ocsp.load_der_ocsp_response(resp_der)
        assert ocsp_resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        assert ocsp_resp.certificate_status == ocsp.OCSPCertStatus.GOOD

def test_process_ocsp_request_revoked(keys_and_certs):
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(
        keys_and_certs["client_cert"],
        keys_and_certs["issuer_cert"],
        hashes.SHA256()
    )
    req = builder.build()
    req_der = req.public_bytes(serialization.Encoding.DER)

    with patch("micropki.repository.get_certificate_by_serial") as mock_get:
        mock_get.return_value = {"status": "revoked", "revocation_date": datetime.now(timezone.utc).isoformat(), "revocation_reason": "keyCompromise"}
        logger = MagicMock()
        
        resp_der = micro_ocsp.process_ocsp_request(
            req_der,
            keys_and_certs["responder_cert"],
            keys_and_certs["responder_key"],
            keys_and_certs["issuer_cert"],
            "db.sqlite",
            logger
        )
        
        ocsp_resp = ocsp.load_der_ocsp_response(resp_der)
        assert ocsp_resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        assert ocsp_resp.certificate_status == ocsp.OCSPCertStatus.REVOKED
        assert ocsp_resp.revocation_reason == x509.ReasonFlags.key_compromise

def test_process_ocsp_request_unknown(keys_and_certs):
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(
        keys_and_certs["client_cert"],
        keys_and_certs["issuer_cert"],
        hashes.SHA256()
    )
    req = builder.build()
    req_der = req.public_bytes(serialization.Encoding.DER)

    with patch("micropki.repository.get_certificate_by_serial") as mock_get:
        mock_get.return_value = None
        logger = MagicMock()
        
        resp_der = micro_ocsp.process_ocsp_request(
            req_der,
            keys_and_certs["responder_cert"],
            keys_and_certs["responder_key"],
            keys_and_certs["issuer_cert"],
            "db.sqlite",
            logger
        )
        
        ocsp_resp = ocsp.load_der_ocsp_response(resp_der)
        assert ocsp_resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        assert ocsp_resp.certificate_status == ocsp.OCSPCertStatus.UNKNOWN

def test_ocsp_responder_process_request(keys_and_certs):
    ocsp_responder.CONFIG["responder_cert"] = keys_and_certs["responder_cert"]
    ocsp_responder.CONFIG["responder_key"] = keys_and_certs["responder_key"]
    ocsp_responder.CONFIG["issuer_cert"] = keys_and_certs["issuer_cert"]
    ocsp_responder.CONFIG["db_path"] = "fake.db"
    ocsp_responder.CONFIG["logger"] = MagicMock()
    
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(
        keys_and_certs["client_cert"],
        keys_and_certs["issuer_cert"],
        hashes.SHA256()
    )
    req = builder.build()
    req_der = req.public_bytes(serialization.Encoding.DER)
    
    with patch("micropki.repository.get_certificate_by_serial") as mock_get:
        mock_get.return_value = {"status": "valid"}
        resp = ocsp_responder._process_request(req_der)
        assert resp.media_type == "application/ocsp-response"
        assert resp.body
        ocsp_resp = ocsp.load_der_ocsp_response(resp.body)
        assert ocsp_resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        assert ocsp_resp.certificate_status == ocsp.OCSPCertStatus.GOOD


def test_ocsp_app_endpoints():
    """Test OCSP responder web endpoints."""
    from fastapi.testclient import TestClient
    client = TestClient(ocsp_responder.app)
    # Test GET /
    response = client.get("/")
    assert response.status_code == 200
    
    # Test POST / with invalid data
    response = client.post(
        "/", 
        content=b"invalid", 
        headers={"Content-Type": "application/ocsp-request"}
    )
    # Current implementation returns 200 with empty body on parse error
    assert response.status_code == 200


def test_ocsp_init_server(tmp_path, keys_and_certs):
    """Test OCSP server initialization with real certs."""
    db = tmp_path / "test.db"
    cert_path = tmp_path / "resp.cert.pem"
    key_path = tmp_path / "resp.key.pem"
    issuer_path = tmp_path / "issuer.cert.pem"
    
    cert_path.write_bytes(keys_and_certs["responder_cert"].public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(keys_and_certs["responder_key"].private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))
    issuer_path.write_bytes(keys_and_certs["issuer_cert"].public_bytes(serialization.Encoding.PEM))
    
    ocsp_responder.init_ocsp_server(
        db_path=str(db),
        responder_cert_path=str(cert_path),
        responder_key_path=str(key_path),
        issuer_cert_path=str(issuer_path)
    )
    assert ocsp_responder.CONFIG["db_path"] == str(db)
