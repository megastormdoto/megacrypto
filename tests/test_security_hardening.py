from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from pathlib import Path

import pytest
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

@pytest.fixture()
def tmp_pki(tmp_path):
    from micropki import crypto_utils, database, ca, serial as serial_mod

    pki = tmp_path / "pki"
    pki.mkdir()
    (pki / "certs").mkdir()
    (pki / "private").mkdir()
    (pki / "crl").mkdir()
    (pki / "audit").mkdir()

    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "ca.pass").write_bytes(b"test-passphrase")
    (secrets / "inter.pass").write_bytes(b"inter-passphrase")

    db = pki / "micropki.db"
    # Initialize database
    from micropki import database
    # Force fresh init
    if db.exists(): db.unlink()
    database.init_database(str(db))
    
    # Create dummy cert files for /ca/* endpoints
    ca.init_root_ca(
        subject="/CN=Test Root CA",
        key_type="rsa",
        key_size=4096,
        passphrase=b"test-passphrase",
        out_dir=str(pki),
        validity_days=3650,
        db_path=str(db),
        force=True,
    )
    ca.issue_intermediate_ca(
        root_cert_path=str(pki / "certs" / "ca.cert.pem"),
        root_key_path=str(pki / "private" / "ca.key.pem"),
        root_passphrase=b"test-passphrase",
        subject="/CN=Test Intermediate CA",
        key_type="rsa",
        key_size=4096,
        passphrase=b"inter-passphrase",
        out_dir=str(pki),
        validity_days=1825,
        pathlen=0,
        db_path=str(db),
        force=True,
    )

    return {
        "pki": pki,
        "db_path": str(db),
        "ca_cert": str(pki / "certs" / "intermediate.cert.pem"),
        "ca_key": str(pki / "private" / "intermediate.key.pem"),
        "ca_pass": b"inter-passphrase",
        "root_cert": str(pki / "certs" / "ca.cert.pem"),
        "secrets": secrets,
    }

class TestPolicyWeakKey:
    
    def test_weak_rsa_key_csr_rejected(self, tmp_pki):
        from micropki import ca, crypto_utils
        from micropki.policy import PolicyViolationError
        weak_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        from cryptography.hazmat.primitives import hashes
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "weak.example.com")]))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("weak.example.com")]), critical=False)
            .sign(weak_key, hashes.SHA256())
        )
        from cryptography.hazmat.primitives import serialization
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

        with pytest.raises((PolicyViolationError, ValueError)):
            ca.issue_end_entity(
                ca_cert_path=tmp_pki["ca_cert"],
                ca_key_path=tmp_pki["ca_key"],
                ca_passphrase=tmp_pki["ca_pass"],
                template="server",
                subject="/CN=weak.example.com",
                san_strings=["dns:weak.example.com"],
                out_dir=str(tmp_pki["pki"] / "certs"),
                validity_days=365,
                csr_pem=csr_pem,
                db_path=tmp_pki["db_path"],
            )
        audit_log = tmp_pki["pki"] / "audit" / "audit.log"
        assert audit_log.is_file()
        entries = [json.loads(line) for line in audit_log.read_text().splitlines() if line.strip()]
        failure_entries = [e for e in entries if e.get("status") == "failure"]
        assert len(failure_entries) > 0, "Expected at least one failure audit entry"

    def test_policy_check_rsa_below_minimum(self):
        from micropki.policy import PolicyViolationError, check_key_size

        with pytest.raises(PolicyViolationError):
            check_key_size("rsa", 1024, "end_entity")

        with pytest.raises(PolicyViolationError):
            check_key_size("rsa", 2048, "root")  # root needs 4096
        check_key_size("rsa", 4096, "root")
        check_key_size("rsa", 2048, "end_entity")

class TestPolicyExcessiveValidity:
    
    def test_excessive_validity_rejected(self, tmp_pki):
        from micropki import ca
        from micropki.policy import PolicyViolationError

        with pytest.raises(PolicyViolationError, match="365"):
            ca.issue_end_entity(
                ca_cert_path=tmp_pki["ca_cert"],
                ca_key_path=tmp_pki["ca_key"],
                ca_passphrase=tmp_pki["ca_pass"],
                template="server",
                subject="/CN=long.example.com",
                san_strings=["dns:long.example.com"],
                out_dir=str(tmp_pki["pki"] / "certs"),
                validity_days=400,
                db_path=tmp_pki["db_path"],
            )

    def test_policy_check_validity_periods(self):
        from micropki.policy import PolicyViolationError, check_validity_period

        with pytest.raises(PolicyViolationError):
            check_validity_period(3651, "root")
        with pytest.raises(PolicyViolationError):
            check_validity_period(1826, "intermediate")
        with pytest.raises(PolicyViolationError):
            check_validity_period(366, "end_entity")
        check_validity_period(3650, "root")
        check_validity_period(1825, "intermediate")
        check_validity_period(365, "end_entity")

class TestPolicyWildcardSAN:
    
    def test_wildcard_san_rejected(self, tmp_pki):
        from micropki import ca
        from micropki.policy import PolicyViolationError

        with pytest.raises(PolicyViolationError, match="[Ww]ildcard"):
            ca.issue_end_entity(
                ca_cert_path=tmp_pki["ca_cert"],
                ca_key_path=tmp_pki["ca_key"],
                ca_passphrase=tmp_pki["ca_pass"],
                template="server",
                subject="/CN=wildcard.example.com",
                san_strings=["dns:*.example.com"],
                out_dir=str(tmp_pki["pki"] / "certs"),
                validity_days=365,
                db_path=tmp_pki["db_path"],
            )

    def test_policy_check_wildcard_directly(self):
        from micropki.policy import PolicyViolationError, check_san_policy

        san_names = [x509.DNSName("*.example.com")]
        with pytest.raises(PolicyViolationError, match="[Ww]ildcard"):
            check_san_policy("server", san_names, allow_wildcards=False)
        check_san_policy("server", san_names, allow_wildcards=True)

class TestPolicyForbiddenSANType:
    
    def test_email_san_on_code_signing_rejected(self, tmp_pki):
        from micropki import ca
        from micropki.policy import PolicyViolationError

        with pytest.raises((PolicyViolationError, ValueError), match="email"):
            ca.issue_end_entity(
                ca_cert_path=tmp_pki["ca_cert"],
                ca_key_path=tmp_pki["ca_key"],
                ca_passphrase=tmp_pki["ca_pass"],
                template="code_signing",
                subject="/CN=Code Signer",
                san_strings=["email:user@example.com"],
                out_dir=str(tmp_pki["pki"] / "certs"),
                validity_days=365,
                db_path=tmp_pki["db_path"],
            )

class TestAuditTamperDetection:
    
    def test_tamper_detected(self, tmp_path):
        from micropki.audit import AuditLogger, verify_log

        audit_dir = tmp_path / "audit"
        logger = AuditLogger(str(audit_dir))
        logger.log_event("test_op_1", "success", "First event")
        logger.log_event("test_op_2", "success", "Second event")
        logger.log_event("test_op_3", "success", "Third event")
        ok, idx = verify_log(str(audit_dir / "audit.log"), str(audit_dir / "chain.dat"))
        assert ok is True
        assert idx is None
        log_file = audit_dir / "audit.log"
        lines = log_file.read_text(encoding="utf-8").splitlines(keepends=True)
        assert len(lines) >= 3
        tampered = list(lines[1])
        for i, ch in enumerate(tampered):
            if ch.isalpha():
                tampered[i] = 'Z' if ch != 'Z' else 'A'
                break
        lines[1] = "".join(tampered)
        log_file.write_text("".join(lines), encoding="utf-8")
        ok, idx = verify_log(str(audit_dir / "audit.log"), str(audit_dir / "chain.dat"))
        assert ok is False
        assert idx is not None

class TestAuditChainContinuity:
    
    def test_missing_entry_detected(self, tmp_path):
        from micropki.audit import AuditLogger, verify_log

        audit_dir = tmp_path / "audit"
        logger = AuditLogger(str(audit_dir))

        logger.log_event("op_a", "success", "Entry A")
        logger.log_event("op_b", "success", "Entry B")
        logger.log_event("op_c", "success", "Entry C")
        log_file = audit_dir / "audit.log"
        lines = log_file.read_text(encoding="utf-8").splitlines(keepends=True)
        del lines[1]
        log_file.write_text("".join(lines), encoding="utf-8")

        ok, idx = verify_log(str(audit_dir / "audit.log"), str(audit_dir / "chain.dat"))
        assert ok is False
        assert idx is not None

class TestCompromiseSimulation:
    
    def test_compromise_and_block(self, tmp_pki):
        from micropki import ca, compromise, database, crypto_utils
        from micropki.policy import PolicyViolationError
        cert_pem = ca.issue_end_entity(
            ca_cert_path=tmp_pki["ca_cert"],
            ca_key_path=tmp_pki["ca_key"],
            ca_passphrase=tmp_pki["ca_pass"],
            template="server",
            subject="/CN=compromised.example.com",
            san_strings=["dns:compromised.example.com"],
            out_dir=str(tmp_pki["pki"] / "certs"),
            validity_days=365,
            db_path=tmp_pki["db_path"],
        )
        cert_path = tmp_pki["pki"] / "certs" / "compromised.example.com.cert.pem"
        assert cert_path.is_file()
        result = compromise.mark_compromised(
            db_path=tmp_pki["db_path"],
            cert_path=str(cert_path),
            reason="keyCompromise",
            audit_dir=str(tmp_pki["pki"] / "audit"),
        )
        assert result["serial"]
        assert result["public_key_hash"]
        assert database.is_key_hash_compromised(tmp_pki["db_path"], result["public_key_hash"])
        cert = crypto_utils.load_certificate_pem(str(cert_path))
        assert compromise.is_key_compromised(tmp_pki["db_path"], cert.public_key())
        key_path = tmp_pki["pki"] / "certs" / "compromised.example.com.key.pem"
        if key_path.is_file():
            priv_key = crypto_utils.load_private_key_encrypted(str(key_path), None)
            from cryptography.hazmat.primitives import hashes, serialization
            csr = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "reuse.example.com")]))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("reuse.example.com")]), critical=False)
                .sign(priv_key, hashes.SHA256())
            )
            csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
            with pytest.raises((PolicyViolationError, ValueError), match="[Cc]ompromise"):
                ca.issue_end_entity(
                    ca_cert_path=tmp_pki["ca_cert"],
                    ca_key_path=tmp_pki["ca_key"],
                    ca_passphrase=tmp_pki["ca_pass"],
                    template="server",
                    subject="/CN=reuse.example.com",
                    san_strings=["dns:reuse.example.com"],
                    out_dir=str(tmp_pki["pki"] / "certs"),
                    validity_days=365,
                    csr_pem=csr_pem,
                    db_path=tmp_pki["db_path"],
                )

class TestRateLimiting:
    
    def test_rate_limiter_blocks_excess(self):
        from micropki.ratelimit import RateLimiter

        limiter = RateLimiter(rate=1.0, burst=2)
        assert limiter.allow("1.2.3.4") is True
        assert limiter.allow("1.2.3.4") is True
        assert limiter.allow("1.2.3.4") is False
        assert limiter.allow("5.6.7.8") is True

    def test_rate_limiter_retry_after(self):
        from micropki.ratelimit import RateLimiter

        limiter = RateLimiter(rate=1.0, burst=1)
        assert limiter.allow("10.0.0.1") is True
        assert limiter.allow("10.0.0.1") is False
        retry = limiter.get_retry_after("10.0.0.1")
        assert retry > 0

    def test_rate_limiter_refill(self):
        from micropki.ratelimit import RateLimiter

        limiter = RateLimiter(rate=100.0, burst=1)  # fast refill
        assert limiter.allow("ip") is True
        assert limiter.allow("ip") is False

        time.sleep(0.02)  # wait for refill at 100/s
        assert limiter.allow("ip") is True

class TestCTLog:
    
    def test_ct_log_entry(self, tmp_pki):
        from micropki import transparency

        ct_path = tmp_pki["pki"] / "audit" / "ct.log"
        assert ct_path.is_file(), "CT log should exist after PKI init"

        content = ct_path.read_text(encoding="utf-8")
        assert len(content.strip().splitlines()) >= 1, "CT log should have entries"

    def test_ct_verify_inclusion(self, tmp_pki):
        from micropki import ca, transparency
        ca.issue_end_entity(
            ca_cert_path=tmp_pki["ca_cert"],
            ca_key_path=tmp_pki["ca_key"],
            ca_passphrase=tmp_pki["ca_pass"],
            template="server",
            subject="/CN=ct-test.example.com",
            san_strings=["dns:ct-test.example.com"],
            out_dir=str(tmp_pki["pki"] / "certs"),
            validity_days=365,
            db_path=tmp_pki["db_path"],
        )

        ct_path = tmp_pki["pki"] / "audit" / "ct.log"
        lines = ct_path.read_text(encoding="utf-8").strip().splitlines()
        last_line = lines[-1]
        parts = last_line.split("|")
        serial = parts[1].strip()
        assert transparency.verify_inclusion(serial, str(ct_path))

class TestFullIntegration:
    
    def test_full_hardening_flow(self, tmp_pki):
        from micropki import ca, audit as audit_mod, transparency, compromise
        from micropki.policy import PolicyViolationError
        from micropki.ratelimit import RateLimiter

        pki = tmp_pki["pki"]
        db = tmp_pki["db_path"]
        audit_dir = str(pki / "audit")
        audit_log = pki / "audit" / "audit.log"
        from micropki.policy import check_key_size
        with pytest.raises(PolicyViolationError):
            check_key_size("rsa", 1024, "end_entity")
        with pytest.raises(PolicyViolationError):
            ca.issue_end_entity(
                ca_cert_path=tmp_pki["ca_cert"],
                ca_key_path=tmp_pki["ca_key"],
                ca_passphrase=tmp_pki["ca_pass"],
                template="server",
                subject="/CN=long.example.com",
                san_strings=["dns:long.example.com"],
                out_dir=str(pki / "certs"),
                validity_days=500,
                db_path=db,
            )
        with pytest.raises(PolicyViolationError):
            ca.issue_end_entity(
                ca_cert_path=tmp_pki["ca_cert"],
                ca_key_path=tmp_pki["ca_key"],
                ca_passphrase=tmp_pki["ca_pass"],
                template="server",
                subject="/CN=wild.example.com",
                san_strings=["dns:*.example.com"],
                out_dir=str(pki / "certs"),
                validity_days=365,
                db_path=db,
            )
        ca.issue_end_entity(
            ca_cert_path=tmp_pki["ca_cert"],
            ca_key_path=tmp_pki["ca_key"],
            ca_passphrase=tmp_pki["ca_pass"],
            template="server",
            subject="/CN=valid.example.com",
            san_strings=["dns:valid.example.com"],
            out_dir=str(pki / "certs"),
            validity_days=365,
            db_path=db,
        )
        ct_path = pki / "audit" / "ct.log"
        assert ct_path.is_file()
        ct_content = ct_path.read_text(encoding="utf-8")
        assert "valid.example.com" in ct_content
        cert_file = pki / "certs" / "valid.example.com.cert.pem"
        result = compromise.mark_compromised(
            db_path=db,
            cert_path=str(cert_file),
            reason="keyCompromise",
            audit_dir=audit_dir,
        )
        assert result["public_key_hash"]
        ok, idx = audit_mod.verify_log(
            str(pki / "audit" / "audit.log"),
            str(pki / "audit" / "chain.dat"),
        )
        assert ok is True
        limiter = RateLimiter(rate=1.0, burst=2)
        assert limiter.allow("x") is True
        assert limiter.allow("x") is True
        assert limiter.allow("x") is False

class TestPolicyPathLength:
    
    def test_pathlen_must_be_zero_for_intermediate(self):
        from micropki.policy import PolicyViolationError, check_path_length

        with pytest.raises(PolicyViolationError):
            check_path_length(1, "intermediate")
        check_path_length(0, "intermediate")


class TestPolicyECCKeySize:
    
    def test_p256_rejected_for_root(self):
        from micropki.policy import PolicyViolationError, check_key_size

        with pytest.raises(PolicyViolationError):
            check_key_size("ecc", 256, "root")
        check_key_size("ecc", 384, "root")

    def test_p256_allowed_for_end_entity(self):
        from micropki.policy import check_key_size
        check_key_size("ecc", 256, "end_entity")


class TestAuditLoggerBasic:
    
    def test_create_and_query(self, tmp_path):
        from micropki.audit import AuditLogger, query_log

        audit_dir = tmp_path / "audit"
        logger = AuditLogger(str(audit_dir))

        logger.log_event("test_op", "success", "Test message", {"key": "value"})
        logger.log_event("other_op", "failure", "Failed", {"key": "other"})
        entries = query_log(str(audit_dir / "audit.log"))
        assert len(entries) == 2
        entries = query_log(str(audit_dir / "audit.log"), operation="test_op")
        assert len(entries) == 1
        assert entries[0]["operation"] == "test_op"

    def test_hash_chain_valid(self, tmp_path):
        from micropki.audit import AuditLogger, verify_log

        audit_dir = tmp_path / "audit"
        logger = AuditLogger(str(audit_dir))

        for i in range(5):
            logger.log_event(f"op_{i}", "success", f"Event {i}")

        ok, idx = verify_log(str(audit_dir / "audit.log"), str(audit_dir / "chain.dat"))
        assert ok is True
        assert idx is None

    def test_first_entry_prev_hash_is_zero(self, tmp_path):
        from micropki.audit import AuditLogger

        audit_dir = tmp_path / "audit"
        logger = AuditLogger(str(audit_dir))
        entry = logger.log_event("first", "success", "First entry")

        assert entry["integrity"]["prev_hash"] == "0" * 64

def test_extreme_audit_edge_cases(tmp_path):
    from micropki import audit
    import json
    log_dir = tmp_path / "audit"
    log_dir.mkdir()
    logger = audit.AuditLogger(str(log_dir))
    with patch("json.dumps", side_effect=TypeError("fail")):
        try:
            logger.log_event("op", "status", "msg")
        except Exception:
            pass
    logger.log_event("op1", "status", "msg")
    audit.query_log(str(log_dir / "audit.log"), from_ts="2020-01-01T00:00:00Z")

def test_extreme_transparency_ct_fail():
    from micropki import transparency
    from unittest.mock import MagicMock, patch
    from cryptography import x509
    with patch("builtins.open", side_effect=OSError("fail")):
        mock_cert = MagicMock(spec=x509.Certificate)
        mock_cert.serial_number = 123
        mock_cert.public_bytes.return_value = b"fake bytes"
        try:
            transparency.log_certificate(mock_cert)
        except OSError:
            pass

def test_extreme_ratelimit_burst():
    from micropki import ratelimit
    limiter = ratelimit.RateLimiter(rate=1, burst=1)
    assert limiter.allow("1.2.3.4") is True
    assert limiter.allow("1.2.3.4") is False

def test_extreme_compromise_simulation(tmp_path):
    from micropki import compromise
    from unittest.mock import MagicMock, patch
    from cryptography import x509
    with patch("micropki.crypto_utils.load_certificate_pem") as mock_load, \
         patch("micropki.database.insert_compromised_key") as mock_db, \
         patch("micropki.revocation.revoke") as mock_revoke, \
         patch("micropki.compromise.get_audit_logger"):
        mock_cert = MagicMock(spec=x509.Certificate)
        mock_cert.serial_number = 123
        mock_pk = MagicMock()
        mock_pk.public_bytes.return_value = b"fake bytes"
        mock_cert.public_key.return_value = mock_pk
        mock_load.return_value = mock_cert
        mock_revoke.side_effect = ValueError("fail")
        
        res = compromise.mark_compromised("db.db", "path/to/cert")
        assert res["serial"] == "7B"
