"""Edge-case tests for MicroPKI (Sprint 8).

TEST-62: Expired certificates.
TEST-63: Wrong key usage.
TEST-64: Malformed inputs.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from micropki import crypto_utils, certificates, chain, validation, database, repository, templates


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tmp_dir():
    d = tempfile.mkdtemp(prefix="micropki_edge_")
    return d


def _make_root_ca(out_dir: str, validity_days: int = 3650):
    """Быстрое создание Root CA для тестов."""
    from micropki import ca
    passphrase = b"test-pass"
    secrets = Path(out_dir) / "secrets"
    secrets.mkdir(exist_ok=True)
    pass_file = secrets / "ca.pass"
    pass_file.write_bytes(passphrase)
    ca.init_root_ca(
        subject="/CN=Test Root CA",
        key_type="rsa",
        key_size=4096,
        passphrase=passphrase,
        out_dir=out_dir,
        validity_days=validity_days,
        force=True,
    )
    return passphrase


def _make_intermediate(out_dir: str, passphrase: bytes):
    """Быстрое создание Intermediate CA."""
    from micropki import ca
    inter_pass = b"inter-pass"
    ca.issue_intermediate_ca(
        root_cert_path=str(Path(out_dir) / "certs" / "ca.cert.pem"),
        root_key_path=str(Path(out_dir) / "private" / "ca.key.pem"),
        root_passphrase=passphrase,
        subject="/CN=Test Intermediate CA",
        key_type="rsa",
        key_size=4096,
        passphrase=inter_pass,
        out_dir=out_dir,
        validity_days=1825,
        pathlen=0,
        force=True,
    )
    return inter_pass


def _issue_cert(out_dir: str, inter_pass: bytes, template: str,
                subject: str, san_strings: list[str] | None = None):
    from micropki import ca
    ca.issue_end_entity(
        ca_cert_path=str(Path(out_dir) / "certs" / "intermediate.cert.pem"),
        ca_key_path=str(Path(out_dir) / "private" / "intermediate.key.pem"),
        ca_passphrase=inter_pass,
        template=template,
        subject=subject,
        san_strings=san_strings or [],
        out_dir=str(Path(out_dir) / "certs"),
        validity_days=365,
    )


def _build_expired_cert():
    """Создаёт пару корневого и истёкшего конечного сертификата."""
    root_key = rsa.generate_private_key(65537, 4096)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Expired Test Root")])
    now = datetime.now(timezone.utc)
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=3650))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=False,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ), critical=True,
        )
        .sign(root_key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(65537, 2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired.example.com")])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(root_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=400))
        .not_valid_after(now - timedelta(days=1))  # expired yesterday
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ), critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("expired.example.com")]), critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )
    return root_cert, leaf_cert, root_key, leaf_key


def _build_wrong_eku_cert():
    """Создаёт сертификат с CLIENT_AUTH EKU (не SERVER_AUTH)."""
    root_key = rsa.generate_private_key(65537, 4096)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EKU Test Root")])
    now = datetime.now(timezone.utc)
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=False,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ), critical=True,
        )
        .sign(root_key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(65537, 2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "client-only.example.com")])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(root_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=False,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ), critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )
    return root_cert, leaf_cert


# ===========================================================================
# TEST-62: Expired Certificate Validation
# ===========================================================================

class TestExpiredCertificates:
    """Тесты для валидации истёкших сертификатов."""

    def test_expired_leaf_fails_chain_validation(self):
        """Истёкший leaf-сертификат должен не пройти валидацию."""
        root_cert, leaf_cert, _, _ = _build_expired_cert()
        with pytest.raises(ValueError, match="expired"):
            chain.validate_chain(leaf_cert, [], root_cert)

    def test_expired_leaf_fails_path_validation(self):
        """validate_path должен вернуть passed=False для истёкшего."""
        root_cert, leaf_cert, _, _ = _build_expired_cert()
        result = validation.validate_path([leaf_cert, root_cert])
        assert not result.passed
        assert any("xpir" in s.detail.lower() or "expired" in s.detail.lower()
                    for cv in result.certs for s in cv.steps if not s.passed)

    def test_expired_cert_with_fixed_validation_time(self):
        """Если задать время валидации до истечения, должен пройти."""
        root_cert, leaf_cert, _, _ = _build_expired_cert()
        past_time = datetime.now(timezone.utc) - timedelta(days=100)
        result = validation.validate_path([leaf_cert, root_cert], now=past_time)
        assert result.passed


# ===========================================================================
# TEST-63: Wrong Key Usage
# ===========================================================================

class TestWrongKeyUsage:
    """Тесты для сертификатов с неправильным EKU."""

    def test_client_cert_has_client_auth_eku(self):
        """Клиентский сертификат должен содержать CLIENT_AUTH."""
        root_cert, leaf_cert = _build_wrong_eku_cert()
        eku = leaf_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku.value
        assert ExtendedKeyUsageOID.SERVER_AUTH not in eku.value

    def test_server_template_issues_server_auth(self):
        """Шаблон server выдаёт SERVER_AUTH EKU."""
        san = [x509.DNSName("test.example.com")]
        ext = templates.get_template_extensions("server", san, is_rsa=True)
        assert ExtendedKeyUsageOID.SERVER_AUTH in ext.extended_key_usage

    def test_client_template_issues_client_auth(self):
        """Шаблон client выдаёт CLIENT_AUTH EKU."""
        ext = templates.get_template_extensions("client", [], is_rsa=True)
        assert ExtendedKeyUsageOID.CLIENT_AUTH in ext.extended_key_usage

    def test_code_signing_template_eku(self):
        """Шаблон code_signing выдаёт CODE_SIGNING EKU."""
        ext = templates.get_template_extensions("code_signing", [], is_rsa=True)
        assert ExtendedKeyUsageOID.CODE_SIGNING in ext.extended_key_usage

    def test_server_san_type_restriction(self):
        """Серверному шаблону нельзя давать email SAN."""
        with pytest.raises(ValueError):
            templates.validate_san_for_template("server", [x509.RFC822Name("a@b.com")])

    def test_client_san_type_restriction(self):
        """Клиентскому шаблону нельзя давать IP SAN."""
        import ipaddress
        with pytest.raises(ValueError):
            templates.validate_san_for_template("client", [x509.IPAddress(ipaddress.ip_address("1.2.3.4"))])


# ===========================================================================
# TEST-64: Malformed Inputs
# ===========================================================================

class TestMalformedInputs:
    """Тесты для некорректных входных данных."""

    def test_malformed_pem_cert_load(self):
        """Загрузка повреждённого PEM-файла должна вызвать ошибку."""
        tmp = tempfile.NamedTemporaryFile(suffix=".pem", delete=False, mode="w")
        try:
            tmp.write("-----BEGIN CERTIFICATE-----\nNOT_VALID_BASE64!!!\n-----END CERTIFICATE-----\n")
            tmp.flush()
            tmp.close()
            with pytest.raises(Exception):
                crypto_utils.load_certificate_pem(tmp.name)
        finally:
            os.unlink(tmp.name)

    def test_malformed_csr_load(self):
        """Загрузка повреждённого CSR-файла должна вызвать ошибку."""
        tmp = tempfile.NamedTemporaryFile(suffix=".csr.pem", delete=False, mode="w")
        try:
            tmp.write("this is not a CSR")
            tmp.flush()
            tmp.close()
            with pytest.raises(Exception):
                crypto_utils.load_csr_pem(tmp.name)
        finally:
            os.unlink(tmp.name)

    def test_empty_subject_dn(self):
        """Пустой Subject DN должен вызвать ValueError."""
        with pytest.raises(ValueError):
            certificates.parse_subject_dn("")

    def test_invalid_subject_dn(self):
        """Некорректный DN (без =) должен вызвать ValueError."""
        with pytest.raises(ValueError):
            certificates.parse_subject_dn("INVALID")

    def test_unsupported_dn_attribute(self):
        """Неизвестный атрибут DN должен вызвать ValueError."""
        with pytest.raises(ValueError):
            certificates.parse_subject_dn("/FOOBAR=value")

    def test_invalid_san_format(self):
        """SAN без типа должен вызвать ValueError."""
        with pytest.raises(ValueError):
            templates.parse_san("nodots")

    def test_invalid_san_type(self):
        """Неизвестный тип SAN должен вызвать ValueError."""
        with pytest.raises(ValueError):
            templates.parse_san("ftp:example.com")

    def test_invalid_ip_san(self):
        """Невалидный IP в SAN должен вызвать ValueError."""
        with pytest.raises(ValueError):
            templates.parse_san("ip:not_an_ip")

    def test_nonexistent_passphrase_file(self):
        """Несуществующий файл пароля должен вызвать FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            crypto_utils.load_passphrase("/nonexistent/path/pass.txt")

    def test_corrupted_audit_log(self):
        """Повреждённый audit.log должен быть обнаружен verify_log."""
        from micropki.audit import AuditLogger, verify_log
        tmp = _tmp_dir()
        try:
            logger = AuditLogger(tmp)
            logger.log_event("test", "success", "entry 1")
            logger.log_event("test", "success", "entry 2")

            # Повреждаем файл
            log_path = Path(tmp) / "audit.log"
            lines = log_path.read_text(encoding="utf-8").splitlines()
            lines[0] = '{"tampered": true}'
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            ok, idx = verify_log(str(log_path), str(Path(tmp) / "chain.dat"))
            assert not ok
            assert idx == 0
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_empty_san_value(self):
        """SAN с пустым значением должен вызвать ValueError."""
        with pytest.raises(ValueError):
            templates.parse_san("dns:")

    def test_unknown_template(self):
        """Неизвестный шаблон должен вызвать ValueError."""
        with pytest.raises(ValueError):
            templates.get_template_extensions("unknown_template", [])

    def test_chain_with_single_cert(self):
        """validate_path с 1 сертификатом не должен пройти."""
        root_cert, _, _, _ = _build_expired_cert()
        result = validation.validate_path([root_cert])
        assert not result.passed

    def test_chain_empty(self):
        """validate_path с пустой цепочкой не должен пройти."""
        result = validation.validate_path([])
        assert not result.passed
