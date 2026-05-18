import tempfile
from pathlib import Path

import pytest

from micropki import crypto_utils
from micropki import certificates


def test_generate_rsa_key():
    key = crypto_utils.generate_rsa_key(4096)
    assert key.key_size == 4096


def test_generate_ecc_key():
    key = crypto_utils.generate_ecc_key(384)
    assert key.curve.name == "secp384r1"


def test_generate_ecc_key_p256():
    key = crypto_utils.generate_ecc_key(256)
    assert key.curve.name == "secp256r1"


def test_generate_ecc_key_unsupported():
    with pytest.raises(ValueError, match="P-256.*P-384"):
        crypto_utils.generate_ecc_key(521)


def test_load_passphrase_strips_newline():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pass") as f:
        f.write(b"secret\n")
        path = f.name
    try:
        data = crypto_utils.load_passphrase(path)
        assert data == b"secret"
    finally:
        Path(path).unlink(missing_ok=True)


def test_load_passphrase_file_not_found():
    with pytest.raises(FileNotFoundError):
        crypto_utils.load_passphrase("/nonexistent/path.pass")


def test_encrypted_key_roundtrip():
    key = crypto_utils.generate_rsa_key(4096)
    passphrase = b"test-passphrase"
    pem = crypto_utils.private_key_to_pem_encrypted(key, passphrase)
    assert b"ENCRYPTED" in pem or b"PRIVATE KEY" in pem

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as f:
        f.write(pem)
        path = f.name
    try:
        loaded = crypto_utils.load_private_key_encrypted(path, passphrase)
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        msg = b"test message"
        sig = loaded.sign(msg, padding.PKCS1v15(), hashes.SHA256())
        key.public_key().verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
    finally:
        Path(path).unlink(missing_ok=True)
