"""Cryptographic utilities for key generation and handling."""

import os
from pathlib import Path
from typing import Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend


def generate_rsa_key(key_size: int = 4096) -> rsa.RSAPrivateKey:
    """
    Generate an RSA private key.

    Args:
        key_size: Key size in bits (must be 4096 for this project).

    Returns:
        RSA private key object.
    """
    if key_size != 4096:
        raise ValueError(f"RSA key size must be 4096, got {key_size}")

    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )


def generate_ecc_key() -> ec.EllipticCurvePrivateKey:
    """
    Generate an ECC private key on NIST P-384 curve.

    Returns:
        ECC private key object.
    """
    return ec.generate_private_key(
        curve=ec.SECP384R1(),
        backend=default_backend()
    )


def encrypt_private_key(
        private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
        passphrase: bytes
) -> bytes:
    """
    Encrypt a private key with a passphrase.

    Args:
        private_key: The private key object.
        passphrase: The passphrase as bytes.

    Returns:
        Encrypted private key in PEM format.
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
    )


def read_passphrase_from_file(passphrase_file: str) -> bytes:
    """
    Read passphrase from file and strip trailing newline.

    Args:
        passphrase_file: Path to the passphrase file.

    Returns:
        Passphrase as bytes.

    Raises:
        FileNotFoundError: If file doesn't exist.
        PermissionError: If file can't be read.
    """
    file_path = Path(passphrase_file)

    if not file_path.exists():
        raise FileNotFoundError(f"Passphrase file not found: {passphrase_file}")

    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"Cannot read passphrase file: {passphrase_file}")

    with open(file_path, 'rb') as f:
        passphrase = f.read()

    # Strip trailing newline if present
    if passphrase.endswith(b'\n'):
        passphrase = passphrase[:-1]
    if passphrase.endswith(b'\r\n'):
        passphrase = passphrase[:-2]

    return passphrase


def save_encrypted_key(
        encrypted_key: bytes,
        output_dir: Path,
        logger=None
) -> Path:
    """
    Save encrypted private key with proper permissions.

    Args:
        encrypted_key: The encrypted key bytes.
        output_dir: Base output directory.
        logger: Optional logger instance.

    Returns:
        Path to the saved key file.
    """
    private_dir = output_dir / "private"
    private_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    key_path = private_dir / "ca.key.pem"

    # Write key with strict permissions
    with open(key_path, 'wb') as f:
        f.write(encrypted_key)

    # Set file permissions to 0o600 (best effort on Windows)
    try:
        os.chmod(key_path, 0o600)
    except:
        pass  # Windows may not support chmod properly

    if logger:
        logger.info(f"Saved encrypted private key to {key_path}")

    return key_path