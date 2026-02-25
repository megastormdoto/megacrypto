"""X.509 certificate handling for MicroPKI."""

import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Union, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend


def parse_dn_string(dn_string: str) -> x509.Name:
    """
    Parse a Distinguished Name string into an x509.Name object.

    Supports formats:
    - "/CN=My Root CA/O=Demo/C=US"
    - "CN=My Root CA,O=Demo,C=US"

    Args:
        dn_string: The DN string to parse.

    Returns:
        x509.Name object.
    """
    attributes = []

    # Handle slash notation (/CN=...)
    if dn_string.startswith('/'):
        # Remove leading slash and split by slash
        parts = dn_string[1:].split('/')
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                oid = _get_oid_from_string(key)
                if oid:
                    attributes.append(x509.NameAttribute(oid, value))
    else:
        # Handle comma-separated format (CN=...,O=...)
        parts = dn_string.split(',')
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                oid = _get_oid_from_string(key.strip())
                if oid:
                    attributes.append(x509.NameAttribute(oid, value.strip()))

    if not attributes:
        raise ValueError(f"Could not parse DN string: {dn_string}")

    return x509.Name(attributes)


def _get_oid_from_string(key: str):
    """Convert DN key string to OID."""
    key = key.strip().upper()
    oid_map = {
        'CN': NameOID.COMMON_NAME,
        'O': NameOID.ORGANIZATION_NAME,
        'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
        'C': NameOID.COUNTRY_NAME,
        'ST': NameOID.STATE_OR_PROVINCE_NAME,
        'L': NameOID.LOCALITY_NAME,
        'E': NameOID.EMAIL_ADDRESS,
        'EMAIL': NameOID.EMAIL_ADDRESS,
        'DC': NameOID.DOMAIN_COMPONENT,
    }
    return oid_map.get(key)


def generate_serial_number() -> int:
    """
    Generate a cryptographically secure random serial number.

    Returns:
        Positive integer with at least 20 bits of entropy (20 bytes).
    """
    # Generate 20 random bytes and convert to integer
    random_bytes = secrets.token_bytes(20)
    serial = int.from_bytes(random_bytes, byteorder='big')

    # Ensure it's positive (it will be, as we're using big-endian)
    return serial


def create_self_signed_certificate(
        subject_dn: str,
        private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
        validity_days: int,
        logger=None
) -> x509.Certificate:
    """
    Create a self-signed X.509 certificate.

    Args:
        subject_dn: Distinguished Name string.
        private_key: The private key to sign the certificate with.
        validity_days: Validity period in days.
        logger: Optional logger instance.

    Returns:
        The generated certificate.
    """
    # Parse subject
    subject = parse_dn_string(subject_dn)

    # Generate serial number
    serial_number = generate_serial_number()
    if logger:
        logger.info(f"Generated serial number: {hex(serial_number)}")

    # Set validity period
    not_valid_before = datetime.now(timezone.utc)
    not_valid_after = not_valid_before + timedelta(days=validity_days)

    # Build certificate
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(subject)  # Self-signed, so issuer = subject
    builder = builder.not_valid_before(not_valid_before)
    builder = builder.not_valid_after(not_valid_after)
    builder = builder.serial_number(serial_number)
    builder = builder.public_key(private_key.public_key())

    # Add extensions
    # Basic Constraints: CA=True, critical
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )

    # Key Usage: keyCertSign and cRLSign, critical
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )

    # Subject Key Identifier
    ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
    builder = builder.add_extension(ski, critical=False)

    # Authority Key Identifier (same as SKI for self-signed)
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key())
    builder = builder.add_extension(aki, critical=False)

    # Determine signature algorithm hash
    if isinstance(private_key, rsa.RSAPrivateKey):
        hash_algorithm = hashes.SHA256()
    else:  # ECC
        hash_algorithm = hashes.SHA384()

    # Sign the certificate
    certificate = builder.sign(
        private_key=private_key,
        algorithm=hash_algorithm,
        backend=default_backend()
    )

    return certificate


def save_certificate(
        certificate: x509.Certificate,
        output_dir: Path,
        logger=None
) -> Path:
    """
    Save certificate to PEM file.

    Args:
        certificate: The certificate to save.
        output_dir: Base output directory.
        logger: Optional logger instance.

    Returns:
        Path to the saved certificate file.
    """
    certs_dir = output_dir / "certs"
    certs_dir.mkdir(parents=True, exist_ok=True)

    cert_path = certs_dir / "ca.cert.pem"

    with open(cert_path, 'wb') as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    if logger:
        logger.info(f"Saved certificate to {cert_path}")

    return cert_path