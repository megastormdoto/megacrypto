"""Root CA operations for MicroPKI."""

from datetime import datetime
from pathlib import Path
from typing import Optional
import logging

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec


def generate_policy_file(
        output_dir: Path,
        subject_dn: str,
        certificate: x509.Certificate,
        key_type: str,
        key_size: int,
        logger: Optional[logging.Logger] = None
) -> Path:
    """
    Generate the policy.txt file with CA information.

    Args:
        output_dir: Base output directory.
        subject_dn: Distinguished Name of the CA.
        certificate: The generated certificate.
        key_type: Type of key (rsa or ecc).
        key_size: Size of the key.
        logger: Optional logger instance.

    Returns:
        Path to the generated policy file.
    """
    policy_path = output_dir / "policy.txt"

    # Get certificate details
    serial_hex = format(certificate.serial_number, 'x')
    not_before = certificate.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    not_after = certificate.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC")

    # Format key algorithm string
    if key_type == "rsa":
        key_algorithm = f"RSA-{key_size}"
    else:
        key_algorithm = f"ECC-P{key_size}"

    # Generate policy content
    policy_content = f"""CERTIFICATE POLICY DOCUMENT
==========================
Version: 1.0
Creation Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}

CA INFORMATION
--------------
CA Name (Subject DN): {subject_dn}
Certificate Serial Number (hex): {serial_hex}
Validity Period: {not_before} to {not_after}
Key Algorithm: {key_algorithm}

STATEMENT OF PURPOSE
--------------------
Root CA for MicroPKI demonstration. This CA is intended for 
educational and testing purposes only. It should not be used 
in production environments.

This certificate is self-signed and serves as the root of 
trust for the MicroPKI infrastructure.

CERTIFICATE EXTENSIONS
----------------------
- Basic Constraints: CA=TRUE (critical)
- Key Usage: keyCertSign, cRLSign, digitalSignature (critical)
- Subject Key Identifier: Included
- Authority Key Identifier: Included (self-signed)

POLICY STATEMENTS
-----------------
1. This CA does not issue certificates to end entities directly.
2. This is a root CA and should be kept offline in production use.
3. The private key is stored encrypted with AES-256.
4. All operations are logged for audit purposes.

END OF POLICY DOCUMENT
"""

    # Write policy file
    with open(policy_path, 'w', encoding='utf-8') as f:
        f.write(policy_content)

    if logger:
        logger.info(f"Generated policy file: {policy_path}")

    return policy_path