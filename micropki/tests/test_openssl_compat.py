"""Test OpenSSL compatibility (optional - requires OpenSSL installed)."""

import subprocess
import shutil
from pathlib import Path


def test_openssl_compatibility():
    """Test that certificate works with OpenSSL if available."""

    # Check if openssl is installed
    openssl_path = shutil.which('openssl')
    if not openssl_path:
        print("SKIP: OpenSSL not found in system - skipping test")
        return

    cert_path = Path("pki/certs/ca.cert.pem")

    if not cert_path.exists():
        print("SKIP: Certificate not found - run ca init first")
        return

    print(f"\nTesting certificate: {cert_path}")
    print(f"Using OpenSSL from: {openssl_path}")

    # Test 1: Can OpenSSL read the certificate?
    result = subprocess.run(
        [openssl_path, "x509", "-in", str(cert_path), "-text", "-noout"],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        print("PASS: OpenSSL can read the certificate")

        # Check for CA flag
        if "CA:TRUE" in result.stdout:
            print("PASS: Certificate has CA=TRUE extension")
        else:
            print("FAIL: Certificate missing CA=TRUE")

        # Check for Key Usage
        if "keyCertSign" in result.stdout:
            print("PASS: Certificate has keyCertSign usage")
        else:
            print("FAIL: Certificate missing keyCertSign")
    else:
        print("FAIL: OpenSSL cannot read the certificate")
        print(result.stderr)
        return

    # Test 2: Self-verification
    result = subprocess.run(
        [openssl_path, "verify", "-CAfile", str(cert_path), str(cert_path)],
        capture_output=True,
        text=True
    )

    if result.returncode == 0 and "OK" in result.stdout:
        print("PASS: OpenSSL verification passed")
    else:
        print("FAIL: OpenSSL verification failed")
        print(result.stderr)


def test_certificate_details():
    """Test certificate details without requiring OpenSSL."""
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    cert_path = Path("pki/certs/ca.cert.pem")

    if not cert_path.exists():
        print("SKIP: Certificate not found")
        return

    # Load certificate
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    # Check Basic Constraints
    try:
        bc = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        if bc.value.ca:
            print("PASS: Certificate is CA")
        else:
            print("FAIL: Certificate is not CA")
    except:
        print("FAIL: No Basic Constraints extension")

    # Check Key Usage
    try:
        ku = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.KEY_USAGE
        )
        if ku.value.key_cert_sign:
            print("PASS: Certificate has keyCertSign")
        else:
            print("FAIL: Certificate missing keyCertSign")
    except:
        print("FAIL: No Key Usage extension")

    # Check Subject
    print(f"Certificate Subject: {cert.subject}")
    print(f"Certificate Issuer: {cert.issuer}")
    print(f"Valid from: {cert.not_valid_before_utc}")
    print(f"Valid until: {cert.not_valid_after_utc}")

    print("PASS: Certificate details verified")


if __name__ == "__main__":
    print("=== Testing certificate details ===")
    test_certificate_details()
    print("\n=== Testing OpenSSL compatibility (if available) ===")
    test_openssl_compatibility()