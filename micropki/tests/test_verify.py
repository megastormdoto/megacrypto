"""Verification script for generated CA."""

import subprocess
import sys
from pathlib import Path


def verify_certificate(cert_path: Path):
    """Verify certificate using OpenSSL."""
    print(f"\n🔍 Verifying certificate: {cert_path}")

    # Check certificate details
    result = subprocess.run(
        ['openssl', 'x509', '-in', str(cert_path), '-text', '-noout'],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        print("✅ Certificate can be parsed")
        print("\nCertificate details:")
        # Print first few lines of certificate info
        lines = result.stdout.split('\n')[:15]
        for line in lines:
            print(f"  {line}")
    else:
        print("❌ Failed to parse certificate")
        print(result.stderr)
        return False

    # Verify self-signed certificate
    result = subprocess.run(
        ['openssl', 'verify', '-CAfile', str(cert_path), str(cert_path)],
        capture_output=True,
        text=True
    )

    if result.returncode == 0 and 'OK' in result.stdout:
        print("\n✅ Self-signature verification passed")
        return True
    else:
        print("\n❌ Self-signature verification failed")
        print(result.stderr)
        return False


if __name__ == '__main__':
    cert_file = Path('./pki/certs/ca.cert.pem')
    if not cert_file.exists():
        print("❌ Certificate not found. Run 'python -m micropki.cli ca init' first.")
        sys.exit(1)

    success = verify_certificate(cert_file)
    sys.exit(0 if success else 1)