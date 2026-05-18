#!/usr/bin/env python3
"""
TEST-2: Demonstrate that the private key corresponds to the certificate's public key.
Usage:
  python scripts/verify_key_cert_match.py <path-to-ca.key.pem> <path-to-ca.cert.pem> [passphrase-file]

If passphrase-file is omitted, the key must be unencrypted (not recommended).
"""
import sys
from pathlib import Path

# Add project root for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def main():
    if len(sys.argv) < 3:
        print("Usage: verify_key_cert_match.py <ca.key.pem> <ca.cert.pem> [passphrase-file]", file=sys.stderr)
        sys.exit(1)
    key_path = Path(sys.argv[1])
    cert_path = Path(sys.argv[2])
    passphrase = None
    if len(sys.argv) >= 4:
        passphrase = Path(sys.argv[3]).read_bytes().rstrip(b"\n\r")

    if not key_path.exists():
        print(f"Key file not found: {key_path}", file=sys.stderr)
        sys.exit(1)
    if not cert_path.exists():
        print(f"Certificate file not found: {cert_path}", file=sys.stderr)
        sys.exit(1)

    key_data = key_path.read_bytes()
    cert_data = cert_path.read_bytes()
    private_key = load_pem_private_key(key_data, password=passphrase, backend=default_backend())
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    public_key = cert.public_key()

    # Sign a test message with the private key
    message = b"MicroPKI key-cert match test"
    if hasattr(private_key, "key_size"):  # RSA
        signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
    else:  # EC
        from cryptography.hazmat.primitives.asymmetric import ec
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))

    print("OK: Private key matches certificate public key (sign/verify succeeded).")
    sys.exit(0)


if __name__ == "__main__":
    main()
