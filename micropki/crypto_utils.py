from __future__ import annotations
import os
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
def make_serial() -> int:
    serial = int.from_bytes(os.urandom(19), "big")
    return serial if serial > 0 else 1
def signing_algorithm(key) -> hashes.HashAlgorithm:
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return hashes.SHA256()
    return hashes.SHA384()
def generate_key(key_type: str, key_size: int):
    if key_type == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    if key_type == "ecc":
        curves = {256: ec.SECP256R1(), 384: ec.SECP384R1()}
        curve = curves.get(key_size)
        if curve is None:
            raise ValueError(f"Unsupported ECC curve size: {key_size}. Must be 256 or 384.")
        return ec.generate_private_key(curve)
    raise ValueError(f"Unsupported key type: {key_type}")
def verify_cert_signature(cert: x509.Certificate, issuer_cert: x509.Certificate) -> None:
    pub = issuer_cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(cert.signature, cert.tbs_certificate_bytes,
                    padding.PKCS1v15(), cert.signature_hash_algorithm)
    else:
        pub.verify(cert.signature, cert.tbs_certificate_bytes,
                    ec.ECDSA(cert.signature_hash_algorithm))
def is_rsa_key(key) -> bool:
    return isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey))
def load_passphrase(path: str) -> bytes:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Passphrase file not found: {path}")
    if not p.is_file():
        raise ValueError(f"Not a file: {path}")
    return p.read_bytes().rstrip(b"\n\r")
def generate_rsa_key(bits: int = 4096) -> rsa.RSAPrivateKey:
    return generate_key("rsa", bits)
def generate_ecc_key(curve_bits: int = 384):
    if curve_bits not in (256, 384):
        raise ValueError("Only P-256 (256) and P-384 (384) are supported for ECC")
    return generate_key("ecc", curve_bits)
def private_key_to_pem_encrypted(key, passphrase: bytes) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )
def private_key_to_pem_unencrypted(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
def cert_to_pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)
def _set_permissions(path_obj: Path, mode: int, logger=None) -> None:
    try:
        path_obj.chmod(mode)
    except OSError:
        if logger:
            logger.warning("Could not set permissions %04o on %s (e.g. Windows)", mode, path_obj)
def write_private_key_pem(path: str, key, passphrase: bytes, logger=None) -> None:
    path_obj = Path(path)
    path_obj.parent.mkdir(parents=True, exist_ok=True)
    path_obj.write_bytes(private_key_to_pem_encrypted(key, passphrase))
    _set_permissions(path_obj, 0o600, logger)
    if logger:
        logger.info("Saved private key to %s", str(path_obj.resolve()))
def write_private_key_unencrypted(path: str, key, logger=None) -> None:
    path_obj = Path(path)
    path_obj.parent.mkdir(parents=True, exist_ok=True)
    path_obj.write_bytes(private_key_to_pem_unencrypted(key))
    _set_permissions(path_obj, 0o600, logger)
    if logger:
        logger.warning("Private key stored UNENCRYPTED at %s", str(path_obj.resolve()))
def ensure_private_dir_permissions(dir_path: str, logger=None) -> None:
    p = Path(dir_path)
    p.mkdir(parents=True, exist_ok=True)
    _set_permissions(p, 0o700, logger)
def load_private_key_encrypted(path: str, passphrase: bytes):
    data = Path(path).read_bytes()
    return serialization.load_pem_private_key(data, password=passphrase)
def load_certificate_pem(path: str) -> x509.Certificate:
    data = Path(path).read_bytes()
    return x509.load_pem_x509_certificate(data)
def load_csr_pem(path: str) -> x509.CertificateSigningRequest:
    data = Path(path).read_bytes()
    return x509.load_pem_x509_csr(data)
