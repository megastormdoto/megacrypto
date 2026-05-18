from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa


class PolicyViolationError(ValueError):
    pass

_RSA_MIN = {
    "root": 4096,
    "intermediate": 3072,
    "end_entity": 3072,  # было 2048, теперь 3072
}

_ECC_MIN_BITS = {
    "root": 384,
    "intermediate": 384,
    "end_entity": 384,  # было 256, теперь 384
}


def check_key_size(key_type: str, key_size: int, role: str) -> None:
    role = role.lower()
    key_type = key_type.lower()

    if key_type == "rsa":
        minimum = _RSA_MIN.get(role, 2048)
        if key_size < minimum:
            raise PolicyViolationError(
                f"RSA key size {key_size} bits is below the minimum {minimum} for {role}"
            )
        if key_size < 2048:
            raise PolicyViolationError(
                f"RSA key size {key_size} bits is below the absolute minimum of 2048"
            )
    elif key_type == "ecc":
        minimum = _ECC_MIN_BITS.get(role, 256)
        if key_size < minimum:
            raise PolicyViolationError(
                f"ECC key size P-{key_size} is below the minimum P-{minimum} for {role}"
            )
    else:
        raise PolicyViolationError(f"Unsupported key type: {key_type}")


def check_public_key_size(public_key, role: str) -> None:
    if isinstance(public_key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        pk = public_key if isinstance(public_key, rsa.RSAPublicKey) else public_key.public_key()
        check_key_size("rsa", pk.key_size, role)
    elif isinstance(public_key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        pk = public_key if isinstance(public_key, ec.EllipticCurvePublicKey) else public_key.public_key()
        check_key_size("ecc", pk.key_size, role)
    else:
        raise PolicyViolationError(f"Unknown key type: {type(public_key)}")

_MAX_VALIDITY_DAYS = {
    "root": 3650,
    "intermediate": 1825,
    "end_entity": 90,  # было 365, теперь 90 дней
}


def check_validity_period(days: int, role: str) -> None:
    role = role.lower()
    maximum = _MAX_VALIDITY_DAYS.get(role)
    if maximum is None:
        raise PolicyViolationError(f"Unknown role: {role}")
    if days > maximum:
        raise PolicyViolationError(
            f"Validity period {days} days exceeds maximum {maximum} for {role}"
        )

def check_san_policy(template: str, san_names: list[x509.GeneralName], allow_wildcards: bool = False) -> None:
    _ALLOWED_SAN_TYPES = {
        "server": {"dns", "ip"},
        "client": {"dns", "email"},
        "code_signing": {"dns", "uri"},
        "ocsp": {"dns", "uri"},
        "vpn": {"dns", "ip", "email"},      # добавлен VPN шаблон
        "ipsec": {"dns", "ip"},              # добавлен IPSec шаблон
    }

    _SAN_TYPE_MAP = {
        x509.DNSName: "dns",
        x509.IPAddress: "ip",
        x509.RFC822Name: "email",
        x509.UniformResourceIdentifier: "uri",
    }

    allowed = _ALLOWED_SAN_TYPES.get(template)
    if allowed is None:
        return  # unknown template — skip SAN policy checks

    for name in san_names:
        san_type = _SAN_TYPE_MAP.get(type(name))
        if san_type is None:
            raise PolicyViolationError(f"Unsupported SAN type: {type(name)}")
        if san_type not in allowed:
            raise PolicyViolationError(
                f"SAN type '{san_type}' is not allowed for template '{template}'. "
                f"Allowed: {', '.join(sorted(allowed))}"
            )
        if not allow_wildcards and san_type == "dns":
            value = name.value if hasattr(name, "value") else str(name)
            if value.startswith("*."):
                raise PolicyViolationError(
                    f"Wildcard SAN '{value}' is not allowed by policy. "
                    f"Use --allow-wildcards to override."
                )

def check_algorithm(key_type: str, hash_name: str | None) -> None:
    if hash_name is None:
        return
    hash_name = hash_name.upper()
    if "SHA1" in hash_name or hash_name == "SHA-1":
        raise PolicyViolationError(
            f"SHA-1 signature algorithm is not allowed. Use SHA-256 or stronger."
        )
    # Запретить MD5
    if hash_name == "MD5":
        raise PolicyViolationError(
            f"MD5 signature algorithm is not allowed. Use SHA-256 or stronger."
        )

    key_type = key_type.lower()
    if key_type == "ecc":
        pass


def check_csr_algorithm(csr: x509.CertificateSigningRequest) -> None:
    hash_algo = csr.signature_hash_algorithm
    if hash_algo is not None:
        name = hash_algo.name.upper()
        if "SHA1" in name:
            raise PolicyViolationError(
                f"CSR uses SHA-1 signature ({name}), which is not allowed."
            )
        if name == "MD5":
            raise PolicyViolationError(
                f"CSR uses MD5 signature, which is not allowed."
            )

def check_path_length(pathlen: int, role: str = "intermediate") -> None:
    if role.lower() == "intermediate" and pathlen > 0:
        raise PolicyViolationError(
            f"Intermediate CA path length must be 0 (got {pathlen}). "
            f"Use --allow-subordinate to override (not implemented)."
        )

def check_csr_key_size(csr: x509.CertificateSigningRequest, role: str = "end_entity") -> None:
    pub = csr.public_key()
    check_public_key_size(pub, role)