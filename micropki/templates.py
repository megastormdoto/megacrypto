from __future__ import annotations
import ipaddress
from dataclasses import dataclass
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

VALID_SAN_TYPES = {"dns", "ip", "email", "uri"}

TEMPLATE_ALLOWED_SAN_TYPES = {
    "server": {"dns", "ip"},
    "client": {"dns", "email"},
    "code_signing": {"dns", "uri"},
    "ocsp": {"dns", "uri"},
    "vpn": {"dns", "ip", "email"},
    "ipsec": {"dns", "ip"},
}

_SAN_PARSERS = {
    "dns": lambda v: x509.DNSName(v),
    "ip": lambda v: x509.IPAddress(_parse_ip(v)),
    "email": lambda v: x509.RFC822Name(v),
    "uri": lambda v: x509.UniformResourceIdentifier(v),
}

_SAN_TYPE_MAP = {
    x509.DNSName: "dns",
    x509.IPAddress: "ip",
    x509.RFC822Name: "email",
    x509.UniformResourceIdentifier: "uri",
}

def _parse_ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        raise ValueError(f"Invalid IP address in SAN: {value}")

def parse_san(san_string: str) -> x509.GeneralName:
    if ":" not in san_string:
        raise ValueError(f"SAN must be type:value, got: {san_string}")
    san_type, _, value = san_string.partition(":")
    san_type, value = san_type.strip().lower(), value.strip()
    if not value:
        raise ValueError(f"SAN value is empty: {san_string}")
    parser = _SAN_PARSERS.get(san_type)
    if parser is None:
        raise ValueError(f"Unsupported SAN type '{san_type}'. Must be one of: {', '.join(sorted(VALID_SAN_TYPES))}")
    return parser(value)

def parse_san_list(san_strings: list[str]) -> list[x509.GeneralName]:
    return [parse_san(s) for s in san_strings]

def validate_san_for_template(template: str, san_names: list[x509.GeneralName]) -> None:
    allowed = TEMPLATE_ALLOWED_SAN_TYPES.get(template)
    if allowed is None:
        raise ValueError(f"Unknown template: {template}")
    for name in san_names:
        san_type = _SAN_TYPE_MAP.get(type(name))
        if san_type is None:
            raise ValueError(f"Unsupported GeneralName type: {type(name)}")
        if san_type not in allowed:
            raise ValueError(
                f"SAN type '{san_type}' is not allowed for template '{template}'. "
                f"Allowed: {', '.join(sorted(allowed))}"
            )

@dataclass
class TemplateExtensions:
    basic_constraints: x509.BasicConstraints
    basic_constraints_critical: bool
    key_usage: x509.KeyUsage
    key_usage_critical: bool
    extended_key_usage: x509.ExtendedKeyUsage
    eku_critical: bool = False
    san: x509.SubjectAlternativeName | None = None
    san_critical: bool = False

def _leaf_key_usage(digital_signature: bool = True, key_encipherment: bool = False) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=digital_signature, key_encipherment=key_encipherment,
        content_commitment=False, data_encipherment=False,
        key_agreement=False, key_cert_sign=False, crl_sign=False,
        encipher_only=False, decipher_only=False,
    )

_LEAF_BC = x509.BasicConstraints(ca=False, path_length=None)

def get_template_extensions(
    template: str,
    san_names: list[x509.GeneralName],
    is_rsa: bool = True,
) -> TemplateExtensions:
    san_ext = x509.SubjectAlternativeName(san_names) if san_names else None

    if template == "server":
        if not san_names:
            raise ValueError("Server certificate requires at least one SAN (dns or ip)")
        return TemplateExtensions(
            basic_constraints=_LEAF_BC, basic_constraints_critical=True,
            key_usage=_leaf_key_usage(key_encipherment=is_rsa), key_usage_critical=True,
            extended_key_usage=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            san=san_ext,
        )

    if template == "client":
        return TemplateExtensions(
            basic_constraints=_LEAF_BC, basic_constraints_critical=True,
            key_usage=_leaf_key_usage(), key_usage_critical=True,
            extended_key_usage=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            san=san_ext,
        )

    if template == "code_signing":
        return TemplateExtensions(
            basic_constraints=_LEAF_BC, basic_constraints_critical=True,
            key_usage=_leaf_key_usage(), key_usage_critical=True,
            extended_key_usage=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            san=san_ext,
        )

    if template == "ocsp":
        return TemplateExtensions(
            basic_constraints=_LEAF_BC, basic_constraints_critical=True,
            key_usage=_leaf_key_usage(digital_signature=True, key_encipherment=False), key_usage_critical=True,
            extended_key_usage=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
            san=san_ext,
        )

    if template == "vpn":
        return TemplateExtensions(
            basic_constraints=_LEAF_BC, basic_constraints_critical=True,
            key_usage=_leaf_key_usage(key_encipherment=is_rsa), key_usage_critical=True,
            extended_key_usage=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]),
            san=san_ext,
        )

    if template == "ipsec":
        return TemplateExtensions(
            basic_constraints=_LEAF_BC, basic_constraints_critical=True,
            key_usage=_leaf_key_usage(key_encipherment=is_rsa), key_usage_critical=True,
            extended_key_usage=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            san=san_ext,
        )

    raise ValueError(f"Unknown template: {template}. Must be server, client, code_signing, ocsp, vpn, or ipsec.")