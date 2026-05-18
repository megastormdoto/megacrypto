import pytest
from cryptography import x509

from micropki.templates import (
    parse_san,
    parse_san_list,
    validate_san_for_template,
    get_template_extensions,
)


def test_parse_san_dns():
    name = parse_san("dns:example.com")
    assert isinstance(name, x509.DNSName)
    assert name.value == "example.com"


def test_parse_san_ip():
    name = parse_san("ip:192.168.1.1")
    assert isinstance(name, x509.IPAddress)


def test_parse_san_email():
    name = parse_san("email:alice@example.com")
    assert isinstance(name, x509.RFC822Name)
    assert name.value == "alice@example.com"


def test_parse_san_uri():
    name = parse_san("uri:https://example.com")
    assert isinstance(name, x509.UniformResourceIdentifier)


def test_parse_san_invalid_type():
    with pytest.raises(ValueError, match="Unsupported SAN type"):
        parse_san("foo:bar")


def test_parse_san_missing_colon():
    with pytest.raises(ValueError, match="type:value"):
        parse_san("example.com")


def test_parse_san_invalid_ip():
    with pytest.raises(ValueError, match="Invalid IP"):
        parse_san("ip:notanip")


def test_validate_san_server_rejects_email():
    names = parse_san_list(["email:a@b.com"])
    with pytest.raises(ValueError, match="not allowed.*server"):
        validate_san_for_template("server", names)


def test_validate_san_code_signing_rejects_ip():
    names = parse_san_list(["ip:1.2.3.4"])
    with pytest.raises(ValueError, match="not allowed.*code_signing"):
        validate_san_for_template("code_signing", names)


def test_validate_san_client_accepts_email():
    names = parse_san_list(["email:a@b.com"])
    validate_san_for_template("client", names)


def test_template_server_requires_san():
    with pytest.raises(ValueError, match="requires at least one SAN"):
        get_template_extensions("server", [], is_rsa=True)


def test_template_server_extensions():
    names = parse_san_list(["dns:example.com"])
    ext = get_template_extensions("server", names, is_rsa=True)
    assert ext.basic_constraints.ca is False
    assert ext.key_usage.digital_signature is True
    assert ext.key_usage.key_encipherment is True
    assert ext.san is not None


def test_template_client_extensions():
    ext = get_template_extensions("client", [], is_rsa=True)
    assert ext.basic_constraints.ca is False
    assert ext.key_usage.digital_signature is True
    assert ext.san is None


def test_template_code_signing_extensions():
    ext = get_template_extensions("code_signing", [], is_rsa=True)
    assert ext.basic_constraints.ca is False
    assert ext.key_usage.digital_signature is True


def test_template_unknown():
    with pytest.raises(ValueError, match="Unknown template"):
        get_template_extensions("invalid", [])
