"""Tests for MicroPKI CA operations."""

import pytest
from pathlib import Path
import tempfile
import os

from micropki import crypto_utils
from micropki import certificates


def test_key_generation_rsa():
    """Test RSA key generation."""
    private_key = crypto_utils.generate_rsa_key(4096)
    assert private_key is not None
    assert private_key.key_size == 4096


def test_key_generation_ecc():
    """Test ECC key generation."""
    private_key = crypto_utils.generate_ecc_key()
    assert private_key is not None
    assert private_key.curve.name == "secp384r1"


def test_dn_parsing_slash_format():
    """Test parsing DN in slash format."""
    dn = "/CN=Test CA/O=Demo/C=US"
    name = certificates.parse_dn_string(dn)
    assert len(name) == 3

    # Check attributes
    attrs = {attr.oid._name: attr.value for attr in name}
    assert attrs['commonName'] == 'Test CA'
    assert attrs['organizationName'] == 'Demo'
    assert attrs['countryName'] == 'US'


def test_dn_parsing_comma_format():
    """Test parsing DN in comma format."""
    dn = "CN=Test CA,O=Demo,C=US"
    name = certificates.parse_dn_string(dn)
    assert len(name) == 3

    attrs = {attr.oid._name: attr.value for attr in name}
    assert attrs['commonName'] == 'Test CA'
    assert attrs['organizationName'] == 'Demo'
    assert attrs['countryName'] == 'US'


def test_serial_number_generation():
    """Test serial number generation."""
    serial1 = certificates.generate_serial_number()
    serial2 = certificates.generate_serial_number()

    # Should be different
    assert serial1 != serial2
    # Should be positive
    assert serial1 > 0
    assert serial2 > 0


def test_passphrase_reading():
    """Test reading passphrase from file."""
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(b"testpassphrase\n")
        f.flush()

        passphrase = crypto_utils.read_passphrase_from_file(f.name)
        assert passphrase == b"testpassphrase"

    os.unlink(f.name)


if __name__ == '__main__':
    pytest.main([__file__])