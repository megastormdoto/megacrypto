import pytest
from datetime import datetime, timedelta, timezone

from cryptography import x509

from micropki import crypto_utils, certificates
from micropki.csr import generate_intermediate_csr, sign_intermediate_csr, issue_end_entity_cert
from micropki.chain import validate_chain, check_validity
from micropki.crypto_utils import verify_cert_signature
from micropki.templates import get_template_extensions, parse_san_list


@pytest.fixture(scope="module")
def pki_chain():
    root_key = crypto_utils.generate_rsa_key(4096)
    root_cert = certificates.build_self_signed_root_ca(
        "/CN=Unit Root CA", root_key, 3650, "rsa", 4096,
    )

    inter_key = crypto_utils.generate_rsa_key(4096)
    inter_csr = generate_intermediate_csr("CN=Unit Intermediate CA", inter_key, 0)
    inter_cert = sign_intermediate_csr(inter_csr, root_cert, root_key, 1825, 0)

    leaf_key = crypto_utils.generate_rsa_key(2048)
    san_names = parse_san_list(["dns:unit.example.com"])
    ext = get_template_extensions("server", san_names, is_rsa=True)
    leaf_cert = issue_end_entity_cert(
        "CN=unit.example.com", leaf_key.public_key(),
        inter_cert, inter_key, 365, ext,
    )
    return root_key, root_cert, inter_key, inter_cert, leaf_key, leaf_cert


def test_validate_chain_ok(pki_chain):
    _, root_cert, _, inter_cert, _, leaf_cert = pki_chain
    chain = validate_chain(leaf_cert, [inter_cert], root_cert)
    assert len(chain) == 3


def test_validate_chain_wrong_root_fails(pki_chain):
    _, _, _, inter_cert, _, leaf_cert = pki_chain
    fake_root_key = crypto_utils.generate_rsa_key(4096)
    fake_root = certificates.build_self_signed_root_ca(
        "/CN=Fake Root", fake_root_key, 3650, "rsa", 4096,
    )
    with pytest.raises(Exception):
        validate_chain(leaf_cert, [inter_cert], fake_root)


def test_check_validity_expired():
    root_key = crypto_utils.generate_rsa_key(4096)
    root_cert = certificates.build_self_signed_root_ca(
        "/CN=Expired Root", root_key, 1, "rsa", 4096,
    )
    future = datetime.now(timezone.utc) + timedelta(days=400)
    with pytest.raises(ValueError, match="expired"):
        check_validity(root_cert, now=future)
