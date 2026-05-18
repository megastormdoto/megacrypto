"""Sprint 2 integration tests: intermediate CA, issue-cert, chain validation, negative cases."""

import subprocess
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID


def _run(*args):
    import sys
    from io import StringIO
    from micropki.cli import main
    stdout = StringIO()
    stderr = StringIO()
    old_stdout, old_stderr, old_argv = sys.stdout, sys.stderr, sys.argv
    sys.stdout, sys.stderr, sys.argv = stdout, stderr, ["micropki"] + [str(a) for a in args]
    try:
        exit_code = main() or 0
    except SystemExit as e:
        exit_code = e.code if e.code is not None else 0
    except Exception as e:
        stderr.write(str(e))
        exit_code = 1
    finally:
        sys.stdout, sys.stderr, sys.argv = old_stdout, old_stderr, old_argv
    return exit_code, stdout.getvalue(), stderr.getvalue()


@pytest.fixture(scope="module")
def pki_dir(tmp_path_factory, run_cli):
    """Set up Root CA + Intermediate CA once for the module."""
    base = tmp_path_factory.mktemp("pki_s2")
    secrets = base / "secrets"
    secrets.mkdir()
    (secrets / "root.pass").write_bytes(b"rootpass")
    (secrets / "inter.pass").write_bytes(b"interpass")
    out = base / "pki"

    code, _, err = run_cli(
        "ca", "init",
        "--subject", "/CN=Test Root CA",
        "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", str(secrets / "root.pass"),
        "--out-dir", str(out),
    )
    assert code == 0, err

    code, _, err = run_cli(
        "ca", "issue-intermediate",
        "--root-cert", str(out / "certs" / "ca.cert.pem"),
        "--root-key", str(out / "private" / "ca.key.pem"),
        "--root-pass-file", str(secrets / "root.pass"),
        "--subject", "CN=Test Intermediate CA,O=MicroPKI",
        "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", str(secrets / "inter.pass"),
        "--out-dir", str(out),
        "--validity-days", "1825",
        "--pathlen", "0",
    )
    assert code == 0, err
    return base


def test_intermediate_cert_exists(pki_dir):
    assert (pki_dir / "pki" / "certs" / "intermediate.cert.pem").exists()
    assert (pki_dir / "pki" / "private" / "intermediate.key.pem").exists()


def test_intermediate_policy_updated(pki_dir):
    policy = (pki_dir / "pki" / "policy.txt").read_text(encoding="utf-8")
    assert "Intermediate CA" in policy
    assert "Path Length Constraint" in policy


def test_intermediate_extensions(pki_dir):
    """Verify Intermediate CA has correct BC, KU, SKI, AKI (PKI-7)."""
    cert_data = (pki_dir / "pki" / "certs" / "intermediate.cert.pem").read_bytes()
    cert = x509.load_pem_x509_certificate(cert_data)

    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.critical is True
    assert bc.value.ca is True
    assert bc.value.path_length == 0

    ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert ku.critical is True
    assert ku.value.key_cert_sign is True
    assert ku.value.crl_sign is True

    cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)


def test_issue_server_cert(pki_dir):
    out = pki_dir / "pki" / "certs"
    code, _, err = _run(
        "ca", "issue-cert",
        "--ca-cert", str(pki_dir / "pki" / "certs" / "intermediate.cert.pem"),
        "--ca-key", str(pki_dir / "pki" / "private" / "intermediate.key.pem"),
        "--ca-pass-file", str(pki_dir / "secrets" / "inter.pass"),
        "--template", "server",
        "--subject", "CN=example.com,O=MicroPKI",
        "--san", "dns:example.com",
        "--san", "dns:www.example.com",
        "--san", "ip:192.168.1.10",
        "--out-dir", str(out),
    )
    assert code == 0, err
    assert (out / "example.com.cert.pem").exists()
    assert (out / "example.com.key.pem").exists()

    cert_data = (out / "example.com.cert.pem").read_bytes()
    cert = x509.load_pem_x509_certificate(cert_data)

    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca is False

    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku.value

    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_names = san.value.get_values_for_type(x509.DNSName)
    assert "example.com" in dns_names
    assert "www.example.com" in dns_names


def test_issue_client_cert(pki_dir):
    out = pki_dir / "pki" / "certs"
    code, _, err = _run(
        "ca", "issue-cert",
        "--ca-cert", str(pki_dir / "pki" / "certs" / "intermediate.cert.pem"),
        "--ca-key", str(pki_dir / "pki" / "private" / "intermediate.key.pem"),
        "--ca-pass-file", str(pki_dir / "secrets" / "inter.pass"),
        "--template", "client",
        "--subject", "CN=Alice Smith",
        "--san", "email:alice@example.com",
        "--out-dir", str(out),
    )
    assert code == 0, err
    assert (out / "Alice_Smith.cert.pem").exists()

    cert_data = (out / "Alice_Smith.cert.pem").read_bytes()
    cert = x509.load_pem_x509_certificate(cert_data)
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku.value


def test_issue_code_signing_cert(pki_dir):
    out = pki_dir / "pki" / "certs"
    code, _, err = _run(
        "ca", "issue-cert",
        "--ca-cert", str(pki_dir / "pki" / "certs" / "intermediate.cert.pem"),
        "--ca-key", str(pki_dir / "pki" / "private" / "intermediate.key.pem"),
        "--ca-pass-file", str(pki_dir / "secrets" / "inter.pass"),
        "--template", "code_signing",
        "--subject", "CN=MicroPKI Code Signer",
        "--out-dir", str(out),
    )
    assert code == 0, err
    assert (out / "MicroPKI_Code_Signer.cert.pem").exists()

    cert_data = (out / "MicroPKI_Code_Signer.cert.pem").read_bytes()
    cert = x509.load_pem_x509_certificate(cert_data)
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert ExtendedKeyUsageOID.CODE_SIGNING in eku.value


def test_verify_chain(pki_dir):
    out = pki_dir / "pki"
    code, stdout, err = _run(
        "ca", "verify-chain",
        "--leaf", str(out / "certs" / "example.com.cert.pem"),
        "--intermediate", str(out / "certs" / "intermediate.cert.pem"),
        "--root", str(out / "certs" / "ca.cert.pem"),
    )
    assert code == 0, err
    assert "OK" in stdout


def test_server_cert_without_san_fails(pki_dir):
    """Server certificate without SAN must fail."""
    out = pki_dir / "pki" / "certs"
    code, _, err = _run(
        "ca", "issue-cert",
        "--ca-cert", str(pki_dir / "pki" / "certs" / "intermediate.cert.pem"),
        "--ca-key", str(pki_dir / "pki" / "private" / "intermediate.key.pem"),
        "--ca-pass-file", str(pki_dir / "secrets" / "inter.pass"),
        "--template", "server",
        "--subject", "CN=noSAN.com",
        "--out-dir", str(out),
    )
    assert code != 0
    assert "SAN" in err or "san" in err.lower()


def test_server_cert_with_email_san_fails(pki_dir):
    """Server cert with email SAN (unsupported type) must fail."""
    out = pki_dir / "pki" / "certs"
    code, _, err = _run(
        "ca", "issue-cert",
        "--ca-cert", str(pki_dir / "pki" / "certs" / "intermediate.cert.pem"),
        "--ca-key", str(pki_dir / "pki" / "private" / "intermediate.key.pem"),
        "--ca-pass-file", str(pki_dir / "secrets" / "inter.pass"),
        "--template", "server",
        "--subject", "CN=badsan.com",
        "--san", "email:bad@example.com",
        "--out-dir", str(out),
    )
    assert code != 0
    assert "not allowed" in err.lower() or "email" in err.lower()


def test_wrong_passphrase_fails(pki_dir):
    """Incorrect passphrase must fail."""
    wrong_pass = pki_dir / "secrets" / "wrong.pass"
    wrong_pass.write_bytes(b"wrongpassword")
    out = pki_dir / "pki" / "certs"
    code, _, err = _run(
        "ca", "issue-cert",
        "--ca-cert", str(pki_dir / "pki" / "certs" / "intermediate.cert.pem"),
        "--ca-key", str(pki_dir / "pki" / "private" / "intermediate.key.pem"),
        "--ca-pass-file", str(wrong_pass),
        "--template", "code_signing",
        "--subject", "CN=WrongPass",
        "--out-dir", str(out),
    )
    assert code != 0


def test_client_full_flow_cli(pki_dir, tmp_path):
    """Full client flow: gen-csr -> (manual issue) -> validate -> check-status."""
    base = pki_dir
    out = base / "pki"
    
    # 1. Gen CSR
    key_path = tmp_path / "user.key"
    csr_path = tmp_path / "user.csr"
    code, _, _ = _run("client", "gen-csr", "--subject", "/CN=User", "--out-key", str(key_path), "--out-csr", str(csr_path))
    assert code == 0

    # 2. Issue cert using the CSR
    code, _, err = _run(
        "ca", "issue-cert",
        "--ca-cert", str(out / "certs" / "intermediate.cert.pem"),
        "--ca-key", str(out / "private" / "intermediate.key.pem"),
        "--ca-pass-file", str(base / "secrets" / "inter.pass"),
        "--template", "client",
        "--subject", "/CN=User", # Still required by CLI even with CSR
        "--csr", str(csr_path),
        "--out-dir", str(tmp_path),
        "--db-path", str(out / "micropki.db")
    )
    assert code == 0, f"issue-cert failed: {err}"
    
    # The file is named User.cert.pem based on subject CN
    cert_file = tmp_path / "User.cert.pem"
    assert cert_file.exists()

    # 3. Validate (providing intermediate to build the chain)
    code, out_text, err = _run(
        "client", "validate",
        "--cert", str(cert_file),
        "--untrusted", str(out / "certs" / "intermediate.cert.pem"),
        "--trusted", str(out / "certs" / "ca.cert.pem")
    )
    assert code == 0, f"validate failed: {err}"
    assert "PASSED" in out_text.upper() or "VALID" in out_text.upper()

    # 4. Generate CRL (so check-status can use it)
    crl_path = tmp_path / "client.crl.pem"
    code, _, _ = _run(
        "ca", "gen-crl",
        "--ca-cert", str(out / "certs" / "intermediate.cert.pem"),
        "--ca-key", str(out / "private" / "intermediate.key.pem"),
        "--ca-pass-file", str(base / "secrets" / "inter.pass"),
        "--out-file", str(crl_path),
        "--db-path", str(out / "micropki.db")
    )
    assert code == 0

    # 5. Check status using the CRL (using Intermediate because it signed both cert and CRL)
    code, out_text, err = _run(
        "client", "check-status",
        "--cert", str(cert_file),
        "--ca-cert", str(out / "certs" / "intermediate.cert.pem"),
        "--crl", str(crl_path)
    )
    assert code == 0, f"check-status failed: {err}"
    assert "GOOD" in out_text.upper()

    # 6. Revoke the certificate
    from micropki import crypto_utils
    cert_obj = crypto_utils.load_certificate_pem(str(cert_file))
    serial_hex = hex(cert_obj.serial_number)[2:].upper()
    code, out_text, err = _run(
        "ca", "revoke",
        serial_hex,
        "--db-path", str(out / "micropki.db"),
        "--force"
    )
    assert code == 0, f"ca revoke failed: {err} | stdout: {out_text}"
    
    # 7. Re-generate CRL
    code, out_list, _ = _run("ca", "list-certs", "--db-path", str(out / "micropki.db"), "--format", "json")
    print(f"DEBUG: Certs in DB: {out_list}")
    
    _run(
        "ca", "gen-crl",
        "--ca-cert", str(out / "certs" / "intermediate.cert.pem"),
        "--ca-key", str(out / "private" / "intermediate.key.pem"),
        "--ca-pass-file", str(base / "secrets" / "inter.pass"),
        "--out-file", str(crl_path),
        "--db-path", str(out / "micropki.db")
    )
    
    # Verify CRL content directly
    from cryptography import x509
    from pathlib import Path
    crl_data = x509.load_pem_x509_crl(Path(crl_path).read_bytes())
    is_revoked_in_crl = any(r.serial_number == cert_obj.serial_number for r in crl_data)
    print(f"DEBUG: Is serial {hex(cert_obj.serial_number)} in CRL? {is_revoked_in_crl}")
    
    # 8. Check status again - should be REVOKED
    code, out_text, err = _run(
        "client", "check-status",
        "--cert", str(cert_file),
        "--ca-cert", str(out / "certs" / "intermediate.cert.pem"),
        "--crl", str(crl_path)
    )
    assert code == 1
    assert "REVOKED" in out_text.upper()

    # 6. Additional formats for list-certs
    _run("ca", "list-certs", "--db-path", str(out / "micropki.db"), "--format", "csv")
    _run("ca", "list-certs", "--db-path", str(out / "micropki.db"), "--format", "json")
    
    # 7. CA verify & Audit verify
    _run("ca", "verify", "--cert", str(cert_file))
    _run("audit", "verify", "--db-path", str(out / "micropki.db"))


def test_cli_help_coverage():
    """Call --help on various commands to cover argument parsing."""
    for cmd in [
        ["ca", "init"], ["ca", "issue-intermediate"], ["ca", "issue-cert"],
        ["ca", "revoke"], ["ca", "gen-crl"], ["ca", "check-revoked"],
        ["ca", "list-certs"], ["ca", "show-cert"], ["ca", "verify"],
        ["client", "gen-csr"], ["client", "validate"], ["client", "check-status"],
        ["client", "request-cert"], ["repo", "serve"], ["ocsp", "serve"],
        ["audit", "verify"], ["audit", "query"], ["demo", "run"], ["db", "init"]
    ]:
        code, out, _ = _run(*(cmd + ["--help"]))
        assert code == 0
        assert "usage" in out.lower()

def test_extreme_cli_error_paths(tmp_path):
    from unittest.mock import patch
    from micropki import cli
    with patch("micropki.audit.verify_log", return_value=(False, 5)):
        with patch("sys.exit", side_effect=SystemExit) as mock_exit:
            with patch("sys.argv", ["micropki", "audit", "query", "--verify"]):
                try:
                    cli.main()
                except SystemExit:
                    pass
                mock_exit.assert_called_with(1)

    with patch("micropki.audit.verify_log", return_value=(False, 5)):
        with patch("sys.exit", side_effect=SystemExit) as mock_exit:
            with patch("sys.argv", ["micropki", "audit", "verify", "--log-file-path", "test.log", "--chain-file", "chain.dat"]):
                try:
                    cli.main()
                except SystemExit:
                    pass
                mock_exit.assert_called_with(1)

    with patch("micropki.repository.get_certificate_by_serial", return_value=None):
        with patch("sys.exit", side_effect=SystemExit) as mock_exit:
            with patch("sys.argv", ["micropki", "ca", "show-cert", "ABCDEF"]):
                try:
                    cli.main()
                except SystemExit:
                    pass
                mock_exit.assert_called_with(1)

def test_extreme_client_coverage(tmp_path):
    from micropki import client
    import json
    from unittest.mock import MagicMock, patch
    
    csr_file = tmp_path / "csr.pem"
    csr_file.write_text("dummy csr content")
    
    # Test request_certificate errors
    with patch("requests.post") as mock_post:
        # HTTP Error
        mock_resp_err = MagicMock(status_code=500, text="Internal Error")
        mock_resp_err.json.return_value = {"detail": "Internal Error"}
        mock_post.return_value = mock_resp_err
        with pytest.raises(Exception, match="Certificate request failed"):
            client.request_certificate(str(csr_file), "server", "http://ca.url")
            
        # JSON parsing error
        mock_resp = MagicMock(status_code=200, text="not json")
        mock_resp.json.side_effect = json.JSONDecodeError("fail", "doc", 0)
        mock_post.return_value = mock_resp
        with pytest.raises(Exception):
            client.request_certificate(str(csr_file), "server", "http://ca.url")

    # Test validate_certificate JSON output and file saving
    cert = MagicMock(spec=x509.Certificate)
    cert.subject.rfc4514_string.return_value = "CN=Leaf"
    root = MagicMock(spec=x509.Certificate)
    root.subject.rfc4514_string.return_value = "CN=Root"
    with patch("micropki.validation.build_chain", return_value=[cert, root]), \
         patch("micropki.validation.validate_path") as mock_val, \
         patch("micropki.crypto_utils.load_certificate_pem", return_value=cert), \
         patch("builtins.open") as mock_open:
         
        mock_val_res = MagicMock()
        mock_val_res.passed = True
        mock_val_res.to_dict.return_value = {"passed": True}
        mock_val.return_value = mock_val_res
        
        # Test JSON format
        res = client.validate_certificate(cert_path="dummy", untrusted_paths=[], trusted_path="dummy", output_format="json")
        assert res.passed is True
        
        # Test with log file
        res = client.validate_certificate(cert_path="dummy", untrusted_paths=[], trusted_path="dummy", log_file="log.txt")
        assert res.passed is True

def test_extreme_ca_verification_fail(tmp_path):
    from micropki import ca
    p = tmp_path / "bad.pem"
    p.write_text("not a cert")
    with pytest.raises(Exception):
        ca.verify_certificate(str(p))
