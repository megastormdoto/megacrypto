import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


# Removed _run_micropki in favor of run_cli fixture


def test_cli_ca_init_missing_subject(run_cli):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pass") as f:
        f.write(b"pass")
        pass_path = f.name
    try:
        code, out, err = run_cli(
            "ca", "init",
            "--passphrase-file", pass_path,
            "--key-type", "rsa", "--key-size", "4096",
        )
        assert code != 0
        assert "subject" in err.lower() or "required" in err.lower()
    finally:
        Path(pass_path).unlink(missing_ok=True)


def test_cli_ca_init_invalid_key_type_ecc_with_256(run_cli):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pass") as f:
        f.write(b"pass")
        pass_path = f.name
    try:
        code, out, err = run_cli(
            "ca", "init",
            "--subject", "/CN=Test",
            "--key-type", "ecc", "--key-size", "256",
            "--passphrase-file", pass_path,
        )
        assert code != 0
        assert "384" in err or "key-size" in err.lower()
    finally:
        Path(pass_path).unlink(missing_ok=True)


def test_cli_ca_init_invalid_dn(run_cli):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pass") as f:
        f.write(b"pass")
        pass_path = f.name
    try:
        code, _, err = run_cli(
            "ca", "init",
            "--subject", "CN=,O=Bad",
            "--key-type", "rsa", "--key-size", "4096",
            "--passphrase-file", pass_path,
        )
        assert code != 0
        assert "subject" in err.lower() or "DN" in err.lower() or "invalid" in err.lower()
    finally:
        Path(pass_path).unlink(missing_ok=True)


def test_cli_ca_init_nonexistent_passphrase_file(run_cli):
    code, out, err = run_cli(
        "ca", "init",
        "--subject", "/CN=Test",
        "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", "/nonexistent/ca.pass",
    )
    assert code != 0
    assert "passphrase" in err.lower() or "exist" in err.lower() or "read" in err.lower()


def test_cli_ca_init_and_verify_self_signed(tmp_path, run_cli):
    pass_file = tmp_path / "ca.pass"
    pass_file.write_bytes(b"secret")
    out_dir = tmp_path / "pki"

    code, _, err = run_cli(
        "ca", "init",
        "--subject", "/CN=Demo Root CA",
        "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", str(pass_file),
        "--out-dir", str(out_dir),
        "--validity-days", "365",
    )
    assert code == 0, err
    cert_path = out_dir / "certs" / "ca.cert.pem"
    assert cert_path.exists()
    assert (out_dir / "private" / "ca.key.pem").exists()
    assert (out_dir / "policy.txt").exists()

    code2, _, err2 = run_cli("ca", "verify", "--cert", str(cert_path))
    assert code2 == 0, err2


def test_cli_ca_init_ecc(tmp_path, run_cli):
    pass_file = tmp_path / "ca.pass"
    pass_file.write_bytes(b"secret")
    out_dir = tmp_path / "pki"

    code, _, err = run_cli(
        "ca", "init",
        "--subject", "CN=ECC Root CA,O=MicroPKI",
        "--key-type", "ecc", "--key-size", "384",
        "--passphrase-file", str(pass_file),
        "--out-dir", str(out_dir),
    )
    assert code == 0, err
    cert_path = out_dir / "certs" / "ca.cert.pem"
    assert cert_path.exists()

    code2, _, err2 = run_cli("ca", "verify", "--cert", str(cert_path))
    assert code2 == 0, err2


def test_cli_ca_init_log_file(tmp_path, run_cli):
    pass_file = tmp_path / "ca.pass"
    pass_file.write_bytes(b"secret")
    out_dir = tmp_path / "pki"
    log_file = tmp_path / "logs" / "ca-init.log"

    code, _, err = run_cli(
        "ca", "init",
        "--subject", "/CN=Log Test",
        "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", str(pass_file),
        "--out-dir", str(out_dir),
        "--log-file", str(log_file),
    )
    assert code == 0, err
    assert log_file.exists()
    log_text = log_file.read_text(encoding="utf-8")
    assert "Starting key generation" in log_text
    assert "Key generation completed" in log_text
    assert "Starting certificate signing" in log_text
    assert "Certificate signing completed" in log_text
    assert "Saved private key" in log_text
    assert "Saved certificate" in log_text
    assert "policy" in log_text.lower()
    assert "secret" not in log_text


def test_cli_ca_init_unwritable_outdir(run_cli, tmp_path):
    pass_path = tmp_path / "ca.pass"
    pass_path.write_bytes(b"pass")
    
    # To ensure it's unwritable on Linux too, try to use a file where a directory should be
    existing_file = tmp_path / "blocked"
    existing_file.write_text("not a directory")
    
    code, _, err = run_cli(
        "ca", "init",
        "--subject", "/CN=Test",
        "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", str(pass_path),
        "--out-dir", str(existing_file),
    )
    assert code != 0


def test_cli_ca_init_refuse_overwrite_without_force(tmp_path, run_cli):
    pass_file = tmp_path / "ca.pass"
    pass_file.write_bytes(b"secret")
    out_dir = tmp_path / "pki"
    (out_dir / "private").mkdir(parents=True)
    (out_dir / "certs").mkdir(parents=True)
    (out_dir / "private" / "ca.key.pem").write_text("existing")
    (out_dir / "certs" / "ca.cert.pem").write_text("existing")

    code, _, err = run_cli(
        "ca", "init",
        "--subject", "/CN=Test",
        "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", str(pass_file),
        "--out-dir", str(out_dir),
    )
    assert code != 0
    assert "overwrite" in err.lower() or "exist" in err.lower()


def test_cli_ca_init_with_force_overwrites(tmp_path, run_cli):
    pass_file = tmp_path / "ca.pass"
    pass_file.write_bytes(b"secret")
    out_dir = tmp_path / "pki"
    (out_dir / "private").mkdir(parents=True)
    (out_dir / "certs").mkdir(parents=True)
    (out_dir / "private" / "ca.key.pem").write_text("old")
    (out_dir / "certs" / "ca.cert.pem").write_text("old")

    code, _, err = run_cli(
        "ca", "init", "--force",
        "--subject", "/CN=Test",
        "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", str(pass_file),
        "--out-dir", str(out_dir),
    )
    assert code == 0, err
    assert (out_dir / "private" / "ca.key.pem").read_bytes().startswith(b"-----BEGIN")

