"""Sprint 3: database and serial integration tests."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from micropki import database, serial


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
def s3_env(tmp_path_factory):
    base = tmp_path_factory.mktemp("pki_s3_db")
    out = base / "pki"
    secrets = base / "secrets"
    certs = out / "certs"
    secrets.mkdir()
    (secrets / "root.pass").write_bytes(b"rootpass")
    (secrets / "inter.pass").write_bytes(b"interpass")
    db_path = out / "micropki.db"

    code, _, err = _run("db", "init", "--db-path", str(db_path))
    assert code == 0, err

    code, _, err = _run(
        "ca", "init",
        "--subject", "/CN=S3 Root CA",
        "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", str(secrets / "root.pass"),
        "--out-dir", str(out),
        "--db-path", str(db_path),
    )
    assert code == 0, err

    code, _, err = _run(
        "ca", "issue-intermediate",
        "--root-cert", str(certs / "ca.cert.pem"),
        "--root-key", str(out / "private" / "ca.key.pem"),
        "--root-pass-file", str(secrets / "root.pass"),
        "--subject", "CN=S3 Intermediate CA,O=MicroPKI",
        "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", str(secrets / "inter.pass"),
        "--out-dir", str(out),
        "--db-path", str(db_path),
    )
    assert code == 0, err

    return {"base": base, "out": out, "secrets": secrets, "db_path": db_path}


def test_db_schema_created(s3_env):
    with sqlite3.connect(s3_env["db_path"]) as conn:
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='certificates'")
        assert cur.fetchone() is not None


def test_issue_5_certs_and_db_records(s3_env):
    out = s3_env["out"]
    db_path = s3_env["db_path"]
    secrets = s3_env["secrets"]
    certs = out / "certs"
    ca_cert = certs / "intermediate.cert.pem"
    ca_key = out / "private" / "intermediate.key.pem"
    pass_file = secrets / "inter.pass"

    cmds = [
        ["--template", "server", "--subject", "CN=s1.example.com", "--san", "dns:s1.example.com"],
        ["--template", "server", "--subject", "CN=s2.example.com", "--san", "dns:s2.example.com"],
        ["--template", "client", "--subject", "CN=Alice", "--san", "email:alice@example.com"],
        ["--template", "client", "--subject", "CN=Bob", "--san", "email:bob@example.com"],
        ["--template", "code_signing", "--subject", "CN=CodeSigner"],
    ]

    for c in cmds:
        code, _, err = _run(
            "ca", "issue-cert",
            "--ca-cert", str(ca_cert),
            "--ca-key", str(ca_key),
            "--ca-pass-file", str(pass_file),
            "--out-dir", str(certs),
            "--db-path", str(db_path),
            *c,
        )
        assert code == 0, err

    rows = database.list_certificates(str(db_path))
    serials = [r["serial_hex"] for r in rows]
    assert len(rows) >= 6
    assert len(serials) == len(set(serials))


def test_ca_list_and_show_cert_cli(s3_env):
    db_path = s3_env["db_path"]
    code, out, err = _run("ca", "list-certs", "--db-path", str(db_path), "--format", "table")
    assert code == 0, err
    assert "SERIAL" in out

    rows = database.list_certificates(str(db_path))
    serial_hex = rows[0]["serial_hex"]
    code, out, err = _run("ca", "show-cert", serial_hex, "--db-path", str(db_path))
    assert code == 0, err
    assert "BEGIN CERTIFICATE" in out


def test_serial_uniqueness_stress():
    vals = [serial.generate_serial_candidate() for _ in range(100)]
    assert len(vals) == len(set(vals))
