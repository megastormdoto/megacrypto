"""Sprint 4: CRL generation, revocation, repository CRL, OpenSSL verify (optional)."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

import pytest
from cryptography import x509

from micropki import database
from micropki import logger as log_module
from micropki import repository
from micropki import revocation as rev_module


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


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _http_get(url: str):
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, resp.read(), dict(resp.headers)


@pytest.fixture()
def pki_env(tmp_path):
    base = tmp_path / "s4"
    out = base / "pki"
    secrets = base / "secrets"
    certs = out / "certs"
    secrets.mkdir(parents=True)
    (secrets / "root.pass").write_bytes(b"rootpass")
    (secrets / "inter.pass").write_bytes(b"interpass")
    db = out / "micropki.db"

    assert _run("db", "init", "--db-path", str(db))[0] == 0
    assert _run(
        "ca", "init",
        "--subject", "/CN=S4 Root", "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", str(secrets / "root.pass"),
        "--out-dir", str(out), "--db-path", str(db),
    )[0] == 0
    assert _run(
        "ca", "issue-intermediate",
        "--root-cert", str(certs / "ca.cert.pem"),
        "--root-key", str(out / "private" / "ca.key.pem"),
        "--root-pass-file", str(secrets / "root.pass"),
        "--subject", "CN=S4 Intermediate,O=MicroPKI",
        "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", str(secrets / "inter.pass"),
        "--out-dir", str(out), "--db-path", str(db),
    )[0] == 0
    assert _run(
        "ca", "issue-cert",
        "--ca-cert", str(certs / "intermediate.cert.pem"),
        "--ca-key", str(out / "private" / "intermediate.key.pem"),
        "--ca-pass-file", str(secrets / "inter.pass"),
        "--template", "server",
        "--subject", "CN=leaf.example.com",
        "--san", "dns:leaf.example.com",
        "--out-dir", str(certs), "--db-path", str(db),
    )[0] == 0

    code, out_json, _ = _run("ca", "list-certs", "--db-path", str(db), "--format", "json")
    assert code == 0
    rows = json.loads(out_json)
    leaf = next(r for r in rows if r["subject"].startswith("CN=leaf.example.com"))
    return {"out": out, "certs": certs, "db": db, "leaf_serial": leaf["serial_hex"], "secrets": secrets}


def test_reason_normalization():
    assert rev_module.normalize_revocation_reason("KEYCOMPROMISE") == "keyCompromise"
    with pytest.raises(ValueError, match="Unsupported"):
        rev_module.normalize_revocation_reason("nope")


def test_revoke_lifecycle_and_crl_contains_serial(pki_env):
    serial = pki_env["leaf_serial"]
    db = str(pki_env["db"])
    out = str(pki_env["out"])

    code, _, err = _run(
        "ca", "revoke", serial, "--reason", "keyCompromise", "--force",
        "--db-path", db, "--out-dir", out,
    )
    assert code == 0, err

    row = database.get_certificate_by_serial(db, serial)
    assert row["status"] == "revoked"
    assert row["revocation_reason"] == "keyCompromise"
    assert row["revocation_date"]

    code2, _, err2 = _run(
        "ca", "gen-crl",
        "--ca", "intermediate",
        "--out-dir", out,
        "--db-path", db,
        "--ca-pass-file", str(pki_env["secrets"] / "inter.pass"),
    )
    assert code2 == 0, err2

    crl_path = Path(out) / "crl" / "intermediate.crl.pem"
    assert crl_path.is_file()
    pem_crl = x509.load_pem_x509_crl(crl_path.read_bytes())
    want = int(serial, 16)
    serials = [r.serial_number for r in pem_crl]
    assert want in serials


def test_revoke_nonexistent_serial(pki_env):
    code, _, _ = _run(
        "ca", "revoke", "deadbeef", "--force",
        "--db-path", str(pki_env["db"]), "--out-dir", str(pki_env["out"]),
    )
    assert code == 1


def test_revoke_already_revoked(pki_env):
    serial = pki_env["leaf_serial"]
    db = str(pki_env["db"])
    out = str(pki_env["out"])
    assert _run("ca", "revoke", serial, "--reason", "superseded", "--force", "--db-path", db, "--out-dir", out)[0] == 0
    code, _, err = _run(
        "ca", "revoke", serial, "--reason", "superseded", "--force",
        "--db-path", db, "--out-dir", out,
    )
    assert code == 0, err
    assert "already revoked" in err.lower()


def test_crl_number_increments(pki_env):
    serial = pki_env["leaf_serial"]
    db = str(pki_env["db"])
    out = str(pki_env["out"])
    pass_file = str(pki_env["secrets"] / "inter.pass")

    assert _run("ca", "revoke", serial, "--force", "--db-path", db, "--out-dir", out)[0] == 0
    assert _run("ca", "gen-crl", "--ca", "intermediate", "--out-dir", out, "--db-path", db, "--ca-pass-file", pass_file)[0] == 0
    p1 = Path(out) / "crl" / "intermediate.crl.pem"
    c1 = x509.load_pem_x509_crl(p1.read_bytes())
    ext1 = c1.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number

    assert _run("ca", "gen-crl", "--ca", "intermediate", "--out-dir", out, "--db-path", db, "--ca-pass-file", pass_file)[0] == 0
    c2 = x509.load_pem_x509_crl(p1.read_bytes())
    ext2 = c2.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    assert ext2 == ext1 + 1


def test_repository_crl_identical_to_file(pki_env):
    serial = pki_env["leaf_serial"]
    db = str(pki_env["db"])
    out = str(pki_env["out"])
    certs = str(pki_env["certs"])
    assert _run("ca", "revoke", serial, "--force", "--db-path", db, "--out-dir", out)[0] == 0
    assert _run(
        "ca", "gen-crl", "--ca", "intermediate", "--out-dir", out, "--db-path", db,
        "--ca-pass-file", str(pki_env["secrets"] / "inter.pass"),
    )[0] == 0

    crl_path = Path(out) / "crl" / "intermediate.crl.pem"
    local = crl_path.read_bytes()

    port = _free_port()
    logger = log_module.setup_logging(None)
    server = repository.create_server("127.0.0.1", port, db, certs, logger, pki_dir=out)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.25)
    st, body, hdrs = _http_get(f"http://127.0.0.1:{port}/crl")
    assert st == 200
    assert hdrs.get("Content-Type") == "application/pkix-crl"
    assert body == local
    assert "ETag" in hdrs
    assert "Last-Modified" in hdrs
    assert "Cache-Control" in hdrs
    server.shutdown()
    server.server_close()


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")
def test_openssl_crl_verify(pki_env):
    serial = pki_env["leaf_serial"]
    db = str(pki_env["db"])
    out = str(pki_env["out"])
    assert _run("ca", "revoke", serial, "--force", "--db-path", db, "--out-dir", out)[0] == 0
    assert _run(
        "ca", "gen-crl", "--ca", "intermediate", "--out-dir", out, "--db-path", db,
        "--ca-pass-file", str(pki_env["secrets"] / "inter.pass"),
    )[0] == 0
    crl = Path(out) / "crl" / "intermediate.crl.pem"
    ca = Path(out) / "certs" / "intermediate.cert.pem"
    r = subprocess.run(
        ["openssl", "crl", "-in", str(crl), "-inform", "PEM", "-CAfile", str(ca), "-noout"],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr
    assert "verify OK" in (r.stderr + r.stdout)


def test_check_revoked_cli(pki_env):
    serial = pki_env["leaf_serial"]
    db = str(pki_env["db"])
    out = str(pki_env["out"])
    assert _run("ca", "revoke", serial, "--force", "--db-path", db, "--out-dir", out)[0] == 0
    assert _run(
        "ca", "gen-crl", "--ca", "intermediate", "--out-dir", out, "--db-path", db,
        "--ca-pass-file", str(pki_env["secrets"] / "inter.pass"),
    )[0] == 0
    crl = Path(out) / "crl" / "intermediate.crl.pem"
    code, stdout, _ = _run(
        "ca", "check-revoked", serial, "--db-path", db, "--crl", str(crl),
    )
    assert code == 0
    assert "status=revoked" in stdout
    assert "crl_contains_serial=yes" in stdout
