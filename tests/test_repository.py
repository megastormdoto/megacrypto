"""Sprint 3: repository API tests."""

from __future__ import annotations

import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from micropki import logger as log_module
from micropki import repository


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
    with urllib.request.urlopen(req, timeout=3) as resp:
        return resp.status, resp.read().decode("utf-8")


@pytest.fixture(scope="module")
def repo_env(tmp_path_factory):
    base = tmp_path_factory.mktemp("pki_s3_repo")
    out = base / "pki"
    secrets = base / "secrets"
    certs = out / "certs"
    secrets.mkdir()
    (secrets / "root.pass").write_bytes(b"rootpass")
    (secrets / "inter.pass").write_bytes(b"interpass")
    db = out / "micropki.db"

    assert _run("db", "init", "--db-path", str(db))[0] == 0
    assert _run(
        "ca", "init", "--subject", "/CN=Repo Root", "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", str(secrets / "root.pass"), "--out-dir", str(out), "--db-path", str(db),
    )[0] == 0
    assert _run(
        "ca", "issue-intermediate",
        "--root-cert", str(certs / "ca.cert.pem"),
        "--root-key", str(out / "private" / "ca.key.pem"),
        "--root-pass-file", str(secrets / "root.pass"),
        "--subject", "CN=Repo Intermediate,O=MicroPKI",
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
        "--subject", "CN=repo.example.com",
        "--san", "dns:repo.example.com",
        "--out-dir", str(certs), "--db-path", str(db),
    )[0] == 0
    assert _run(
        "ca", "gen-crl",
        "--ca", "intermediate",
        "--out-dir", str(out),
        "--db-path", str(db),
        "--ca-pass-file", str(secrets / "inter.pass"),
        "--next-update", "7",
    )[0] == 0

    return {"out": out, "certs": certs, "db": db}


def test_repository_endpoints(repo_env):
    port = _free_port()
    logger = log_module.setup_logging(None)
    server = repository.create_server("127.0.0.1", port, str(repo_env["db"]), str(repo_env["certs"]), logger)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.2)
    base = f"http://127.0.0.1:{port}"

    st, body = _http_get(f"{base}/ca/root")
    assert st == 200
    assert "BEGIN CERTIFICATE" in body

    st, body = _http_get(f"{base}/ca/intermediate")
    assert st == 200
    assert "BEGIN CERTIFICATE" in body

    code, out, err = _run("ca", "list-certs", "--db-path", str(repo_env["db"]), "--format", "json")
    assert code == 0, err
    import json
    serial_hex = json.loads(out)[0]["serial_hex"]
    st, body = _http_get(f"{base}/certificate/{serial_hex}")
    assert st == 200
    assert "BEGIN CERTIFICATE" in body

    with pytest.raises(urllib.error.HTTPError) as e:
        _http_get(f"{base}/certificate/XYZ")
    assert e.value.code == 400

    st, body = _http_get(f"{base}/crl")
    assert st == 200
    assert "BEGIN X509 CRL" in body

    server.shutdown()
    server.server_close()


def test_repo_module_init(tmp_path):
    """Cover repo.py initialization."""
    from micropki import repo
    db = tmp_path / "test.db"
    certs = tmp_path / "certs"
    certs.mkdir()
    repo.init_server(db_path=str(db), cert_dir=str(certs))
    assert repo.app is not None


def test_repo_app_endpoints(tmp_path):
    """Cover repo.py endpoints via TestClient."""
    from fastapi.testclient import TestClient
    from micropki import repo
    import json
    from unittest.mock import MagicMock, patch
    
    db = tmp_path / "test.db"
    certs = tmp_path / "certs"
    certs.mkdir()
    
    # Initialize database
    from micropki import database
    # Force fresh init
    if db.exists(): db.unlink()
    database.init_database(str(db))
    
    # Create dummy cert files for /ca/* endpoints
    (certs / "ca.cert.pem").write_text("root cert")
    (certs / "intermediate.cert.pem").write_text("inter cert")
    
    # Setup CA config for repo
    repo.CA_CONFIG["ca_cert_path"] = str(tmp_path / "ca.crt")
    repo.CA_CONFIG["ca_key_path"] = str(tmp_path / "ca.key")
    repo.CA_CONFIG["ca_passphrase"] = "dummy"
    Path(repo.CA_CONFIG["ca_cert_path"]).write_text("ca cert")
    Path(repo.CA_CONFIG["ca_key_path"]).write_text("ca key")
    
    repo.init_server(db_path=str(db), cert_dir=str(certs))
    
    with TestClient(repo.app) as client:
        # Basic endpoints
        client.get("/crl")
        client.get("/ca/root")
        client.get("/ca/intermediate")
        client.get("/certificates")
        
        # Success request-cert mock
        with patch("micropki.ca.issue_end_entity") as mock_issue:
            mock_issue.return_value = "FAKE_CERT_PEM"
            res = client.post("/request-cert", json={
                "csr_pem": "test",
                "template": "client",
                "validity_days": 365
            })
            assert res.status_code == 201
            assert res.text == "FAKE_CERT_PEM"

        # Failure request-cert mock (ValueError)
        with patch("micropki.ca.issue_end_entity", side_effect=ValueError("Bad template")):
            res = client.post("/request-cert", json={
                "csr_pem": "test",
                "template": "client"
            })
            assert res.status_code == 400
            
        # Exception request-cert mock
        with patch("micropki.ca.issue_end_entity", side_effect=Exception("Crash")):
            res = client.post("/request-cert", json={
                "csr_pem": "test",
                "template": "client"
            })
            assert res.status_code == 500

        # Success fetch cert (was download)
        with patch("micropki.repo.get_certificate_by_serial", return_value={"cert_pem": "PEMTXT", "status": "valid"}):
            res = client.get("/certificate/123")
            assert res.status_code == 200
            assert "PEMTXT" in res.text
            
        # Error in fetch cert
        with patch("micropki.repo.get_certificate_by_serial", side_effect=Exception("DB Error")):
            res = client.get("/certificate/123")
            assert res.status_code == 500

        # Certificate not found (404)
        with patch("micropki.repo.get_certificate_by_serial", return_value=None):
            assert client.get("/certificate/ABCD").status_code == 404

        # Missing CRL level
        assert client.get("/crl?ca=invalid").status_code == 400
