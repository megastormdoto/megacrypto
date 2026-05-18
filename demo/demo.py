"""
MicroPKI end-to-end demo (Sprint 8).
Uses a temp directory under the system TEMP folder to avoid OneDrive/locking issues on Windows.
"""
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def _rmtree_compat(path: Path) -> None:
    """Best-effort recursive delete on Windows (read-only files, scanners, OneDrive)."""

    def _chmod_and_retry(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass

    if not path.exists():
        return
    # Python 3.12+: onexc; older: onerror
    try:
        shutil.rmtree(path, onexc=lambda f, q, e: _chmod_and_retry(f, q, e))
    except TypeError:
        shutil.rmtree(path, onerror=lambda f, q, e: _chmod_and_retry(f, q, e))


def _wait_tcp(host: str, port: int, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return
        except OSError:
            time.sleep(0.2)
    raise TimeoutError(f"{host}:{port} did not accept connections within {timeout}s")


def run_cmd(cmd, env=None, check=True, expect_failure=False):
    print(f"\n[DEMO] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, env=env, text=True, capture_output=True)
    if result.returncode != 0:
        tag = "[INFO]" if expect_failure else "[FAIL]"
        print(f"{tag} Exit code {result.returncode}")
        if result.stdout.strip():
            print(f"STDOUT:\n{result.stdout}")
        if result.stderr.strip():
            print(f"STDERR:\n{result.stderr}")
        if expect_failure:
            if check:
                raise ValueError("use check=False together with expect_failure")
        elif check:
            sys.exit(result.returncode)
    elif expect_failure:
        print("[FAIL] Command should have failed but exited 0")
        sys.exit(1)
    else:
        print("[PASS] Command succeeded.")
    return result


def main():
    print("========================================")
    print("      MicroPKI Demonstration Script     ")
    print("========================================")

    # Work in TEMP — avoids PermissionError deleting demo_pki under OneDrive/Git folder on Windows
    workspace = Path(tempfile.mkdtemp(prefix="micropki_demo_"))
    demo_pki = workspace / "demo_pki"
    demo_secrets = workspace / "demo_secrets"

    repo_proc = None
    ocsp_proc = None

    try:
        print(f"\n--- Demo workspace (ephemeral): {workspace} ---")

        # 1. Setup Environment
        print("\n--- 1. Setting up Environment ---")
        demo_pki.mkdir(parents=True)
        demo_secrets.mkdir(parents=True)

        ca_pass = demo_secrets / "ca.pass"
        inter_pass = demo_secrets / "inter.pass"
        ca_pass.write_text("demo-root-pass", encoding="utf-8")
        inter_pass.write_text("demo-inter-pass", encoding="utf-8")

        micropki_cmd = [sys.executable, "-m", "micropki"]

        # 2. Initialise the Root CA
        print("\n--- 2. Initialising Root CA ---")
        run_cmd(micropki_cmd + [
            "ca", "init",
            "--subject", "/CN=Demo Root CA",
            "--key-type", "rsa", "--key-size", "4096",
            "--passphrase-file", str(ca_pass),
            "--out-dir", str(demo_pki),
            "--validity-days", "3650",
        ])

        # 3. Initialise the Intermediate CA
        print("\n--- 3. Initialising Intermediate CA ---")
        run_cmd(micropki_cmd + [
            "ca", "issue-intermediate",
            "--root-cert", str(demo_pki / "certs" / "ca.cert.pem"),
            "--root-key", str(demo_pki / "private" / "ca.key.pem"),
            "--root-pass-file", str(ca_pass),
            "--subject", "/CN=Demo Intermediate CA",
            "--key-type", "rsa", "--key-size", "4096",
            "--passphrase-file", str(inter_pass),
            "--out-dir", str(demo_pki),
            "--validity-days", "1825",
            "--pathlen", "0",
        ])

        # 4. Issue Server, Client, and OCSP Certificates
        print("\n--- 4. Issuing Certificates ---")
        run_cmd(micropki_cmd + [
            "ca", "issue-cert",
            "--ca-cert", str(demo_pki / "certs" / "intermediate.cert.pem"),
            "--ca-key", str(demo_pki / "private" / "intermediate.key.pem"),
            "--ca-pass-file", str(inter_pass),
            "--template", "server",
            "--subject", "/CN=demo.example.com",
            "--san", "dns:demo.example.com",
            "--out-dir", str(demo_pki / "certs"),
            "--db-path", str(demo_pki / "micropki.db"),
        ])
        run_cmd(micropki_cmd + [
            "ca", "issue-cert",
            "--ca-cert", str(demo_pki / "certs" / "intermediate.cert.pem"),
            "--ca-key", str(demo_pki / "private" / "intermediate.key.pem"),
            "--ca-pass-file", str(inter_pass),
            "--template", "client",
            "--subject", "/CN=Demo Client",
            "--san", "email:client@example.com",
            "--out-dir", str(demo_pki / "certs"),
            "--db-path", str(demo_pki / "micropki.db"),
        ])
        run_cmd(micropki_cmd + [
            "ca", "issue-ocsp-cert",
            "--ca-cert", str(demo_pki / "certs" / "intermediate.cert.pem"),
            "--ca-key", str(demo_pki / "private" / "intermediate.key.pem"),
            "--ca-pass-file", str(inter_pass),
            "--subject", "/CN=Demo OCSP Responder",
            "--out-dir", str(demo_pki / "certs"),
            "--db-path", str(demo_pki / "micropki.db"),
        ])

        # 5. Start Servers
        print("\n--- 5. Starting Repo and OCSP Servers ---")
        repo_proc = subprocess.Popen(
            micropki_cmd + [
                "repo", "serve",
                "--host", "127.0.0.1", "--port", "8080",
                "--db-path", str(demo_pki / "micropki.db"),
                "--cert-dir", str(demo_pki / "certs"),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        ocsp_proc = subprocess.Popen(
            micropki_cmd + [
                "ocsp", "serve",
                "--host", "127.0.0.1", "--port", "8081",
                "--db-path", str(demo_pki / "micropki.db"),
                "--responder-cert", str(demo_pki / "certs" / "Demo_OCSP_Responder.cert.pem"),
                "--responder-key", str(demo_pki / "certs" / "Demo_OCSP_Responder.key.pem"),
                "--ca-cert", str(demo_pki / "certs" / "intermediate.cert.pem"),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        _wait_tcp("127.0.0.1", 8080)
        _wait_tcp("127.0.0.1", 8081)

        # 6. Perform Validation
        print("\n--- 6. Performing Certificate Validation (OCSP & CRL) ---")
        run_cmd(micropki_cmd + [
            "client", "validate",
            "--cert", str(demo_pki / "certs" / "demo.example.com.cert.pem"),
            "--untrusted", str(demo_pki / "certs" / "intermediate.cert.pem"),
            "--trusted", str(demo_pki / "certs" / "ca.cert.pem"),
            "--ocsp", "--ocsp-url", "http://127.0.0.1:8081",
            "--mode", "full",
        ])

        # 6b. Policy enforcement — invalid SAN for template must be rejected
        print("\n--- 6b. Policy Enforcement (reject invalid request) ---")
        bad = run_cmd(
            micropki_cmd + [
                "ca", "issue-cert",
                "--ca-cert", str(demo_pki / "certs" / "intermediate.cert.pem"),
                "--ca-key", str(demo_pki / "private" / "intermediate.key.pem"),
                "--ca-pass-file", str(inter_pass),
                "--template", "client",
                "--subject", "/CN=Bad Policy Client",
                "--san", "uri:https://example.com",
                "--out-dir", str(demo_pki / "certs"),
                "--db-path", str(demo_pki / "micropki.db"),
            ],
            check=False,
            expect_failure=True,
        )
        if bad.returncode != 0:
            print("[PASS] Issuance correctly rejected by policy.")
        else:
            print("[FAIL] Policy violation should have failed issuance.")
            sys.exit(1)

        # 7. Revoke Certificate
        print("\n--- 7. Revoking Server Certificate ---")
        res = run_cmd(micropki_cmd + [
            "ca", "list-certs", "--db-path", str(demo_pki / "micropki.db"), "--format", "json",
        ])
        certs = json.loads(res.stdout)
        server_serial = None
        for c in certs:
            if "demo.example.com" in (c.get("subject") or ""):
                server_serial = c["serial_hex"]
                break

        if server_serial:
            run_cmd(micropki_cmd + [
                "ca", "revoke", server_serial,
                "--reason", "keyCompromise",
                "--db-path", str(demo_pki / "micropki.db"),
                "--force",
            ])

            print("\n--- 8. Demonstrating Revoked Status ---")
            res_val = run_cmd(
                micropki_cmd + [
                    "client", "validate",
                    "--cert", str(demo_pki / "certs" / "demo.example.com.cert.pem"),
                    "--untrusted", str(demo_pki / "certs" / "intermediate.cert.pem"),
                    "--trusted", str(demo_pki / "certs" / "ca.cert.pem"),
                    "--ocsp", "--ocsp-url", "http://127.0.0.1:8081",
                    "--mode", "full",
                ],
                check=False,
                expect_failure=True,
            )

            if res_val.returncode != 0:
                print("[PASS] Validation failed as expected for revoked certificate.")
            else:
                print("[FAIL] Validation succeeded but should have failed!")
                sys.exit(1)
        else:
            print("[FAIL] Could not find server certificate serial.")
            sys.exit(1)

        # 9. Audit log integrity
        print("\n--- 9. Verifying Audit Log Integrity ---")
        run_cmd(micropki_cmd + [
            "audit", "verify",
            "--log-file-path", str(demo_pki / "audit" / "audit.log"),
            "--chain-file", str(demo_pki / "audit" / "chain.dat"),
        ])

        print("\n[SUCCESS] Demo completed successfully!")
        print(f"Artifacts (until deleted): {demo_pki}")
    finally:
        print("\n--- 10. Stopping Servers ---")
        for proc in (repo_proc, ocsp_proc):
            if proc is not None and proc.poll() is None:
                proc.terminate()
        for proc in (repo_proc, ocsp_proc):
            if proc is not None:
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
        print("Servers stopped.")

        _rmtree_compat(workspace)
        print(f"Removed temp workspace: {workspace}")


if __name__ == "__main__":
    main()
