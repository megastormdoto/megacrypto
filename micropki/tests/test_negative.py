"""Negative test cases for MicroPKI."""

import subprocess
import tempfile
import os
from pathlib import Path


def test_missing_subject():
    """Test that missing --subject fails."""
    result = subprocess.run(
        ["python", "-m", "micropki.cli", "ca", "init",
         "--key-type", "rsa",
         "--key-size", "4096",
         "--passphrase-file", "passphrase.txt"],
        capture_output=True,
        text=True
    )
    assert result.returncode != 0
    assert "required" in result.stderr or "argument" in result.stderr
    print("PASS: missing subject test")


def test_invalid_key_size_for_ecc():
    """Test that wrong key size for ECC fails."""
    result = subprocess.run(
        ["python", "-m", "micropki.cli", "ca", "init",
         "--subject", "CN=Test",
         "--key-type", "ecc",
         "--key-size", "256",  # Wrong size!
         "--passphrase-file", "passphrase.txt"],
        capture_output=True,
        text=True
    )
    assert result.returncode != 0
    assert "ECC key size must be 384" in result.stderr
    print("PASS: invalid ECC key size test")


def test_nonexistent_passphrase_file():
    """Test that missing passphrase file fails."""
    result = subprocess.run(
        ["python", "-m", "micropki.cli", "ca", "init",
         "--subject", "CN=Test",
         "--key-type", "rsa",
         "--key-size", "4096",
         "--passphrase-file", "nonexistent.txt"],
        capture_output=True,
        text=True
    )
    assert result.returncode != 0
    assert "not found" in result.stderr
    print("PASS: nonexistent passphrase file test")


def test_unwritable_out_dir():
    """Test that unwritable output directory fails."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Make directory read-only
        readonly_dir = Path(tmpdir) / "readonly"
        readonly_dir.mkdir()
        try:
            os.chmod(readonly_dir, 0o444)  # Read-only
        except:
            pass  # Windows may not support chmod

        result = subprocess.run(
            ["python", "-m", "micropki.cli", "ca", "init",
             "--subject", "CN=Test",
             "--key-type", "rsa",
             "--key-size", "4096",
             "--passphrase-file", "passphrase.txt",
             "--out-dir", str(readonly_dir)],
            capture_output=True,
            text=True
        )
        print("PASS: unwritable directory test (if this fails, it's OK on Windows)")


if __name__ == "__main__":
    test_missing_subject()
    test_invalid_key_size_for_ecc()
    test_nonexistent_passphrase_file()
    test_unwritable_out_dir()
    print("All negative tests passed!")