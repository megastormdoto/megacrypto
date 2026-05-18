"""Performance tests for MicroPKI (Sprint 8).

TEST-65: Issue 1000 certificates and measure performance.
TEST-66: Simulate OCSP/CRL load (optional).

Run with: pytest tests/test_performance.py -v -m perf
Or:       pytest tests/test_performance.py -v --run-perf
"""
from __future__ import annotations

import shutil
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from micropki import ca, crypto_utils, database, repository, validation, chain


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def perf_pki_dir():
    """Создаёт временную PKI-инфраструктуру для performance-тестов."""
    tmp = tempfile.mkdtemp(prefix="micropki_perf_")
    passphrase = b"perf-test-pass"
    inter_pass = b"perf-inter-pass"

    # Root CA
    ca.init_root_ca(
        subject="/CN=Perf Root CA",
        key_type="rsa",
        key_size=4096,
        passphrase=passphrase,
        out_dir=tmp,
        validity_days=3650,
        force=True,
    )

    # Intermediate CA
    ca.issue_intermediate_ca(
        root_cert_path=str(Path(tmp) / "certs" / "ca.cert.pem"),
        root_key_path=str(Path(tmp) / "private" / "ca.key.pem"),
        root_passphrase=passphrase,
        subject="/CN=Perf Intermediate CA",
        key_type="rsa",
        key_size=4096,
        passphrase=inter_pass,
        out_dir=tmp,
        validity_days=1825,
        pathlen=0,
        force=True,
    )

    yield {
        "dir": tmp,
        "root_pass": passphrase,
        "inter_pass": inter_pass,
    }

    shutil.rmtree(tmp, ignore_errors=True)





# ===========================================================================
# TEST-65: 1000 Certificate Issuance Performance
# ===========================================================================

@pytest.mark.perf
class TestPerformance1000Certs:
    """Выпуск 1000 сертификатов и измерение производительности."""

    def test_issue_1000_certificates(self, perf_pki_dir, request):
        """Выпускает 1000 сертификатов и замеряет время."""
        if not request.config.getoption("--run-perf", default=False):
            pytest.skip("Performance tests disabled. Use --run-perf to enable.")

        pki_dir = perf_pki_dir["dir"]
        inter_pass = perf_pki_dir["inter_pass"]
        ca_cert = str(Path(pki_dir) / "certs" / "intermediate.cert.pem")
        ca_key = str(Path(pki_dir) / "private" / "intermediate.key.pem")
        db_path = str(Path(pki_dir) / "micropki.db")

        num_certs = 1000
        issued_certs = []

        print(f"\n{'='*60}")
        print(f"  Performance Test: Issuing {num_certs} certificates")
        print(f"{'='*60}")

        start_time = time.time()

        for i in range(num_certs):
            cn = f"perf-{i:04d}.example.com"
            try:
                cert_pem = ca.issue_end_entity(
                    ca_cert_path=ca_cert,
                    ca_key_path=ca_key,
                    ca_passphrase=inter_pass,
                    template="server",
                    subject=f"/CN={cn}",
                    san_strings=[f"dns:{cn}"],
                    out_dir=str(Path(pki_dir) / "certs"),
                    validity_days=365,
                    db_path=db_path,
                )
                issued_certs.append(cn)
            except Exception as e:
                print(f"  Failed at certificate {i}: {e}")
                break

        issue_time = time.time() - start_time
        certs_per_sec = len(issued_certs) / issue_time if issue_time > 0 else 0

        print(f"\n  Issued: {len(issued_certs)} certificates")
        print(f"  Time:   {issue_time:.2f} seconds")
        print(f"  Rate:   {certs_per_sec:.1f} certs/sec")

        assert len(issued_certs) == num_certs, f"Only {len(issued_certs)} of {num_certs} certs issued"

        # Validate all 1000 certs
        print(f"\n  Validating {len(issued_certs)} certificates...")
        root_cert = crypto_utils.load_certificate_pem(str(Path(pki_dir) / "certs" / "ca.cert.pem"))
        inter_cert = crypto_utils.load_certificate_pem(ca_cert)

        start_val = time.time()
        passed = 0
        failed = 0
        for cn in issued_certs:
            cert_path = Path(pki_dir) / "certs" / f"{cn}.cert.pem"
            if not cert_path.exists():
                # may have been written with safe filename
                candidates = list(Path(pki_dir / "certs").glob(f"perf*{cn.split('.')[0].split('-')[1]}*.cert.pem"))
                if candidates:
                    cert_path = candidates[0]
            try:
                leaf = crypto_utils.load_certificate_pem(str(cert_path))
                result = validation.validate_path([leaf, inter_cert, root_cert])
                if result.passed:
                    passed += 1
                else:
                    failed += 1
            except Exception:
                failed += 1

        val_time = time.time() - start_val
        val_rate = len(issued_certs) / val_time if val_time > 0 else 0

        print(f"  Validation time: {val_time:.2f} seconds")
        print(f"  Validation rate: {val_rate:.1f} certs/sec")
        print(f"  Passed: {passed}, Failed: {failed}")
        print(f"{'='*60}")

        # At least 90% should pass validation
        assert passed >= num_certs * 0.9, f"Only {passed} of {num_certs} passed validation"

    def test_database_query_performance(self, perf_pki_dir, request):
        """Проверяет скорость запросов к БД после массовой вставки."""
        if not request.config.getoption("--run-perf", default=False):
            pytest.skip("Performance tests disabled. Use --run-perf to enable.")

        db_path = str(Path(perf_pki_dir["dir"]) / "micropki.db")

        start = time.time()
        rows = repository.list_certificates(db_path=db_path)
        query_time = time.time() - start

        print(f"\n  DB query: {len(rows)} rows in {query_time:.3f}s")
        assert query_time < 5.0, f"DB query took {query_time:.1f}s (expected < 5s)"
