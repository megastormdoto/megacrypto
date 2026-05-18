from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from . import crypto_utils


@dataclass
class StepResult:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class CertValidation:
    subject: str
    steps: list[StepResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(s.passed for s in self.steps)


@dataclass
class ValidationResult:
    passed: bool
    chain: list[str] = field(default_factory=list)
    certs: list[CertValidation] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "chain": self.chain,
            "certificates": [
                {
                    "subject": c.subject,
                    "passed": c.passed,
                    "steps": [{"name": s.name, "passed": s.passed, "detail": s.detail} for s in c.steps],
                }
                for c in self.certs
            ],
            "error": self.error,
        }


def build_chain(
    leaf: x509.Certificate,
    untrusted: list[x509.Certificate],
    trusted: list[x509.Certificate],
) -> list[x509.Certificate]:
    chain = [leaf]
    current = leaf
    used = set()
    candidates = list(untrusted)
    max_depth = len(candidates) + len(trusted) + 1
    for _ in range(max_depth):
        issuer_name = current.issuer
        if current.issuer == current.subject:
            break
        found = False
        for t in trusted:
            if t.subject == issuer_name:
                try:
                    crypto_utils.verify_cert_signature(current, t)
                    chain.append(t)
                    return chain
                except Exception:
                    continue
        for i, c in enumerate(candidates):
            if i in used:
                continue
            if c.subject == issuer_name:
                try:
                    crypto_utils.verify_cert_signature(current, c)
                    chain.append(c)
                    used.add(i)
                    current = c
                    found = True
                    break
                except Exception:
                    continue
        if not found:
            break
    for t in trusted:
        if t.subject == current.issuer:
            try:
                crypto_utils.verify_cert_signature(current, t)
                chain.append(t)
                return chain
            except Exception:
                pass
    raise ValueError(
        f"Cannot build chain: no trusted issuer found for '{current.subject.rfc4514_string()}'"
    )


def _check_signature(subject_cert, issuer_cert) -> StepResult:
    try:
        crypto_utils.verify_cert_signature(subject_cert, issuer_cert)
        return StepResult("signature", True, "Signature valid")
    except Exception as e:
        return StepResult("signature", False, f"Signature invalid: {e}")


def _check_validity(cert, now) -> StepResult:
    nb = cert.not_valid_before_utc
    na = cert.not_valid_after_utc
    if now < nb:
        return StepResult("validity", False, f"Not yet valid (notBefore={nb.isoformat()})")
    if now > na:
        return StepResult("validity", False, f"Expired (notAfter={na.isoformat()})")
    return StepResult("validity", True, f"Valid from {nb.isoformat()} to {na.isoformat()}")


def _check_basic_constraints(cert, expect_ca) -> StepResult:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if bc.value.ca != expect_ca:
            return StepResult(
                "basic_constraints", False,
                f"CA={bc.value.ca}, expected CA={expect_ca}",
            )
        return StepResult("basic_constraints", True, f"CA={bc.value.ca}")
    except x509.ExtensionNotFound:
        if expect_ca:
            return StepResult("basic_constraints", False, "Missing BasicConstraints on CA cert")
        return StepResult("basic_constraints", True, "No BasicConstraints (leaf OK)")


def _check_path_length(cert, subordinate_ca_count) -> StepResult:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if bc.value.path_length is not None:
            if subordinate_ca_count > bc.value.path_length:
                return StepResult(
                    "path_length", False,
                    f"pathLenConstraint={bc.value.path_length}, but {subordinate_ca_count} subordinate CAs",
                )
            return StepResult(
                "path_length", True,
                f"pathLenConstraint={bc.value.path_length}, {subordinate_ca_count} subordinate CAs",
            )
        return StepResult("path_length", True, "No pathLenConstraint")
    except x509.ExtensionNotFound:
        return StepResult("path_length", True, "No BasicConstraints")


def _check_key_usage_ca(cert) -> StepResult:
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        if not ku.value.key_cert_sign:
            return StepResult("key_usage", False, "CA cert missing keyCertSign")
        return StepResult("key_usage", True, "keyCertSign present")
    except x509.ExtensionNotFound:
        return StepResult("key_usage", True, "No KeyUsage extension")


def _check_key_usage_leaf(cert) -> StepResult:
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        if not ku.value.digital_signature:
            return StepResult("key_usage", False, "Leaf cert missing digitalSignature")
        return StepResult("key_usage", True, "digitalSignature present")
    except x509.ExtensionNotFound:
        return StepResult("key_usage", True, "No KeyUsage extension")


def validate_path(
    chain: list[x509.Certificate],
    now: datetime | None = None,
) -> ValidationResult:
    if not chain or len(chain) < 2:
        return ValidationResult(passed=False, error="Chain must have at least 2 certificates (leaf + root)")
    now = now or datetime.now(timezone.utc)
    result = ValidationResult(passed=True)
    result.chain = [c.subject.rfc4514_string() for c in chain]
    leaf = chain[0]
    root = chain[-1]
    intermediates = chain[1:-1]
    leaf_cv = CertValidation(subject=leaf.subject.rfc4514_string())
    leaf_cv.steps.append(_check_validity(leaf, now))
    leaf_cv.steps.append(_check_basic_constraints(leaf, expect_ca=False))
    leaf_cv.steps.append(_check_key_usage_leaf(leaf))
    leaf_cv.steps.append(_check_signature(leaf, chain[1]))
    result.certs.append(leaf_cv)
    for i, inter in enumerate(intermediates):
        cv = CertValidation(subject=inter.subject.rfc4514_string())
        cv.steps.append(_check_validity(inter, now))
        cv.steps.append(_check_basic_constraints(inter, expect_ca=True))
        cv.steps.append(_check_key_usage_ca(inter))
        subordinate_ca_count = i
        cv.steps.append(_check_path_length(inter, subordinate_ca_count))
        issuer = chain[1 + i + 1]
        cv.steps.append(_check_signature(inter, issuer))
        result.certs.append(cv)
    root_cv = CertValidation(subject=root.subject.rfc4514_string())
    root_cv.steps.append(_check_validity(root, now))
    root_cv.steps.append(_check_basic_constraints(root, expect_ca=True))
    root_cv.steps.append(_check_key_usage_ca(root))
    root_cv.steps.append(_check_signature(root, root))
    result.certs.append(root_cv)
    for cv in result.certs:
        if not cv.passed:
            result.passed = False
            for s in cv.steps:
                if not s.passed:
                    result.error = f"{cv.subject}: {s.name} — {s.detail}"
                    break
            break
    return result
