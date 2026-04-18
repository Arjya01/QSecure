"""
Q-Secure | cert_parser.py
Parse X.509 certificates and assess their quantum safety.
"""

from __future__ import annotations

import hashlib
import ssl
import socket
from datetime import datetime, timezone
from typing import Optional

from .models import CertificateInfo, QuantumRiskLevel

# ---------------------------------------------------------------------------
# Quantum-safe algorithm tables
# ---------------------------------------------------------------------------

# Public key algorithms that are quantum-resistant (NIST PQC)
PQC_KEY_ALGORITHMS: set[str] = {
    "ML-DSA", "ML-KEM", "SLH-DSA",
    "CRYSTALS-Dilithium", "CRYSTALS-Kyber",
    "Falcon", "SPHINCS+",
    "id-ML-DSA-44", "id-ML-DSA-65", "id-ML-DSA-87",
    "id-SLH-DSA-SHA2-128s", "id-SLH-DSA-SHA2-128f",
}

# Signature algorithms that are NOT quantum-safe
QUANTUM_VULNERABLE_SIG_ALGOS: set[str] = {
    "sha256WithRSAEncryption",
    "sha384WithRSAEncryption",
    "sha512WithRSAEncryption",
    "sha1WithRSAEncryption",
    "md5WithRSAEncryption",
    "rsassaPss",
    "ecdsa-with-SHA256",
    "ecdsa-with-SHA384",
    "ecdsa-with-SHA512",
    "ecdsa-with-SHA1",
    "dsaWithSHA256",
    "dsaWithSHA1",
}

NIST_STANDARD_MAP: dict[str, str] = {
    "ML-KEM":  "FIPS-203",
    "ML-DSA":  "FIPS-204",
    "SLH-DSA": "FIPS-205",
}

DEPRECATED_WEAK_KEY_SIZES: dict[str, int] = {
    "RSA": 2048,     # < 2048 is weak
    "DSA": 2048,
    "EC":  256,      # < 256 is weak
    "DH":  2048,
}


def _normalize_key_algo(raw: str) -> str:
    """Normalise openssl-style algorithm names to canonical form."""
    raw = raw.upper()
    if "RSA" in raw:
        return "RSA"
    if "EC" in raw or "ECDSA" in raw:
        return "EC"
    if "DSA" in raw:
        return "DSA"
    if "ML-DSA" in raw or "MLDSA" in raw or "DILITHIUM" in raw:
        return "ML-DSA"
    if "ML-KEM" in raw or "MLKEM" in raw or "KYBER" in raw:
        return "ML-KEM"
    if "SLH-DSA" in raw or "SLHDSA" in raw or "SPHINCS" in raw or "FALCON" in raw:
        return "SLH-DSA"
    return raw


def _assess_cert_quantum_risk(
    pub_key_algo: str,
    pub_key_size: int,
    sig_algo: str,
) -> tuple[bool, QuantumRiskLevel, Optional[str]]:
    """
    Return (is_quantum_safe, risk_level, nist_standard).
    """
    norm = _normalize_key_algo(pub_key_algo)

    # PQC algorithms
    if norm in ("ML-DSA", "ML-KEM", "SLH-DSA"):
        return True, QuantumRiskLevel.NONE, NIST_STANDARD_MAP.get(norm)

    # RSA: vulnerable to Shor's algorithm regardless of key size
    if norm == "RSA":
        if pub_key_size < 2048:
            return False, QuantumRiskLevel.CRITICAL, None
        return False, QuantumRiskLevel.HIGH, None

    # EC: smaller effective security loss from Grover
    if norm == "EC":
        if pub_key_size < 256:
            return False, QuantumRiskLevel.CRITICAL, None
        if pub_key_size >= 384:
            return False, QuantumRiskLevel.MEDIUM, None
        return False, QuantumRiskLevel.HIGH, None

    # DSA: vulnerable
    if norm == "DSA":
        return False, QuantumRiskLevel.HIGH, None

    return False, QuantumRiskLevel.HIGH, None


def parse_certificate_from_pem(pem_data: bytes) -> Optional[CertificateInfo]:
    """
    Parse a PEM certificate and return a CertificateInfo.
    Uses the `cryptography` library.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
        from cryptography.x509.oid import ExtensionOID

        cert = x509.load_pem_x509_certificate(pem_data)
        now = datetime.now(timezone.utc)

        # Subject / Issuer
        def _get_attr(name_obj, oid) -> str:
            try:
                return name_obj.get_attributes_for_oid(oid)[0].value
            except (IndexError, Exception):
                return ""

        from cryptography.x509.oid import NameOID
        subject_cn = _get_attr(cert.subject, NameOID.COMMON_NAME)
        subject_o  = _get_attr(cert.subject, NameOID.ORGANIZATION_NAME)
        subject_c  = _get_attr(cert.subject, NameOID.COUNTRY_NAME)
        issuer_cn  = _get_attr(cert.issuer, NameOID.COMMON_NAME)
        issuer_o   = _get_attr(cert.issuer, NameOID.ORGANIZATION_NAME)

        # Validity
        not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after  = cert.not_valid_after_utc  if hasattr(cert, "not_valid_after_utc")  else cert.not_valid_after.replace(tzinfo=timezone.utc)
        is_expired = now > not_after

        # Self-signed
        is_self_signed = cert.subject == cert.issuer

        # Signature algorithm
        try:
            sig_algo = cert.signature_algorithm_oid._name or cert.signature_hash_algorithm.name
        except Exception:
            sig_algo = str(cert.signature_algorithm_oid)

        # Public key
        pub_key = cert.public_key()
        if isinstance(pub_key, rsa.RSAPublicKey):
            pub_key_algo = "RSA"
            pub_key_size = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            pub_key_algo = "EC"
            pub_key_size = pub_key.key_size
        elif isinstance(pub_key, dsa.DSAPublicKey):
            pub_key_algo = "DSA"
            pub_key_size = pub_key.key_size
        else:
            # May be a PQC key
            pub_key_algo = type(pub_key).__name__
            pub_key_size = 0

        # SAN entries
        san_entries: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                san_entries.append(str(name.value))
        except Exception:
            pass

        # Fingerprint
        fingerprint = cert.fingerprint(
            __import__("cryptography.hazmat.primitives.hashes", fromlist=["SHA256"]).SHA256()
        ).hex()
        fingerprint_fmt = ":".join(fingerprint[i:i+2].upper() for i in range(0, len(fingerprint), 2))

        # Serial number
        serial = format(cert.serial_number, "X")

        # Quantum assessment
        is_qs, risk, nist_std = _assess_cert_quantum_risk(pub_key_algo, pub_key_size, sig_algo)

        return CertificateInfo(
            subject_cn=subject_cn,
            subject_o=subject_o,
            subject_c=subject_c,
            issuer_cn=issuer_cn,
            issuer_o=issuer_o,
            serial_number=serial,
            not_before=not_before,
            not_after=not_after,
            is_expired=is_expired,
            is_self_signed=is_self_signed,
            signature_algorithm=sig_algo,
            public_key_algorithm=pub_key_algo,
            public_key_size=pub_key_size,
            san_entries=san_entries,
            chain_valid=not is_self_signed,
            fingerprint_sha256=fingerprint_fmt,
            is_quantum_safe_cert=is_qs,
            quantum_risk=risk,
            nist_standard=nist_std,
        )
    except Exception as exc:
        # Return a minimal failing cert record
        return CertificateInfo(
            subject_cn="PARSE_ERROR",
            issuer_cn="PARSE_ERROR",
            chain_valid=False,
            quantum_risk=QuantumRiskLevel.HIGH,
            notes=f"Certificate parse error: {exc}",  # type: ignore[call-arg]
        )


def fetch_certificate_from_host(hostname: str, port: int = 443, timeout: int = 10) -> Optional[CertificateInfo]:
    """
    Fetch the leaf certificate from a live host over TLS and parse it.
    Returns None on connection failure.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE   # We want to inspect even invalid certs

        with socket.create_connection((hostname, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                der_cert = tls_sock.getpeercert(binary_form=True)

        if der_cert is None:
            return None

        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert).encode()
        return parse_certificate_from_pem(pem_cert)

    except Exception:
        return None
