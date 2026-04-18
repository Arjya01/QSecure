"""
Q-Secure | cbom_generator.py
Cryptographic Bill of Materials (CBOM) generator.

Produces one entry per distinct cryptographic component found in a scan result.
Each entry maps to NIST FIPS standards and includes CERT-IN compliance status.
"""

from __future__ import annotations

from typing import Optional

from .models import (
    CBOMComponentType,
    CBOMEntry,
    CipherDetail,
    CertificateInfo,
    KeyExchangeAssessment,
    MigrationPriority,
    QuantumRiskLevel,
    ScanResult,
    TLSVersionResult,
    TLSVersion,
)

# ---------------------------------------------------------------------------
# NIST PQC replacement map
# ---------------------------------------------------------------------------

REPLACEMENT_MAP: dict[str, str] = {
    # Key exchange
    "RSA":           "ML-KEM-768 (FIPS-203) + X25519 hybrid",
    "ECDHE":         "ML-KEM-768 (FIPS-203)",
    "DHE":           "ML-KEM-1024 (FIPS-203)",
    "DH":            "ML-KEM-1024 (FIPS-203)",
    "ECDH":          "ML-KEM-768 (FIPS-203)",
    # Authentication / signature
    "RSA-SIG":       "ML-DSA-65 or ML-DSA-87 (FIPS-204)",
    "ECDSA":         "ML-DSA-44 (FIPS-204)",
    "DSA":           "ML-DSA-65 (FIPS-204)",
    # Symmetric / MAC (already quantum-safe with large enough keys)
    "AES-128":       "AES-256-GCM (Grover-resistant at 128-bit post-quantum level)",
    "AES-256":       "No change required (Grover-resistant)",
    "CHACHA20":      "No change required",
    "3DES":          "AES-256-GCM",
    "DES":           "AES-256-GCM",
    "RC4":           "AES-256-GCM",
    # Hash / MAC
    "SHA1":          "SHA-384 or SHA3-256",
    "MD5":           "SHA-384",
    "SHA256":        "SHA-384 (provides 192-bit post-quantum security)",
    "SHA384":        "No change required",
    # TLS versions
    "SSLv2":         "TLS 1.3",
    "SSLv3":         "TLS 1.3",
    "TLSv1.0":       "TLS 1.3",
    "TLSv1.1":       "TLS 1.3",
    "TLSv1.2":       "TLS 1.3 with PQC key exchange",
    "TLSv1.3":       "TLS 1.3 + ML-KEM hybrid (already best practice)",
    # Certificate types
    "RSA-CERT":      "ML-DSA-65 (FIPS-204)",
    "EC-CERT":       "ML-DSA-44 (FIPS-204)",
    "DSA-CERT":      "ML-DSA-65 (FIPS-204)",
}

NIST_STANDARD_FOR: dict[str, str] = {
    "RSA": None,
    "ECDHE": None,
    "DHE": None,
    "AES": None,
    "ML-KEM": "FIPS-203",
    "ML-DSA": "FIPS-204",
    "SLH-DSA": "FIPS-205",
}

# CERT-IN compliance: algorithms that meet CERT-IN (India NCIIPC/CERT-In) cryptographic guidelines
CERT_IN_COMPLIANT: set[str] = {
    "AES-256", "AES-128", "CHACHA20",
    "SHA256", "SHA384", "SHA512",
    "ECDHE", "RSA",
    "TLSv1.2", "TLSv1.3",
    "ML-KEM", "ML-DSA", "SLH-DSA",
}

INSECURE_ALGOS: set[str] = {
    "RC4", "DES", "3DES", "MD5", "SHA1", "NULL",
    "EXPORT", "SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1",
}


def _cert_in_compliant(name: str) -> bool:
    n = name.upper()
    for insecure in INSECURE_ALGOS:
        if insecure in n:
            return False
    for safe in CERT_IN_COMPLIANT:
        if safe.upper() in n:
            return True
    return False


def _risk_from_replacement_key(key: str) -> QuantumRiskLevel:
    no_change = ("No change required",)
    if any(k in REPLACEMENT_MAP.get(key, "") for k in no_change):
        return QuantumRiskLevel.LOW
    if key in ("SSLv2", "SSLv3", "TLSv1.0", "RC4", "NULL", "DES", "EXPORT"):
        return QuantumRiskLevel.CRITICAL
    if key in ("RSA", "ECDHE", "DHE", "ECDSA", "RSA-SIG", "RSA-CERT", "EC-CERT"):
        return QuantumRiskLevel.HIGH
    if key in ("TLSv1.1", "TLSv1.2", "3DES", "SHA1", "MD5", "SHA256"):
        return QuantumRiskLevel.MEDIUM
    return QuantumRiskLevel.MEDIUM


def _priority_from_risk(risk: QuantumRiskLevel) -> MigrationPriority:
    mapping = {
        QuantumRiskLevel.CRITICAL: MigrationPriority.IMMEDIATE,
        QuantumRiskLevel.HIGH:     MigrationPriority.HIGH,
        QuantumRiskLevel.MEDIUM:   MigrationPriority.MEDIUM,
        QuantumRiskLevel.LOW:      MigrationPriority.LOW,
        QuantumRiskLevel.NONE:     MigrationPriority.NONE,
    }
    return mapping.get(risk, MigrationPriority.MEDIUM)


# ---------------------------------------------------------------------------
# Entry builders
# ---------------------------------------------------------------------------

def _protocol_entries(tls_versions: list[TLSVersionResult]) -> list[CBOMEntry]:
    entries = []
    counter = 1
    for v in tls_versions:
        if not v.supported:
            continue
        ver_str = v.version.value
        risk = _risk_from_replacement_key(ver_str)
        entries.append(CBOMEntry(
            entry_id=f"CBOM-PROTO-{counter:03d}",
            component_type=CBOMComponentType.PROTOCOL,
            name=f"TLS/{ver_str}",
            version=ver_str,
            quantum_risk=risk,
            migration_priority=_priority_from_risk(risk),
            recommended_replacement=REPLACEMENT_MAP.get(ver_str, "TLS 1.3"),
            nist_fips_standard=None,
            cert_in_compliant=_cert_in_compliant(ver_str),
            notes=f"Protocol {'is insecure/deprecated' if v.is_insecure or v.is_deprecated else 'is acceptable'}",
        ))
        counter += 1
    return entries


def _cipher_entries(ciphers: list[CipherDetail]) -> list[CBOMEntry]:
    entries = []
    seen: set[str] = set()
    counter = 1

    for c in ciphers:
        # KEX entry
        kex = c.key_exchange.upper()
        if kex and kex not in seen:
            seen.add(kex)
            risk = QuantumRiskLevel.CRITICAL if c.quantum_risk == QuantumRiskLevel.CRITICAL else c.quantum_risk
            replacement_key = kex if kex in REPLACEMENT_MAP else "ECDHE"
            entries.append(CBOMEntry(
                entry_id=f"CBOM-KEX-{counter:03d}",
                component_type=CBOMComponentType.ALGORITHM,
                name=f"{c.key_exchange} Key Exchange",
                version="",
                key_size=c.key_size,
                quantum_risk=risk,
                migration_priority=_priority_from_risk(risk),
                recommended_replacement=REPLACEMENT_MAP.get(replacement_key, f"ML-KEM-768 (FIPS-203)"),
                nist_fips_standard="FIPS-203" if c.is_quantum_vulnerable is False else None,
                cert_in_compliant=_cert_in_compliant(c.key_exchange),
                notes=(
                    "Post-quantum key exchange" if not c.is_quantum_vulnerable
                    else "Vulnerable to Shor's algorithm"
                ),
            ))
            counter += 1

        # Encryption algorithm entry
        enc = c.encryption.upper()
        enc_key = enc.split("_")[0] if "_" in enc else enc
        enc_label = f"ENC-{enc}"
        if enc and enc_label not in seen:
            seen.add(enc_label)
            # Symmetric encryption is generally quantum-safe with AES-256
            if "AES256" in enc.replace("-", "") or "AES_256" in enc:
                enc_risk = QuantumRiskLevel.LOW
            elif "AES128" in enc.replace("-", "") or "AES_128" in enc:
                enc_risk = QuantumRiskLevel.LOW
            elif "RC4" in enc or "DES" in enc:
                enc_risk = QuantumRiskLevel.CRITICAL
            else:
                enc_risk = QuantumRiskLevel.LOW

            enc_replace_key = "AES-256" if "AES" in enc else enc_key
            entries.append(CBOMEntry(
                entry_id=f"CBOM-ENC-{counter:03d}",
                component_type=CBOMComponentType.ALGORITHM,
                name=f"Symmetric: {c.encryption}",
                version="",
                quantum_risk=enc_risk,
                migration_priority=_priority_from_risk(enc_risk),
                recommended_replacement=REPLACEMENT_MAP.get(enc_replace_key, "AES-256-GCM"),
                nist_fips_standard=None,
                cert_in_compliant=_cert_in_compliant(enc),
                notes="AEAD cipher" if "GCM" in enc.upper() or "CCM" in enc.upper() else "",
            ))
            counter += 1

    return entries


def _cert_entry(cert: Optional[CertificateInfo]) -> list[CBOMEntry]:
    if cert is None:
        return []

    algo = cert.public_key_algorithm.upper()
    replacement_key = f"{algo}-CERT" if f"{algo}-CERT" in REPLACEMENT_MAP else "EC-CERT"

    # Determine NIST standard
    nist = cert.nist_standard
    if algo in ("ML-DSA",):
        nist = "FIPS-204"
    elif algo in ("ML-KEM",):
        nist = "FIPS-203"
    elif algo in ("SLH-DSA",):
        nist = "FIPS-205"

    return [CBOMEntry(
        entry_id="CBOM-CERT-001",
        component_type=CBOMComponentType.CERTIFICATE,
        name=f"X.509 Certificate ({cert.public_key_algorithm}-{cert.public_key_size})",
        version="X.509 v3",
        key_size=cert.public_key_size,
        quantum_risk=cert.quantum_risk,
        migration_priority=_priority_from_risk(cert.quantum_risk),
        recommended_replacement=REPLACEMENT_MAP.get(replacement_key, f"ML-DSA-65 (FIPS-204)"),
        nist_fips_standard=nist,
        cert_in_compliant=(cert.is_quantum_safe_cert or cert.public_key_size >= 2048),
        notes=(
            f"Subject: {cert.subject_cn} | "
            f"Issuer: {cert.issuer_cn} | "
            f"{'EXPIRED' if cert.is_expired else 'Valid'} | "
            f"{'Self-Signed' if cert.is_self_signed else 'CA-Signed'}"
        ),
    )]


def _sig_algo_entry(cert: Optional[CertificateInfo]) -> list[CBOMEntry]:
    if cert is None or not cert.signature_algorithm:
        return []

    sig = cert.signature_algorithm
    sig_upper = sig.upper()

    if "RSA" in sig_upper:
        risk = QuantumRiskLevel.HIGH
        replacement = REPLACEMENT_MAP["RSA-SIG"]
        nist = "FIPS-204"
    elif "ECDSA" in sig_upper or "EC" in sig_upper:
        risk = QuantumRiskLevel.HIGH
        replacement = REPLACEMENT_MAP["ECDSA"]
        nist = "FIPS-204"
    elif "ML-DSA" in sig_upper or "DILITHIUM" in sig_upper:
        risk = QuantumRiskLevel.NONE
        replacement = "Already post-quantum"
        nist = "FIPS-204"
    elif "SLH-DSA" in sig_upper or "SPHINCS" in sig_upper:
        risk = QuantumRiskLevel.NONE
        replacement = "Already post-quantum"
        nist = "FIPS-205"
    else:
        risk = QuantumRiskLevel.MEDIUM
        replacement = f"ML-DSA-65 (FIPS-204)"
        nist = "FIPS-204"

    return [CBOMEntry(
        entry_id="CBOM-SIG-001",
        component_type=CBOMComponentType.ALGORITHM,
        name=f"Signature Algorithm: {sig}",
        version="",
        quantum_risk=risk,
        migration_priority=_priority_from_risk(risk),
        recommended_replacement=replacement,
        nist_fips_standard=nist,
        cert_in_compliant=_cert_in_compliant(sig),
        notes="Vulnerable to Shor's algorithm" if risk in (QuantumRiskLevel.HIGH, QuantumRiskLevel.CRITICAL) else "Post-quantum safe",
    )]


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def generate_cbom(result: ScanResult) -> list[CBOMEntry]:
    """
    Build the full CBOM from a completed ScanResult.
    Returns a list of CBOMEntry objects, one per distinct cryptographic component.
    """
    entries: list[CBOMEntry] = []

    # 1. TLS protocol versions
    entries.extend(_protocol_entries(result.tls_versions))

    # 2. Cipher components (KEX + encryption)
    entries.extend(_cipher_entries(result.ciphers))

    # 3. Certificate
    entries.extend(_cert_entry(result.certificate))

    # 4. Signature algorithm (from cert)
    entries.extend(_sig_algo_entry(result.certificate))

    # Re-number sequentially
    for i, entry in enumerate(entries, start=1):
        entry.entry_id = f"CBOM-{i:03d}"

    return entries
