"""
Q-Secure | quantum_assessor.py
Weighted quantum safety scoring engine + vulnerability finder.

Scoring weights:
  TLS version quality   -> 20%
  Cipher suite quality  -> 25%
  Certificate strength  -> 25%
  Key exchange safety   -> 30%
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from .models import (
    CertificateInfo,
    CipherDetail,
    KeyExchangeAssessment,
    MigrationPriority,
    QuantumLabel,
    QuantumRiskLevel,
    QuantumSafetyScore,
    QuantumTier,
    Severity,
    TLSVersion,
    TLSVersionResult,
    VulnerabilityFinding,
)

# NIST PQC standards
FIPS_203 = "FIPS-203 (ML-KEM)"
FIPS_204 = "FIPS-204 (ML-DSA)"
FIPS_205 = "FIPS-205 (SLH-DSA)"


# ---------------------------------------------------------------------------
# TLS version score (weight 20%)
# ---------------------------------------------------------------------------

def score_tls_versions(tls_versions: list[TLSVersionResult]) -> float:
    """
    Score 0-100 based on supported TLS versions.
    Only TLS 1.2 and 1.3 are acceptable.
    TLS 1.3 support adds bonus points.
    Any insecure version penalises heavily.
    """
    if not tls_versions:
        return 0.0

    supported = {v.version for v in tls_versions if v.supported}
    insecure  = {v.version for v in tls_versions if v.supported and v.is_insecure}
    deprecated = {v.version for v in tls_versions if v.supported and v.is_deprecated}

    score = 100.0

    # Major penalties for insecure protocols
    if TLSVersion.SSL_2 in insecure:
        score -= 60
    if TLSVersion.SSL_3 in insecure:
        score -= 50
    if TLSVersion.TLS_10 in insecure:
        score -= 30
    if TLSVersion.TLS_11 in deprecated:
        score -= 15

    # Reward for TLS 1.3
    if TLSVersion.TLS_13 in supported:
        bonus = 10
        score = min(100.0, score + bonus)

    # Penalty if TLS 1.3 not even supported
    if TLSVersion.TLS_13 not in supported:
        score -= 10

    # Penalty if TLS 1.2 not supported (very old server)
    if TLSVersion.TLS_12 not in supported and not supported:
        score = 0.0

    return max(0.0, min(100.0, score))


# ---------------------------------------------------------------------------
# Cipher suite score (weight 25%)
# ---------------------------------------------------------------------------

_CIPHER_WEAKNESS_PENALTIES: dict[str, float] = {
    "RC4":     40,
    "NULL":    60,
    "EXPORT":  50,
    "DES":     40,
    "3DES":    25,
    "MD5":     20,
    "ANON":    60,
    "RSA_KEX": 15,   # RSA key exchange (no forward secrecy)
}

_CIPHER_BONUS: dict[str, float] = {
    "GCM":       10,
    "CHACHA20":  10,
    "POLY1305":   5,
    "ECDHE":     10,
    "DHE":        5,
    "SHA384":     5,
    "SHA256":     3,
}


def score_ciphers(ciphers: list[CipherDetail]) -> float:
    """Score 0-100 based on cipher suite quality."""
    if not ciphers:
        return 0.0

    score = 80.0   # Start at 80, adjustments follow

    for cipher in ciphers:
        cipher_str = cipher.iana_name.upper()

        # Penalties
        for weakness, penalty in _CIPHER_WEAKNESS_PENALTIES.items():
            if weakness in cipher_str:
                score -= penalty

        # Key exchange penalty
        if cipher.key_exchange.upper() == "RSA" and not cipher.is_forward_secret:
            score -= _CIPHER_WEAKNESS_PENALTIES["RSA_KEX"]

        # Bonuses
        for feature, bonus in _CIPHER_BONUS.items():
            if feature in cipher_str:
                score += bonus

        # Forward secrecy bonus
        if cipher.is_forward_secret:
            score += 5

    return max(0.0, min(100.0, score))


# ---------------------------------------------------------------------------
# Certificate strength score (weight 25%)
# ---------------------------------------------------------------------------

def score_certificate(cert: Optional[CertificateInfo]) -> float:
    """Score 0-100 based on certificate cryptographic strength."""
    if cert is None:
        return 0.0

    score = 70.0

    # Expired certificate
    if cert.is_expired:
        score -= 40

    # Self-signed
    if cert.is_self_signed:
        score -= 20

    # PQC cert
    if cert.is_quantum_safe_cert:
        score += 30
        return min(100.0, score)

    # RSA key size
    algo = cert.public_key_algorithm.upper()
    size = cert.public_key_size

    if "RSA" in algo:
        if size < 1024:
            score -= 50
        elif size < 2048:
            score -= 30
        elif size == 2048:
            score -= 10   # Acceptable but quantum-vulnerable
        elif size >= 4096:
            score += 5    # Larger but still quantum-vulnerable

    elif "EC" in algo:
        if size < 256:
            score -= 30
        elif size >= 384:
            score += 10
        elif size >= 521:
            score += 15

    # Signature algorithm penalties
    sig = cert.signature_algorithm.upper()
    if "MD5" in sig or "SHA1" in sig:
        score -= 25
    elif "SHA384" in sig or "SHA512" in sig:
        score += 5

    return max(0.0, min(100.0, score))


# ---------------------------------------------------------------------------
# Key exchange score (weight 30%)
# ---------------------------------------------------------------------------

def score_key_exchange(kex: Optional[KeyExchangeAssessment]) -> float:
    """Score 0-100 based on key exchange quantum safety."""
    if kex is None:
        return 0.0

    if kex.is_post_quantum:
        # PQC KEX - check specific algorithm quality
        algo = kex.algorithm.upper()
        if "ML-KEM-1024" in algo or "768" in algo:
            return 95.0
        if "ML-KEM" in algo or "KYBER" in algo:
            return 90.0
        return 85.0

    score = 40.0   # Classical KEX baseline

    algo = kex.algorithm.upper()

    if "ECDHE" in algo:
        score = 50.0
        if kex.key_size >= 384:
            score += 10
        elif kex.key_size >= 256:
            score += 5
    elif "DHE" in algo or "EDH" in algo:
        score = 40.0
        if kex.key_size >= 2048:
            score += 5
        elif kex.key_size < 1024:
            score -= 20
    elif "RSA" in algo:
        score = 20.0  # RSA KEX: no forward secrecy + quantum-vulnerable

    return max(0.0, min(100.0, score))


# ---------------------------------------------------------------------------
# Grade + label derivation
# ---------------------------------------------------------------------------

def _derive_grade(score: float) -> str:
    if score >= 95: return "A+"
    if score >= 85: return "A"
    if score >= 75: return "B"
    if score >= 65: return "C"
    if score >= 50: return "D"
    return "F"


def _derive_label(score: float, kex: Optional[KeyExchangeAssessment]) -> QuantumLabel:
    if kex and kex.is_post_quantum and score >= 85:
        return QuantumLabel.QUANTUM_SAFE
    if score >= 60:
        return QuantumLabel.PQC_READY
    return QuantumLabel.NOT_QUANTUM_SAFE


def _derive_tier(score: float) -> QuantumTier:
    if score >= 90: return QuantumTier.ELITE_PQC
    if score >= 60: return QuantumTier.STANDARD
    if score >= 30: return QuantumTier.LEGACY
    return QuantumTier.CRITICAL


def _derive_migration_urgency(score: float) -> MigrationPriority:
    if score >= 85: return MigrationPriority.NONE
    if score >= 70: return MigrationPriority.LOW
    if score >= 55: return MigrationPriority.MEDIUM
    if score >= 30: return MigrationPriority.HIGH
    return MigrationPriority.IMMEDIATE


def _derive_summary(score: float, label: QuantumLabel, tier: QuantumTier) -> str:
    summaries = {
        QuantumLabel.QUANTUM_SAFE: (
            "This endpoint employs post-quantum cryptographic algorithms conforming to NIST FIPS standards. "
            "It is resistant to attacks from both classical and quantum computers."
        ),
        QuantumLabel.PQC_READY: (
            "This endpoint uses strong classical cryptography with no immediate vulnerabilities, "
            "but has not yet deployed post-quantum key exchange or certificates. "
            "Migration to NIST-standardised PQC algorithms (FIPS-203/204/205) is recommended."
        ),
        QuantumLabel.NOT_QUANTUM_SAFE: (
            "This endpoint uses cryptographic algorithms that are vulnerable to quantum attacks. "
            "Shor's algorithm on a sufficiently powerful quantum computer can break the key exchange "
            "and potentially decrypt traffic retroactively (harvest-now-decrypt-later). "
            "Immediate remediation required."
        ),
    }
    return summaries.get(label, "Assessment inconclusive.")


# ---------------------------------------------------------------------------
# Vulnerability detection
# ---------------------------------------------------------------------------

_vuln_id_counter = 0


def _next_id() -> str:
    global _vuln_id_counter
    _vuln_id_counter += 1
    return f"QS-{_vuln_id_counter:03d}"


def detect_vulnerabilities(
    tls_versions: list[TLSVersionResult],
    ciphers: list[CipherDetail],
    cert: Optional[CertificateInfo],
    kex: Optional[KeyExchangeAssessment],
) -> list[VulnerabilityFinding]:
    global _vuln_id_counter
    _vuln_id_counter = 0  # Reset per scan

    findings: list[VulnerabilityFinding] = []

    # --- TLS version vulnerabilities ---
    supported_versions = {v.version for v in tls_versions if v.supported}

    if TLSVersion.SSL_2 in supported_versions:
        findings.append(VulnerabilityFinding(
            id=_next_id(), title="SSLv2 Enabled",
            severity=Severity.CRITICAL,
            description="SSLv2 is cryptographically broken and enables DROWN attack.",
            affected_component="TLS Protocol",
            recommendation="Immediately disable SSLv2 on the server.",
            cve_references=["CVE-2016-0800"],
            nist_references=["SP 800-52 Rev.2"],
        ))

    if TLSVersion.SSL_3 in supported_versions:
        findings.append(VulnerabilityFinding(
            id=_next_id(), title="SSLv3 Enabled - POODLE Vulnerability",
            severity=Severity.CRITICAL,
            description="SSLv3 support exposes the server to POODLE attack (CBC padding oracle).",
            affected_component="TLS Protocol",
            recommendation="Disable SSLv3 immediately.",
            cve_references=["CVE-2014-3566"],
        ))

    if TLSVersion.TLS_10 in supported_versions:
        findings.append(VulnerabilityFinding(
            id=_next_id(), title="TLS 1.0 Enabled - BEAST/CRIME Risk",
            severity=Severity.HIGH,
            description=(
                "TLS 1.0 is deprecated (RFC 8996). It is susceptible to BEAST and CRIME attacks. "
                "PCI-DSS 3.2+ explicitly prohibits TLS 1.0 for payment processing."
            ),
            affected_component="TLS Protocol",
            recommendation="Disable TLS 1.0. Enforce TLS 1.2 minimum, prefer TLS 1.3.",
            cve_references=["CVE-2011-3389"],
            nist_references=["NIST SP 800-52 Rev.2"],
        ))

    if TLSVersion.TLS_11 in supported_versions:
        findings.append(VulnerabilityFinding(
            id=_next_id(), title="TLS 1.1 Enabled - Deprecated Protocol",
            severity=Severity.MEDIUM,
            description="TLS 1.1 is deprecated per RFC 8996 and lacks modern AEAD ciphers.",
            affected_component="TLS Protocol",
            recommendation="Disable TLS 1.1. Use TLS 1.2+ with AEAD ciphers.",
            nist_references=["NIST SP 800-52 Rev.2"],
        ))

    if TLSVersion.TLS_13 not in supported_versions:
        findings.append(VulnerabilityFinding(
            id=_next_id(), title="TLS 1.3 Not Supported",
            severity=Severity.LOW,
            description=(
                "TLS 1.3 provides improved security and performance. "
                "It eliminates legacy cipher suites and mandates forward secrecy."
            ),
            affected_component="TLS Protocol",
            recommendation="Enable TLS 1.3 support on the server.",
            nist_references=["NIST SP 800-52 Rev.2"],
        ))

    # --- Cipher vulnerabilities ---
    for cipher in ciphers:
        cn = cipher.iana_name.upper()

        if "RC4" in cn:
            findings.append(VulnerabilityFinding(
                id=_next_id(), title="RC4 Cipher Suite Enabled",
                severity=Severity.CRITICAL,
                description="RC4 has multiple statistical biases making plaintext recovery possible.",
                affected_component=f"Cipher Suite: {cipher.iana_name}",
                recommendation="Remove all RC4 cipher suites immediately.",
                cve_references=["CVE-2015-2808"],
                nist_references=["NIST SP 800-52"],
            ))

        if "NULL" in cn:
            findings.append(VulnerabilityFinding(
                id=_next_id(), title="NULL Cipher Suite - No Encryption",
                severity=Severity.CRITICAL,
                description="NULL cipher suite provides authentication without any encryption.",
                affected_component=f"Cipher Suite: {cipher.iana_name}",
                recommendation="Remove all NULL cipher suites.",
            ))

        if "EXPORT" in cn:
            findings.append(VulnerabilityFinding(
                id=_next_id(), title="EXPORT-Grade Cipher - FREAK/Logjam",
                severity=Severity.CRITICAL,
                description="Export-grade ciphers use intentionally weakened key lengths (<=512-bit).",
                affected_component=f"Cipher Suite: {cipher.iana_name}",
                recommendation="Remove all EXPORT cipher suites.",
                cve_references=["CVE-2015-0204", "CVE-2015-4000"],
            ))

        if "3DES" in cn or "DES" in cn:
            findings.append(VulnerabilityFinding(
                id=_next_id(), title="3DES/DES Cipher Suite - SWEET32",
                severity=Severity.HIGH,
                description="DES-based ciphers have 64-bit block sizes vulnerable to birthday attacks.",
                affected_component=f"Cipher Suite: {cipher.iana_name}",
                recommendation="Replace 3DES with AES-128-GCM or AES-256-GCM.",
                cve_references=["CVE-2016-2183"],
            ))

        if not cipher.is_forward_secret and cipher.key_exchange.upper() == "RSA":
            findings.append(VulnerabilityFinding(
                id=_next_id(), title="RSA Key Exchange - No Forward Secrecy",
                severity=Severity.HIGH,
                description=(
                    "RSA key exchange does not provide forward secrecy. "
                    "Recorded ciphertext can be decrypted if the private key is later compromised. "
                    "Quantum computers running Shor's algorithm can break RSA key exchange."
                ),
                affected_component=f"Cipher Suite: {cipher.iana_name}",
                quantum_relevant=True,
                recommendation=(
                    "Replace RSA key exchange with ECDHE or DHE. "
                    "Migrate to ML-KEM (FIPS-203) for post-quantum forward secrecy."
                ),
                nist_references=[FIPS_203],
            ))

        if cipher.is_quantum_vulnerable and cipher.key_exchange.upper() in ("ECDHE", "DHE"):
            findings.append(VulnerabilityFinding(
                id=_next_id(), title=f"Classical Key Exchange Vulnerable to Quantum Attack",
                severity=Severity.MEDIUM,
                description=(
                    f"{cipher.key_exchange} key exchange is secure against classical computers "
                    "but vulnerable to Shor's algorithm on quantum hardware. "
                    "This exposes past sessions to harvest-now-decrypt-later attacks."
                ),
                affected_component=f"Key Exchange: {cipher.key_exchange}",
                quantum_relevant=True,
                recommendation=(
                    f"Migrate key exchange to ML-KEM-768 or ML-KEM-1024 ({FIPS_203}). "
                    "X25519+ML-KEM hybrid is recommended as a transition strategy."
                ),
                nist_references=[FIPS_203],
            ))

    # --- Certificate vulnerabilities ---
    if cert:
        if cert.is_expired:
            findings.append(VulnerabilityFinding(
                id=_next_id(), title="Certificate Expired",
                severity=Severity.CRITICAL,
                description=f"Certificate expired on {cert.not_after}. TLS handshake will fail for strict clients.",
                affected_component="X.509 Certificate",
                quantum_relevant=False,
                recommendation="Renew the certificate immediately.",
            ))

        if cert.is_self_signed:
            findings.append(VulnerabilityFinding(
                id=_next_id(), title="Self-Signed Certificate",
                severity=Severity.HIGH,
                description=(
                    "Self-signed certificates are not trusted by browsers/clients by default. "
                    "They provide no third-party authentication assurance."
                ),
                affected_component="X.509 Certificate",
                quantum_relevant=False,
                recommendation="Replace with a certificate from a trusted CA (DigiCert, Let's Encrypt).",
            ))

        algo = cert.public_key_algorithm.upper()
        size = cert.public_key_size

        if "RSA" in algo and size < 2048:
            findings.append(VulnerabilityFinding(
                id=_next_id(), title=f"Weak RSA Key - {size}-bit",
                severity=Severity.CRITICAL,
                description=(
                    f"RSA-{size} is below the NIST recommended minimum of 2048 bits. "
                    "It is trivially factorable with classical hardware and trivially broken by quantum."
                ),
                affected_component=f"Certificate Public Key (RSA-{size})",
                quantum_relevant=True,
                recommendation=f"Replace with RSA-4096 at minimum, or migrate to ML-DSA ({FIPS_204}).",
                nist_references=[FIPS_204],
            ))

        elif "RSA" in algo:
            findings.append(VulnerabilityFinding(
                id=_next_id(), title=f"RSA Certificate Quantum Vulnerable",
                severity=Severity.MEDIUM,
                description=(
                    f"RSA-{size} certificates are broken by Shor's algorithm. "
                    "Harvest-now-decrypt-later attacks can compromise certificate authenticity retroactively."
                ),
                affected_component=f"Certificate Public Key (RSA-{size})",
                quantum_relevant=True,
                recommendation=f"Migrate certificate to ML-DSA-65 or ML-DSA-87 ({FIPS_204}).",
                nist_references=[FIPS_204],
            ))

        if "EC" in algo and size < 256:
            findings.append(VulnerabilityFinding(
                id=_next_id(), title=f"Weak EC Key - {size}-bit",
                severity=Severity.HIGH,
                description=f"EC-{size} provides fewer than 128 bits of classical security.",
                affected_component=f"Certificate Public Key (EC-{size})",
                quantum_relevant=True,
                recommendation=f"Use EC-384 minimum or migrate to ML-DSA ({FIPS_204}).",
                nist_references=[FIPS_204],
            ))

        sig = cert.signature_algorithm.upper()
        if "SHA1" in sig or "MD5" in sig:
            findings.append(VulnerabilityFinding(
                id=_next_id(), title="Weak Certificate Signature Hash (SHA-1/MD5)",
                severity=Severity.HIGH,
                description="SHA-1 and MD5 certificate signatures are cryptographically broken.",
                affected_component=f"Certificate Signature Algorithm: {cert.signature_algorithm}",
                quantum_relevant=False,
                recommendation="Reissue certificate with SHA-256 or SHA-384.",
                cve_references=["CVE-2005-4900"],
            ))

        # Check upcoming expiry (within 30 days)
        if cert.not_after and not cert.is_expired:
            days_left = (cert.not_after.replace(tzinfo=None if cert.not_after.tzinfo else None) - datetime.utcnow()).days
            if days_left < 30:
                findings.append(VulnerabilityFinding(
                    id=_next_id(), title=f"Certificate Expiring Soon ({days_left} days)",
                    severity=Severity.HIGH,
                    description=f"Certificate expires on {cert.not_after}.",
                    affected_component="X.509 Certificate",
                    quantum_relevant=False,
                    recommendation="Renew certificate before expiry.",
                ))

    # --- Key exchange quantum vulnerability ---
    if kex and not kex.is_post_quantum:
        pass  # Already covered in cipher findings

    return findings


# ---------------------------------------------------------------------------
# Main scoring function
# ---------------------------------------------------------------------------

def compute_quantum_score(
    tls_versions: list[TLSVersionResult],
    ciphers: list[CipherDetail],
    cert: Optional[CertificateInfo],
    kex: Optional[KeyExchangeAssessment],
) -> QuantumSafetyScore:
    """
    Compute the composite quantum safety score.
    Weighted: TLS 20% + Cipher 25% + Cert 25% + KEX 30%
    """
    tls_score  = score_tls_versions(tls_versions)
    cip_score  = score_ciphers(ciphers)
    cert_score = score_certificate(cert)
    kex_score  = score_key_exchange(kex)

    overall = (
        tls_score  * 0.20 +
        cip_score  * 0.25 +
        cert_score * 0.25 +
        kex_score  * 0.30
    )
    overall = max(0.0, min(100.0, overall))

    label   = _derive_label(overall, kex)
    tier    = _derive_tier(overall)
    grade   = _derive_grade(overall)
    urgency = _derive_migration_urgency(overall)
    summary = _derive_summary(overall, label, tier)

    # Cyber rating: 0-1000, non-linear scaling
    cyber_rating = round((overall / 100.0) ** 1.2 * 1000, 1)

    return QuantumSafetyScore(
        overall_score=round(overall, 1),
        label=label,
        tier=tier,
        cyber_rating=cyber_rating,
        tls_version_score=round(tls_score, 1),
        cipher_quality_score=round(cip_score, 1),
        certificate_strength_score=round(cert_score, 1),
        key_exchange_score=round(kex_score, 1),
        grade=grade,
        summary=summary,
        migration_urgency=urgency,
    )
