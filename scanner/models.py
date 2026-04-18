"""
Q-Secure | Quantum-Proof Systems Scanner
models.py — Core dataclasses. This is the contract everything else follows.
Phase 2: Extended with 7 new scan surface models.
Team Cyber Sentinels | NFSU Gandhinagar
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ScanStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED  = "FAILED"
    PARTIAL = "PARTIAL"


class QuantumLabel(str, Enum):
    QUANTUM_SAFE     = "QUANTUM_SAFE"       # PQC algorithms in use
    PQC_READY        = "PQC_READY"          # Classical-safe, migration path clear
    NOT_QUANTUM_SAFE = "NOT_QUANTUM_SAFE"   # Vulnerable to Shor/Grover


class QuantumTier(str, Enum):
    ELITE_PQC = "ELITE_PQC"   # 90-100
    STANDARD  = "STANDARD"    # 60-89
    LEGACY    = "LEGACY"      # 30-59
    CRITICAL  = "CRITICAL"    # 0-29


class QuantumRiskLevel(str, Enum):
    NONE     = "NONE"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class Severity(str, Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class TLSVersion(str, Enum):
    SSL_2  = "SSLv2"
    SSL_3  = "SSLv3"
    TLS_10 = "TLSv1.0"
    TLS_11 = "TLSv1.1"
    TLS_12 = "TLSv1.2"
    TLS_13 = "TLSv1.3"


class CBOMComponentType(str, Enum):
    ALGORITHM   = "algorithm"
    KEY         = "key"
    CERTIFICATE = "certificate"
    PROTOCOL    = "protocol"


class MigrationPriority(str, Enum):
    IMMEDIATE = "IMMEDIATE"   # Must fix now
    HIGH      = "HIGH"        # Fix this quarter
    MEDIUM    = "MEDIUM"      # Planned migration
    LOW       = "LOW"         # Monitor, defer
    NONE      = "NONE"        # Already compliant


class AttackSurfaceRating(str, Enum):
    MINIMAL  = "MINIMAL"
    MODERATE = "MODERATE"
    LARGE    = "LARGE"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Core scan-target descriptor
# ---------------------------------------------------------------------------

@dataclass
class ScanTarget:
    hostname: str
    port: int = 443
    label: Optional[str] = None                 # Human-readable name e.g. "PNB Netbanking"
    tags: list[str] = field(default_factory=list)  # e.g. ["payment", "critical"]


# ---------------------------------------------------------------------------
# TLS results
# ---------------------------------------------------------------------------

@dataclass
class TLSVersionResult:
    version: TLSVersion
    supported: bool
    is_deprecated: bool                          # TLS < 1.2 is deprecated
    is_insecure: bool                            # SSLv2/3 + TLS 1.0/1.1
    notes: str = ""


@dataclass
class CipherDetail:
    iana_name: str                               # e.g. TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    openssl_name: str = ""                       # e.g. ECDHE-RSA-AES256-GCM-SHA384
    key_exchange: str = ""                       # e.g. ECDHE, RSA, DHE
    authentication: str = ""                     # e.g. RSA, ECDSA
    encryption: str = ""                         # e.g. AES-256-GCM
    mac: str = ""                                # e.g. SHA384
    key_size: int = 0                            # bits
    is_forward_secret: bool = False
    is_quantum_vulnerable: bool = True           # True for RSA/DH key exchange
    quantum_risk: QuantumRiskLevel = QuantumRiskLevel.HIGH
    tls_version: TLSVersion = TLSVersion.TLS_12


@dataclass
class KeyExchangeAssessment:
    algorithm: str                               # e.g. ECDHE, RSA, ML-KEM-768
    key_size: int                                # bits
    is_post_quantum: bool = False
    quantum_risk: QuantumRiskLevel = QuantumRiskLevel.HIGH
    nist_standard: Optional[str] = None          # e.g. FIPS-203
    notes: str = ""


# ---------------------------------------------------------------------------
# Certificate information
# ---------------------------------------------------------------------------

@dataclass
class CertificateInfo:
    subject_cn: str
    subject_o: str = ""
    subject_c: str = ""
    issuer_cn: str = ""
    issuer_o: str = ""
    serial_number: str = ""
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    is_expired: bool = False
    is_self_signed: bool = False
    signature_algorithm: str = ""               # e.g. sha256WithRSAEncryption
    public_key_algorithm: str = ""              # e.g. RSA, EC, ML-DSA
    public_key_size: int = 0                    # bits
    san_entries: list[str] = field(default_factory=list)
    chain_valid: bool = False
    fingerprint_sha256: str = ""
    is_quantum_safe_cert: bool = False          # True if PQC key/sig algorithm
    quantum_risk: QuantumRiskLevel = QuantumRiskLevel.HIGH
    nist_standard: Optional[str] = None         # applicable FIPS standard


# ---------------------------------------------------------------------------
# Vulnerability finding
# ---------------------------------------------------------------------------

@dataclass
class VulnerabilityFinding:
    id: str                                     # e.g. QS-001
    title: str
    severity: Severity
    description: str
    affected_component: str                     # e.g. "TLS cipher suite", "certificate key"
    quantum_relevant: bool = True
    recommendation: str = ""
    cve_references: list[str] = field(default_factory=list)
    nist_references: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Quantum safety score
# ---------------------------------------------------------------------------

@dataclass
class QuantumSafetyScore:
    overall_score: float                        # 0-100
    label: QuantumLabel
    tier: QuantumTier
    cyber_rating: float                         # 0-1000

    # Sub-scores (0-100 each)
    tls_version_score: float = 0.0             # weight 20%
    cipher_quality_score: float = 0.0          # weight 25%
    certificate_strength_score: float = 0.0    # weight 25%
    key_exchange_score: float = 0.0            # weight 30%

    grade: str = "F"                            # A+ / A / B / C / D / F
    summary: str = ""
    migration_urgency: MigrationPriority = MigrationPriority.IMMEDIATE


# ---------------------------------------------------------------------------
# CBOM entry
# ---------------------------------------------------------------------------

@dataclass
class CBOMEntry:
    entry_id: str                               # e.g. CBOM-001
    component_type: CBOMComponentType
    name: str                                   # Algorithm/protocol name
    version: str = ""
    key_size: int = 0
    quantum_risk: QuantumRiskLevel = QuantumRiskLevel.HIGH
    migration_priority: MigrationPriority = MigrationPriority.HIGH
    recommended_replacement: str = ""
    nist_fips_standard: Optional[str] = None    # e.g. FIPS-203
    cert_in_compliant: bool = False
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "component_type": self.component_type.value,
            "name": self.name,
            "version": self.version,
            "key_size": self.key_size,
            "quantum_risk": self.quantum_risk.value,
            "migration_priority": self.migration_priority.value,
            "recommended_replacement": self.recommended_replacement,
            "nist_fips_standard": self.nist_fips_standard,
            "cert_in_compliant": self.cert_in_compliant,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Phase 2 — SSH scan result
# ---------------------------------------------------------------------------

@dataclass
class SSHAlgorithmInfo:
    name: str
    quantum_risk: QuantumRiskLevel
    notes: str = ""


@dataclass
class SSHScanResult:
    host_key_algorithms: list[SSHAlgorithmInfo] = field(default_factory=list)
    kex_algorithms: list[SSHAlgorithmInfo] = field(default_factory=list)
    encryption_algorithms: list[str] = field(default_factory=list)
    server_banner: str = ""
    overall_risk: QuantumRiskLevel = QuantumRiskLevel.HIGH
    notes: str = ""
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "host_key_algorithms": [
                {"name": a.name, "quantum_risk": a.quantum_risk.value, "notes": a.notes}
                for a in self.host_key_algorithms
            ],
            "kex_algorithms": [
                {"name": a.name, "quantum_risk": a.quantum_risk.value, "notes": a.notes}
                for a in self.kex_algorithms
            ],
            "encryption_algorithms": self.encryption_algorithms,
            "server_banner": self.server_banner,
            "overall_risk": self.overall_risk.value,
            "notes": self.notes,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Phase 2 — DNSSEC result
# ---------------------------------------------------------------------------

@dataclass
class DNSSECResult:
    enabled: bool = False
    chain_valid: bool = False
    dnskey_algorithm: str = ""                  # e.g. RSA/SHA-256, Ed448
    dnskey_algorithm_safe: bool = False         # Ed448 = safe, RSA = not
    ds_record_found: bool = False
    rrsig_found: bool = False
    quantum_risk: QuantumRiskLevel = QuantumRiskLevel.HIGH
    notes: str = ""
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "chain_valid": self.chain_valid,
            "dnskey_algorithm": self.dnskey_algorithm,
            "dnskey_algorithm_safe": self.dnskey_algorithm_safe,
            "ds_record_found": self.ds_record_found,
            "rrsig_found": self.rrsig_found,
            "quantum_risk": self.quantum_risk.value,
            "notes": self.notes,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Phase 2 — HTTP security headers result
# ---------------------------------------------------------------------------

@dataclass
class HeaderCheck:
    header_name: str
    present: bool
    value: str = ""
    notes: str = ""
    severity_if_missing: Severity = Severity.MEDIUM


@dataclass
class HeadersScanResult:
    headers_checked: list[HeaderCheck] = field(default_factory=list)
    security_score: int = 0                     # 0-100
    hsts_enabled: bool = False
    hsts_max_age: int = 0
    hsts_preload: bool = False
    csp_present: bool = False
    x_frame_options: str = ""
    x_content_type_options: bool = False
    hpkp_present: bool = False
    referrer_policy: str = ""
    permissions_policy: bool = False
    notes: str = ""
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "headers_checked": [
                {
                    "header_name": h.header_name,
                    "present": h.present,
                    "value": h.value,
                    "notes": h.notes,
                    "severity_if_missing": h.severity_if_missing.value,
                }
                for h in self.headers_checked
            ],
            "security_score": self.security_score,
            "hsts_enabled": self.hsts_enabled,
            "hsts_max_age": self.hsts_max_age,
            "hsts_preload": self.hsts_preload,
            "csp_present": self.csp_present,
            "x_frame_options": self.x_frame_options,
            "x_content_type_options": self.x_content_type_options,
            "hpkp_present": self.hpkp_present,
            "referrer_policy": self.referrer_policy,
            "permissions_policy": self.permissions_policy,
            "notes": self.notes,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Phase 2 — CT log result
# ---------------------------------------------------------------------------

@dataclass
class CTCertEntry:
    issuer_cn: str
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    is_recent: bool = False                     # Issued in last 30 days
    is_unexpected_ca: bool = False
    serial_number: str = ""
    san_entries: list[str] = field(default_factory=list)


@dataclass
class CTLogResult:
    total_certs_found: int = 0
    cert_history: list[CTCertEntry] = field(default_factory=list)
    unexpected_cas: list[str] = field(default_factory=list)
    recent_certs_count: int = 0                 # Issued in last 30 days
    flagged: bool = False
    flag_reason: str = ""
    notes: str = ""
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "total_certs_found": self.total_certs_found,
            "cert_history": [
                {
                    "issuer_cn": c.issuer_cn,
                    "not_before": c.not_before,
                    "not_after": c.not_after,
                    "is_recent": c.is_recent,
                    "is_unexpected_ca": c.is_unexpected_ca,
                    "serial_number": c.serial_number,
                    "san_entries": c.san_entries,
                }
                for c in self.cert_history
            ],
            "unexpected_cas": self.unexpected_cas,
            "recent_certs_count": self.recent_certs_count,
            "flagged": self.flagged,
            "flag_reason": self.flag_reason,
            "notes": self.notes,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Phase 2 — JWT detection result
# ---------------------------------------------------------------------------

@dataclass
class JWTFinding:
    source: str                                 # e.g. "Authorization header", "cookie", "body"
    algorithm: str                              # e.g. RS256, ES256, HS256, EdDSA
    quantum_risk: QuantumRiskLevel
    notes: str = ""


@dataclass
class JWTScanResult:
    jwts_found: list[JWTFinding] = field(default_factory=list)
    overall_risk: QuantumRiskLevel = QuantumRiskLevel.NONE
    notes: str = ""
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "jwts_found": [
                {
                    "source": j.source,
                    "algorithm": j.algorithm,
                    "quantum_risk": j.quantum_risk.value,
                    "notes": j.notes,
                }
                for j in self.jwts_found
            ],
            "overall_risk": self.overall_risk.value,
            "notes": self.notes,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Phase 2 — QUIC/HTTP3 detection result
# ---------------------------------------------------------------------------

@dataclass
class QUICResult:
    h3_advertised: bool = False                 # Alt-Svc: h3 header present
    quic_detected_udp: bool = False             # UDP port 443 probe succeeded
    alt_svc_value: str = ""
    versions_advertised: list[str] = field(default_factory=list)
    flagged: bool = False                       # Flagged if TLS scan may have missed this surface
    notes: str = ""
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "h3_advertised": self.h3_advertised,
            "quic_detected_udp": self.quic_detected_udp,
            "alt_svc_value": self.alt_svc_value,
            "versions_advertised": self.versions_advertised,
            "flagged": self.flagged,
            "notes": self.notes,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Phase 2 — Subdomain enumeration result
# ---------------------------------------------------------------------------

@dataclass
class SubdomainResult:
    subdomain: str
    root_domain: str = ""
    ip_address: Optional[str] = None
    record_type: str = "UNKNOWN"
    is_live: bool = False
    tls_weak: bool = False
    tls_version: Optional[str] = None
    source: str = "dns"                         # "crt.sh" or "dns"
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "subdomain": self.subdomain,
            "root_domain": self.root_domain,
            "ip_address": self.ip_address,
            "record_type": self.record_type,
            "is_live": self.is_live,
            "tls_weak": self.tls_weak,
            "tls_version": self.tls_version,
            "source": self.source,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Top-level scan result (Phase 2 extended)
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    target: ScanTarget
    scan_status: ScanStatus
    scan_timestamp: datetime = field(default_factory=datetime.utcnow)
    scan_duration_seconds: float = 0.0
    error_message: Optional[str] = None

    # TLS data
    tls_versions: list[TLSVersionResult] = field(default_factory=list)
    negotiated_tls_version: Optional[TLSVersion] = None
    ciphers: list[CipherDetail] = field(default_factory=list)
    preferred_cipher: Optional[CipherDetail] = None

    # Certificate data
    certificate: Optional[CertificateInfo] = None

    # Key exchange
    key_exchange: Optional[KeyExchangeAssessment] = None

    # Assessment outputs
    quantum_score: Optional[QuantumSafetyScore] = None
    vulnerabilities: list[VulnerabilityFinding] = field(default_factory=list)
    cbom: list[CBOMEntry] = field(default_factory=list)

    # Phase 2 — Extended scan surfaces
    ssh_result: Optional[SSHScanResult] = None
    dnssec_result: Optional[DNSSECResult] = None
    headers_result: Optional[HeadersScanResult] = None
    ct_log_result: Optional[CTLogResult] = None
    jwt_result: Optional[JWTScanResult] = None
    quic_result: Optional[QUICResult] = None
    subdomains: list[SubdomainResult] = field(default_factory=list)

    # Phase 2 — Extended scoring
    extended_risk_score: float = 0.0
    attack_surface_rating: str = ""             # MINIMAL / MODERATE / LARGE / CRITICAL

    # Metadata
    is_mock: bool = False
    scanner_version: str = "2.0.0"

    def to_dict(self) -> dict:
        """Return a fully JSON-serialisable representation."""
        def _dt(d) -> Optional[str]:
            return d.isoformat() if d else None

        return {
            "target": {
                "hostname": self.target.hostname,
                "port": self.target.port,
                "label": self.target.label,
                "tags": self.target.tags,
            },
            "scan_status": self.scan_status.value,
            "scan_timestamp": _dt(self.scan_timestamp),
            "scan_duration_seconds": self.scan_duration_seconds,
            "error_message": self.error_message,
            "negotiated_tls_version": self.negotiated_tls_version.value if self.negotiated_tls_version else None,
            "tls_versions": [
                {
                    "version": v.version.value,
                    "supported": v.supported,
                    "is_deprecated": v.is_deprecated,
                    "is_insecure": v.is_insecure,
                    "notes": v.notes,
                }
                for v in self.tls_versions
            ],
            "ciphers": [
                {
                    "iana_name": c.iana_name,
                    "key_exchange": c.key_exchange,
                    "authentication": c.authentication,
                    "encryption": c.encryption,
                    "mac": c.mac,
                    "is_forward_secret": c.is_forward_secret,
                    "is_quantum_vulnerable": c.is_quantum_vulnerable,
                    "quantum_risk": c.quantum_risk.value,
                }
                for c in self.ciphers
            ],
            "certificate": (
                {
                    "subject_cn": self.certificate.subject_cn,
                    "issuer_cn": self.certificate.issuer_cn,
                    "not_before": _dt(self.certificate.not_before),
                    "not_after": _dt(self.certificate.not_after),
                    "is_expired": self.certificate.is_expired,
                    "is_self_signed": self.certificate.is_self_signed,
                    "signature_algorithm": self.certificate.signature_algorithm,
                    "public_key_algorithm": self.certificate.public_key_algorithm,
                    "public_key_size": self.certificate.public_key_size,
                    "san_entries": self.certificate.san_entries,
                    "chain_valid": self.certificate.chain_valid,
                    "fingerprint_sha256": self.certificate.fingerprint_sha256,
                    "is_quantum_safe_cert": self.certificate.is_quantum_safe_cert,
                    "quantum_risk": self.certificate.quantum_risk.value,
                    "nist_standard": self.certificate.nist_standard,
                }
                if self.certificate else None
            ),
            "key_exchange": (
                {
                    "algorithm": self.key_exchange.algorithm,
                    "key_size": self.key_exchange.key_size,
                    "is_post_quantum": self.key_exchange.is_post_quantum,
                    "quantum_risk": self.key_exchange.quantum_risk.value,
                    "nist_standard": self.key_exchange.nist_standard,
                    "notes": self.key_exchange.notes,
                }
                if self.key_exchange else None
            ),
            "quantum_score": (
                {
                    "overall_score": self.quantum_score.overall_score,
                    "label": self.quantum_score.label.value,
                    "tier": self.quantum_score.tier.value,
                    "cyber_rating": self.quantum_score.cyber_rating,
                    "tls_version_score": self.quantum_score.tls_version_score,
                    "cipher_quality_score": self.quantum_score.cipher_quality_score,
                    "certificate_strength_score": self.quantum_score.certificate_strength_score,
                    "key_exchange_score": self.quantum_score.key_exchange_score,
                    "grade": self.quantum_score.grade,
                    "summary": self.quantum_score.summary,
                    "migration_urgency": self.quantum_score.migration_urgency.value,
                }
                if self.quantum_score else None
            ),
            "vulnerabilities": [
                {
                    "id": v.id,
                    "title": v.title,
                    "severity": v.severity.value,
                    "description": v.description,
                    "affected_component": v.affected_component,
                    "quantum_relevant": v.quantum_relevant,
                    "recommendation": v.recommendation,
                    "cve_references": v.cve_references,
                    "nist_references": v.nist_references,
                }
                for v in self.vulnerabilities
            ],
            "cbom": [e.to_dict() for e in self.cbom],
            # Phase 2 surfaces
            "ssh_result": self.ssh_result.to_dict() if self.ssh_result else None,
            "dnssec_result": self.dnssec_result.to_dict() if self.dnssec_result else None,
            "headers_result": self.headers_result.to_dict() if self.headers_result else None,
            "ct_log_result": self.ct_log_result.to_dict() if self.ct_log_result else None,
            "jwt_result": self.jwt_result.to_dict() if self.jwt_result else None,
            "quic_result": self.quic_result.to_dict() if self.quic_result else None,
            "subdomains": [s.to_dict() for s in self.subdomains],
            "extended_risk_score": self.extended_risk_score,
            "attack_surface_rating": self.attack_surface_rating,
            "is_mock": self.is_mock,
            "scanner_version": self.scanner_version,
        }
