"""
Q-Secure | mock_data.py  (Phase 2 Extended)
Five realistic mock profiles — all 8 scan surfaces populated.
"""

from __future__ import annotations
from datetime import datetime, timezone, timedelta
from typing import Optional

from .models import (
    CBOMComponentType, CBOMEntry, CertificateInfo, CipherDetail,
    CTCertEntry, CTLogResult, DNSSECResult, HeaderCheck, HeadersScanResult,
    JWTFinding, JWTScanResult, KeyExchangeAssessment, MigrationPriority,
    QuantumLabel, QuantumRiskLevel, QuantumSafetyScore, QuantumTier,
    QUICResult, ScanResult, ScanStatus, ScanTarget, Severity,
    SSHAlgorithmInfo, SSHScanResult, SubdomainResult, TLSVersion,
    TLSVersionResult, VulnerabilityFinding,
)
from .cbom_generator import generate_cbom
from .quantum_assessor import compute_quantum_score, detect_vulnerabilities

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dt(year, month, day) -> datetime:
    return datetime(year, month, day, tzinfo=timezone.utc)

def _make_tlsv(version: TLSVersion, supported: bool) -> TLSVersionResult:
    _meta = {
        TLSVersion.SSL_2:  (True, True), TLSVersion.SSL_3:  (True, True),
        TLSVersion.TLS_10: (True, True), TLSVersion.TLS_11: (True, True),
        TLSVersion.TLS_12: (False, False), TLSVersion.TLS_13: (False, False),
    }
    dep, ins = _meta[version]
    note = "Deprecated — migrate to TLS 1.3" if (supported and dep) else ""
    return TLSVersionResult(version=version, supported=supported,
                            is_deprecated=dep, is_insecure=ins, notes=note)

def _cipher(iana, kex, auth, enc, mac, fs, q_vuln, risk,
            tls_ver=TLSVersion.TLS_12, key_size=256) -> CipherDetail:
    return CipherDetail(
        iana_name=iana, openssl_name=iana.replace("TLS_","").replace("_","-"),
        key_exchange=kex, authentication=auth, encryption=enc, mac=mac,
        key_size=key_size, is_forward_secret=fs,
        is_quantum_vulnerable=q_vuln, quantum_risk=risk, tls_version=tls_ver,
    )

def _ssh_algo(name, risk, notes="") -> SSHAlgorithmInfo:
    return SSHAlgorithmInfo(name=name, quantum_risk=risk, notes=notes)

def _header_check(name, present, value="", notes="", sev=Severity.MEDIUM) -> HeaderCheck:
    return HeaderCheck(header_name=name, present=present, value=value,
                       notes=notes, severity_if_missing=sev)

def _ct_entry(issuer, not_before, not_after, recent=False,
              unexpected=False, serial="", sans=None) -> CTCertEntry:
    return CTCertEntry(
        issuer_cn=issuer, not_before=not_before, not_after=not_after,
        is_recent=recent, is_unexpected_ca=unexpected,
        serial_number=serial, san_entries=sans or [],
    )

def _compute_attack_surface(r: ScanResult) -> tuple[float, str]:
    """Compute extended_risk_score and attack_surface_rating."""
    score = r.quantum_score.overall_score if r.quantum_score else 50.0
    penalty = 0.0
    if r.ssh_result and r.ssh_result.overall_risk == QuantumRiskLevel.CRITICAL:
        penalty += 15
    if r.dnssec_result and not r.dnssec_result.enabled:
        penalty += 10
    if r.headers_result and r.headers_result.security_score < 50:
        penalty += 10
    if r.ct_log_result and r.ct_log_result.flagged:
        penalty += 8
    if r.jwt_result and r.jwt_result.overall_risk == QuantumRiskLevel.CRITICAL:
        penalty += 12
    if r.quic_result and r.quic_result.flagged:
        penalty += 5
    extended = max(0.0, score - penalty)
    if extended >= 80:   rating = "MINIMAL"
    elif extended >= 55: rating = "MODERATE"
    elif extended >= 30: rating = "LARGE"
    else:                rating = "CRITICAL"
    return round(extended, 1), rating


# ---------------------------------------------------------------------------
# Profile 1 — pnbindia.in
# ---------------------------------------------------------------------------

def _mock_pnbindia_in() -> ScanResult:
    target = ScanTarget(hostname="pnbindia.in", port=443,
                        label="PNB Corporate Website", tags=["public","corporate","web"])

    tls_versions = [
        _make_tlsv(TLSVersion.TLS_13, False), _make_tlsv(TLSVersion.TLS_12, True),
        _make_tlsv(TLSVersion.TLS_11, False), _make_tlsv(TLSVersion.TLS_10, True),
    ]
    ciphers = [
        _cipher("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","ECDHE","RSA","AES-256-GCM","SHA384",True,True,QuantumRiskLevel.HIGH),
        _cipher("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","ECDHE","RSA","AES-128-GCM","SHA256",True,True,QuantumRiskLevel.HIGH),
        _cipher("TLS_RSA_WITH_AES_256_CBC_SHA256","RSA","RSA","AES-256-CBC","SHA256",False,True,QuantumRiskLevel.CRITICAL),
    ]
    cert = CertificateInfo(
        subject_cn="pnbindia.in", subject_o="Punjab National Bank", subject_c="IN",
        issuer_cn="DigiCert TLS RSA SHA256 2020 CA1", issuer_o="DigiCert Inc",
        serial_number="0A:BC:12:EF:34:56", not_before=_dt(2025,4,1), not_after=_dt(2027,4,1),
        is_expired=False, is_self_signed=False, signature_algorithm="sha256WithRSAEncryption",
        public_key_algorithm="RSA", public_key_size=2048, san_entries=["pnbindia.in","www.pnbindia.in"],
        chain_valid=True, fingerprint_sha256="4A:B1:2C:D3:E5:F6:78:90:AB:CD:EF:12:34:56:78:90",
        is_quantum_safe_cert=False, quantum_risk=QuantumRiskLevel.HIGH,
    )
    kex = KeyExchangeAssessment(algorithm="ECDHE", key_size=256, is_post_quantum=False,
                                 quantum_risk=QuantumRiskLevel.HIGH,
                                 notes="Classical ECDHE — vulnerable to Shor's algorithm")

    score = compute_quantum_score(tls_versions, ciphers, cert, kex)
    vulns = detect_vulnerabilities(tls_versions, ciphers, cert, kex)

    # Phase 2 surfaces
    ssh_result = None  # No SSH on corporate website

    dnssec_result = DNSSECResult(
        enabled=False, chain_valid=False, ds_record_found=False, rrsig_found=False,
        quantum_risk=QuantumRiskLevel.HIGH,
        notes="DNSSEC not configured — DNS responses unauthenticated, cache poisoning risk",
    )

    headers_result = HeadersScanResult(
        headers_checked=[
            _header_check("Strict-Transport-Security", True, "max-age=31536000; includeSubDomains",
                          sev=Severity.HIGH),
            _header_check("Content-Security-Policy", True, "default-src 'self'; script-src 'self' 'unsafe-inline'",
                          sev=Severity.HIGH),
            _header_check("X-Frame-Options", True, "SAMEORIGIN"),
            _header_check("X-Content-Type-Options", True, "nosniff"),
            _header_check("Referrer-Policy", True, "strict-origin-when-cross-origin"),
            _header_check("Permissions-Policy", False, notes="Permissions-Policy header not set", sev=Severity.LOW),
            _header_check("X-XSS-Protection", True, "1; mode=block"),
            _header_check("Public-Key-Pins", False, notes="HPKP absent (deprecated)", sev=Severity.LOW),
            _header_check("Cross-Origin-Opener-Policy", False, notes="COOP not set", sev=Severity.LOW),
        ],
        security_score=70, hsts_enabled=True, hsts_max_age=31536000, hsts_preload=False,
        csp_present=True, x_frame_options="SAMEORIGIN", x_content_type_options=True,
        referrer_policy="strict-origin-when-cross-origin",
        notes="Good headers but HSTS preload missing — not in HSTS preload list",
    )

    ct_log_result = CTLogResult(
        total_certs_found=3,
        cert_history=[
            _ct_entry("DigiCert TLS RSA SHA256 2020 CA1","2025-04-01","2027-04-01",serial="0A:BC:12:EF",sans=["pnbindia.in","www.pnbindia.in"]),
            _ct_entry("DigiCert TLS RSA SHA256 2020 CA1","2023-04-01","2025-04-01",serial="0A:BC:11:AB",sans=["pnbindia.in"]),
            _ct_entry("DigiCert TLS RSA SHA256 2020 CA1","2021-04-01","2023-04-01",serial="0A:BC:10:CD",sans=["pnbindia.in"]),
        ],
        unexpected_cas=[], recent_certs_count=0, flagged=False,
        notes="3 certificates found, all issued by DigiCert — clean CT log history",
    )

    jwt_result = JWTScanResult(
        jwts_found=[], overall_risk=QuantumRiskLevel.NONE,
        notes="No JWTs detected on corporate homepage",
    )

    quic_result = QUICResult(
        h3_advertised=False, quic_detected_udp=False,
        notes="No QUIC/HTTP3 detected — standard TCP TLS only",
    )

    subdomains = [
        SubdomainResult("www.pnbindia.in","203.160.80.12",True,False,"TLSv1.2","dns","TLS 1.2 (weak — no 1.3)"),
        SubdomainResult("mail.pnbindia.in","203.160.80.20",True,True,"TLSv1.1","dns","Weak TLS 1.1 detected"),
        SubdomainResult("portal.pnbindia.in","203.160.80.45",True,False,"TLSv1.3","crt.sh","TLSv1.3"),
    ]

    result = ScanResult(
        target=target, scan_status=ScanStatus.SUCCESS,
        scan_timestamp=datetime.now(timezone.utc), scan_duration_seconds=2.41,
        tls_versions=tls_versions, negotiated_tls_version=TLSVersion.TLS_12,
        ciphers=ciphers, preferred_cipher=ciphers[0], certificate=cert,
        key_exchange=kex, quantum_score=score, vulnerabilities=vulns, is_mock=True,
        ssh_result=ssh_result, dnssec_result=dnssec_result,
        headers_result=headers_result, ct_log_result=ct_log_result,
        jwt_result=jwt_result, quic_result=quic_result, subdomains=subdomains,
    )
    result.cbom = generate_cbom(result)
    result.extended_risk_score, result.attack_surface_rating = _compute_attack_surface(result)
    return result


# ---------------------------------------------------------------------------
# Profile 2 — netbanking.pnbindia.in
# ---------------------------------------------------------------------------

def _mock_netbanking_pnbindia_in() -> ScanResult:
    target = ScanTarget(hostname="netbanking.pnbindia.in", port=443,
                        label="PNB Net Banking Portal",
                        tags=["payment","critical","banking","customer-facing"])

    tls_versions = [
        _make_tlsv(TLSVersion.TLS_13, False), _make_tlsv(TLSVersion.TLS_12, True),
        _make_tlsv(TLSVersion.TLS_11, True),  _make_tlsv(TLSVersion.TLS_10, True),
    ]
    ciphers = [
        _cipher("TLS_RSA_WITH_RC4_128_SHA","RSA","RSA","RC4-128","SHA1",False,True,QuantumRiskLevel.CRITICAL),
        _cipher("TLS_RSA_WITH_AES_128_CBC_SHA","RSA","RSA","AES-128-CBC","SHA1",False,True,QuantumRiskLevel.CRITICAL),
        _cipher("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","ECDHE","RSA","AES-128-GCM","SHA256",True,True,QuantumRiskLevel.HIGH),
    ]
    cert = CertificateInfo(
        subject_cn="netbanking.pnbindia.in", subject_o="Punjab National Bank", subject_c="IN",
        issuer_cn="Comodo RSA Certification Authority", issuer_o="Comodo CA Limited",
        serial_number="0F:A1:B2:C3:D4:E5", not_before=_dt(2021,1,15), not_after=_dt(2024,1,15),
        is_expired=True, is_self_signed=False, signature_algorithm="sha1WithRSAEncryption",
        public_key_algorithm="RSA", public_key_size=1024,
        san_entries=["netbanking.pnbindia.in"], chain_valid=True,
        fingerprint_sha256="FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00",
        is_quantum_safe_cert=False, quantum_risk=QuantumRiskLevel.CRITICAL,
    )
    kex = KeyExchangeAssessment(algorithm="RSA", key_size=1024, is_post_quantum=False,
                                 quantum_risk=QuantumRiskLevel.CRITICAL,
                                 notes="RSA-1024: classically weak + trivially quantum-broken")

    score = compute_quantum_score(tls_versions, ciphers, cert, kex)
    vulns = detect_vulnerabilities(tls_versions, ciphers, cert, kex)

    ssh_result = SSHScanResult(
        host_key_algorithms=[
            _ssh_algo("ssh-rsa", QuantumRiskLevel.CRITICAL, "RSA host key — broken by Shor's algorithm"),
            _ssh_algo("rsa-sha2-256", QuantumRiskLevel.CRITICAL, "Still RSA underneath"),
        ],
        kex_algorithms=[
            _ssh_algo("diffie-hellman-group14-sha256", QuantumRiskLevel.HIGH, "DH-2048 — quantum-vulnerable"),
            _ssh_algo("diffie-hellman-group1-sha1", QuantumRiskLevel.CRITICAL, "DH-1024 — Logjam-vulnerable"),
        ],
        encryption_algorithms=["aes128-ctr","aes192-ctr","aes256-ctr"],
        server_banner="SSH-2.0-OpenSSH_7.4",
        overall_risk=QuantumRiskLevel.CRITICAL,
        notes="Legacy OpenSSH 7.4 with only RSA host keys — CRITICAL quantum exposure",
    )

    dnssec_result = DNSSECResult(
        enabled=False, quantum_risk=QuantumRiskLevel.HIGH,
        notes="DNSSEC absent on critical banking subdomain — HIGH risk",
    )

    headers_result = HeadersScanResult(
        headers_checked=[
            _header_check("Strict-Transport-Security", True, "max-age=31536000", sev=Severity.HIGH),
            _header_check("Content-Security-Policy", True, "default-src 'self'", sev=Severity.HIGH),
            _header_check("X-Frame-Options", True, "DENY"),
            _header_check("X-Content-Type-Options", True, "nosniff"),
            _header_check("Referrer-Policy", False, notes="Missing", sev=Severity.LOW),
            _header_check("Permissions-Policy", False, notes="Missing", sev=Severity.LOW),
            _header_check("X-XSS-Protection", True, "1; mode=block"),
            _header_check("Public-Key-Pins", False, notes="HPKP absent", sev=Severity.LOW),
            _header_check("Cross-Origin-Opener-Policy", False, notes="Missing", sev=Severity.LOW),
        ],
        security_score=60, hsts_enabled=True, hsts_max_age=31536000, hsts_preload=False,
        csp_present=True, x_frame_options="DENY", x_content_type_options=True,
        notes="Basic headers present but missing several best-practice headers",
    )

    ct_log_result = CTLogResult(
        total_certs_found=4,
        cert_history=[
            _ct_entry("Comodo RSA Certification Authority","2021-01-15","2024-01-15",serial="0F:A1:B2",sans=["netbanking.pnbindia.in"]),
            _ct_entry("Let's Encrypt Authority X3","2024-11-01","2025-01-30",recent=True,unexpected=True,serial="LE:24:AB",sans=["netbanking.pnbindia.in"]),
            _ct_entry("Comodo RSA Certification Authority","2019-01-15","2021-01-15",serial="0E:A1:B2",sans=["netbanking.pnbindia.in"]),
            _ct_entry("DigiCert TLS RSA SHA256 2020 CA1","2024-12-15","2025-12-15",recent=True,unexpected=False,serial="DB:24:CC",sans=["netbanking.pnbindia.in"]),
        ],
        unexpected_cas=["Let's Encrypt Authority X3"],
        recent_certs_count=2, flagged=True,
        flag_reason="Unexpected CA: Let's Encrypt (unusual for banking). 2 certs issued in last 30 days.",
        notes="Flagged: unexpected CA and multiple recent issuances indicate possible mis-issuance",
    )

    jwt_result = JWTScanResult(
        jwts_found=[
            JWTFinding(source="Response header: Set-Cookie", algorithm="RS256",
                       quantum_risk=QuantumRiskLevel.CRITICAL,
                       notes="RSA-2048 JWT signature — broken by Shor's algorithm"),
        ],
        overall_risk=QuantumRiskLevel.CRITICAL,
        notes="CRITICAL: Banking session tokens use RS256 (RSA) — quantum-vulnerable",
    )

    quic_result = QUICResult(
        h3_advertised=False, quic_detected_udp=False,
        notes="No QUIC detected — TLS-only",
    )

    subdomains = [
        SubdomainResult("www.pnbindia.in","203.160.80.12",True,False,"TLSv1.2","dns","Parent domain"),
    ]

    result = ScanResult(
        target=target, scan_status=ScanStatus.SUCCESS,
        scan_timestamp=datetime.now(timezone.utc), scan_duration_seconds=3.18,
        tls_versions=tls_versions, negotiated_tls_version=TLSVersion.TLS_12,
        ciphers=ciphers, preferred_cipher=ciphers[0], certificate=cert,
        key_exchange=kex, quantum_score=score, vulnerabilities=vulns, is_mock=True,
        ssh_result=ssh_result, dnssec_result=dnssec_result,
        headers_result=headers_result, ct_log_result=ct_log_result,
        jwt_result=jwt_result, quic_result=quic_result, subdomains=subdomains,
    )
    result.cbom = generate_cbom(result)
    result.extended_risk_score, result.attack_surface_rating = _compute_attack_surface(result)
    return result


# ---------------------------------------------------------------------------
# Profile 3 — api.pnbindia.in
# ---------------------------------------------------------------------------

def _mock_api_pnbindia_in() -> ScanResult:
    target = ScanTarget(hostname="api.pnbindia.in", port=443,
                        label="PNB API Gateway", tags=["api","internal","microservices"])

    tls_versions = [
        _make_tlsv(TLSVersion.TLS_13, True), _make_tlsv(TLSVersion.TLS_12, False),
        _make_tlsv(TLSVersion.TLS_11, False), _make_tlsv(TLSVersion.TLS_10, False),
    ]
    ciphers = [
        _cipher("TLS_AES_256_GCM_SHA384","TLS1.3-ECDHE","ECDSA","AES-256-GCM","SHA384",True,True,QuantumRiskLevel.MEDIUM,TLSVersion.TLS_13),
        _cipher("TLS_CHACHA20_POLY1305_SHA256","TLS1.3-ECDHE","ECDSA","CHACHA20-POLY1305","SHA256",True,True,QuantumRiskLevel.MEDIUM,TLSVersion.TLS_13),
    ]
    cert = CertificateInfo(
        subject_cn="api.pnbindia.in", subject_o="Punjab National Bank", subject_c="IN",
        issuer_cn="GlobalSign ECC OV SSL CA 2018", issuer_o="GlobalSign nv-sa",
        serial_number="2A:3B:4C:5D:6E:7F", not_before=_dt(2025,4,1), not_after=_dt(2027,4,1),
        is_expired=False, is_self_signed=False, signature_algorithm="ecdsa-with-SHA384",
        public_key_algorithm="EC", public_key_size=384,
        san_entries=["api.pnbindia.in","api-v2.pnbindia.in"], chain_valid=True,
        fingerprint_sha256="1A:2B:3C:4D:5E:6F:70:81:92:A3:B4:C5:D6:E7:F8:09",
        is_quantum_safe_cert=False, quantum_risk=QuantumRiskLevel.MEDIUM,
    )
    kex = KeyExchangeAssessment(algorithm="ECDHE", key_size=384, is_post_quantum=False,
                                 quantum_risk=QuantumRiskLevel.MEDIUM,
                                 notes="ECDHE P-384 — quantum-vulnerable to Shor")

    score = compute_quantum_score(tls_versions, ciphers, cert, kex)
    vulns = detect_vulnerabilities(tls_versions, ciphers, cert, kex)

    ssh_result = SSHScanResult(
        host_key_algorithms=[
            _ssh_algo("ssh-ed25519", QuantumRiskLevel.MEDIUM, "Ed25519 — best classical SSH, quantum-vulnerable"),
            _ssh_algo("ecdsa-sha2-nistp256", QuantumRiskLevel.HIGH, "ECDSA P-256 — Shor-vulnerable fallback"),
        ],
        kex_algorithms=[
            _ssh_algo("curve25519-sha256", QuantumRiskLevel.MEDIUM, "X25519 — quantum-vulnerable"),
            _ssh_algo("diffie-hellman-group16-sha512", QuantumRiskLevel.HIGH, "DH-4096 — quantum-vulnerable"),
        ],
        encryption_algorithms=["chacha20-poly1305@openssh.com","aes256-gcm@openssh.com"],
        server_banner="SSH-2.0-OpenSSH_8.9",
        overall_risk=QuantumRiskLevel.HIGH,
        notes="Modern OpenSSH but no PQC KEX — quantum migration needed",
    )

    dnssec_result = DNSSECResult(
        enabled=False, quantum_risk=QuantumRiskLevel.HIGH,
        notes="DNSSEC not enabled on API gateway subdomain",
    )

    headers_result = HeadersScanResult(
        headers_checked=[
            _header_check("Strict-Transport-Security", True, "max-age=63072000; includeSubDomains; preload", sev=Severity.HIGH),
            _header_check("Content-Security-Policy", True, "default-src 'none'; frame-ancestors 'none'", sev=Severity.HIGH),
            _header_check("X-Frame-Options", True, "DENY"),
            _header_check("X-Content-Type-Options", True, "nosniff"),
            _header_check("Referrer-Policy", True, "no-referrer"),
            _header_check("Permissions-Policy", True, "geolocation=(), microphone=()"),
            _header_check("X-XSS-Protection", True, "1; mode=block"),
            _header_check("Public-Key-Pins", False, notes="HPKP absent", sev=Severity.LOW),
            _header_check("Cross-Origin-Opener-Policy", True, "same-origin"),
        ],
        security_score=90, hsts_enabled=True, hsts_max_age=63072000, hsts_preload=True,
        csp_present=True, x_frame_options="DENY", x_content_type_options=True,
        referrer_policy="no-referrer", permissions_policy=True,
        notes="Excellent security headers — HSTS preload enabled",
    )

    ct_log_result = CTLogResult(
        total_certs_found=2,
        cert_history=[
            _ct_entry("GlobalSign ECC OV SSL CA 2018","2025-04-01","2027-04-01",serial="2A:3B:4C",sans=["api.pnbindia.in","api-v2.pnbindia.in"]),
            _ct_entry("GlobalSign ECC OV SSL CA 2018","2023-04-01","2025-04-01",serial="2A:3B:3C",sans=["api.pnbindia.in"]),
        ],
        unexpected_cas=[], recent_certs_count=0, flagged=False,
        notes="Clean CT log — only GlobalSign ECC certificates",
    )

    jwt_result = JWTScanResult(
        jwts_found=[
            JWTFinding(source="Response header: Authorization", algorithm="ES256",
                       quantum_risk=QuantumRiskLevel.HIGH,
                       notes="ECDSA P-256 JWT — broken by Shor's algorithm"),
        ],
        overall_risk=QuantumRiskLevel.HIGH,
        notes="API uses ES256 (ECDSA) JWT tokens — HIGH quantum risk",
    )

    quic_result = QUICResult(
        h3_advertised=True, quic_detected_udp=True,
        alt_svc_value='h3=":443"; ma=86400, h3-29=":443"; ma=86400',
        versions_advertised=["h3","h3-29"], flagged=True,
        notes="HTTP/3 active — QUIC TLS stack is separate attack surface. Standard TCP scan insufficient.",
    )

    subdomains = [
        SubdomainResult("api-v2.pnbindia.in","203.160.80.50",True,False,"TLSv1.3","crt.sh","TLSv1.3"),
        SubdomainResult("app.pnbindia.in","203.160.80.55",True,False,"TLSv1.3","dns","TLSv1.3"),
    ]

    result = ScanResult(
        target=target, scan_status=ScanStatus.SUCCESS,
        scan_timestamp=datetime.now(timezone.utc), scan_duration_seconds=1.67,
        tls_versions=tls_versions, negotiated_tls_version=TLSVersion.TLS_13,
        ciphers=ciphers, preferred_cipher=ciphers[0], certificate=cert,
        key_exchange=kex, quantum_score=score, vulnerabilities=vulns, is_mock=True,
        ssh_result=ssh_result, dnssec_result=dnssec_result,
        headers_result=headers_result, ct_log_result=ct_log_result,
        jwt_result=jwt_result, quic_result=quic_result, subdomains=subdomains,
    )
    result.cbom = generate_cbom(result)
    result.extended_risk_score, result.attack_surface_rating = _compute_attack_surface(result)
    return result


# ---------------------------------------------------------------------------
# Profile 4 — vpn.pnbindia.in
# ---------------------------------------------------------------------------

def _mock_vpn_pnbindia_in() -> ScanResult:
    target = ScanTarget(hostname="vpn.pnbindia.in", port=443,
                        label="PNB Employee VPN Gateway", tags=["vpn","internal","remote-access"])

    tls_versions = [
        _make_tlsv(TLSVersion.TLS_13, False), _make_tlsv(TLSVersion.TLS_12, True),
        _make_tlsv(TLSVersion.TLS_11, True),  _make_tlsv(TLSVersion.TLS_10, True),
    ]
    ciphers = [
        _cipher("TLS_DHE_RSA_WITH_AES_128_CBC_SHA","DHE","RSA","AES-128-CBC","SHA1",True,True,QuantumRiskLevel.HIGH,key_size=1024),
        _cipher("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA","DHE","RSA","3DES-EDE-CBC","SHA1",True,True,QuantumRiskLevel.CRITICAL,key_size=1024),
        _cipher("TLS_RSA_WITH_AES_128_CBC_SHA","RSA","RSA","AES-128-CBC","SHA1",False,True,QuantumRiskLevel.CRITICAL),
    ]
    cert = CertificateInfo(
        subject_cn="vpn.pnbindia.in", subject_o="Punjab National Bank IT Dept", subject_c="IN",
        issuer_cn="vpn.pnbindia.in", issuer_o="Punjab National Bank IT Dept",
        serial_number="01", not_before=_dt(2020,1,1), not_after=_dt(2023,1,1),
        is_expired=True, is_self_signed=True, signature_algorithm="sha256WithRSAEncryption",
        public_key_algorithm="RSA", public_key_size=2048, san_entries=["vpn.pnbindia.in"],
        chain_valid=False, fingerprint_sha256="DE:AD:BE:EF:CA:FE:BA:BE:DE:AD:BE:EF:CA:FE:BA:BE",
        is_quantum_safe_cert=False, quantum_risk=QuantumRiskLevel.HIGH,
    )
    kex = KeyExchangeAssessment(algorithm="DHE", key_size=1024, is_post_quantum=False,
                                 quantum_risk=QuantumRiskLevel.CRITICAL,
                                 notes="DHE-1024: Logjam-vulnerable + trivially quantum-broken")

    score = compute_quantum_score(tls_versions, ciphers, cert, kex)
    vulns = detect_vulnerabilities(tls_versions, ciphers, cert, kex)

    ssh_result = SSHScanResult(
        host_key_algorithms=[
            _ssh_algo("ssh-rsa", QuantumRiskLevel.CRITICAL, "RSA-2048 host key — the only host key type offered"),
        ],
        kex_algorithms=[
            _ssh_algo("diffie-hellman-group1-sha1", QuantumRiskLevel.CRITICAL, "DH-1024 SHA1 — Logjam + quantum-broken"),
            _ssh_algo("diffie-hellman-group14-sha1", QuantumRiskLevel.CRITICAL, "DH-2048 SHA1 — quantum-broken"),
        ],
        encryption_algorithms=["aes128-cbc","3des-cbc","blowfish-cbc"],
        server_banner="SSH-2.0-OpenSSH_6.6",
        overall_risk=QuantumRiskLevel.CRITICAL,
        notes="CRITICAL: Legacy OpenSSH 6.6, only ssh-rsa, CBC-mode ciphers, DH-1024 KEX",
    )

    dnssec_result = DNSSECResult(
        enabled=False, quantum_risk=QuantumRiskLevel.HIGH,
        notes="No DNSSEC — VPN gateway DNS spoofable, enables credential theft",
    )

    headers_result = HeadersScanResult(
        headers_checked=[
            _header_check("Strict-Transport-Security", False, notes="Missing HSTS — HTTPS not enforced", sev=Severity.HIGH),
            _header_check("Content-Security-Policy", False, notes="CSP missing", sev=Severity.HIGH),
            _header_check("X-Frame-Options", True, "SAMEORIGIN"),
            _header_check("X-Content-Type-Options", False, notes="Missing", sev=Severity.MEDIUM),
            _header_check("Referrer-Policy", False, notes="Missing", sev=Severity.LOW),
            _header_check("Permissions-Policy", False, notes="Missing", sev=Severity.LOW),
            _header_check("X-XSS-Protection", False, notes="Missing", sev=Severity.LOW),
            _header_check("Public-Key-Pins", False, notes="HPKP absent", sev=Severity.LOW),
            _header_check("Cross-Origin-Opener-Policy", False, notes="Missing", sev=Severity.LOW),
        ],
        security_score=10, hsts_enabled=False, hsts_max_age=0, hsts_preload=False,
        csp_present=False, x_frame_options="SAMEORIGIN", x_content_type_options=False,
        notes="CRITICAL: VPN gateway has near-zero HTTP security headers",
    )

    ct_log_result = CTLogResult(
        total_certs_found=5,
        cert_history=[
            _ct_entry("vpn.pnbindia.in (self-signed)","2020-01-01","2023-01-01",serial="01",sans=["vpn.pnbindia.in"]),
            _ct_entry("Let's Encrypt Authority X3","2023-05-01","2023-07-30",recent=False,unexpected=True,serial="LE:23:AA",sans=["vpn.pnbindia.in"]),
            _ct_entry("ZeroSSL RSA Domain Secure Site CA","2023-08-01","2023-10-31",recent=False,unexpected=True,serial="ZS:23:BB",sans=["vpn.pnbindia.in"]),
            _ct_entry("Sectigo RSA Domain Validation CA","2024-01-01","2025-01-01",recent=False,unexpected=False,serial="SC:24:CC",sans=["vpn.pnbindia.in"]),
            _ct_entry("Let's Encrypt E5","2024-11-15","2025-02-13",recent=True,unexpected=True,serial="LE:E5:DD",sans=["vpn.pnbindia.in"]),
        ],
        unexpected_cas=["Let's Encrypt Authority X3","ZeroSSL RSA Domain Secure Site CA","Let's Encrypt E5"],
        recent_certs_count=1, flagged=True,
        flag_reason="Multiple unexpected CAs (ZeroSSL, Let's Encrypt) on VPN gateway — possible hijack indicators.",
        notes="FLAGGED: 3 unexpected CAs found in CT log — VPN cert legitimacy questionable",
    )

    jwt_result = JWTScanResult(
        jwts_found=[], overall_risk=QuantumRiskLevel.NONE,
        notes="No JWTs detected (VPN login page pre-auth)",
    )

    quic_result = QUICResult(
        h3_advertised=False, quic_detected_udp=False,
        notes="No QUIC — legacy VPN, TCP only",
    )

    subdomains = [
        SubdomainResult("vpn2.pnbindia.in","203.160.80.61",False,False,None,"dns","DNS resolves but not live"),
    ]

    result = ScanResult(
        target=target, scan_status=ScanStatus.SUCCESS,
        scan_timestamp=datetime.now(timezone.utc), scan_duration_seconds=4.03,
        tls_versions=tls_versions, negotiated_tls_version=TLSVersion.TLS_12,
        ciphers=ciphers, preferred_cipher=ciphers[0], certificate=cert,
        key_exchange=kex, quantum_score=score, vulnerabilities=vulns, is_mock=True,
        ssh_result=ssh_result, dnssec_result=dnssec_result,
        headers_result=headers_result, ct_log_result=ct_log_result,
        jwt_result=jwt_result, quic_result=quic_result, subdomains=subdomains,
    )
    result.cbom = generate_cbom(result)
    result.extended_risk_score, result.attack_surface_rating = _compute_attack_surface(result)
    return result


# ---------------------------------------------------------------------------
# Profile 5 — quantum-ready.example.com
# ---------------------------------------------------------------------------

def _mock_quantum_ready() -> ScanResult:
    target = ScanTarget(hostname="quantum-ready.example.com", port=443,
                        label="PQC Reference Implementation", tags=["reference","pqc","nist","elite"])

    tls_versions = [
        _make_tlsv(TLSVersion.TLS_13, True),  _make_tlsv(TLSVersion.TLS_12, False),
        _make_tlsv(TLSVersion.TLS_11, False), _make_tlsv(TLSVersion.TLS_10, False),
    ]
    ciphers = [
        _cipher("TLS_MLKEM768_X25519_AES_256_GCM_SHA384","X25519MLKEM768","ML-DSA","AES-256-GCM","SHA384",True,False,QuantumRiskLevel.NONE,TLSVersion.TLS_13,768),
        _cipher("TLS_AES_256_GCM_SHA384","TLS1.3-ECDHE","ML-DSA","AES-256-GCM","SHA384",True,False,QuantumRiskLevel.NONE,TLSVersion.TLS_13),
    ]
    cert = CertificateInfo(
        subject_cn="quantum-ready.example.com", subject_o="NIST PQC Reference Labs", subject_c="US",
        issuer_cn="NIST PQC Test CA - ML-DSA-87", issuer_o="NIST",
        serial_number="PQC:2024:001", not_before=_dt(2024,10,1), not_after=_dt(2027,10,1),
        is_expired=False, is_self_signed=False, signature_algorithm="id-ML-DSA-65",
        public_key_algorithm="ML-DSA", public_key_size=3293,
        san_entries=["quantum-ready.example.com","pqc.example.com"], chain_valid=True,
        fingerprint_sha256="A1:B2:C3:D4:E5:F6:07:18:29:3A:4B:5C:6D:7E:8F:90",
        is_quantum_safe_cert=True, quantum_risk=QuantumRiskLevel.NONE, nist_standard="FIPS-204",
    )
    kex = KeyExchangeAssessment(algorithm="X25519MLKEM768", key_size=768, is_post_quantum=True,
                                 quantum_risk=QuantumRiskLevel.NONE, nist_standard="FIPS-203",
                                 notes="Hybrid X25519+ML-KEM-768 — classical + post-quantum security")

    score = compute_quantum_score(tls_versions, ciphers, cert, kex)
    vulns = detect_vulnerabilities(tls_versions, ciphers, cert, kex)

    ssh_result = SSHScanResult(
        host_key_algorithms=[
            _ssh_algo("id-ml-dsa-65", QuantumRiskLevel.NONE, "ML-DSA-65 — NIST FIPS-204, quantum-safe"),
            _ssh_algo("ssh-ed25519", QuantumRiskLevel.MEDIUM, "Ed25519 fallback for legacy clients"),
        ],
        kex_algorithms=[
            _ssh_algo("mlkem768x25519-sha256", QuantumRiskLevel.NONE, "ML-KEM-768+X25519 hybrid — NIST FIPS-203"),
            _ssh_algo("curve25519-sha256", QuantumRiskLevel.MEDIUM, "X25519 fallback"),
        ],
        encryption_algorithms=["chacha20-poly1305@openssh.com","aes256-gcm@openssh.com"],
        server_banner="SSH-2.0-OpenSSH_9.7-PQC",
        overall_risk=QuantumRiskLevel.LOW,
        notes="PQC-capable SSH — ML-DSA host key + ML-KEM-768 KEX available",
    )

    dnssec_result = DNSSECResult(
        enabled=True, chain_valid=True, dnskey_algorithm="Ed448",
        dnskey_algorithm_safe=True, ds_record_found=True, rrsig_found=True,
        quantum_risk=QuantumRiskLevel.LOW,
        notes="DNSSEC enabled with Ed448 — most quantum-resistant classical DNSSEC algorithm",
    )

    headers_result = HeadersScanResult(
        headers_checked=[
            _header_check("Strict-Transport-Security", True, "max-age=63072000; includeSubDomains; preload", sev=Severity.HIGH),
            _header_check("Content-Security-Policy", True, "default-src 'none'; script-src 'self'", sev=Severity.HIGH),
            _header_check("X-Frame-Options", True, "DENY"),
            _header_check("X-Content-Type-Options", True, "nosniff"),
            _header_check("Referrer-Policy", True, "no-referrer"),
            _header_check("Permissions-Policy", True, "geolocation=(), camera=(), microphone=()"),
            _header_check("X-XSS-Protection", True, "1; mode=block"),
            _header_check("Public-Key-Pins", True, 'pin-sha256="base64=="; max-age=5184000', sev=Severity.LOW),
            _header_check("Cross-Origin-Opener-Policy", True, "same-origin"),
        ],
        security_score=100, hsts_enabled=True, hsts_max_age=63072000, hsts_preload=True,
        csp_present=True, x_frame_options="DENY", x_content_type_options=True,
        referrer_policy="no-referrer", permissions_policy=True, hpkp_present=True,
        notes="Perfect headers score — all security headers present including HSTS preload",
    )

    ct_log_result = CTLogResult(
        total_certs_found=2,
        cert_history=[
            _ct_entry("NIST PQC Test CA - ML-DSA-87","2024-10-01","2027-10-01",serial="PQC:2024:001",sans=["quantum-ready.example.com","pqc.example.com"]),
            _ct_entry("NIST PQC Test CA - ML-DSA-65","2022-10-01","2024-10-01",serial="PQC:2022:001",sans=["quantum-ready.example.com"]),
        ],
        unexpected_cas=[], recent_certs_count=0, flagged=False,
        notes="Clean CT history — only legitimate NIST PQC test CA certificates",
    )

    jwt_result = JWTScanResult(
        jwts_found=[
            JWTFinding(source="Response header: Authorization", algorithm="EdDSA",
                       quantum_risk=QuantumRiskLevel.LOW,
                       notes="EdDSA (Ed25519) JWT — low quantum risk, future migration to ML-DSA recommended"),
        ],
        overall_risk=QuantumRiskLevel.LOW,
        notes="JWTs use EdDSA — best classical option, low quantum risk",
    )

    quic_result = QUICResult(
        h3_advertised=True, quic_detected_udp=True,
        alt_svc_value='h3=":443"; ma=86400',
        versions_advertised=["h3"], flagged=True,
        notes="HTTP/3 enabled. QUIC TLS uses same ML-KEM-768 config as TCP TLS — consistent PQC posture.",
    )

    subdomains = [
        SubdomainResult("pqc.example.com","198.51.100.1",True,False,"TLSv1.3","crt.sh","TLSv1.3 with ML-KEM-768"),
        SubdomainResult("api.example.com","198.51.100.2",True,False,"TLSv1.3","dns","TLSv1.3"),
    ]

    result = ScanResult(
        target=target, scan_status=ScanStatus.SUCCESS,
        scan_timestamp=datetime.now(timezone.utc), scan_duration_seconds=0.98,
        tls_versions=tls_versions, negotiated_tls_version=TLSVersion.TLS_13,
        ciphers=ciphers, preferred_cipher=ciphers[0], certificate=cert,
        key_exchange=kex, quantum_score=score, vulnerabilities=vulns, is_mock=True,
        ssh_result=ssh_result, dnssec_result=dnssec_result,
        headers_result=headers_result, ct_log_result=ct_log_result,
        jwt_result=jwt_result, quic_result=quic_result, subdomains=subdomains,
    )
    result.cbom = generate_cbom(result)
    result.extended_risk_score, result.attack_surface_rating = _compute_attack_surface(result)
    return result


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

MOCK_PROFILES: dict[str, callable] = {
    "pnbindia.in":               _mock_pnbindia_in,
    "netbanking.pnbindia.in":    _mock_netbanking_pnbindia_in,
    "api.pnbindia.in":           _mock_api_pnbindia_in,
    "vpn.pnbindia.in":           _mock_vpn_pnbindia_in,
    "quantum-ready.example.com": _mock_quantum_ready,
}

MOCK_PROFILE_META = {
    "pnbindia.in":               {"label": "PNB Corporate Website",   "tags": ["public","corporate"]},
    "netbanking.pnbindia.in":    {"label": "PNB Net Banking Portal",  "tags": ["payment","critical"]},
    "api.pnbindia.in":           {"label": "PNB API Gateway",         "tags": ["api","internal"]},
    "vpn.pnbindia.in":           {"label": "PNB VPN Gateway",         "tags": ["vpn","internal"]},
    "quantum-ready.example.com": {"label": "PQC Reference Impl.",     "tags": ["pqc","reference"]},
}


def mock_scan(hostname: str) -> ScanResult:
    factory = MOCK_PROFILES.get(hostname.lower().strip())
    if factory:
        return factory()
    target = ScanTarget(hostname=hostname, port=443, label="Unknown Host")
    return ScanResult(
        target=target, scan_status=ScanStatus.FAILED,
        scan_timestamp=datetime.now(timezone.utc), scan_duration_seconds=0.0,
        error_message=(
            f"No mock profile for '{hostname}'. "
            "Available: " + ", ".join(MOCK_PROFILES.keys())
        ),
        is_mock=True,
    )


def get_all_mock_hostnames() -> list[str]:
    return list(MOCK_PROFILES.keys())
