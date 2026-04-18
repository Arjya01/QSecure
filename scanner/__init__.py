"""
Q-Secure | scanner/__init__.py  (Phase 2)
Unified public interface — 8 scan surfaces.
web/app.py calls scan() / batch_scan() from here.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Optional

from .models import ScanResult, ScanStatus, ScanTarget
from .mock_data import mock_scan, get_all_mock_hostnames, MOCK_PROFILE_META
from .tls_scanner import scan_tls
from .quantum_assessor import compute_quantum_score, detect_vulnerabilities
from .cbom_generator import generate_cbom
from .ssh_scanner import scan_ssh
from .dnssec_checker import check_dnssec
from .headers_scanner import scan_headers
from .ct_log_checker import check_ct_logs
from .jwt_detector import scan_jwt
from .quic_detector import detect_quic
from .subdomain_enumerator import enumerate_subdomains

MOCK_MODE: bool = False
_MAX_WORKERS = 10
_SCANNER_VERSION = "2.0.0"

_DEFAULT_SURFACES = {
    "tls": True, "ssh": True, "dnssec": True, "headers": True,
    "ct_log": True, "jwt": True, "quic": True, "subdomains": True,
}


def _compute_attack_surface(result: ScanResult) -> tuple[float, str]:
    base = result.quantum_score.overall_score if result.quantum_score else 50.0
    penalty = 0.0
    if result.ssh_result and result.ssh_result.overall_risk.value == "CRITICAL":
        penalty += 15
    from .models import QuantumRiskLevel
    if result.dnssec_result and not result.dnssec_result.enabled:
        penalty += 10
    if result.headers_result and result.headers_result.security_score < 50:
        penalty += 10
    if result.ct_log_result and result.ct_log_result.flagged:
        penalty += 8
    if result.jwt_result and result.jwt_result.overall_risk == QuantumRiskLevel.CRITICAL:
        penalty += 12
    if result.quic_result and result.quic_result.flagged:
        penalty += 5
    extended = max(0.0, base - penalty)
    if extended >= 80:   rating = "MINIMAL"
    elif extended >= 55: rating = "MODERATE"
    elif extended >= 30: rating = "LARGE"
    else:                rating = "CRITICAL"
    return round(extended, 1), rating


def real_scan(hostname: str, port: int = 443, surfaces: Optional[dict] = None) -> ScanResult:
    """Live scan across all enabled surfaces. Never raises."""
    s = {**_DEFAULT_SURFACES, **(surfaces or {})}
    target = ScanTarget(hostname=hostname, port=port)
    start = time.monotonic()

    try:
        raw = scan_tls(target) if s.get("tls", True) else {
            "tls_versions": [], "ciphers": [], "certificate": None,
            "key_exchange": None, "preferred_cipher": None,
            "negotiated_tls_version": None,
            "scan_status": ScanStatus.PARTIAL, "error_message": "TLS scan disabled",
        }

        tls_versions   = raw["tls_versions"]
        ciphers        = raw["ciphers"]
        cert           = raw["certificate"]
        kex            = raw["key_exchange"]
        preferred      = raw["preferred_cipher"]
        negotiated_ver = raw["negotiated_tls_version"]
        status         = raw["scan_status"]
        error_msg      = raw["error_message"]

        quantum_score = None
        vulns = []
        if status != ScanStatus.FAILED:
            quantum_score = compute_quantum_score(tls_versions, ciphers, cert, kex)
            vulns         = detect_vulnerabilities(tls_versions, ciphers, cert, kex)

        result = ScanResult(
            target=target,
            scan_status=status,
            scan_timestamp=datetime.now(timezone.utc),
            scan_duration_seconds=round(time.monotonic() - start, 3),
            error_message=error_msg,
            tls_versions=tls_versions,
            negotiated_tls_version=negotiated_ver,
            ciphers=ciphers,
            preferred_cipher=preferred,
            certificate=cert,
            key_exchange=kex,
            quantum_score=quantum_score,
            vulnerabilities=vulns,
            is_mock=False,
            scanner_version=_SCANNER_VERSION,
        )
        if status != ScanStatus.FAILED:
            result.cbom = generate_cbom(result)

        # Extended surfaces (parallel where sensible)
        if s.get("ssh", True):
            result.ssh_result = scan_ssh(hostname)
        if s.get("dnssec", True):
            result.dnssec_result = check_dnssec(hostname)
        if s.get("headers", True):
            result.headers_result = scan_headers(hostname, port)
        if s.get("ct_log", True):
            result.ct_log_result = check_ct_logs(hostname)
        if s.get("jwt", True):
            result.jwt_result = scan_jwt(hostname, port)
        if s.get("quic", True):
            result.quic_result = detect_quic(hostname, port)
        if s.get("subdomains", True):
            result.subdomains = enumerate_subdomains(hostname)

        result.extended_risk_score, result.attack_surface_rating = _compute_attack_surface(result)
        result.scan_duration_seconds = round(time.monotonic() - start, 3)
        return result

    except Exception as exc:
        return ScanResult(
            target=target,
            scan_status=ScanStatus.FAILED,
            scan_timestamp=datetime.now(timezone.utc),
            scan_duration_seconds=round(time.monotonic() - start, 3),
            error_message=str(exc),
            is_mock=False,
            scanner_version=_SCANNER_VERSION,
        )


def scan(hostname: str, port: int = 443, surfaces: Optional[dict] = None,
         mock: Optional[bool] = None) -> ScanResult:
    """Scan a single hostname. Respects MOCK_MODE unless mock= is specified."""
    use_mock = MOCK_MODE if mock is None else mock
    if use_mock:
        return mock_scan(hostname)
    return real_scan(hostname, port, surfaces)


def batch_scan(hostnames: list[str], port: int = 443,
               surfaces: Optional[dict] = None, mock: Optional[bool] = None) -> list[ScanResult]:
    """Concurrently scan multiple hostnames."""
    results: dict[str, ScanResult] = {}
    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        futures = {pool.submit(scan, h, port, surfaces, mock): h for h in hostnames}
        for future in as_completed(futures):
            host = futures[future]
            try:
                results[host] = future.result()
            except Exception as exc:
                results[host] = ScanResult(
                    target=ScanTarget(hostname=host, port=port),
                    scan_status=ScanStatus.FAILED,
                    scan_timestamp=datetime.now(timezone.utc),
                    error_message=f"Unexpected error: {exc}",
                    is_mock=MOCK_MODE if mock is None else mock,
                    scanner_version=_SCANNER_VERSION,
                )
    return [results[h] for h in hostnames]


def scan_all_mock_profiles() -> list[ScanResult]:
    return batch_scan(get_all_mock_hostnames())


def toggle_mock_mode() -> bool:
    global MOCK_MODE
    MOCK_MODE = not MOCK_MODE
    return MOCK_MODE


def get_mock_profile_meta() -> dict:
    return MOCK_PROFILE_META
