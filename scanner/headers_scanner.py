"""
Q-Secure | headers_scanner.py
Analyse HTTPS security response headers and compute a 0-100 security score.
"""

from __future__ import annotations

import re
from typing import Optional

from .models import HeadersScanResult, HeaderCheck, Severity


# ---------------------------------------------------------------------------
# Header scoring weights (total = 100)
# ---------------------------------------------------------------------------

_HEADER_SPECS: list[tuple[str, int, Severity, str]] = [
    # (header_name, points, severity_if_missing, description)
    ("Strict-Transport-Security",    25, Severity.HIGH,     "HSTS missing — HTTPS not enforced, quantum-safe TLS can be bypassed"),
    ("Content-Security-Policy",      20, Severity.HIGH,     "CSP missing — XSS injection risk"),
    ("X-Frame-Options",              10, Severity.MEDIUM,   "Clickjacking protection missing"),
    ("X-Content-Type-Options",       10, Severity.MEDIUM,   "MIME sniffing enabled — potential content injection"),
    ("Referrer-Policy",              10, Severity.LOW,      "Referrer leakage possible"),
    ("Permissions-Policy",           10, Severity.LOW,      "Feature policy not set"),
    ("X-XSS-Protection",              5, Severity.LOW,      "XSS protection header missing (legacy, low impact)"),
    ("Public-Key-Pins",               5, Severity.LOW,      "HPKP absent (deprecated but checked)"),
    ("Cross-Origin-Opener-Policy",    5, Severity.LOW,      "COOP header missing"),
]


def scan_headers(hostname: str, port: int = 443, timeout: float = 8.0) -> HeadersScanResult:
    """
    Make an HTTPS request and analyse security headers.
    Returns HeadersScanResult. Never raises.
    """
    try:
        import requests
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    except ImportError:
        return HeadersScanResult(
            error="requests not installed — run: pip install requests",
        )

    url = f"https://{hostname}" if port == 443 else f"https://{hostname}:{port}"

    try:
        resp = requests.get(
            url,
            timeout=timeout,
            verify=False,              # We assess TLS separately
            allow_redirects=True,
            headers={"User-Agent": "QSecure-Scanner/2.0"},
        )
        headers = {k.lower(): v for k, v in resp.headers.items()}
    except Exception as exc:
        return HeadersScanResult(
            error=str(exc),
            notes="Could not fetch headers — host may be down or refuse connection",
        )

    checks: list[HeaderCheck] = []
    total_score = 0

    for name, points, severity, desc in _HEADER_SPECS:
        key = name.lower()
        present = key in headers
        value = headers.get(key, "")
        if present:
            total_score += points
        checks.append(HeaderCheck(
            header_name=name,
            present=present,
            value=value[:200] if value else "",
            notes="" if present else desc,
            severity_if_missing=severity,
        ))

    # Parse HSTS details
    hsts_value = headers.get("strict-transport-security", "")
    hsts_enabled = bool(hsts_value)
    hsts_max_age = 0
    hsts_preload = False
    if hsts_value:
        ma = re.search(r"max-age=(\d+)", hsts_value)
        hsts_max_age = int(ma.group(1)) if ma else 0
        hsts_preload = "preload" in hsts_value.lower()

    # Partial score bonus for HSTS preload
    if hsts_preload and not (total_score >= 100):
        # already counted in base points
        pass

    return HeadersScanResult(
        headers_checked=checks,
        security_score=min(100, total_score),
        hsts_enabled=hsts_enabled,
        hsts_max_age=hsts_max_age,
        hsts_preload=hsts_preload,
        csp_present="content-security-policy" in headers,
        x_frame_options=headers.get("x-frame-options", ""),
        x_content_type_options="nosniff" in headers.get("x-content-type-options", "").lower(),
        hpkp_present="public-key-pins" in headers,
        referrer_policy=headers.get("referrer-policy", ""),
        permissions_policy="permissions-policy" in headers,
        notes=f"Checked against {len(_HEADER_SPECS)} security headers. Score: {min(100, total_score)}/100",
    )
