"""
Q-Secure | jwt_detector.py
Detect JWTs in HTTP responses and assess algorithm quantum risk.
"""

from __future__ import annotations

import re
import base64
import json
from typing import Optional

from .models import JWTScanResult, JWTFinding, QuantumRiskLevel


# JWT pattern: three base64url-encoded segments separated by dots
_JWT_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
)

# Algorithm → quantum risk
_ALG_RISK: dict[str, tuple[QuantumRiskLevel, str]] = {
    # RSA-based — CRITICAL
    "RS256": (QuantumRiskLevel.CRITICAL, "RSA-2048 signature — broken by Shor's algorithm"),
    "RS384": (QuantumRiskLevel.CRITICAL, "RSA-3072 signature — broken by Shor's algorithm"),
    "RS512": (QuantumRiskLevel.CRITICAL, "RSA-4096 signature — broken by Shor's algorithm"),
    "PS256": (QuantumRiskLevel.CRITICAL, "RSASSA-PSS — still RSA underneath, Shor-vulnerable"),
    "PS384": (QuantumRiskLevel.CRITICAL, "RSASSA-PSS — still RSA underneath, Shor-vulnerable"),
    "PS512": (QuantumRiskLevel.CRITICAL, "RSASSA-PSS — still RSA underneath, Shor-vulnerable"),
    # ECDSA-based — HIGH
    "ES256": (QuantumRiskLevel.HIGH, "ECDSA P-256 — broken by Shor's algorithm"),
    "ES384": (QuantumRiskLevel.HIGH, "ECDSA P-384 — broken by Shor's algorithm"),
    "ES512": (QuantumRiskLevel.HIGH, "ECDSA P-521 — broken by Shor's algorithm"),
    # HMAC-based — MEDIUM
    "HS256": (QuantumRiskLevel.MEDIUM, "HMAC-SHA256 — symmetric, Grover halves effective key length"),
    "HS384": (QuantumRiskLevel.MEDIUM, "HMAC-SHA384 — symmetric, Grover weakens but 192-bit post-quantum"),
    "HS512": (QuantumRiskLevel.LOW,    "HMAC-SHA512 — 256-bit post-quantum security, acceptable"),
    # EdDSA — LOW
    "EdDSA": (QuantumRiskLevel.LOW, "Ed25519/Ed448 — strong classical, somewhat quantum-vulnerable"),
    # None — should be flagged differently
    "none":  (QuantumRiskLevel.CRITICAL, "Algorithm 'none' — unsigned JWT! Critical security flaw"),
}


def _decode_jwt_header(token: str) -> Optional[dict]:
    """Decode the JWT header without verification."""
    try:
        header_b64 = token.split(".")[0]
        # Add padding
        header_b64 += "=" * (4 - len(header_b64) % 4)
        header_bytes = base64.urlsafe_b64decode(header_b64)
        return json.loads(header_bytes)
    except Exception:
        return None


def _assess_jwt(token: str, source: str) -> Optional[JWTFinding]:
    """Decode and assess a single JWT token."""
    header = _decode_jwt_header(token)
    if not header:
        return None
    alg = header.get("alg", "unknown")
    risk, note = _ALG_RISK.get(alg, (QuantumRiskLevel.HIGH, f"Unknown algorithm: {alg}"))
    return JWTFinding(
        source=source,
        algorithm=alg,
        quantum_risk=risk,
        notes=note,
    )


def _worst_risk(findings: list[JWTFinding]) -> QuantumRiskLevel:
    order = [QuantumRiskLevel.CRITICAL, QuantumRiskLevel.HIGH, QuantumRiskLevel.MEDIUM,
             QuantumRiskLevel.LOW, QuantumRiskLevel.NONE]
    for lvl in order:
        if any(f.quantum_risk == lvl for f in findings):
            return lvl
    return QuantumRiskLevel.NONE


def scan_jwt(hostname: str, port: int = 443, timeout: float = 8.0) -> JWTScanResult:
    """
    Make an HTTP request and scan for JWTs in headers and body.
    Returns JWTScanResult. Never raises.
    """
    try:
        import requests
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    except ImportError:
        return JWTScanResult(
            error="requests not installed — run: pip install requests",
        )

    url = f"https://{hostname}" if port == 443 else f"https://{hostname}:{port}"

    try:
        resp = requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": "QSecure-Scanner/2.0"},
        )
    except Exception as exc:
        return JWTScanResult(
            error=str(exc),
            notes="Could not connect to host",
        )

    findings: list[JWTFinding] = []
    seen_tokens: set[str] = set()

    # Scan all response headers
    for header_name, header_value in resp.headers.items():
        for match in _JWT_PATTERN.finditer(header_value):
            token = match.group(0)
            if token not in seen_tokens:
                seen_tokens.add(token)
                finding = _assess_jwt(token, f"Response header: {header_name}")
                if finding:
                    findings.append(finding)

    # Scan response body (first 10KB to avoid huge payloads)
    body_text = resp.text[:10240]
    for match in _JWT_PATTERN.finditer(body_text):
        token = match.group(0)
        if token not in seen_tokens:
            seen_tokens.add(token)
            finding = _assess_jwt(token, "Response body")
            if finding:
                findings.append(finding)

    overall = _worst_risk(findings) if findings else QuantumRiskLevel.NONE

    return JWTScanResult(
        jwts_found=findings,
        overall_risk=overall,
        notes=(
            f"Found {len(findings)} JWT(s) in response"
            if findings else "No JWTs detected in response headers or body"
        ),
    )
