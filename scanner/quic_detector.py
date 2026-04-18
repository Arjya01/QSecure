"""
Q-Secure | quic_detector.py
Detect QUIC/HTTP3 support via Alt-Svc header and UDP probe.
"""

from __future__ import annotations

import re
import socket
from typing import Optional

from .models import QUICResult


_ALT_SVC_H3_PATTERN = re.compile(r'h3(?:-\d+)?=', re.IGNORECASE)


def _probe_quic_udp(hostname: str, port: int = 443, timeout: float = 3.0) -> bool:
    """
    Very basic QUIC probe: send a QUIC Initial packet stub to UDP 443.
    Returns True if we get any response (even an error packet).
    This is a best-effort heuristic, not a full QUIC handshake.
    """
    try:
        ip = socket.gethostbyname(hostname)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # Minimal QUIC Initial packet (Long Header, Version 1)
        # This is intentionally malformed but enough to elicit a Version Negotiation
        # or Retry from a live QUIC server
        stub = bytes([
            0xc0,               # Long header + QUIC bit
            0x00, 0x00, 0x00, 0x01,  # Version 1
            0x08,               # DCID length = 8
            *([0xAB] * 8),      # Random DCID
            0x00,               # SCID length = 0
            0x00,               # Token length = 0
            0x04, 0x00,         # Packet length (4 bytes remaining)
            0x00, 0x00, 0x00, 0x00,  # Packet number
        ])

        sock.sendto(stub, (ip, port))
        try:
            data, _ = sock.recvfrom(1024)
            return len(data) > 0
        except socket.timeout:
            return False
        finally:
            sock.close()
    except Exception:
        return False


def detect_quic(hostname: str, port: int = 443, timeout: float = 8.0) -> QUICResult:
    """
    Check for QUIC/HTTP3 support via Alt-Svc header + UDP probe.
    Returns QUICResult. Never raises.
    """
    try:
        import requests
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    except ImportError:
        return QUICResult(
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
        return QUICResult(
            error=str(exc),
            notes="Could not connect to host",
        )

    # Parse Alt-Svc header
    alt_svc = resp.headers.get("Alt-Svc", resp.headers.get("alt-svc", ""))
    h3_advertised = bool(alt_svc and _ALT_SVC_H3_PATTERN.search(alt_svc))

    versions: list[str] = []
    if alt_svc:
        for part in alt_svc.split(","):
            part = part.strip()
            if "h3" in part.lower():
                proto = part.split("=")[0].strip()
                if proto not in versions:
                    versions.append(proto)

    # Only probe UDP if Alt-Svc suggests QUIC (or always probe)
    quic_udp = _probe_quic_udp(hostname, port, timeout=min(timeout, 3.0))

    detected = h3_advertised or quic_udp
    flagged = detected  # Flag if QUIC detected — standard TCP TLS scan may have missed this

    notes_parts = []
    if h3_advertised:
        notes_parts.append(f"HTTP/3 advertised via Alt-Svc: {alt_svc[:100]}")
    if quic_udp:
        notes_parts.append("QUIC response detected on UDP 443")
    if not detected:
        notes_parts.append("No QUIC/HTTP3 detected")

    return QUICResult(
        h3_advertised=h3_advertised,
        quic_detected_udp=quic_udp,
        alt_svc_value=alt_svc[:200] if alt_svc else "",
        versions_advertised=versions,
        flagged=flagged,
        notes=". ".join(notes_parts),
    )
