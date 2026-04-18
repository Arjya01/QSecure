"""
Q-Secure | ssh_scanner.py
Connect to port 22, extract SSH algorithms, assess quantum risk.
Fails gracefully on timeout / closed port.
"""

from __future__ import annotations

import socket
import re
from typing import Optional

from .models import SSHScanResult, SSHAlgorithmInfo, QuantumRiskLevel


# ---------------------------------------------------------------------------
# Algorithm risk mapping
# ---------------------------------------------------------------------------

_HOST_KEY_RISK: dict[str, tuple[QuantumRiskLevel, str]] = {
    # CRITICAL — RSA, DSA
    "ssh-rsa":           (QuantumRiskLevel.CRITICAL, "RSA host key — broken by Shor's algorithm"),
    "ssh-dss":           (QuantumRiskLevel.CRITICAL, "DSA host key — broken by Shor's algorithm"),
    "rsa-sha2-256":      (QuantumRiskLevel.CRITICAL, "RSA-SHA2-256 host key — still RSA underneath"),
    "rsa-sha2-512":      (QuantumRiskLevel.CRITICAL, "RSA-SHA2-512 host key — still RSA underneath"),
    # HIGH — ECDSA
    "ecdsa-sha2-nistp256": (QuantumRiskLevel.HIGH, "ECDSA P-256 — broken by Shor's algorithm"),
    "ecdsa-sha2-nistp384": (QuantumRiskLevel.HIGH, "ECDSA P-384 — broken by Shor's algorithm"),
    "ecdsa-sha2-nistp521": (QuantumRiskLevel.HIGH, "ECDSA P-521 — broken by Shor's algorithm"),
    # MEDIUM — Ed25519
    "ssh-ed25519":       (QuantumRiskLevel.MEDIUM, "Ed25519 — strong classical, still quantum-vulnerable (Grover weakens)"),
    "ssh-ed448":         (QuantumRiskLevel.MEDIUM, "Ed448 — strong classical, still quantum-vulnerable"),
    # SAFE — PQC
    "ssh-ml-dsa-65":     (QuantumRiskLevel.NONE, "ML-DSA-65 — NIST FIPS-204 compliant, quantum-safe"),
    "id-ml-dsa-65":      (QuantumRiskLevel.NONE, "ML-DSA-65 — NIST FIPS-204 compliant, quantum-safe"),
    "crystals-dilithium":(QuantumRiskLevel.NONE, "CRYSTALS-Dilithium — PQC lattice signature"),
}

_KEX_RISK: dict[str, tuple[QuantumRiskLevel, str]] = {
    "diffie-hellman-group1-sha1":        (QuantumRiskLevel.CRITICAL, "DH-1024 — Logjam-vulnerable + quantum-broken"),
    "diffie-hellman-group14-sha1":       (QuantumRiskLevel.CRITICAL, "DH-2048-SHA1 — quantum-vulnerable"),
    "diffie-hellman-group14-sha256":     (QuantumRiskLevel.HIGH,     "DH-2048 — quantum-vulnerable"),
    "diffie-hellman-group16-sha512":     (QuantumRiskLevel.HIGH,     "DH-4096 — quantum-vulnerable"),
    "ecdh-sha2-nistp256":                (QuantumRiskLevel.HIGH,     "ECDH P-256 — quantum-vulnerable"),
    "ecdh-sha2-nistp384":                (QuantumRiskLevel.HIGH,     "ECDH P-384 — quantum-vulnerable"),
    "ecdh-sha2-nistp521":                (QuantumRiskLevel.HIGH,     "ECDH P-521 — quantum-vulnerable"),
    "curve25519-sha256":                 (QuantumRiskLevel.MEDIUM,   "X25519 — quantum-vulnerable (Shor)"),
    "curve25519-sha256@libssh.org":      (QuantumRiskLevel.MEDIUM,   "X25519 — quantum-vulnerable (Shor)"),
    "sntrup761x25519-sha512@openssh.com":(QuantumRiskLevel.LOW,      "NTRU+X25519 hybrid — semi-quantum-safe"),
    "mlkem768x25519-sha256":             (QuantumRiskLevel.NONE,     "ML-KEM-768+X25519 hybrid — NIST FIPS-203 compliant"),
}


def _classify_host_key(algo: str) -> SSHAlgorithmInfo:
    key = algo.lower().strip()
    for pattern, (risk, note) in _HOST_KEY_RISK.items():
        if pattern in key:
            return SSHAlgorithmInfo(name=algo, quantum_risk=risk, notes=note)
    # ECDSA catch-all
    if key.startswith("ecdsa"):
        return SSHAlgorithmInfo(
            name=algo, quantum_risk=QuantumRiskLevel.HIGH,
            notes="ECDSA variant — broken by Shor's algorithm"
        )
    return SSHAlgorithmInfo(
        name=algo, quantum_risk=QuantumRiskLevel.MEDIUM, notes="Unknown key type"
    )


def _classify_kex(algo: str) -> SSHAlgorithmInfo:
    key = algo.lower().strip()
    if key in _KEX_RISK:
        risk, note = _KEX_RISK[key]
        return SSHAlgorithmInfo(name=algo, quantum_risk=risk, notes=note)
    if "mlkem" in key or "ml-kem" in key:
        return SSHAlgorithmInfo(name=algo, quantum_risk=QuantumRiskLevel.NONE, notes="ML-KEM hybrid — PQC safe")
    if "ecdh" in key:
        return SSHAlgorithmInfo(name=algo, quantum_risk=QuantumRiskLevel.HIGH, notes="ECDH — quantum-vulnerable")
    return SSHAlgorithmInfo(name=algo, quantum_risk=QuantumRiskLevel.MEDIUM, notes="Unknown KEX algorithm")


def _worst_risk(algos: list[SSHAlgorithmInfo]) -> QuantumRiskLevel:
    order = [QuantumRiskLevel.CRITICAL, QuantumRiskLevel.HIGH, QuantumRiskLevel.MEDIUM,
             QuantumRiskLevel.LOW, QuantumRiskLevel.NONE]
    for lvl in order:
        if any(a.quantum_risk == lvl for a in algos):
            return lvl
    return QuantumRiskLevel.NONE


# ---------------------------------------------------------------------------
# Low-level SSH banner + KEXINIT parser
# ---------------------------------------------------------------------------

def _recv_banner(sock: socket.socket) -> str:
    """Read the SSH version banner (first line)."""
    data = b""
    while len(data) < 256:
        chunk = sock.recv(64)
        if not chunk:
            break
        data += chunk
        if b"\n" in data:
            break
    return data.split(b"\n")[0].decode("utf-8", errors="replace").strip()


def _recv_kexinit(sock: socket.socket) -> bytes:
    """Read one SSH binary packet (enough to get KEXINIT payload)."""
    # Read packet length
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            return b""
        header += chunk
    pkt_len = int.from_bytes(header, "big")
    payload = b""
    remaining = min(pkt_len, 4096)
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            break
        payload += chunk
        remaining -= len(chunk)
    return payload


def _parse_name_list(data: bytes, offset: int) -> tuple[list[str], int]:
    """Parse an SSH name-list (uint32 length + UTF-8 comma string)."""
    if offset + 4 > len(data):
        return [], offset
    length = int.from_bytes(data[offset:offset + 4], "big")
    offset += 4
    if offset + length > len(data):
        return [], offset
    names = data[offset:offset + length].decode("utf-8", errors="replace").split(",")
    return [n.strip() for n in names if n.strip()], offset + length


def _parse_kexinit_payload(payload: bytes) -> dict[str, list[str]]:
    """
    Parse SSH_MSG_KEXINIT (msg type 20).
    Returns dict with keys: kex_algos, host_key_algos, enc_cs, enc_sc
    """
    # byte[0] = padding length, byte[1] = message type
    if len(payload) < 2:
        return {}
    msg_type = payload[1]
    if msg_type != 20:  # SSH_MSG_KEXINIT
        return {}
    # Skip: padding_length(1) + msg_type(1) + cookie(16) = 18
    offset = 18
    kex_algos, offset      = _parse_name_list(payload, offset)
    host_key_algos, offset = _parse_name_list(payload, offset)
    enc_cs, offset         = _parse_name_list(payload, offset)
    enc_sc, offset         = _parse_name_list(payload, offset)
    return {
        "kex_algos": kex_algos,
        "host_key_algos": host_key_algos,
        "enc_cs": enc_cs,
        "enc_sc": enc_sc,
    }


# ---------------------------------------------------------------------------
# Public scanner
# ---------------------------------------------------------------------------

def scan_ssh(hostname: str, port: int = 22, timeout: float = 5.0) -> Optional[SSHScanResult]:
    """
    Connect to SSH and extract algorithm lists.
    Returns None if port is closed / timed out.
    Returns SSHScanResult with error set on partial failure.
    """
    try:
        sock = socket.create_connection((hostname, port), timeout=timeout)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None  # Port closed or unreachable

    try:
        banner = _recv_banner(sock)

        # Send our banner so server continues handshake
        sock.sendall(b"SSH-2.0-QSecure_Scanner_2.0\r\n")

        kexinit_raw = _recv_kexinit(sock)
        parsed = _parse_kexinit_payload(kexinit_raw)

        host_key_algos = [_classify_host_key(a) for a in parsed.get("host_key_algos", [])]
        kex_algos      = [_classify_kex(a)       for a in parsed.get("kex_algos", [])]
        enc_algos      = parsed.get("enc_cs", [])

        all_algos = host_key_algos + kex_algos
        overall   = _worst_risk(all_algos) if all_algos else QuantumRiskLevel.HIGH

        return SSHScanResult(
            host_key_algorithms=host_key_algos,
            kex_algorithms=kex_algos,
            encryption_algorithms=enc_algos,
            server_banner=banner,
            overall_risk=overall,
            notes=f"Scanned {len(host_key_algos)} host key and {len(kex_algos)} KEX algorithms",
        )

    except Exception as exc:
        return SSHScanResult(
            server_banner="",
            overall_risk=QuantumRiskLevel.HIGH,
            error=str(exc),
            notes="Partial SSH scan — connection succeeded but algorithm parsing failed",
        )
    finally:
        try:
            sock.close()
        except Exception:
            pass
