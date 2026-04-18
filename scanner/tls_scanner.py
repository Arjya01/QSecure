"""
Q-Secure | tls_scanner.py
Real TLS scanning: version detection, cipher enumeration, certificate fetch.
"""

from __future__ import annotations

import socket
import ssl
import time
from typing import Optional

from .models import (
    CipherDetail,
    KeyExchangeAssessment,
    QuantumRiskLevel,
    ScanStatus,
    ScanTarget,
    TLSVersion,
    TLSVersionResult,
)
from .cert_parser import fetch_certificate_from_host

SCAN_TIMEOUT = 10  # seconds

# ---------------------------------------------------------------------------
# TLS version metadata
# ---------------------------------------------------------------------------

_TLS_VERSION_META: dict[TLSVersion, dict] = {
    TLSVersion.SSL_2:  {"deprecated": True,  "insecure": True},
    TLSVersion.SSL_3:  {"deprecated": True,  "insecure": True},
    TLSVersion.TLS_10: {"deprecated": True,  "insecure": True},
    TLSVersion.TLS_11: {"deprecated": True,  "insecure": True},
    TLSVersion.TLS_12: {"deprecated": False, "insecure": False},
    TLSVersion.TLS_13: {"deprecated": False, "insecure": False},
}

# ---------------------------------------------------------------------------
# Cipher suite decomposition
# ---------------------------------------------------------------------------

# Key exchange algorithms vulnerable to quantum (Shor's algorithm)
QUANTUM_VULNERABLE_KEX: set[str] = {"RSA", "DH", "DHE", "ECDH", "ECDHE"}

# Key exchange algorithms that are post-quantum
POST_QUANTUM_KEX: set[str] = {"ML-KEM", "KYBER", "MLKEM", "X25519MLKEM768"}


def _decompose_cipher(iana_name: str, tls_version: TLSVersion) -> dict:
    """
    Decompose a cipher suite name into its cryptographic components.
    Handles IANA names like TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    and TLS 1.3 names like TLS_AES_256_GCM_SHA384.
    """
    parts = iana_name.replace("TLS_", "").replace("WITH_", "WITH|").split("|")

    if tls_version == TLSVersion.TLS_13:
        # TLS 1.3 format: TLS_AES_256_GCM_SHA384 — no KEX/auth in name
        tokens = iana_name.replace("TLS_", "").split("_")
        # Last token is MAC, rest is cipher
        mac = tokens[-1] if tokens else ""
        encryption = "_".join(tokens[:-1]) if len(tokens) > 1 else iana_name
        return {
            "key_exchange": "TLS1.3-ECDHE/DHE",
            "authentication": "ECDSA/RSA",
            "encryption": encryption,
            "mac": mac,
            "is_forward_secret": True,
            "is_quantum_vulnerable": True,   # KEX is still classical in most TLS 1.3
            "quantum_risk": QuantumRiskLevel.MEDIUM,  # Better than older TLS
        }

    # Classic format: TLS_<KEX>_<AUTH>_WITH_<ENC>_<MAC>
    # e.g. TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    raw = iana_name.removeprefix("TLS_")
    if "_WITH_" in raw:
        kex_auth, enc_mac = raw.split("_WITH_", 1)
    else:
        kex_auth = raw
        enc_mac = ""

    kex_auth_parts = kex_auth.split("_")
    # Heuristic: first token is KEX, second is AUTH (if two tokens)
    if len(kex_auth_parts) >= 2:
        kex  = kex_auth_parts[0]
        auth = kex_auth_parts[1]
    elif len(kex_auth_parts) == 1:
        kex  = kex_auth_parts[0]
        auth = kex_auth_parts[0]
    else:
        kex  = "UNKNOWN"
        auth = "UNKNOWN"

    # Encryption + MAC from the right side
    enc_mac_parts = enc_mac.split("_")
    mac_algo = enc_mac_parts[-1] if enc_mac_parts else ""
    enc_algo = "_".join(enc_mac_parts[:-1]) if len(enc_mac_parts) > 1 else enc_mac

    # Determine forward secrecy
    is_fs = kex in ("ECDHE", "DHE", "EDH")

    # Quantum risk of key exchange
    is_pq = kex.upper() in POST_QUANTUM_KEX
    is_qv = kex.upper() in QUANTUM_VULNERABLE_KEX and not is_pq

    if is_pq:
        qrisk = QuantumRiskLevel.NONE
    elif kex in ("ECDHE",):
        qrisk = QuantumRiskLevel.HIGH   # vulnerable to Shor
    elif kex == "RSA":
        qrisk = QuantumRiskLevel.CRITICAL  # no forward secrecy + quantum vulnerable
    elif kex in ("DHE", "DH"):
        qrisk = QuantumRiskLevel.HIGH
    else:
        qrisk = QuantumRiskLevel.HIGH

    # Flag especially weak things
    if any(w in iana_name.upper() for w in ("RC4", "NULL", "EXPORT", "DES", "MD5", "ANON")):
        qrisk = QuantumRiskLevel.CRITICAL
        is_fs = False

    return {
        "key_exchange": kex,
        "authentication": auth,
        "encryption": enc_algo,
        "mac": mac_algo,
        "is_forward_secret": is_fs,
        "is_quantum_vulnerable": is_qv or not is_pq,
        "quantum_risk": qrisk,
    }


def _check_tls_version(hostname: str, port: int, ssl_version) -> bool:
    """Try to connect using a specific SSL/TLS protocol version. Returns True if supported."""
    try:
        ctx = ssl.SSLContext(ssl_version)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=SCAN_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                return True
    except (ssl.SSLError, OSError, ConnectionRefusedError, socket.timeout):
        return False
    except Exception:
        return False


def _get_negotiated_cipher_and_version(hostname: str, port: int) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Connect with the best available TLS context and return
    (cipher_iana_name, tls_version_string, openssl_cipher_name).
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=SCAN_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cipher = tls_sock.cipher()
                version = tls_sock.version()
                if cipher:
                    return cipher[0], version, cipher[0]
    except Exception:
        pass
    return None, None, None


def _enumerate_tls_versions(hostname: str, port: int) -> list[TLSVersionResult]:
    """Probe which TLS versions the server accepts."""
    results: list[TLSVersionResult] = []

    version_probes = [
        (TLSVersion.TLS_13, getattr(ssl, "PROTOCOL_TLS_CLIENT", ssl.PROTOCOL_TLS)),
        (TLSVersion.TLS_12, getattr(ssl, "PROTOCOL_TLSv1_2", None)),
        (TLSVersion.TLS_11, getattr(ssl, "PROTOCOL_TLSv1_1", None)),
        (TLSVersion.TLS_10, getattr(ssl, "PROTOCOL_TLSv1", None)),
    ]

    for version_enum, proto_const in version_probes:
        if proto_const is None:
            # Python version doesn't expose this protocol (deprecated/removed)
            results.append(TLSVersionResult(
                version=version_enum,
                supported=False,
                is_deprecated=_TLS_VERSION_META[version_enum]["deprecated"],
                is_insecure=_TLS_VERSION_META[version_enum]["insecure"],
                notes="Not probed (protocol removed from Python ssl module)",
            ))
            continue

        # For TLS 1.3 and 1.2, use the generic TLS context with min/max version pinning
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            if version_enum == TLSVersion.TLS_13:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            elif version_enum == TLSVersion.TLS_12:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            elif version_enum == TLSVersion.TLS_11:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_1
                ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            elif version_enum == TLSVersion.TLS_10:
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                ctx.maximum_version = ssl.TLSVersion.TLSv1

            supported = False
            with socket.create_connection((hostname, port), timeout=SCAN_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    supported = True
        except (ssl.SSLError, OSError, socket.timeout, AttributeError):
            supported = False
        except Exception:
            supported = False

        meta = _TLS_VERSION_META[version_enum]
        results.append(TLSVersionResult(
            version=version_enum,
            supported=supported,
            is_deprecated=meta["deprecated"],
            is_insecure=meta["insecure"],
            notes="Deprecated — migrate to TLS 1.3" if (supported and meta["deprecated"]) else "",
        ))

    return results


def _build_cipher_details(
    openssl_name: str,
    tls_version_str: Optional[str],
) -> CipherDetail:
    """Build a CipherDetail from the negotiated cipher name."""
    # Map TLS version string to enum
    _version_map = {
        "TLSv1": TLSVersion.TLS_10,
        "TLSv1.1": TLSVersion.TLS_11,
        "TLSv1.2": TLSVersion.TLS_12,
        "TLSv1.3": TLSVersion.TLS_13,
    }
    tls_ver_enum = _version_map.get(tls_version_str or "", TLSVersion.TLS_12)

    # Build IANA-style name
    iana_name = openssl_name if openssl_name.startswith("TLS_") else f"TLS_{openssl_name.replace('-', '_')}"

    decomp = _decompose_cipher(iana_name, tls_ver_enum)

    return CipherDetail(
        iana_name=iana_name,
        openssl_name=openssl_name,
        key_exchange=decomp["key_exchange"],
        authentication=decomp["authentication"],
        encryption=decomp["encryption"],
        mac=decomp["mac"],
        is_forward_secret=decomp["is_forward_secret"],
        is_quantum_vulnerable=decomp["is_quantum_vulnerable"],
        quantum_risk=decomp["quantum_risk"],
        tls_version=tls_ver_enum,
    )


def _build_key_exchange(cipher: Optional[CipherDetail]) -> Optional[KeyExchangeAssessment]:
    """Derive a KeyExchangeAssessment from the preferred cipher detail."""
    if cipher is None:
        return None

    kex = cipher.key_exchange.upper()
    is_pq = kex in POST_QUANTUM_KEX

    nist_map = {
        "ML-KEM": "FIPS-203",
        "MLKEM": "FIPS-203",
        "X25519MLKEM768": "FIPS-203",
    }

    # Estimate key size from encryption field
    size = 0
    enc = cipher.encryption.upper()
    for token in enc.split("_"):
        if token.isdigit():
            size = int(token)
            break

    return KeyExchangeAssessment(
        algorithm=cipher.key_exchange,
        key_size=size if size else 256,
        is_post_quantum=is_pq,
        quantum_risk=cipher.quantum_risk,
        nist_standard=nist_map.get(kex),
        notes=(
            "Post-quantum key exchange detected" if is_pq
            else "Classical KEX — vulnerable to Shor's algorithm on a sufficiently large quantum computer"
        ),
    )


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def scan_tls(target: ScanTarget) -> dict:
    """
    Perform a real TLS scan against `target`.

    Returns a dict with keys:
        tls_versions, ciphers, preferred_cipher,
        certificate, key_exchange, scan_status, error_message
    """
    hostname = target.hostname
    port = target.port
    result: dict = {
        "tls_versions": [],
        "ciphers": [],
        "preferred_cipher": None,
        "certificate": None,
        "key_exchange": None,
        "negotiated_tls_version": None,
        "scan_status": ScanStatus.SUCCESS,
        "error_message": None,
    }

    try:
        # 1. Enumerate supported TLS versions
        result["tls_versions"] = _enumerate_tls_versions(hostname, port)

        # 2. Get negotiated cipher + version
        cipher_name, version_str, openssl_name = _get_negotiated_cipher_and_version(hostname, port)

        if cipher_name is None:
            result["scan_status"] = ScanStatus.FAILED
            result["error_message"] = f"Could not establish TLS connection to {hostname}:{port}"
            return result

        # 3. Build cipher detail
        preferred = _build_cipher_details(openssl_name or cipher_name, version_str)
        result["preferred_cipher"] = preferred
        result["ciphers"] = [preferred]

        # Map version string to enum
        _ver_map = {
            "TLSv1": TLSVersion.TLS_10,
            "TLSv1.1": TLSVersion.TLS_11,
            "TLSv1.2": TLSVersion.TLS_12,
            "TLSv1.3": TLSVersion.TLS_13,
        }
        result["negotiated_tls_version"] = _ver_map.get(version_str or "", TLSVersion.TLS_12)

        # 4. Fetch and parse certificate
        cert_info = fetch_certificate_from_host(hostname, port, timeout=SCAN_TIMEOUT)
        result["certificate"] = cert_info

        # 5. Build key exchange assessment
        result["key_exchange"] = _build_key_exchange(preferred)

    except socket.timeout:
        result["scan_status"] = ScanStatus.FAILED
        result["error_message"] = f"Connection timed out after {SCAN_TIMEOUT}s"
    except ConnectionRefusedError:
        result["scan_status"] = ScanStatus.FAILED
        result["error_message"] = f"Connection refused on {hostname}:{port}"
    except socket.gaierror as e:
        result["scan_status"] = ScanStatus.FAILED
        result["error_message"] = f"DNS resolution failed: {e}"
    except Exception as e:
        result["scan_status"] = ScanStatus.PARTIAL
        result["error_message"] = f"Partial scan error: {e}"

    return result
