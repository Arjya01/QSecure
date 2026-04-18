"""
Q-Secure | dnssec_checker.py
Check DNSSEC enablement and chain of trust using dnspython.
Fails gracefully if dnspython is not installed.
"""

from __future__ import annotations

from typing import Optional

from .models import DNSSECResult, QuantumRiskLevel


# ---------------------------------------------------------------------------
# DNSKEY algorithm numbers → quantum risk
# RFC 8624 algorithm numbers
# ---------------------------------------------------------------------------

_DNSKEY_ALGO_MAP: dict[int, tuple[str, QuantumRiskLevel, bool]] = {
    1:  ("RSA/MD5",       QuantumRiskLevel.CRITICAL, False),
    3:  ("DSA/SHA-1",     QuantumRiskLevel.CRITICAL, False),
    5:  ("RSA/SHA-1",     QuantumRiskLevel.CRITICAL, False),
    6:  ("DSA-NSEC3/SHA1",QuantumRiskLevel.CRITICAL, False),
    7:  ("RSASHA1-NSEC3", QuantumRiskLevel.CRITICAL, False),
    8:  ("RSA/SHA-256",   QuantumRiskLevel.HIGH,     False),
    10: ("RSA/SHA-512",   QuantumRiskLevel.HIGH,     False),
    12: ("GOST R 34.10",  QuantumRiskLevel.HIGH,     False),
    13: ("ECDSA P-256",   QuantumRiskLevel.HIGH,     False),
    14: ("ECDSA P-384",   QuantumRiskLevel.HIGH,     False),
    15: ("Ed25519",       QuantumRiskLevel.MEDIUM,   False),
    16: ("Ed448",         QuantumRiskLevel.LOW,      True),   # Best classical, most quantum-safe classical option
}


def _algo_info(algo_num: int) -> tuple[str, QuantumRiskLevel, bool]:
    return _DNSKEY_ALGO_MAP.get(algo_num, (f"Unknown({algo_num})", QuantumRiskLevel.HIGH, False))


# ---------------------------------------------------------------------------
# Public checker
# ---------------------------------------------------------------------------

def check_dnssec(hostname: str, timeout: float = 5.0) -> DNSSECResult:
    """
    Check DNSSEC status for the given hostname.
    Returns a DNSSECResult. Never raises.
    """
    try:
        import dns.resolver
        import dns.dnssec
        import dns.rdatatype
        import dns.flags
    except ImportError:
        return DNSSECResult(
            enabled=False,
            error="dnspython not installed — run: pip install dnspython",
            notes="Install dnspython to enable DNSSEC checking",
            quantum_risk=QuantumRiskLevel.HIGH,
        )

    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.use_edns(0, dns.flags.DO, 1232)  # Request DNSSEC data

        # Step 1: Check for DS record at parent (indicates DNSSEC delegation)
        ds_found = False
        parent = ".".join(hostname.split(".")[1:]) if "." in hostname else hostname
        try:
            resolver.resolve(hostname, "DS")
            ds_found = True
        except Exception:
            pass

        # Step 2: Check for DNSKEY record at zone apex
        dnskey_algo_num = 0
        try:
            ans = resolver.resolve(hostname, "DNSKEY")
            for rdata in ans:
                dnskey_algo_num = rdata.algorithm
                break
        except Exception:
            pass

        # Step 3: Check for RRSIG on A record
        rrsig_found = False
        try:
            ans = resolver.resolve(hostname, "A")
            # Check if response has DNSSEC data
            if ans.response.flags & dns.flags.AD:
                rrsig_found = True
        except Exception:
            pass

        # Determine if DNSSEC is enabled
        enabled = ds_found or rrsig_found or (dnskey_algo_num > 0)

        algo_name, risk, algo_safe = _algo_info(dnskey_algo_num) if dnskey_algo_num else ("None", QuantumRiskLevel.HIGH, False)

        # If DNSSEC not enabled at all, risk is HIGH
        if not enabled:
            return DNSSECResult(
                enabled=False,
                chain_valid=False,
                ds_record_found=False,
                rrsig_found=False,
                quantum_risk=QuantumRiskLevel.HIGH,
                notes="DNSSEC not enabled — DNS responses can be spoofed (DNS cache poisoning attacks)",
            )

        chain_valid = ds_found and rrsig_found

        return DNSSECResult(
            enabled=True,
            chain_valid=chain_valid,
            dnskey_algorithm=algo_name,
            dnskey_algorithm_safe=algo_safe,
            ds_record_found=ds_found,
            rrsig_found=rrsig_found,
            quantum_risk=risk if enabled else QuantumRiskLevel.HIGH,
            notes=(
                f"DNSSEC enabled with {algo_name}. "
                + ("Chain of trust validated." if chain_valid else "Chain of trust incomplete.")
            ),
        )

    except Exception as exc:
        return DNSSECResult(
            enabled=False,
            error=str(exc),
            quantum_risk=QuantumRiskLevel.HIGH,
            notes="DNSSEC check failed — treating as not enabled",
        )
