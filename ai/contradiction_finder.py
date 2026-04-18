"""
Q-Secure | ai/contradiction_finder.py
Phase 5 — Cross-Layer Contradiction Detection.

Detects conditions where two security controls contradict each other,
creating a false sense of assurance.
"""

from __future__ import annotations
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Contradiction:
    title: str
    layers_involved: list[str]
    description: str
    severity: str                   # CRITICAL / HIGH / MEDIUM
    false_assurance_risk: str       # What the false assurance makes you believe
    resolution: str
    contradiction_id: str = ""

    def to_dict(self) -> dict:
        return {
            "contradiction_id": self.contradiction_id,
            "title": self.title,
            "layers_involved": self.layers_involved,
            "description": self.description,
            "severity": self.severity,
            "false_assurance_risk": self.false_assurance_risk,
            "resolution": self.resolution,
        }


# ---------------------------------------------------------------------------
# Finder
# ---------------------------------------------------------------------------

class ContradictionFinder:

    def find(self, scan: dict) -> list[Contradiction]:
        """Find contradictions within a single scan."""
        contradictions: list[Contradiction] = []

        contradictions.extend(self._c1_strong_tls_missing_dnssec(scan))
        contradictions.extend(self._c2_pqc_ready_vulnerable_jwt(scan))
        contradictions.extend(self._c3_tls13_with_legacy(scan))
        contradictions.extend(self._c4_good_cipher_score_rsa_kex(scan))
        contradictions.extend(self._c5_valid_cert_unexpected_ct(scan))
        contradictions.extend(self._c6_high_score_critical_subdomain(scan))
        contradictions.extend(self._c7_hsts_short_maxage(scan))

        for i, c in enumerate(contradictions, 1):
            c.contradiction_id = f"C{i:02d}"

        return contradictions

    def find_all(self, scan_list: list[dict]) -> list[Contradiction]:
        """Find contradictions across multiple assets (enterprise view)."""
        per_asset = []
        for scan in scan_list:
            per_asset.extend(self.find(scan))

        # Add cross-asset contradictions
        per_asset.extend(self._cross_asset_uneven_migration(scan_list))

        for i, c in enumerate(per_asset, 1):
            c.contradiction_id = f"C{i:02d}"
        return per_asset

    # ------------------------------------------------------------------
    # C1 — Strong TLS + Missing DNSSEC
    # ------------------------------------------------------------------
    def _c1_strong_tls_missing_dnssec(self, scan: dict) -> list[Contradiction]:
        tls_score = (scan.get("quantum_score") or {}).get("tls_version_score", 0)
        dnssec    = scan.get("dnssec_result") or {}
        if tls_score > 70 and not dnssec.get("enabled"):
            return [Contradiction(
                title="Strong TLS + Missing DNSSEC",
                layers_involved=["TLS", "DNSSEC"],
                description=(
                    f"TLS configuration scores {tls_score:.0f}/100 but DNSSEC is disabled. "
                    "An attacker can poison DNS before TLS is ever established, redirecting "
                    "clients to a malicious endpoint — the TLS strength is irrelevant."
                ),
                severity="HIGH",
                false_assurance_risk="Strong TLS score suggests good security, but DNS hijacking bypasses it entirely.",
                resolution="Enable DNSSEC to protect the DNS resolution that precedes TLS handshake.",
            )]
        return []

    # ------------------------------------------------------------------
    # C2 — PQC_READY Label + Vulnerable JWT
    # ------------------------------------------------------------------
    def _c2_pqc_ready_vulnerable_jwt(self, scan: dict) -> list[Contradiction]:
        label = (scan.get("quantum_score") or {}).get("label", "")
        jwt_r = scan.get("jwt_result") or {}
        vuln_algs = [j["algorithm"] for j in (jwt_r.get("jwts_found") or [])
                     if j.get("algorithm") in ("RS256", "ES256", "RS384", "ES384")]
        if label == "PQC_READY" and vuln_algs:
            return [Contradiction(
                title="PQC-Ready Transport + Quantum-Vulnerable JWTs",
                layers_involved=["TLS", "JWT"],
                description=(
                    f"Transport layer is labelled PQC_READY but JWT signing uses "
                    f"{', '.join(set(vuln_algs))}. Quantum-safe transport does not protect "
                    "the application layer tokens — an attacker who harvests JWTs can forge "
                    "authentication tokens."
                ),
                severity="HIGH",
                false_assurance_risk="PQC_READY label implies the system is quantum-safe, but auth tokens remain breakable.",
                resolution="Migrate JWT signing to ML-DSA-65 (FIPS-204) or at minimum EdDSA (Ed25519).",
            )]
        return []

    # ------------------------------------------------------------------
    # C3 — TLS 1.3 + Legacy Protocols Still Enabled
    # ------------------------------------------------------------------
    def _c3_tls13_with_legacy(self, scan: dict) -> list[Contradiction]:
        versions = scan.get("tls_versions") or []
        has_13   = any(v.get("version") == "TLSv1.3" and v.get("supported") for v in versions)
        legacy   = [v["version"] for v in versions if v.get("supported") and v.get("is_insecure")]
        if has_13 and legacy:
            return [Contradiction(
                title="TLS 1.3 Enabled + Legacy Insecure Versions Active",
                layers_involved=["TLS"],
                description=(
                    f"TLS 1.3 is correctly enabled but {', '.join(legacy)} remain active. "
                    "An active network attacker can force a protocol downgrade to the weakest "
                    "supported version, bypassing TLS 1.3's improved security entirely."
                ),
                severity="HIGH",
                false_assurance_risk="TLS 1.3 support implies secure connections, but downgrade to TLS 1.0/SSL is possible.",
                resolution=f"Disable {', '.join(legacy)} in TLS server configuration. Accept only TLS 1.2 and TLS 1.3.",
            )]
        return []

    # ------------------------------------------------------------------
    # C4 — Good Cipher Score + RSA Key Exchange
    # ------------------------------------------------------------------
    def _c4_good_cipher_score_rsa_kex(self, scan: dict) -> list[Contradiction]:
        cipher_score = (scan.get("quantum_score") or {}).get("cipher_quality_score", 0)
        kex = scan.get("key_exchange") or {}
        alg = kex.get("algorithm", "").upper()
        is_rsa_kex = "RSA" in alg and "ECDHE" not in alg and "DHE" not in alg
        if cipher_score > 60 and is_rsa_kex:
            return [Contradiction(
                title="Good Cipher Suite Score + RSA Static Key Exchange",
                layers_involved=["TLS", "Key Exchange"],
                description=(
                    f"Cipher suites score {cipher_score:.0f}/100 (modern AEAD encryption) "
                    f"but RSA static key exchange means there is no forward secrecy. "
                    "All past sessions can be decrypted retroactively if the RSA private key is compromised "
                    "— either by theft or quantum attack."
                ),
                severity="HIGH",
                false_assurance_risk="Good cipher score implies modern encryption, but lack of PFS exposes all historical sessions.",
                resolution="Replace RSA static key exchange with ECDHE or ML-KEM for forward secrecy.",
            )]
        return []

    # ------------------------------------------------------------------
    # C5 — Valid Certificate + Unexpected CT Log Entry
    # ------------------------------------------------------------------
    def _c5_valid_cert_unexpected_ct(self, scan: dict) -> list[Contradiction]:
        cert = scan.get("certificate") or {}
        ct   = scan.get("ct_log_result") or {}
        if not cert.get("is_expired") and (ct.get("flagged") or ct.get("unexpected_cas")):
            unexpected = ct.get("unexpected_cas") or []
            return [Contradiction(
                title="Valid Certificate + Unexpected CT Log Entry",
                layers_involved=["Certificate", "CT Log"],
                description=(
                    "The currently served certificate appears valid but CT logs show certificates "
                    f"issued by unexpected authorities: {', '.join(unexpected) or 'unknown CA'}. "
                    "This could indicate certificate misissuance, a compromised CA, or historical "
                    "MITM attacks."
                ),
                severity="CRITICAL",
                false_assurance_risk="Valid current certificate masks historical or parallel certificate fraud.",
                resolution="Investigate all CT log entries, revoke unexpected certificates, implement CAA DNS records.",
            )]
        return []

    # ------------------------------------------------------------------
    # C6 — High Overall Score + Critical Subdomain Risk
    # ------------------------------------------------------------------
    def _c6_high_score_critical_subdomain(self, scan: dict) -> list[Contradiction]:
        score = (scan.get("quantum_score") or {}).get("overall_score", 0)
        subs  = scan.get("subdomains") or []
        critical_subs = [s for s in subs if s.get("tls_weak")]
        if score > 65 and critical_subs:
            return [Contradiction(
                title="Strong Primary Domain + Weak Subdomain TLS",
                layers_involved=["TLS", "Subdomains"],
                description=(
                    f"Primary domain scores {score:.0f}/100 but {len(critical_subs)} subdomain(s) "
                    f"have weak TLS: {', '.join(s['subdomain'] for s in critical_subs[:3])}. "
                    "Attackers target the weakest surface — the primary domain strength is irrelevant "
                    "if a subdomain can be used as a pivot."
                ),
                severity="HIGH",
                false_assurance_risk="High primary score masks the full attack surface exposed through weaker subdomains.",
                resolution="Apply the same TLS hardening standards to all subdomains. Audit with Q-Secure batch scan.",
            )]
        return []

    # ------------------------------------------------------------------
    # C7 — HSTS Present + max-age Too Short
    # ------------------------------------------------------------------
    def _c7_hsts_short_maxage(self, scan: dict) -> list[Contradiction]:
        headers = scan.get("headers_result") or {}
        if headers.get("hsts_enabled"):
            max_age = headers.get("hsts_max_age", 0)
            if max_age < 2592000:  # Less than 30 days
                return [Contradiction(
                    title="HSTS Present + max-age Too Short",
                    layers_involved=["HTTP Headers"],
                    description=(
                        f"HSTS is enabled but max-age is only {max_age} seconds "
                        f"({max_age // 86400} days). Short HSTS lifetime means clients "
                        "frequently re-check via unprotected HTTP, leaving a window for SSLstrip attacks."
                    ),
                    severity="MEDIUM",
                    false_assurance_risk="HSTS enabled looks compliant but short max-age provides minimal protection.",
                    resolution="Set HSTS max-age to at least 31536000 (1 year); consider includeSubDomains and preload.",
                )]
        return []

    # ------------------------------------------------------------------
    # Cross-asset: Uneven PQC Migration
    # ------------------------------------------------------------------
    def _cross_asset_uneven_migration(self, scan_list: list[dict]) -> list[Contradiction]:
        if len(scan_list) < 2:
            return []
        labels = [(s.get("target", {}).get("hostname", "?"),
                   (s.get("quantum_score") or {}).get("label", ""))
                  for s in scan_list]
        pqc_ready = [h for h, l in labels if l in ("QUANTUM_SAFE", "PQC_READY")]
        not_safe  = [h for h, l in labels if l == "NOT_QUANTUM_SAFE"]
        if pqc_ready and not_safe:
            return [Contradiction(
                title="Uneven Enterprise PQC Migration",
                layers_involved=["Enterprise", "TLS"],
                description=(
                    f"Infrastructure has a split quantum posture: "
                    f"{len(pqc_ready)} assets are PQC-ready ({', '.join(pqc_ready[:3])}) "
                    f"while {len(not_safe)} remain NOT_QUANTUM_SAFE ({', '.join(not_safe[:3])}). "
                    "Uneven migration means attackers simply target the weakest assets."
                ),
                severity="HIGH",
                false_assurance_risk="Partially migrated infrastructure appears more secure than it is — the weakest link dominates.",
                resolution="Prioritize migration of NOT_QUANTUM_SAFE assets. Use Q-Secure batch scan to track enterprise progress.",
            )]
        return []
