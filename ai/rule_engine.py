"""
Q-Secure | ai/rule_engine.py
Phase 5 — Deterministic Cross-Layer Risk Analysis.

Runs on every scan result regardless of Groq availability.
No API dependency. Always produces output.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class RiskAmplifier:
    title: str
    description: str
    severity: str                   # CRITICAL / HIGH / MEDIUM / LOW
    affected_layers: list[str]
    score_impact: float             # Negative value — subtracted from base score
    rule_id: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "affected_layers": self.affected_layers,
            "score_impact": self.score_impact,
        }


@dataclass
class RuleEngineResult:
    asset_hostname: str
    base_score: float               # Original quantum_score.overall_score
    cross_layer_risk_score: float   # Total negative impact from all amplifiers
    effective_security_score: float # base_score + cross_layer_risk_score (clamped 0-100)
    risk_amplifiers: list[RiskAmplifier] = field(default_factory=list)
    priority_rank: int = 0          # 1 = highest priority to fix (set by caller)
    rules_evaluated: int = 0

    def to_dict(self) -> dict:
        return {
            "asset_hostname": self.asset_hostname,
            "base_score": round(self.base_score, 2),
            "cross_layer_risk_score": round(self.cross_layer_risk_score, 2),
            "effective_security_score": round(self.effective_security_score, 2),
            "risk_amplifiers": [a.to_dict() for a in self.risk_amplifiers],
            "priority_rank": self.priority_rank,
            "rules_evaluated": self.rules_evaluated,
        }


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------

# Sensitive endpoint keywords indicating financial data classification
_FINANCIAL_KEYWORDS = {
    "netbanking", "payment", "transfer", "swift", "transaction",
    "credit", "debit", "loan", "account", "wallet", "fin", "bank",
    "invest", "trade", "clearing", "rtgs", "neft",
}

_AUTH_KEYWORDS = {
    "login", "auth", "portal", "secure", "internal", "sso", "admin",
    "identity", "oauth", "token", "api",
}


def _hostname_contains(hostname: str, keywords: set[str]) -> list[str]:
    h = hostname.lower()
    return [kw for kw in keywords if kw in h]


class RuleEngine:
    """
    Stateless deterministic rule evaluator.
    Call evaluate(scan_dict) → RuleEngineResult.
    scan_dict must be the output of ScanResult.to_dict().
    """

    def evaluate(self, scan: dict) -> RuleEngineResult:
        hostname   = scan.get("target", {}).get("hostname", "unknown")
        base_score = (scan.get("quantum_score") or {}).get("overall_score", 0.0)
        amplifiers: list[RiskAmplifier] = []

        amplifiers.extend(self._rule1_false_sense_of_security(scan))
        amplifiers.extend(self._rule2_hndl_critical_window(scan, hostname))
        amplifiers.extend(self._rule3_incomplete_pqc(scan))
        amplifiers.extend(self._rule4_shadow_it_risk(scan))
        amplifiers.extend(self._rule5_management_plane(scan))
        amplifiers.extend(self._rule6_cert_trust_chain(scan))
        amplifiers.extend(self._rule7_protocol_downgrade(scan))
        amplifiers.extend(self._rule8_quic_blind_spot(scan))

        total_impact = sum(a.score_impact for a in amplifiers)
        effective = max(0.0, min(100.0, base_score + total_impact))

        return RuleEngineResult(
            asset_hostname=hostname,
            base_score=base_score,
            cross_layer_risk_score=total_impact,
            effective_security_score=effective,
            risk_amplifiers=amplifiers,
            rules_evaluated=8,
        )

    # ------------------------------------------------------------------
    # Rule 1 — False Sense of Security
    # IF tls_score > 70 AND dnssec_missing → -20
    # ------------------------------------------------------------------
    def _rule1_false_sense_of_security(self, scan: dict) -> list[RiskAmplifier]:
        qs = scan.get("quantum_score") or {}
        tls_score = qs.get("tls_version_score", 0)
        dnssec = scan.get("dnssec_result") or {}
        dnssec_enabled = dnssec.get("enabled", False)

        if tls_score > 70 and not dnssec_enabled:
            return [RiskAmplifier(
                rule_id="R01",
                title="False Sense of Security",
                description=(
                    "Strong TLS configuration (score {:.0f}) is undermined by missing DNSSEC. "
                    "An attacker can poison DNS to redirect clients to a malicious endpoint "
                    "before TLS protections ever engage."
                ).format(tls_score),
                severity="HIGH",
                affected_layers=["TLS", "DNSSEC"],
                score_impact=-20.0,
            )]
        return []

    # ------------------------------------------------------------------
    # Rule 2 — HNDL Critical Window
    # IF KEX is RSA or DHE AND sensitive endpoint → -25
    # ------------------------------------------------------------------
    def _rule2_hndl_critical_window(self, scan: dict, hostname: str) -> list[RiskAmplifier]:
        kex = scan.get("key_exchange") or {}
        alg = kex.get("algorithm", "").upper()
        is_vulnerable_kex = any(x in alg for x in ("RSA", "DHE")) and "ECDHE" not in alg

        signals = _hostname_contains(hostname, _FINANCIAL_KEYWORDS)
        if is_vulnerable_kex and signals:
            return [RiskAmplifier(
                rule_id="R02",
                title="HNDL Critical Window — Financial Endpoint",
                description=(
                    "RSA/DHE key exchange on a financial endpoint ({hostname}) is the highest "
                    "priority Harvest-Now-Decrypt-Later target. Adversaries archiving traffic "
                    "today can decrypt all session data once a cryptographically-relevant "
                    "quantum computer is available. Sensitivity signals: {signals}."
                ).format(hostname=hostname, signals=", ".join(signals)),
                severity="CRITICAL",
                affected_layers=["TLS", "Key Exchange"],
                score_impact=-25.0,
            )]
        return []

    # ------------------------------------------------------------------
    # Rule 3 — Incomplete PQC Migration
    # IF label PQC_READY AND JWT is RS256/ES256 → -15
    # ------------------------------------------------------------------
    def _rule3_incomplete_pqc(self, scan: dict) -> list[RiskAmplifier]:
        label = (scan.get("quantum_score") or {}).get("label", "")
        jwt_result = scan.get("jwt_result") or {}
        jwts = jwt_result.get("jwts_found") or []
        vuln_algs = [j["algorithm"] for j in jwts if j.get("algorithm") in ("RS256", "ES256", "RS384", "ES384")]

        if label == "PQC_READY" and vuln_algs:
            return [RiskAmplifier(
                rule_id="R03",
                title="Incomplete PQC Migration — JWT Layer",
                description=(
                    "Transport layer is PQC-ready but JWT signing remains quantum-vulnerable "
                    "({algs}). This partial migration creates false assurance — the application "
                    "auth tokens can be forged once classical cryptography is broken."
                ).format(algs=", ".join(set(vuln_algs))),
                severity="HIGH",
                affected_layers=["JWT", "TLS"],
                score_impact=-15.0,
            )]
        return []

    # ------------------------------------------------------------------
    # Rule 4 — Shadow IT Cryptographic Risk
    # IF subdomains > 0 AND any have weak TLS → -10 per (max -30)
    # ------------------------------------------------------------------
    def _rule4_shadow_it_risk(self, scan: dict) -> list[RiskAmplifier]:
        subs = scan.get("subdomains") or []
        weak = [s for s in subs if s.get("tls_weak")]
        if not weak:
            return []
        impact = min(30.0, len(weak) * 10.0)
        return [RiskAmplifier(
            rule_id="R04",
            title="Shadow IT Cryptographic Risk",
            description=(
                "{n} discovered subdomain(s) have weaker cryptographic posture than the "
                "primary domain: {subs}. Attackers pivot through the weakest surface."
            ).format(n=len(weak), subs=", ".join(s.get("subdomain", "?") for s in weak[:5])),
            severity="HIGH" if len(weak) >= 3 else "MEDIUM",
            affected_layers=["Subdomains", "TLS"],
            score_impact=-impact,
        )]

    # ------------------------------------------------------------------
    # Rule 5 — Management Plane Exposure
    # IF SSH uses RSA host key AND TLS label NOT_QUANTUM_SAFE → -20
    # ------------------------------------------------------------------
    def _rule5_management_plane(self, scan: dict) -> list[RiskAmplifier]:
        ssh = scan.get("ssh_result") or {}
        hk_algos = ssh.get("host_key_algorithms") or []
        rsa_hk = any("rsa" in a.get("name", "").lower() for a in hk_algos)

        label = (scan.get("quantum_score") or {}).get("label", "")
        if rsa_hk and label == "NOT_QUANTUM_SAFE":
            return [RiskAmplifier(
                rule_id="R05",
                title="Dual-Layer Quantum Exposure",
                description=(
                    "Both the application layer (TLS: NOT_QUANTUM_SAFE) and management plane "
                    "(SSH RSA host key) are quantum-vulnerable. A single quantum attacker "
                    "compromises both data-in-transit and administrative access."
                ),
                severity="CRITICAL",
                affected_layers=["SSH", "TLS"],
                score_impact=-20.0,
            )]
        return []

    # ------------------------------------------------------------------
    # Rule 6 — Certificate Trust Chain Risk
    # IF CT log has unexpected CA or recent unexpected cert → -30
    # ------------------------------------------------------------------
    def _rule6_cert_trust_chain(self, scan: dict) -> list[RiskAmplifier]:
        ct = scan.get("ct_log_result") or {}
        unexpected_cas = ct.get("unexpected_cas") or []
        flagged = ct.get("flagged", False)

        if flagged or unexpected_cas:
            return [RiskAmplifier(
                rule_id="R06",
                title="Certificate Trust Chain Risk",
                description=(
                    "CT logs show certificates issued by unexpected authorities: {cas}. "
                    "This may indicate certificate misissuance, unauthorized CA, or an "
                    "active MITM attack — all amplified by missing HPKP."
                ).format(cas=", ".join(unexpected_cas) if unexpected_cas else "flagged entry"),
                severity="CRITICAL",
                affected_layers=["Certificate", "CT Log"],
                score_impact=-30.0,
            )]
        return []

    # ------------------------------------------------------------------
    # Rule 7 — Protocol Downgrade Window
    # IF TLS 1.3 supported AND TLS 1.0/1.1 also enabled → -15
    # ------------------------------------------------------------------
    def _rule7_protocol_downgrade(self, scan: dict) -> list[RiskAmplifier]:
        versions = scan.get("tls_versions") or []
        has_13 = any(v.get("version") == "TLSv1.3" and v.get("supported") for v in versions)
        legacy  = [v["version"] for v in versions if v.get("supported") and v.get("is_insecure")]

        if has_13 and legacy:
            return [RiskAmplifier(
                rule_id="R07",
                title="Protocol Downgrade Attack Surface",
                description=(
                    "TLS 1.3 is available but legacy insecure versions are still enabled: "
                    "{legacy}. Attackers force downgrade to exploit weaker protocol versions, "
                    "bypassing PFS and modern cipher protections."
                ).format(legacy=", ".join(legacy)),
                severity="HIGH",
                affected_layers=["TLS"],
                score_impact=-15.0,
            )]
        return []

    # ------------------------------------------------------------------
    # Rule 8 — QUIC Blind Spot
    # IF QUIC detected AND not separately assessed → -10
    # ------------------------------------------------------------------
    def _rule8_quic_blind_spot(self, scan: dict) -> list[RiskAmplifier]:
        quic = scan.get("quic_result") or {}
        if quic.get("flagged") or quic.get("h3_advertised"):
            return [RiskAmplifier(
                rule_id="R08",
                title="QUIC / HTTP3 Blind Spot",
                description=(
                    "QUIC/HTTP3 is detected on this host but was not separately assessed for "
                    "quantum cryptographic posture. Standard TCP TLS scans miss the QUIC stack. "
                    "QUIC implementations may use different cipher negotiation."
                ),
                severity="MEDIUM",
                affected_layers=["QUIC", "TLS"],
                score_impact=-10.0,
            )]
        return []
