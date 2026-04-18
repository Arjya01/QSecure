"""
Q-Secure | ai/hndl_ranker.py
Phase 5 — Harvest Now Decrypt Later Priority Scoring.

Calculates which assets are highest-priority targets for adversaries
who are archiving encrypted traffic today to decrypt with future quantum computers.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Sensitivity signal sets
# ---------------------------------------------------------------------------

_HIGH_SENSITIVITY = {
    "netbanking", "payment", "transfer", "swift", "transaction",
    "credit", "debit", "loan", "account", "wallet", "clearing",
    "rtgs", "neft", "trade", "invest", "fintech", "treasury",
}

_MEDIUM_SENSITIVITY = {
    "login", "auth", "portal", "secure", "internal", "sso",
    "identity", "oauth", "api", "admin", "dashboard", "mgmt",
}

_LOW_SENSITIVITY = {
    "static", "cdn", "assets", "img", "media", "docs", "blog",
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class HNDLProfile:
    asset_hostname: str
    hndl_risk_score: float              # 0–100
    hndl_risk_tier: str                 # CRITICAL / HIGH / MEDIUM / LOW
    data_sensitivity_signals: list[str]
    time_to_quantum_threat: str         # e.g. "5–10 years"
    harvest_window_open: bool           # True if RSA/DHE key exchange is active
    reasoning: str
    scored_at: str = ""

    def to_dict(self) -> dict:
        return {
            "asset_hostname": self.asset_hostname,
            "hndl_risk_score": round(self.hndl_risk_score, 2),
            "hndl_risk_tier": self.hndl_risk_tier,
            "data_sensitivity_signals": self.data_sensitivity_signals,
            "time_to_quantum_threat": self.time_to_quantum_threat,
            "harvest_window_open": self.harvest_window_open,
            "reasoning": self.reasoning,
            "scored_at": self.scored_at,
        }


# ---------------------------------------------------------------------------
# Ranker
# ---------------------------------------------------------------------------

class HNDLRanker:
    """
    Score a single scan dict and produce an HNDLProfile.
    Higher hndl_risk_score = higher priority for adversaries.
    """

    def score(self, scan: dict) -> HNDLProfile:
        hostname = scan.get("target", {}).get("hostname", "unknown")
        h = hostname.lower()
        score = 0.0
        signals: list[str] = []
        reasons: list[str] = []

        # --- Hostname sensitivity signals ---
        for kw in _HIGH_SENSITIVITY:
            if kw in h:
                score += 20
                signals.append(f"High: '{kw}' in hostname")
                reasons.append(f"hostname pattern '{kw}' indicates financial/high-value data")

        for kw in _MEDIUM_SENSITIVITY:
            if kw in h:
                score += 10
                signals.append(f"Medium: '{kw}' in hostname")
                reasons.append(f"hostname pattern '{kw}' indicates auth/admin surface")

        for kw in _LOW_SENSITIVITY:
            if kw in h:
                score = max(0, score - 10)
                signals.append(f"Low-value: '{kw}' in hostname")

        # --- Key exchange vulnerability ---
        kex = scan.get("key_exchange") or {}
        kex_alg = kex.get("algorithm", "").upper()
        harvest_window = False
        if any(x in kex_alg for x in ("RSA", "DHE")) and "ECDHE" not in kex_alg:
            score += 25
            harvest_window = True
            signals.append("RSA/DHE key exchange — no forward secrecy")
            reasons.append("RSA/DHE key exchange archives all session keys; decryptable on future CRQC")
        elif not kex.get("is_post_quantum"):
            score += 10
            harvest_window = True
            signals.append("Classical key exchange — vulnerable to HNDL")
            reasons.append("Classical key exchange can be broken by Shor's algorithm")
        else:
            reasons.append("Post-quantum key exchange detected — HNDL window partially closed")

        # --- Certificate long-lived (long validity = more archived traffic) ---
        cert = scan.get("certificate") or {}
        not_before = cert.get("not_before")
        not_after  = cert.get("not_after")
        if not_before and not_after:
            try:
                nb = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
                na = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                validity_days = (na - nb).days
                if validity_days > 730:
                    score += 10
                    signals.append(f"Long-lived certificate ({validity_days} days)")
                    reasons.append("Long validity period extends the HNDL harvest window")
            except Exception:
                pass

        # --- No PFS (no forward secrecy in cipher suites) ---
        ciphers = scan.get("ciphers") or []
        non_pfs = [c for c in ciphers if not c.get("is_forward_secret")]
        if len(non_pfs) > len(ciphers) / 2 and ciphers:
            score += 10
            signals.append(f"{len(non_pfs)}/{len(ciphers)} ciphers lack forward secrecy")
            reasons.append("Non-PFS ciphers allow retroactive decryption of archived sessions")

        # --- Admin interfaces (high-value secondary target) ---
        ssh = scan.get("ssh_result") or {}
        if ssh and not ssh.get("error"):
            score += 5
            signals.append("SSH management plane exposed")
            reasons.append("SSH access allows lateral movement once keys are cracked")

        # Cap at 100
        score = min(100.0, score)

        # Tier assignment
        if score >= 70:
            tier = "CRITICAL"
        elif score >= 45:
            tier = "HIGH"
        elif score >= 20:
            tier = "MEDIUM"
        else:
            tier = "LOW"

        reasoning = " | ".join(reasons) if reasons else "No significant HNDL risk signals detected."

        return HNDLProfile(
            asset_hostname=hostname,
            hndl_risk_score=score,
            hndl_risk_tier=tier,
            data_sensitivity_signals=signals,
            time_to_quantum_threat="5–10 years (NIST estimate for CRQC)",
            harvest_window_open=harvest_window,
            reasoning=reasoning,
            scored_at=datetime.now(timezone.utc).isoformat(),
        )

    def rank(self, scan_list: list[dict]) -> list[HNDLProfile]:
        """Score and rank multiple assets. Returns sorted by HNDL risk descending."""
        profiles = [self.score(s) for s in scan_list]
        return sorted(profiles, key=lambda p: p.hndl_risk_score, reverse=True)
