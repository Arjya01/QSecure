"""
Q-Secure | ai/narrative_generator.py
Phase 5 — Report Narrative Generation.

Two modes:
  1. Groq LLM (when GROQ_API_KEY set and groq installed)
  2. Rule-based fallback (always works offline)

Never shows error state to user — rule-based always succeeds.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .groq_client import GroqClient
from .prompt_builder import (
    build_executive_prompt,
    build_technical_prompt,
    build_migration_prompt,
)
from .rule_engine import RuleEngine


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class NarrativeResult:
    asset_hostname: str
    executive_summary: str
    technical_analysis: str
    key_findings: list[str]
    immediate_actions: list[str]
    generated_by: str               # "GROQ_LLM" or "RULE_BASED"
    generated_at: str
    model_used: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "asset_hostname": self.asset_hostname,
            "executive_summary": self.executive_summary,
            "technical_analysis": self.technical_analysis,
            "key_findings": self.key_findings,
            "immediate_actions": self.immediate_actions,
            "generated_by": self.generated_by,
            "generated_at": self.generated_at,
            "model_used": self.model_used,
        }


@dataclass
class EnterpriseNarrative:
    total_assets: int
    enterprise_summary: str
    critical_patterns: list[str]
    infrastructure_contradictions: list[str]
    top_hndl_targets: list[str]
    enterprise_migration_priority: list[str]
    generated_by: str
    generated_at: str

    def to_dict(self) -> dict:
        return {
            "total_assets": self.total_assets,
            "enterprise_summary": self.enterprise_summary,
            "critical_patterns": self.critical_patterns,
            "infrastructure_contradictions": self.infrastructure_contradictions,
            "top_hndl_targets": self.top_hndl_targets,
            "enterprise_migration_priority": self.enterprise_migration_priority,
            "generated_by": self.generated_by,
            "generated_at": self.generated_at,
        }


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

class NarrativeGenerator:

    def __init__(self):
        self._groq   = GroqClient()
        self._engine = RuleEngine()

    # ------------------------------------------------------------------
    # Single asset narrative
    # ------------------------------------------------------------------
    def generate_narrative(
        self,
        scan: dict,
        rule_result: Optional[dict] = None,
        hndl_profile: Optional[dict] = None,
        roadmap: Optional[dict] = None,
    ) -> NarrativeResult:
        if rule_result is None:
            rule_result = self._engine.evaluate(scan).to_dict()
        if hndl_profile is None:
            from .hndl_ranker import HNDLRanker
            hndl_profile = HNDLRanker().score(scan).to_dict()
        if roadmap is None:
            from .migration_planner import MigrationPlanner
            roadmap = MigrationPlanner().generate(scan).to_dict()

        if self._groq.is_available():
            result = self._groq_narrative(scan, rule_result, hndl_profile, roadmap)
            if result:
                return result

        return self._rule_based_narrative(scan, rule_result, hndl_profile, roadmap)

    def _groq_narrative(self, scan, rule_result, hndl_profile, roadmap) -> Optional[NarrativeResult]:
        try:
            sys_exec, usr_exec = build_executive_prompt(scan, rule_result, hndl_profile)
            executive = self._groq.complete(sys_exec, usr_exec, max_tokens=400)
            if not executive:
                return None

            sys_tech, usr_tech = build_technical_prompt(scan, rule_result, roadmap)
            technical = self._groq.complete(sys_tech, usr_tech, max_tokens=600, fast_mode=False)

            hostname = scan.get("target", {}).get("hostname", "unknown")
            amplifiers = rule_result.get("risk_amplifiers") or []
            actions = roadmap.get("phases", [{}])[0].get("actions", []) if roadmap.get("phases") else []

            return NarrativeResult(
                asset_hostname=hostname,
                executive_summary=executive or "",
                technical_analysis=technical or self._build_rule_technical(scan, rule_result),
                key_findings=[a["title"] for a in amplifiers[:5]],
                immediate_actions=[a["title"] for a in actions[:4]],
                generated_by="GROQ_LLM",
                generated_at=datetime.now(timezone.utc).isoformat(),
                model_used=GroqClient.PRIMARY_MODEL,
            )
        except Exception:
            return None

    def _rule_based_narrative(self, scan, rule_result, hndl_profile, roadmap) -> NarrativeResult:
        hostname  = scan.get("target", {}).get("hostname", "unknown")
        qs        = scan.get("quantum_score") or {}
        score     = qs.get("overall_score", 0)
        label     = qs.get("label", "UNKNOWN")
        grade     = qs.get("grade", "?")
        effective = rule_result.get("effective_security_score", score)
        amplifiers = rule_result.get("risk_amplifiers") or []
        hndl_tier = hndl_profile.get("hndl_risk_tier", "UNKNOWN")

        executive = (
            f"{hostname} has a quantum safety score of {score:.0f}/100 (grade {grade}), "
            f"classified as {label.replace('_',' ')}. "
        )
        if effective < score:
            executive += (
                f"Cross-layer analysis identifies {len(amplifiers)} risk amplifiers that reduce the "
                f"effective security score to {effective:.0f}/100 — meaning individual surface scores "
                f"overstate the actual security posture. "
            )
        if hndl_tier in ("CRITICAL", "HIGH"):
            executive += (
                f"This asset is classified {hndl_tier} HNDL priority: adversaries are likely archiving "
                f"encrypted traffic today for future quantum decryption. "
            )
        if score < 40:
            executive += (
                "Immediate remediation is required. The current cryptographic configuration provides "
                "no meaningful protection against a cryptographically-relevant quantum computer. "
                "All encrypted sessions are at risk of retroactive decryption."
            )
        elif score < 70:
            executive += (
                "Significant remediation effort is needed within the next quarter to reduce "
                "HNDL exposure and achieve a defensible quantum posture before the threat window narrows."
            )
        else:
            executive += (
                "The asset has reasonable quantum posture but cross-layer risks must be addressed "
                "to achieve full ELITE_PQC certification."
            )

        technical = self._build_rule_technical(scan, rule_result)

        key_findings = [a["title"] for a in amplifiers[:5]]
        if not key_findings:
            key_findings = [f"Base quantum score: {score:.0f}/100 ({label.replace('_',' ')})"]

        phases = roadmap.get("phases") or []
        immediate_actions = []
        for phase in phases[:2]:
            for action in (phase.get("actions") or [])[:2]:
                immediate_actions.append(action["title"])

        return NarrativeResult(
            asset_hostname=hostname,
            executive_summary=executive,
            technical_analysis=technical,
            key_findings=key_findings,
            immediate_actions=immediate_actions,
            generated_by="RULE_BASED",
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def _build_rule_technical(self, scan: dict, rule_result: dict) -> str:
        qs     = scan.get("quantum_score") or {}
        cert   = scan.get("certificate") or {}
        kex    = scan.get("key_exchange") or {}
        subs   = scan.get("subdomains") or []
        vulns  = scan.get("vulnerabilities") or []
        amplifiers = rule_result.get("risk_amplifiers") or []

        lines = [
            f"Score breakdown: TLS version={qs.get('tls_version_score',0):.0f} | "
            f"Cipher quality={qs.get('cipher_quality_score',0):.0f} | "
            f"Cert strength={qs.get('certificate_strength_score',0):.0f} | "
            f"KEX={qs.get('key_exchange_score',0):.0f}",
            f"Certificate: {cert.get('public_key_algorithm','?')} {cert.get('public_key_size',0)}b | "
            f"quantum-safe={cert.get('is_quantum_safe_cert')}",
            f"Key exchange: {kex.get('algorithm','?')} | PQC={kex.get('is_post_quantum')} | "
            f"risk={kex.get('quantum_risk','?')}",
            f"Subdomains: {len(subs)} total | weak-TLS={sum(1 for s in subs if s.get('tls_weak'))}",
            f"Vulnerabilities: {len(vulns)} | critical={sum(1 for v in vulns if v.get('severity')=='CRITICAL')}",
            "",
            "Cross-layer risk amplifiers:",
        ]
        for a in amplifiers:
            lines.append(
                f"  [{a['rule_id']}] {a['title']} "
                f"(layers: {', '.join(a['affected_layers'])}, impact: {a['score_impact']:+.0f})"
            )
        if not amplifiers:
            lines.append("  None detected.")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Enterprise narrative across multiple assets
    # ------------------------------------------------------------------
    def generate_enterprise(self, scan_list: list[dict]) -> EnterpriseNarrative:
        from .prompt_builder import build_contradiction_prompt
        from .contradiction_finder import ContradictionFinder
        from .hndl_ranker import HNDLRanker

        hostnames = [s.get("target", {}).get("hostname", "?") for s in scan_list]
        hndl_profiles = HNDLRanker().rank(scan_list)
        contradictions = ContradictionFinder().find_all(scan_list)

        # Try Groq for enterprise summary
        enterprise_text = None
        generated_by = "RULE_BASED"
        if self._groq.is_available() and scan_list:
            sys_p, usr_p = build_contradiction_prompt(scan_list)
            enterprise_text = self._groq.complete(sys_p, usr_p, max_tokens=600)
            if enterprise_text:
                generated_by = "GROQ_LLM"

        if not enterprise_text:
            scores = [(s.get("target", {}).get("hostname", "?"),
                       (s.get("quantum_score") or {}).get("overall_score", 0))
                      for s in scan_list]
            avg = sum(sc for _, sc in scores) / len(scores) if scores else 0
            critical_count = sum(1 for _, sc in scores if sc < 30)
            enterprise_text = (
                f"Enterprise analysis of {len(scan_list)} assets. "
                f"Average quantum score: {avg:.0f}/100. "
                f"{critical_count} assets in CRITICAL tier require immediate attention. "
                f"{len(contradictions)} cross-layer contradictions detected across the infrastructure."
            )

        return EnterpriseNarrative(
            total_assets=len(scan_list),
            enterprise_summary=enterprise_text,
            critical_patterns=[c.title for c in contradictions[:5]],
            infrastructure_contradictions=[c.description for c in contradictions[:3]],
            top_hndl_targets=[p.asset_hostname for p in hndl_profiles[:3] if p.hndl_risk_tier in ("CRITICAL", "HIGH")],
            enterprise_migration_priority=hostnames[:5],
            generated_by=generated_by,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )
