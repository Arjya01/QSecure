"""
Q-Secure | backend/services/ai_service.py
Phase 5 — AI service layer between routes and ai/ package.
"""

from __future__ import annotations
import sys, os, json
from datetime import datetime, timezone

# Reach the ai/ package
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _ROOT)

from ai.rule_engine import RuleEngine
from ai.hndl_ranker import HNDLRanker
from ai.anomaly_detector import AnomalyDetector
from ai.migration_planner import MigrationPlanner
from ai.narrative_generator import NarrativeGenerator
from ai.contradiction_finder import ContradictionFinder
from ai.groq_client import GroqClient
from ai.prompt_builder import build_migration_prompt

from extensions import db
from models.scan import ScanResult

# Singletons
_rule_engine  = RuleEngine()
_hndl_ranker  = HNDLRanker()
_anomaly_det  = AnomalyDetector()
_migration_pl = MigrationPlanner()
_narrative_g  = NarrativeGenerator()
_contra_find  = ContradictionFinder()
_groq         = GroqClient()


def _get_scan_data(asset_id: int) -> tuple[dict | None, dict | None]:
    """Return (latest_scan_dict, previous_scan_dict) for an asset."""
    scans = (ScanResult.query
             .filter_by(asset_id=asset_id)
             .order_by(ScanResult.started_at.desc())
             .limit(2).all())
    latest   = scans[0].get_scan_data() if len(scans) >= 1 else None
    previous = scans[1].get_scan_data() if len(scans) >= 2 else None
    return latest, previous


# ---------------------------------------------------------------------------
# Analyze single asset
# ---------------------------------------------------------------------------

def analyze_asset(asset_id: int) -> dict:
    latest, previous = _get_scan_data(asset_id)
    if not latest:
        return {"error": "No scan data found for asset"}

    rule_result    = _rule_engine.evaluate(latest).to_dict()
    hndl_profile   = _hndl_ranker.score(latest).to_dict()
    roadmap        = _migration_pl.generate(latest).to_dict()
    contradictions = [c.to_dict() for c in _contra_find.find(latest)]
    anomalies      = None
    if previous:
        anomalies = _anomaly_det.compare(previous, latest).to_dict()

    return {
        "asset_id": asset_id,
        "rule_result": rule_result,
        "hndl_profile": hndl_profile,
        "roadmap": roadmap,
        "contradictions": contradictions,
        "anomalies": anomalies,
        "groq_available": _groq.is_available(),
    }


# ---------------------------------------------------------------------------
# Enterprise analysis (all assets)
# ---------------------------------------------------------------------------

def analyze_enterprise(asset_ids: list[int]) -> dict:
    scan_list = []
    asset_analyses = []

    for aid in asset_ids:
        latest, previous = _get_scan_data(aid)
        if latest:
            scan_list.append(latest)
            rule_result = _rule_engine.evaluate(latest).to_dict()
            anomaly_data = _anomaly_det.compare(previous, latest).to_dict() if previous else None
            asset_analyses.append({
                "asset_id": aid,
                "hostname": latest.get("target", {}).get("hostname", ""),
                "quantum_score": (latest.get("quantum_score") or {}).get("overall_score", 0),
                "label": (latest.get("quantum_score") or {}).get("label", ""),
                "rule_result": rule_result,
                "anomaly": anomaly_data,
            })

    if not scan_list:
        return {"error": "No scan data found"}

    hndl_profiles  = [p.to_dict() for p in _hndl_ranker.rank(scan_list)]
    contradictions = [c.to_dict() for c in _contra_find.find_all(scan_list)]
    narrative      = _narrative_g.generate_enterprise(scan_list).to_dict()

    # Aggregate all rule findings with asset context
    rule_findings = []
    for analysis in asset_analyses:
        for amp in analysis["rule_result"].get("risk_amplifiers", []):
            rule_findings.append({**amp, "asset_hostname": analysis["hostname"]})

    # Link asset_id into HNDL profiles
    hostname_to_aid = {a["hostname"]: a["asset_id"] for a in asset_analyses}
    for profile in hndl_profiles:
        hn = profile.get("asset_hostname", "")
        if hn in hostname_to_aid:
            profile["asset_id"] = hostname_to_aid[hn]

    # Summary stats
    effective_scores = [
        a["rule_result"]["effective_security_score"]
        for a in asset_analyses
        if a["rule_result"].get("effective_security_score") is not None
    ]
    harvest_open = sum(1 for p in hndl_profiles if p.get("harvest_window_open"))
    degradations = sum(
        1 for a in asset_analyses
        if a["anomaly"] and a["anomaly"].get("degradation_detected")
    )

    return {
        "total_assets": len(scan_list),
        "hndl_profiles": hndl_profiles,
        "contradictions": contradictions,
        "enterprise_narrative": narrative,
        "rule_findings": rule_findings,
        "asset_analyses": asset_analyses,
        "effective_score_avg": round(sum(effective_scores) / len(effective_scores), 1) if effective_scores else 0,
        "harvest_windows_open": harvest_open,
        "degradations_detected": degradations,
        "groq_available": _groq.is_available(),
    }


# ---------------------------------------------------------------------------
# Migration roadmap
# ---------------------------------------------------------------------------

def get_roadmap(asset_id: int, ai_enhance: bool = True) -> dict:
    latest, _ = _get_scan_data(asset_id)
    if not latest:
        return {"error": "No scan data found"}

    roadmap = _migration_pl.generate(latest)

    if ai_enhance and _groq.is_available():
        rule_result = _rule_engine.evaluate(latest).to_dict()
        sys_p, usr_p = build_migration_prompt(latest, rule_result)
        ai_guidance  = _groq.complete(sys_p, usr_p, max_tokens=600)
        if ai_guidance:
            roadmap.ai_enhanced = True
            if roadmap.phases:
                roadmap.phases[0].risk_if_delayed = (
                    roadmap.phases[0].risk_if_delayed + "\n\nAI Guidance: " + ai_guidance
                )

    return roadmap.to_dict()


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------

def get_anomalies(asset_id: int) -> dict:
    latest, previous = _get_scan_data(asset_id)
    if not latest:
        return {"error": "No scan data found"}
    if not previous:
        return {"asset_id": asset_id, "message": "Only one scan available — need 2+ scans for comparison"}

    return _anomaly_det.compare(previous, latest).to_dict()


# ---------------------------------------------------------------------------
# HNDL ranking across all assets
# ---------------------------------------------------------------------------

def get_hndl_ranking(asset_ids: list[int]) -> dict:
    scan_list = []
    for aid in asset_ids:
        latest, _ = _get_scan_data(aid)
        if latest:
            scan_list.append((aid, latest))

    profiles = []
    for aid, scan in scan_list:
        p = _hndl_ranker.score(scan).to_dict()
        p["asset_id"] = aid
        profiles.append(p)

    profiles.sort(key=lambda p: p["hndl_risk_score"], reverse=True)
    return {"rankings": profiles, "total": len(profiles)}


# ---------------------------------------------------------------------------
# Dashboard helpers  (used by routes/dashboard.py)
# ---------------------------------------------------------------------------

def generate_enterprise_insight(stats: dict) -> dict:
    """
    Return a concise AI-generated insight string from enterprise stats.
    Falls back to a rule-based summary when Groq is unavailable.
    """
    total    = stats.get("total_assets", 0)
    critical = stats.get("risk_distribution", {}).get("critical", 0)
    not_safe = stats.get("label_distribution", {}).get("NOT_QUANTUM_SAFE", 0)
    avg_score = stats.get("average_quantum_score", 0)
    cyber     = stats.get("enterprise_cyber_rating", {}).get("score", 0)

    if _groq.is_available():
        sys_prompt = (
            "You are a quantum-security analyst writing a 2-sentence executive insight "
            "for a CISO dashboard. Be concise, factual, and action-oriented."
        )
        user_prompt = (
            f"Enterprise snapshot: {total} assets, {critical} critical-risk assets, "
            f"{not_safe} assets NOT_QUANTUM_SAFE, average quantum score {avg_score:.1f}/100, "
            f"cyber rating {cyber:.0f}/1000. "
            "Write a 2-sentence insight highlighting the main risk and recommended priority."
        )
        text = _groq.complete(sys_prompt, user_prompt, max_tokens=150, fast_mode=True)
        if text:
            return {"insight": text, "generated_by": "GROQ_LLM"}

    # Rule-based fallback
    if critical > 0:
        insight = (
            f"{critical} of {total} assets are at critical quantum risk — immediate TLS and key-exchange "
            f"remediation is required. Target ML-KEM-768 hybrid deployment within 90 days."
        )
    elif not_safe > total // 2:
        insight = (
            f"Over half of your {total} assets remain quantum-unsafe (avg score {avg_score:.0f}/100). "
            f"Prioritise cipher-suite upgrades and DNSSEC hardening across the estate."
        )
    else:
        insight = (
            f"Quantum posture is partially hardened — avg score {avg_score:.0f}/100, "
            f"cyber rating {cyber:.0f}/1000. Continue PQC migration to eliminate remaining legacy ciphers."
        )
    return {"insight": insight, "generated_by": "RULE_ENGINE"}


def generate_action_plan(stats: dict, details: dict) -> dict:
    """
    Return a prioritised action plan based on enterprise stats + scan details.
    Falls back to a rule-based plan when Groq is unavailable.
    """
    total    = stats.get("total_assets", 0)
    critical = stats.get("risk_distribution", {}).get("critical", 0)
    cbom     = details.get("cbom", [])
    vulns    = details.get("vulnerabilities", [])
    ciphers  = details.get("ciphers", [])

    if _groq.is_available():
        sys_prompt = (
            "You are a quantum-security engineer. Produce a JSON action plan with keys: "
            "'immediate' (list of ≤3 strings), 'short_term' (list of ≤3 strings), "
            "'long_term' (list of ≤3 strings). Each item is one concrete action."
        )
        cbom_names = [c.get("algorithm") or c.get("name", "") for c in cbom[:10]]
        vuln_names = [v.get("name") or v.get("type", "") for v in vulns[:6]]
        user_prompt = (
            f"Enterprise: {total} assets, {critical} critical. "
            f"Detected algorithms: {cbom_names}. Vulnerabilities: {vuln_names}. "
            "Return only valid JSON, no extra text."
        )
        text = _groq.complete(sys_prompt, user_prompt, max_tokens=400, fast_mode=True)
        if text:
            import re
            m = re.search(r"\{.*\}", text, re.DOTALL)
            if m:
                try:
                    plan = json.loads(m.group())
                    plan["generated_by"] = "GROQ_LLM"
                    return plan
                except json.JSONDecodeError:
                    pass

    # Rule-based fallback
    plan: dict = {"immediate": [], "short_term": [], "long_term": [], "generated_by": "RULE_ENGINE"}

    weak_algs = {c.get("algorithm") or c.get("name", "") for c in cbom
                 if (c.get("quantum_risk") or c.get("risk", "")) in ("HIGH", "CRITICAL")}

    if critical > 0:
        plan["immediate"].append(f"Remediate {critical} critical-risk assets — disable RSA KEX and TLS 1.0/1.1 immediately")
    if "RSA" in str(weak_algs) or "DHE" in str(weak_algs):
        plan["immediate"].append("Replace RSA/DHE key exchange with X25519 or ML-KEM-768 hybrid on all TLS endpoints")
    if vulns:
        plan["immediate"].append(f"Patch {len(vulns)} detected vulnerabilities (BEAST, POODLE, ROBOT patterns)")

    plan["short_term"] = [
        "Deploy DNSSEC on all public-facing domains to close HNDL attack surface",
        "Enable HSTS with max-age ≥ 31536000 and includeSubDomains across the estate",
        "Rotate RSA certificates to ECDSA P-256 or Ed25519 as interim step",
    ]
    plan["long_term"] = [
        "Complete ML-KEM-768 hybrid TLS rollout on all assets (FIPS-203)",
        "Migrate JWT signing to ML-DSA (FIPS-204) on all authentication services",
        "Establish quarterly PQC posture reviews and automate regression detection",
    ]
    # Trim to 3 items max
    for key in ("immediate", "short_term", "long_term"):
        plan[key] = plan[key][:3]

    return plan


# ---------------------------------------------------------------------------
# Narrative generation
# ---------------------------------------------------------------------------

def generate_narrative(asset_id: int) -> dict:
    latest, _ = _get_scan_data(asset_id)
    if not latest:
        return {"error": "No scan data found"}

    rule_result  = _rule_engine.evaluate(latest).to_dict()
    hndl_profile = _hndl_ranker.score(latest).to_dict()
    roadmap      = _migration_pl.generate(latest).to_dict()

    result = _narrative_g.generate_narrative(latest, rule_result, hndl_profile, roadmap)
    return result.to_dict()
