"""
Q-Secure | ai/prompt_builder.py
Phase 5 — Structured Prompt Construction.

Converts scan data into token-efficient summaries before sending to Groq.
Never dumps raw JSON — always summarizes into structured text.
"""

from __future__ import annotations


def _summarize_scan(scan: dict) -> str:
    """Compact 300-token summary of a scan result."""
    hostname  = scan.get("target", {}).get("hostname", "?")
    qs        = scan.get("quantum_score") or {}
    cert      = scan.get("certificate") or {}
    kex       = scan.get("key_exchange") or {}
    dnssec    = scan.get("dnssec_result") or {}
    headers   = scan.get("headers_result") or {}
    ssh       = scan.get("ssh_result") or {}
    jwt_r     = scan.get("jwt_result") or {}
    ct        = scan.get("ct_log_result") or {}
    quic      = scan.get("quic_result") or {}
    subs      = scan.get("subdomains") or []
    vulns     = scan.get("vulnerabilities") or []

    tls_13 = any(v.get("version") == "TLSv1.3" and v.get("supported") for v in (scan.get("tls_versions") or []))
    insec  = [v["version"] for v in (scan.get("tls_versions") or []) if v.get("is_insecure") and v.get("supported")]

    return f"""ASSET: {hostname}
SCORE: {qs.get('overall_score', 0):.0f}/100 | GRADE: {qs.get('grade','?')} | LABEL: {qs.get('label','?')} | TIER: {qs.get('tier','?')}
CYBER_RATING: {qs.get('cyber_rating',0):.0f}/1000 | ATTACK_SURFACE: {scan.get('attack_surface_rating','?')}

TLS: version={scan.get('negotiated_tls_version','?')} | tls13={tls_13} | insecure={insec or 'none'}
CERT: algo={cert.get('public_key_algorithm','?')} key={cert.get('public_key_size',0)}b | expired={cert.get('is_expired')} | pqc={cert.get('is_quantum_safe_cert')}
KEX: algo={kex.get('algorithm','?')} | pqc={kex.get('is_post_quantum')} | risk={kex.get('quantum_risk','?')}
SSH: risk={ssh.get('overall_risk','N/A')} | hk_algos={len(ssh.get('host_key_algorithms') or [])}
DNSSEC: enabled={dnssec.get('enabled')} | chain_valid={dnssec.get('chain_valid')} | algo={dnssec.get('dnskey_algorithm','?')}
HEADERS: score={headers.get('security_score',0)} | hsts={headers.get('hsts_enabled')} | csp={headers.get('csp_present')}
CT_LOG: flagged={ct.get('flagged')} | certs={ct.get('total_certs_found',0)} | unexpected_cas={ct.get('unexpected_cas',[])}
JWT: found={len(jwt_r.get('jwts_found') or [])} | risk={jwt_r.get('overall_risk','N/A')}
QUIC: h3={quic.get('h3_advertised')} | flagged={quic.get('flagged')}
SUBDOMAINS: total={len(subs)} | weak_tls={sum(1 for s in subs if s.get('tls_weak'))}
VULNERABILITIES: {len(vulns)} total | critical={sum(1 for v in vulns if v.get('severity') == 'CRITICAL')}"""


def build_executive_prompt(scan: dict, rule_result: dict, hndl_profile: dict) -> tuple[str, str]:
    """
    2–3 paragraph board-level narrative.
    Returns (system_prompt, user_prompt).
    """
    system = (
        "You are Q-Secure's quantum security advisor writing executive briefings for board-level "
        "audiences. Your tone is direct, professional, and serious but not alarmist. "
        "Never use jargon without explanation. Focus on business consequences and urgency. "
        "Write in flowing prose paragraphs, not bullet points."
    )
    scan_summary = _summarize_scan(scan)
    amplifiers = rule_result.get("risk_amplifiers") or []
    top_risks = "\n".join(f"- {a['title']}: {a['description'][:120]}" for a in amplifiers[:3])
    hndl_tier = hndl_profile.get("hndl_risk_tier", "?")

    user = f"""Write a 2–3 paragraph executive summary of this asset's quantum cryptographic risk.

{scan_summary}

TOP CROSS-LAYER RISKS IDENTIFIED:
{top_risks or "No critical cross-layer risks detected."}

HNDL RISK TIER: {hndl_tier}
EFFECTIVE SECURITY SCORE (after cross-layer penalties): {rule_result.get('effective_security_score', 0):.0f}

Requirements:
- Paragraph 1: Overall cryptographic posture in plain language.
- Paragraph 2: Top 3 risks and their business consequences.
- Paragraph 3: Urgency and consequence of inaction.
- Max 250 words total."""

    return system, user


def build_technical_prompt(scan: dict, rule_result: dict, roadmap: dict) -> tuple[str, str]:
    """
    Detailed technical analysis for security engineers.
    Returns (system_prompt, user_prompt).
    """
    system = (
        "You are Q-Secure's cryptographic analysis engine producing technical security reports. "
        "Your audience is security engineers and cryptographers. Be precise, reference NIST standards, "
        "cite specific algorithm names and parameters. Use technical terms without explanation."
    )
    scan_summary = _summarize_scan(scan)
    amplifiers = rule_result.get("risk_amplifiers") or []
    amp_text   = "\n".join(
        f"[{a['rule_id']}] {a['title']} | layers={a['affected_layers']} | impact={a['score_impact']}"
        for a in amplifiers
    )
    phases     = roadmap.get("phases") or []
    phase_summary = "\n".join(
        f"Phase {p['phase_number']} ({p['timeframe']}): {p['phase_name']} — {len(p.get('actions',[]))} actions"
        for p in phases
    )

    user = f"""Produce a technical cryptographic analysis report.

SCAN DATA:
{scan_summary}

CROSS-LAYER RISK AMPLIFIERS:
{amp_text or "None detected."}

MIGRATION PHASES:
{phase_summary or "Not generated."}

Requirements:
- Analyze each quantum-vulnerable component with NIST standard references.
- Identify which FIPS-203/204/205 standards apply to each finding.
- Highlight cross-layer contradictions (e.g., good TLS but vulnerable KEX).
- Note any partial PQC migration patterns.
- Max 400 words."""

    return system, user


def build_migration_prompt(scan: dict, rule_result: dict) -> tuple[str, str]:
    """
    Enhance rule-based roadmap with specific implementation guidance.
    Returns (system_prompt, user_prompt).
    """
    system = (
        "You are a NIST PQC migration specialist. Provide concise, actionable implementation guidance "
        "for migrating financial infrastructure to post-quantum cryptography. Reference specific "
        "OpenSSL commands, configuration parameters, and FIPS standards."
    )
    scan_summary = _summarize_scan(scan)
    amplifiers   = rule_result.get("risk_amplifiers") or []
    top_issue    = amplifiers[0] if amplifiers else {}

    user = f"""Provide targeted PQC migration guidance for this asset.

{scan_summary}

HIGHEST PRIORITY RISK: {top_issue.get('title', 'None')}
{top_issue.get('description', '')}

For each of the following, provide 2–3 specific implementation steps:
1. Immediate action (this week) to reduce HNDL exposure
2. Short-term (1 month): transport layer PQC deployment
3. Medium-term (6 months): full stack PQC

Be specific to the detected configuration above. Max 350 words."""

    return system, user


def build_contradiction_prompt(scan_list: list[dict]) -> tuple[str, str]:
    """
    Takes multiple scan dicts, finds infrastructure-wide patterns.
    Returns (system_prompt, user_prompt).
    """
    system = (
        "You are Q-Secure's enterprise cryptographic intelligence engine. "
        "Analyze patterns across multiple assets to find infrastructure-wide contradictions "
        "and systemic risks invisible when looking at each asset individually."
    )
    summaries = "\n\n".join(_summarize_scan(s) for s in scan_list[:8])

    user = f"""Analyze these {len(scan_list)} assets for enterprise-wide cryptographic patterns.

{summaries}

Identify:
1. Cross-asset patterns (e.g., all assets use same CA, all have missing DNSSEC)
2. Contradictions (e.g., some assets PQC-ready, others CRITICAL — uneven migration)
3. Systemic risks (single point of failure in CA chain, shared SSH infrastructure)
4. Top 3 infrastructure-wide recommendations

Max 400 words. Focus on patterns only visible across multiple assets."""

    return system, user
