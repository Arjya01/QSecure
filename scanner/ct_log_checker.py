"""
Q-Secure | ct_log_checker.py
Query crt.sh API for certificate transparency log data.
Flags unexpected CAs and recently issued certificates.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Optional

from .models import CTLogResult, CTCertEntry


# Known legitimate CAs for PNB-like banking infrastructure
_KNOWN_BANKING_CAS = {
    "digicert", "globalsign", "sectigo", "comodo", "entrust",
    "godaddy", "verisign", "symantec", "let's encrypt", "letsencrypt",
    "amazon", "cloudflare", "microsoft", "google", "nist",
    "national informatics centre", "nic", "controller of certifying authorities",
}


def _is_unexpected_ca(issuer: str) -> bool:
    """Check if issuer is not from a known/expected CA set."""
    lower = issuer.lower()
    return not any(k in lower for k in _KNOWN_BANKING_CAS)


def _parse_date(date_str: Optional[str]) -> Optional[datetime]:
    """Parse ISO date from crt.sh response."""
    if not date_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(date_str[:19], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def check_ct_logs(hostname: str, timeout: float = 10.0) -> CTLogResult:
    """
    Query crt.sh for CT log entries for the domain.
    Returns CTLogResult. Never raises.
    """
    try:
        import requests
    except ImportError:
        return CTLogResult(
            error="requests not installed — run: pip install requests",
        )

    # Strip leading wildcard/subdomain to query the apex domain
    apex = hostname.lstrip("*.")

    try:
        resp = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{apex}", "output": "json"},
            timeout=timeout,
            headers={"User-Agent": "QSecure-Scanner/2.0"},
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        return CTLogResult(
            error=str(exc),
            notes="Failed to query crt.sh — check network connectivity",
        )

    if not isinstance(data, list):
        return CTLogResult(notes="crt.sh returned unexpected response format")

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=30)

    entries: list[CTCertEntry] = []
    unexpected_cas: set[str] = set()
    recent_count = 0
    seen_ids: set[str] = set()

    for item in data[:200]:  # Cap at 200 to avoid huge payloads
        cert_id = str(item.get("id", ""))
        if cert_id in seen_ids:
            continue
        seen_ids.add(cert_id)

        issuer = item.get("issuer_name", "") or item.get("issuer_ca_id", "")
        not_before_str = item.get("not_before") or item.get("entry_timestamp")
        not_after_str  = item.get("not_after")
        common_name    = item.get("common_name", "")
        name_value     = item.get("name_value", common_name)

        not_before_dt = _parse_date(not_before_str)
        is_recent = not_before_dt is not None and not_before_dt >= cutoff
        if is_recent:
            recent_count += 1

        is_unexpected = _is_unexpected_ca(str(issuer))
        if is_unexpected and str(issuer):
            unexpected_cas.add(str(issuer)[:80])

        san_list = [s.strip() for s in name_value.split("\n") if s.strip()] if name_value else []

        entries.append(CTCertEntry(
            issuer_cn=str(issuer)[:80],
            not_before=not_before_str[:10] if not_before_str else None,
            not_after=not_after_str[:10] if not_after_str else None,
            is_recent=is_recent,
            is_unexpected_ca=is_unexpected,
            serial_number=str(item.get("serial_number", ""))[:20],
            san_entries=san_list[:10],
        ))

    flagged = bool(unexpected_cas) or recent_count > 3
    flag_reason = ""
    if unexpected_cas:
        flag_reason += f"Unexpected CA(s): {', '.join(list(unexpected_cas)[:3])}. "
    if recent_count > 3:
        flag_reason += f"{recent_count} certificates issued in last 30 days — possible mis-issuance."

    return CTLogResult(
        total_certs_found=len(entries),
        cert_history=entries[:50],  # Return max 50 for the UI
        unexpected_cas=list(unexpected_cas),
        recent_certs_count=recent_count,
        flagged=flagged,
        flag_reason=flag_reason.strip(),
        notes=f"Found {len(entries)} certificate entries in CT logs for {apex}",
    )
