"""
Q-Secure | subdomain_enumerator.py
Multi-source passive subdomain enumeration with DNS validation.
"""

from __future__ import annotations

import random
import socket
import string
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver

from common.domain_utils import get_registered_domain
from .models import SubdomainResult


_COMMON_SUBDOMAINS = [
    "www", "api", "vpn", "mail", "netbanking", "mobile", "app",
    "admin", "portal", "gateway", "secure", "online", "m", "web",
    "auth", "login", "pay", "payments", "cdn", "static", "dev",
    "staging", "uat", "test", "demo", "jira", "confluence", "git",
    "gitlab", "github", "jenkins", "corp", "internal", "intranet",
    "sso", "identity", "oauth", "api-dev", "api-v1", "api-v2",
    "metrics", "grafana", "prometheus", "kibana", "elastic", "logs",
    "monitor", "status", "support", "help", "docs", "kb", "wiki",
    "assets", "media", "images", "videos", "blog", "news", "forum",
    "store", "shop", "cart", "checkout", "billing", "invoice",
    "partner", "b2b", "vendor", "supplier", "agent", "broker",
    "crm", "erp", "hr", "benefits", "mail2", "smtp", "pop3", "imap",
    "exchange", "owa", "webmail", "cloud", "aws", "azure", "gcp",
    "remote", "desktop", "citrix", "rdp", "vdi", "workspace",
    "services", "svc", "microservices", "sandbox", "beta", "alpha",
    "ns1", "ns2", "dns1", "dns2", "mx", "mx1", "ftp", "sftp",
    "db", "database", "sql", "mysql", "postgres", "mongodb", "redis",
]


def _resolver(timeout: float):
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def _resolve_dns_metadata(subdomain: str, timeout: float = 3.0) -> tuple[list[str], str]:
    """Resolve a host and return address-like answers plus record type."""
    resolver = _resolver(timeout)
    values: list[str] = []
    record_types: list[str] = []

    for record_type in ("A", "AAAA"):
        try:
            answers = resolver.resolve(subdomain, record_type)
            resolved = sorted({answer.to_text() for answer in answers})
            if resolved:
                values.extend(resolved)
                record_types.append(record_type)
        except Exception:
            pass

    if values:
        return values, "/".join(record_types)

    try:
        cname_answers = resolver.resolve(subdomain, "CNAME")
        cname = cname_answers[0].target.to_text().rstrip(".")
        return [cname], "CNAME"
    except Exception:
        return [], "UNKNOWN"


def _detect_wildcard_target(apex: str, timeout: float = 4.0) -> tuple[set[str], str]:
    probe = "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
    answers, record_type = _resolve_dns_metadata(f"{probe}.{apex}", timeout)
    return set(answers), record_type


def _is_live(hostname: str, timeout: float = 3.0) -> bool:
    """Check whether common web ports are reachable."""
    for port in (443, 80):
        try:
            with socket.create_connection((hostname, port), timeout=timeout):
                return True
        except Exception:
            continue
    return False


def _check_tls_version(hostname: str, port: int = 443, timeout: float = 5.0) -> tuple[bool, str]:
    """Quick TLS version check. Returns (is_weak, version_string)."""
    try:
        import ssl

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                version = ssock.version() or "Unknown"
                is_weak = version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3")
                return is_weak, version
    except Exception:
        return False, ""


def _query_crtsh_subdomains(apex: str, timeout: float = 10.0) -> list[str]:
    try:
        import requests

        resp = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{apex}", "output": "json"},
            timeout=timeout,
            headers={"User-Agent": "QSecure-Scanner/2.0"},
        )
        resp.raise_for_status()
        data = resp.json()
        subdomains = set()
        for item in data:
            name = item.get("common_name", "") or ""
            for entry in item.get("name_value", "").split("\n"):
                candidate = entry.strip().lstrip("*.").lower()
                if candidate.endswith(apex) and candidate != apex:
                    subdomains.add(candidate)
            if name.endswith(apex) and name != apex:
                subdomains.add(name.lstrip("*.").lower())
        return list(subdomains)[:100]
    except Exception:
        return []


def _query_hackertarget(apex: str, timeout: float = 10.0) -> list[str]:
    try:
        import requests

        resp = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={apex}",
            timeout=timeout,
            headers={"User-Agent": "QSecure-Scanner/2.0"},
        )
        if resp.status_code != 200 or "error" in resp.text.lower():
            return []

        subdomains = set()
        for line in resp.text.splitlines():
            if "," not in line:
                continue
            host = line.split(",", 1)[0].strip().lower()
            if host.endswith(apex) and host != apex:
                subdomains.add(host)
        return list(subdomains)[:100]
    except Exception:
        return []


def _query_otx(apex: str, timeout: float = 10.0) -> list[str]:
    try:
        import requests

        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{apex}/passive_dns",
            timeout=timeout,
            headers={"User-Agent": "QSecure-Scanner/2.0"},
        )
        resp.raise_for_status()
        data = resp.json()
        subdomains = set()
        for item in data.get("passive_dns", []):
            host = item.get("hostname", "").strip().lower()
            if host.endswith(apex) and host != apex:
                subdomains.add(host)
        return list(subdomains)[:100]
    except Exception:
        return []


def _check_subdomain(
    fqdn: str,
    apex: str,
    source: str,
    wildcard_answers: set[str],
    wildcard_record_type: str,
) -> SubdomainResult:
    answers, record_type = _resolve_dns_metadata(fqdn)
    if not answers:
        return SubdomainResult(
            subdomain=fqdn,
            root_domain=apex,
            ip_address=None,
            record_type=record_type,
            is_live=False,
            tls_weak=False,
            source=source,
            notes="DNS resolution failed",
        )

    wildcard_match = bool(wildcard_answers) and set(answers) == wildcard_answers and record_type == wildcard_record_type
    live = _is_live(fqdn)
    tls_weak, tls_ver = _check_tls_version(fqdn) if live else (False, "")

    if wildcard_match:
        notes = "Resolved via wildcard DNS pattern"
    elif tls_weak:
        notes = f"Weak TLS version detected: {tls_ver}"
    elif live and tls_ver:
        notes = f"TLS {tls_ver}"
    elif live:
        notes = "Live (TLS check failed)"
    else:
        notes = f"Resolved ({record_type})"

    return SubdomainResult(
        subdomain=fqdn,
        root_domain=apex,
        ip_address=answers[0],
        record_type=record_type,
        is_live=live and not wildcard_match,
        tls_weak=tls_weak,
        tls_version=tls_ver if tls_ver else None,
        source=source,
        notes=notes,
    )


def enumerate_subdomains(hostname: str, timeout: float = 10.0) -> list[SubdomainResult]:
    """
    Passive subdomain enumeration. Never brute-forces.
    Returns validated SubdomainResult entries and never raises.
    """
    apex = get_registered_domain(hostname)
    if not apex:
        return []

    wildcard_answers, wildcard_record_type = _detect_wildcard_target(apex)
    tasks: dict[str, str] = {}

    for query_fn, source_name in (
        (_query_crtsh_subdomains, "crt.sh"),
        (_query_hackertarget, "hackertarget"),
        (_query_otx, "alienvault"),
    ):
        try:
            for subdomain in query_fn(apex, timeout):
                tasks[subdomain] = source_name
        except Exception:
            pass

    for word in _COMMON_SUBDOMAINS:
        candidate = f"{word}.{apex}"
        tasks.setdefault(candidate, "dns")

    results: list[SubdomainResult] = []
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {
            pool.submit(_check_subdomain, fqdn, apex, source, wildcard_answers, wildcard_record_type): fqdn
            for fqdn, source in tasks.items()
        }
        for future in as_completed(futures):
            try:
                result = future.result(timeout=15)
                if result.notes == "Resolved via wildcard DNS pattern" and result.source == "dns":
                    continue
                results.append(result)
            except Exception:
                pass

    deduped: dict[str, SubdomainResult] = {}
    for result in results:
        existing = deduped.get(result.subdomain)
        if not existing or (result.is_live and not existing.is_live):
            deduped[result.subdomain] = result

    ordered = list(deduped.values())
    ordered.sort(
        key=lambda result: (
            not result.is_live,
            result.source not in ("crt.sh", "alienvault", "hackertarget"),
            result.subdomain,
        )
    )
    return ordered[:100]
