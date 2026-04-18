"""Advanced Security Scanners: HTTP Headers, DNS, API Security.

Covers every security header, DNS record, and API endpoint check
relevant to banking and financial applications worldwide.
"""

import logging
import socket
import ssl
import json
import struct
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ═══════════════════════════ HTTP SECURITY HEADERS ═══════════════════════════

SECURITY_HEADERS = {
    "strict-transport-security": {
        "label": "HSTS", "severity": "critical", "category": "transport",
        "description": "Enforces HTTPS connections, prevents SSL stripping attacks",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "banking_relevance": "Mandatory for all banking portals per PCI DSS and RBI guidelines",
    },
    "content-security-policy": {
        "label": "CSP", "severity": "high", "category": "injection",
        "description": "Prevents XSS, clickjacking, and code injection attacks",
        "recommendation": "Implement strict CSP with nonce-based script loading",
        "banking_relevance": "Critical for preventing XSS in internet banking and payment pages",
    },
    "x-frame-options": {
        "label": "X-Frame-Options", "severity": "high", "category": "clickjacking",
        "description": "Prevents clickjacking by controlling iframe embedding",
        "recommendation": "Set X-Frame-Options: DENY or SAMEORIGIN",
        "banking_relevance": "Prevents clickjacking attacks on login and transaction pages",
    },
    "x-content-type-options": {
        "label": "X-Content-Type-Options", "severity": "medium", "category": "mime",
        "description": "Prevents MIME-type sniffing attacks",
        "recommendation": "Set X-Content-Type-Options: nosniff",
        "banking_relevance": "Prevents malicious file execution on banking portals",
    },
    "x-xss-protection": {
        "label": "X-XSS-Protection", "severity": "medium", "category": "xss",
        "description": "Enables browser's built-in XSS filter",
        "recommendation": "Set X-XSS-Protection: 1; mode=block",
        "banking_relevance": "Additional XSS defense layer for older browsers",
    },
    "referrer-policy": {
        "label": "Referrer-Policy", "severity": "medium", "category": "privacy",
        "description": "Controls referrer information sent with requests",
        "recommendation": "Set Referrer-Policy: strict-origin-when-cross-origin",
        "banking_relevance": "Prevents leaking sensitive URLs with account/session info",
    },
    "permissions-policy": {
        "label": "Permissions-Policy", "severity": "medium", "category": "features",
        "description": "Controls browser feature access (camera, mic, geolocation)",
        "recommendation": "Restrict unnecessary features: Permissions-Policy: camera=(), microphone=()",
        "banking_relevance": "Limits attack surface from browser feature abuse",
    },
    "cache-control": {
        "label": "Cache-Control", "severity": "high", "category": "caching",
        "description": "Controls how responses are cached",
        "recommendation": "For banking: Cache-Control: no-store, no-cache, must-revalidate, private",
        "banking_relevance": "Critical to prevent caching of sensitive financial data",
    },
    "pragma": {
        "label": "Pragma", "severity": "low", "category": "caching",
        "description": "HTTP/1.0 cache control",
        "recommendation": "Set Pragma: no-cache for backward compatibility",
        "banking_relevance": "Ensures no caching on legacy proxies",
    },
    "x-permitted-cross-domain-policies": {
        "label": "X-Permitted-Cross-Domain-Policies", "severity": "low", "category": "cross-domain",
        "description": "Controls Flash/PDF cross-domain policy loading",
        "recommendation": "Set to none: X-Permitted-Cross-Domain-Policies: none",
        "banking_relevance": "Prevents Flash-based cross-domain attacks",
    },
    "cross-origin-opener-policy": {
        "label": "COOP", "severity": "medium", "category": "isolation",
        "description": "Isolates browsing context from cross-origin windows",
        "recommendation": "Set Cross-Origin-Opener-Policy: same-origin",
        "banking_relevance": "Prevents Spectre-style side-channel attacks on banking sessions",
    },
    "cross-origin-embedder-policy": {
        "label": "COEP", "severity": "medium", "category": "isolation",
        "description": "Controls cross-origin resource embedding",
        "recommendation": "Set Cross-Origin-Embedder-Policy: require-corp",
        "banking_relevance": "Enables cross-origin isolation for enhanced security",
    },
    "cross-origin-resource-policy": {
        "label": "CORP", "severity": "medium", "category": "isolation",
        "description": "Controls who can load resources cross-origin",
        "recommendation": "Set Cross-Origin-Resource-Policy: same-origin",
        "banking_relevance": "Prevents unauthorized embedding of banking resources",
    },
    "expect-ct": {
        "label": "Expect-CT", "severity": "medium", "category": "certificate",
        "description": "Enforces Certificate Transparency requirements",
        "recommendation": "Set Expect-CT: max-age=86400, enforce",
        "banking_relevance": "Detects misissued certificates targeting banking domains",
    },
    "feature-policy": {
        "label": "Feature-Policy", "severity": "low", "category": "features",
        "description": "Legacy predecessor to Permissions-Policy",
        "recommendation": "Migrate to Permissions-Policy header",
        "banking_relevance": "Legacy browser feature control",
    },
}

# Headers that should NOT be present (information disclosure)
DANGEROUS_HEADERS = {
    "server": {"label": "Server Header", "severity": "low",
               "description": "Reveals web server software and version"},
    "x-powered-by": {"label": "X-Powered-By", "severity": "low",
                     "description": "Reveals application framework"},
    "x-aspnet-version": {"label": "X-AspNet-Version", "severity": "medium",
                         "description": "Reveals ASP.NET version"},
    "x-aspnetmvc-version": {"label": "X-AspNetMvc-Version", "severity": "medium",
                            "description": "Reveals MVC framework version"},
    "x-generator": {"label": "X-Generator", "severity": "low",
                    "description": "Reveals content management system"},
}


def scan_http_headers(hostname, port=443, path="/"):
    """Scan HTTP security headers of a target."""
    import http.client

    results = {
        "hostname": hostname, "port": port,
        "present_headers": [], "missing_headers": [],
        "info_disclosure": [], "score": 0,
        "grade": "F", "details": {},
    }

    try:
        if port == 443:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(hostname, port, timeout=15, context=ctx)
        else:
            conn = http.client.HTTPConnection(hostname, port, timeout=15)

        conn.request("HEAD", path, headers={"Host": hostname, "User-Agent": "Q-Secure/2.0 PQC-Scanner"})
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        results["status_code"] = resp.status
        results["raw_headers"] = dict(resp.getheaders())

        # Check security headers
        for hdr_key, hdr_info in SECURITY_HEADERS.items():
            if hdr_key in headers:
                value = headers[hdr_key]
                quality = _assess_header_quality(hdr_key, value)
                results["present_headers"].append({
                    **hdr_info, "header": hdr_key, "value": value, "quality": quality,
                })
            else:
                results["missing_headers"].append({
                    **hdr_info, "header": hdr_key,
                })

        # Check info disclosure headers
        for hdr_key, hdr_info in DANGEROUS_HEADERS.items():
            if hdr_key in headers:
                results["info_disclosure"].append({
                    **hdr_info, "header": hdr_key, "value": headers[hdr_key],
                    "recommendation": f"Remove {hdr_key} header to prevent information disclosure",
                })

        # Cookie security
        cookies = [v for k, v in resp.getheaders() if k.lower() == "set-cookie"]
        cookie_issues = []
        for cookie in cookies:
            cl = cookie.lower()
            if "secure" not in cl:
                cookie_issues.append({"cookie": cookie.split("=")[0], "issue": "Missing Secure flag"})
            if "httponly" not in cl:
                cookie_issues.append({"cookie": cookie.split("=")[0], "issue": "Missing HttpOnly flag"})
            if "samesite" not in cl:
                cookie_issues.append({"cookie": cookie.split("=")[0], "issue": "Missing SameSite attribute"})
        results["cookie_issues"] = cookie_issues

        # Calculate score
        total_headers = len(SECURITY_HEADERS)
        present = len(results["present_headers"])
        high_quality = sum(1 for h in results["present_headers"] if h.get("quality") == "good")

        base_score = (present / total_headers) * 70
        quality_bonus = (high_quality / max(present, 1)) * 20
        disclosure_penalty = len(results["info_disclosure"]) * 3
        cookie_penalty = len(cookie_issues) * 2

        results["score"] = max(0, min(100, round(base_score + quality_bonus - disclosure_penalty - cookie_penalty)))
        results["grade"] = _score_to_grade(results["score"])
        results["total_checks"] = total_headers
        results["passed_checks"] = present

        conn.close()
    except Exception as e:
        logger.error(f"HTTP header scan error for {hostname}: {e}")
        results["error"] = str(e)

    return results


def _assess_header_quality(header, value):
    """Assess if a header value follows best practices."""
    v = value.lower()
    if header == "strict-transport-security":
        return "good" if "max-age=" in v and int(v.split("max-age=")[1].split(";")[0].strip()) >= 31536000 else "weak"
    if header == "content-security-policy":
        return "good" if "default-src" in v and "'unsafe-inline'" not in v else "weak"
    if header == "x-frame-options":
        return "good" if v in ("deny", "sameorigin") else "weak"
    if header == "cache-control":
        return "good" if "no-store" in v or "private" in v else "weak"
    return "good"


def _score_to_grade(score):
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 60: return "C"
    if score >= 50: return "D"
    return "F"


# ═══════════════════════════ DNS SECURITY SCANNER ═══════════════════════════

def scan_dns_security(hostname):
    """Scan DNS security configuration."""
    import subprocess

    results = {
        "hostname": hostname,
        "checks": [],
        "score": 0,
        "records": {},
    }

    dns_checks = [
        ("A", "A record resolution"),
        ("AAAA", "IPv6 (AAAA) record"),
        ("MX", "Mail exchanger records"),
        ("TXT", "TXT records (SPF/DKIM/DMARC)"),
        ("CAA", "Certificate Authority Authorization"),
        ("NS", "Nameserver records"),
    ]

    for record_type, description in dns_checks:
        try:
            output = subprocess.run(
                ["dig", "+short", record_type, hostname],
                capture_output=True, text=True, timeout=10
            )
            records = [r.strip() for r in output.stdout.strip().split("\n") if r.strip()]
            results["records"][record_type] = records

            if records:
                results["checks"].append({
                    "check": description,
                    "record_type": record_type,
                    "status": "present",
                    "values": records,
                    "severity": "info",
                })
            else:
                sev = "high" if record_type == "CAA" else "info"
                results["checks"].append({
                    "check": description,
                    "record_type": record_type,
                    "status": "missing",
                    "severity": sev,
                })
        except Exception:
            results["checks"].append({
                "check": description,
                "record_type": record_type,
                "status": "error",
                "severity": "info",
            })

    # Check for SPF
    txt_records = results["records"].get("TXT", [])
    has_spf = any("v=spf1" in r for r in txt_records)
    results["checks"].append({
        "check": "SPF (Sender Policy Framework)",
        "status": "pass" if has_spf else "missing",
        "severity": "high" if not has_spf else "info",
        "recommendation": "Add SPF TXT record to prevent email spoofing" if not has_spf else None,
    })

    # Check for DMARC
    try:
        dmarc_out = subprocess.run(
            ["dig", "+short", "TXT", f"_dmarc.{hostname}"],
            capture_output=True, text=True, timeout=10
        )
        has_dmarc = "v=DMARC1" in dmarc_out.stdout
    except Exception:
        has_dmarc = False

    results["checks"].append({
        "check": "DMARC (Domain-based Message Authentication)",
        "status": "pass" if has_dmarc else "missing",
        "severity": "high" if not has_dmarc else "info",
        "recommendation": "Add DMARC policy to prevent domain spoofing" if not has_dmarc else None,
    })

    # Check CAA
    caa_records = results["records"].get("CAA", [])
    results["checks"].append({
        "check": "CAA (Certificate Authority Authorization)",
        "status": "pass" if caa_records else "missing",
        "severity": "medium" if not caa_records else "info",
        "recommendation": "Add CAA record to restrict certificate issuance" if not caa_records else None,
        "banking_relevance": "Prevents unauthorized CAs from issuing certificates for banking domains",
    })

    # DNSSEC check
    try:
        dnssec_out = subprocess.run(
            ["dig", "+dnssec", "+short", hostname],
            capture_output=True, text=True, timeout=10
        )
        has_dnssec = "RRSIG" in dnssec_out.stdout or "ad" in subprocess.run(
            ["dig", "+noall", "+comments", hostname],
            capture_output=True, text=True, timeout=10
        ).stdout.lower()
    except Exception:
        has_dnssec = False

    results["checks"].append({
        "check": "DNSSEC validation",
        "status": "pass" if has_dnssec else "missing",
        "severity": "high" if not has_dnssec else "info",
        "recommendation": "Enable DNSSEC to prevent DNS spoofing attacks" if not has_dnssec else None,
        "banking_relevance": "Critical for banking — prevents DNS cache poisoning redirecting users to phishing sites",
    })

    # Score
    passed = sum(1 for c in results["checks"] if c["status"] in ("pass", "present"))
    total = len(results["checks"])
    results["score"] = round(passed / total * 100) if total > 0 else 0
    results["grade"] = _score_to_grade(results["score"])

    return results


# ═══════════════════════════ API SECURITY CHECKS ═══════════════════════════

API_SECURITY_CHECKS = [
    {"id": "cors", "name": "CORS Configuration", "severity": "high",
     "description": "Check if CORS allows overly permissive origins"},
    {"id": "rate_limit", "name": "Rate Limiting", "severity": "high",
     "description": "Check for rate limiting headers (X-RateLimit-*)"},
    {"id": "auth_header", "name": "Authentication Required", "severity": "critical",
     "description": "Check if endpoints require authentication"},
    {"id": "api_version", "name": "API Versioning", "severity": "medium",
     "description": "Check for proper API versioning in URL or headers"},
    {"id": "error_handling", "name": "Error Information Disclosure", "severity": "high",
     "description": "Check if errors expose stack traces or internal details"},
    {"id": "content_type", "name": "Content-Type Enforcement", "severity": "medium",
     "description": "Check if API enforces proper Content-Type"},
    {"id": "deprecated_methods", "name": "HTTP Method Restriction", "severity": "medium",
     "description": "Check if TRACE/TRACK/OPTIONS are restricted"},
]


def scan_api_security(hostname, port=443, base_path="/api"):
    """Scan API endpoint security."""
    import http.client

    results = {
        "hostname": hostname,
        "checks": [],
        "score": 0,
        "grade": "F",
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(hostname, port, timeout=15, context=ctx)

        # Test CORS
        conn.request("OPTIONS", base_path, headers={
            "Host": hostname, "Origin": "https://evil.com",
            "Access-Control-Request-Method": "GET",
        })
        resp = conn.getresponse()
        resp.read()
        cors_header = dict(resp.getheaders()).get("Access-Control-Allow-Origin", "")
        results["checks"].append({
            "id": "cors", "name": "CORS Configuration",
            "status": "fail" if cors_header == "*" else "pass",
            "severity": "high",
            "detail": f"ACAO: {cors_header}" if cors_header else "No CORS header",
        })

        # Test rate limiting
        conn.request("GET", base_path, headers={"Host": hostname})
        resp = conn.getresponse()
        resp.read()
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        has_rate_limit = any("ratelimit" in k or "x-rate" in k for k in hdrs)
        results["checks"].append({
            "id": "rate_limit", "name": "Rate Limiting",
            "status": "pass" if has_rate_limit else "warning",
            "severity": "high",
            "detail": "Rate limiting headers detected" if has_rate_limit else "No rate limiting headers found",
        })

        # Test authentication
        results["checks"].append({
            "id": "auth_header", "name": "Authentication Required",
            "status": "pass" if resp.status in (401, 403) else "warning",
            "severity": "critical",
            "detail": f"Response code: {resp.status}",
        })

        # Test HTTP methods
        for method in ["TRACE", "TRACK"]:
            try:
                conn.request(method, base_path, headers={"Host": hostname})
                r = conn.getresponse()
                r.read()
                results["checks"].append({
                    "id": f"method_{method.lower()}", "name": f"{method} Method",
                    "status": "fail" if r.status == 200 else "pass",
                    "severity": "medium",
                    "detail": f"{method} returns {r.status}",
                })
            except Exception:
                results["checks"].append({
                    "id": f"method_{method.lower()}", "name": f"{method} Method",
                    "status": "pass", "severity": "medium",
                })

        # Security headers specific to APIs
        api_headers = ["x-request-id", "x-correlation-id"]
        for ah in api_headers:
            results["checks"].append({
                "id": ah.replace("-", "_"), "name": f"{ah} Header",
                "status": "pass" if ah in hdrs else "info",
                "severity": "low",
            })

        conn.close()

        passed = sum(1 for c in results["checks"] if c["status"] == "pass")
        total = len(results["checks"])
        results["score"] = round(passed / total * 100) if total > 0 else 0
        results["grade"] = _score_to_grade(results["score"])

    except Exception as e:
        results["error"] = str(e)

    return results
