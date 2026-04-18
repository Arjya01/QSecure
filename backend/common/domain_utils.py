"""Q-Secure | backend/common/domain_utils.py
Utilities for extracting and normalising registered (root) domain names.
Uses tldextract when available; falls back to a simple last-two-parts heuristic.
"""

from __future__ import annotations

try:
    import tldextract as _tldextract
    _USE_TLDEXTRACT = True
except ImportError:
    _USE_TLDEXTRACT = False


def get_registered_domain(hostname: str | None) -> str | None:
    """
    Return the registered (root) domain for a hostname.

    Examples
    --------
    >>> get_registered_domain("api.nfsu.ac.in")
    'nfsu.ac.in'
    >>> get_registered_domain("sub.example.com")
    'example.com'
    >>> get_registered_domain("localhost")
    'localhost'
    >>> get_registered_domain(None)
    None
    """
    if not hostname:
        return None

    # Strip protocol, path, and port
    hostname = (
        hostname
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
        .split(":")[0]
        .strip()
        .lower()
    )

    if not hostname:
        return None

    if _USE_TLDEXTRACT:
        extracted = _tldextract.extract(hostname)
        # tldextract returns (subdomain, domain, suffix)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        if extracted.domain:
            return extracted.domain
        return hostname

    # Fallback: return last two dot-separated parts
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname
