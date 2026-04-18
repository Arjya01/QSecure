"""Shared hostname and registered-domain helpers."""

from __future__ import annotations

from urllib.parse import urlparse

try:
    import tldextract  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    tldextract = None


_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None) if tldextract else None

_MULTI_LABEL_SUFFIXES = {
    "ac.in", "co.in", "org.in", "gov.in", "net.in", "edu.in", "mil.in", "res.in", "nic.in",
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.nz", "org.nz", "gov.nz", "ac.nz",
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
}


def normalize_hostname(value: str | None) -> str:
    raw = (value or "").strip().lower()
    if not raw:
        return ""

    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.hostname or raw
    else:
        raw = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in raw:
            raw = raw.rsplit("@", 1)[-1]
        if raw.startswith("[") and "]" in raw:
            raw = raw[1:raw.index("]")]
        elif raw.count(":") == 1:
            host, port = raw.rsplit(":", 1)
            if port.isdigit():
                raw = host

    return raw.strip(".")


def get_registered_domain(hostname: str | None) -> str:
    host = normalize_hostname(hostname)
    if not host:
        return ""

    if _EXTRACTOR:
        extracted = _EXTRACTOR(host)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}".lower()
        if extracted.domain:
            return extracted.domain.lower()

    parts = host.split(".")
    if len(parts) <= 2:
        return host

    suffix = ".".join(parts[-2:])
    if suffix in _MULTI_LABEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])
