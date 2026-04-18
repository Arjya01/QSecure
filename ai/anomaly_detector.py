"""
Q-Secure | ai/anomaly_detector.py
Phase 5 — Scan-over-Scan Degradation Detection.

Compares two scan dicts (previous vs current) and detects cryptographic regressions.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Anomaly:
    anomaly_type: str
    severity: str                   # CRITICAL / HIGH / MEDIUM / LOW
    previous_value: str
    current_value: str
    description: str
    possible_causes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "previous_value": self.previous_value,
            "current_value": self.current_value,
            "description": self.description,
            "possible_causes": self.possible_causes,
        }


@dataclass
class AnomalyResult:
    asset_hostname: str
    anomalies_detected: list[Anomaly] = field(default_factory=list)
    degradation_detected: bool = False
    improvement_detected: bool = False
    score_delta: float = 0.0
    scan_date_compared: Optional[str] = None
    current_scan_date: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "asset_hostname": self.asset_hostname,
            "anomalies_detected": [a.to_dict() for a in self.anomalies_detected],
            "degradation_detected": self.degradation_detected,
            "improvement_detected": self.improvement_detected,
            "score_delta": round(self.score_delta, 2),
            "scan_date_compared": self.scan_date_compared,
            "current_scan_date": self.current_scan_date,
        }


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """
    Compare previous_scan dict with current_scan dict.
    Both must be ScanResult.to_dict() output.
    """

    def compare(self, previous: dict, current: dict) -> AnomalyResult:
        hostname = current.get("target", {}).get("hostname", "unknown")
        anomalies: list[Anomaly] = []

        # Score delta
        prev_score = (previous.get("quantum_score") or {}).get("overall_score", 0.0)
        curr_score = (current.get("quantum_score") or {}).get("overall_score", 0.0)
        delta = curr_score - prev_score

        # 1. Score drop > 10 points
        if delta < -10:
            anomalies.append(Anomaly(
                anomaly_type="SCORE_DEGRADATION",
                severity="HIGH" if delta < -20 else "MEDIUM",
                previous_value=f"{prev_score:.1f}",
                current_value=f"{curr_score:.1f}",
                description=f"Quantum safety score dropped {abs(delta):.1f} points.",
                possible_causes=[
                    "Certificate renewal with weaker algorithm",
                    "TLS configuration change",
                    "New vulnerable cipher suites added",
                    "Key exchange algorithm downgraded",
                ],
            ))

        # Score improvement
        if delta > 5:
            anomalies.append(Anomaly(
                anomaly_type="SCORE_IMPROVEMENT",
                severity="LOW",
                previous_value=f"{prev_score:.1f}",
                current_value=f"{curr_score:.1f}",
                description=f"Quantum safety score improved {delta:.1f} points.",
                possible_causes=["Configuration hardening", "Certificate upgrade", "TLS upgrade"],
            ))

        # 2. Label regression
        prev_label = (previous.get("quantum_score") or {}).get("label", "")
        curr_label = (current.get("quantum_score") or {}).get("label", "")
        label_order = {"QUANTUM_SAFE": 3, "PQC_READY": 2, "NOT_QUANTUM_SAFE": 1, "": 0}
        if label_order.get(curr_label, 0) < label_order.get(prev_label, 0):
            anomalies.append(Anomaly(
                anomaly_type="LABEL_REGRESSION",
                severity="CRITICAL",
                previous_value=prev_label,
                current_value=curr_label,
                description=f"Quantum safety label regressed from {prev_label} to {curr_label}.",
                possible_causes=[
                    "PQC certificate replaced with classical certificate",
                    "Key exchange algorithm downgraded",
                    "Post-quantum cipher suites removed",
                ],
            ))

        # 3. TLS version regression
        prev_versions = {v["version"]: v for v in (previous.get("tls_versions") or [])}
        curr_versions = {v["version"]: v for v in (current.get("tls_versions") or [])}

        for ver in ("TLSv1.3", "TLSv1.2"):
            was_supported = prev_versions.get(ver, {}).get("supported", False)
            now_supported = curr_versions.get(ver, {}).get("supported", False)
            if was_supported and not now_supported:
                anomalies.append(Anomaly(
                    anomaly_type="TLS_VERSION_REGRESSION",
                    severity="HIGH",
                    previous_value=f"{ver}: supported",
                    current_value=f"{ver}: not supported",
                    description=f"{ver} was previously supported but is no longer available.",
                    possible_causes=[
                        "TLS configuration rolled back",
                        "Server OS/OpenSSL downgrade",
                        "Load balancer config change",
                    ],
                ))

        for ver in ("TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"):
            was_supported = prev_versions.get(ver, {}).get("supported", False)
            now_supported = curr_versions.get(ver, {}).get("supported", False)
            if not was_supported and now_supported:
                anomalies.append(Anomaly(
                    anomaly_type="INSECURE_PROTOCOL_ENABLED",
                    severity="CRITICAL",
                    previous_value=f"{ver}: disabled",
                    current_value=f"{ver}: ENABLED",
                    description=f"Insecure protocol {ver} was disabled but is now enabled.",
                    possible_causes=[
                        "Accidental configuration rollback",
                        "Compatibility change for legacy clients",
                        "Unauthorized configuration change",
                    ],
                ))

        # 4. Cipher suite downgrade
        prev_vuln_count = sum(1 for c in (previous.get("ciphers") or []) if c.get("is_quantum_vulnerable"))
        curr_vuln_count = sum(1 for c in (current.get("ciphers") or []) if c.get("is_quantum_vulnerable"))
        if curr_vuln_count > prev_vuln_count:
            anomalies.append(Anomaly(
                anomaly_type="CIPHER_SUITE_DOWNGRADE",
                severity="HIGH",
                previous_value=f"{prev_vuln_count} quantum-vulnerable ciphers",
                current_value=f"{curr_vuln_count} quantum-vulnerable ciphers",
                description=f"Number of quantum-vulnerable cipher suites increased from {prev_vuln_count} to {curr_vuln_count}.",
                possible_causes=[
                    "New cipher suites added without review",
                    "TLS library update changed defaults",
                    "Legacy compatibility mode enabled",
                ],
            ))

        # 5. Certificate algorithm change (weakening)
        prev_cert = previous.get("certificate") or {}
        curr_cert = current.get("certificate") or {}
        prev_algo = prev_cert.get("public_key_algorithm", "")
        curr_algo = curr_cert.get("public_key_algorithm", "")
        prev_size = prev_cert.get("public_key_size", 0)
        curr_size = curr_cert.get("public_key_size", 0)

        if prev_cert and curr_cert:
            if prev_cert.get("is_quantum_safe_cert") and not curr_cert.get("is_quantum_safe_cert"):
                anomalies.append(Anomaly(
                    anomaly_type="CERT_ALGORITHM_REGRESSION",
                    severity="CRITICAL",
                    previous_value=f"Quantum-safe: {prev_algo} {prev_size}b",
                    current_value=f"Classical: {curr_algo} {curr_size}b",
                    description="Certificate was replaced: quantum-safe algorithm → classical algorithm.",
                    possible_causes=["Certificate authority change", "Renewal process defaulted to RSA"],
                ))
            elif curr_size < prev_size and curr_size > 0:
                anomalies.append(Anomaly(
                    anomaly_type="KEY_SIZE_REDUCTION",
                    severity="HIGH",
                    previous_value=f"{prev_size} bits",
                    current_value=f"{curr_size} bits",
                    description=f"Certificate public key size reduced from {prev_size}b to {curr_size}b.",
                    possible_causes=["Performance optimization", "Misconfigured renewal template"],
                ))

        # 6. New subdomain appeared
        prev_subs = {s["subdomain"] for s in (previous.get("subdomains") or [])}
        curr_subs = {s["subdomain"] for s in (current.get("subdomains") or [])}
        new_subs = curr_subs - prev_subs
        if new_subs:
            new_weak = [s for s in (current.get("subdomains") or [])
                        if s["subdomain"] in new_subs and s.get("tls_weak")]
            sev = "HIGH" if new_weak else "MEDIUM"
            anomalies.append(Anomaly(
                anomaly_type="NEW_SUBDOMAIN_DISCOVERED",
                severity=sev,
                previous_value=f"{len(prev_subs)} subdomains",
                current_value=f"{len(curr_subs)} subdomains (+{len(new_subs)} new)",
                description=f"New subdomains detected: {', '.join(list(new_subs)[:5])}."
                            + (f" {len(new_weak)} have weak TLS." if new_weak else ""),
                possible_causes=[
                    "New service deployment",
                    "DNS record added",
                    "Subdomain takeover risk",
                ],
            ))

        # 7. New vulnerabilities since last scan
        prev_vuln_ids = {v["id"] for v in (previous.get("vulnerabilities") or [])}
        curr_vuln_ids = {v["id"] for v in (current.get("vulnerabilities") or [])}
        new_vulns = curr_vuln_ids - prev_vuln_ids
        if new_vulns:
            new_vuln_details = [v for v in (current.get("vulnerabilities") or []) if v["id"] in new_vulns]
            critical = [v for v in new_vuln_details if v.get("severity") in ("CRITICAL", "HIGH")]
            anomalies.append(Anomaly(
                anomaly_type="NEW_VULNERABILITIES",
                severity="CRITICAL" if critical else "MEDIUM",
                previous_value=f"{len(prev_vuln_ids)} vulnerabilities",
                current_value=f"{len(curr_vuln_ids)} vulnerabilities (+{len(new_vulns)} new)",
                description=f"New vulnerability findings: {', '.join(list(new_vulns)[:5])}.",
                possible_causes=[
                    "Scanner rule updates detected previously-missed issues",
                    "Configuration changed introducing new weakness",
                ],
            ))

        # 8. HSTS header disappeared
        prev_hdr = previous.get("headers_result") or {}
        curr_hdr = current.get("headers_result") or {}
        if prev_hdr.get("hsts_enabled") and not curr_hdr.get("hsts_enabled"):
            anomalies.append(Anomaly(
                anomaly_type="HSTS_DISAPPEARED",
                severity="HIGH",
                previous_value="HSTS: enabled",
                current_value="HSTS: MISSING",
                description="HSTS header was present in previous scan but is now missing.",
                possible_causes=[
                    "Web server/proxy reconfiguration",
                    "CDN cache configuration change",
                    "Deployment rollback",
                ],
            ))

        # 9. DNSSEC validation failure
        prev_dns = previous.get("dnssec_result") or {}
        curr_dns = current.get("dnssec_result") or {}
        if prev_dns.get("chain_valid") and not curr_dns.get("chain_valid") and curr_dns.get("enabled"):
            anomalies.append(Anomaly(
                anomaly_type="DNSSEC_VALIDATION_FAILURE",
                severity="CRITICAL",
                previous_value="DNSSEC chain: valid",
                current_value="DNSSEC chain: INVALID",
                description="DNSSEC chain validation failed — DNS responses may not be authenticated.",
                possible_causes=[
                    "DNSSEC key rollover misconfiguration",
                    "Expired RRSIG records",
                    "DNS zone file error",
                    "Potential DNS hijacking",
                ],
            ))

        degradation = any(
            a.anomaly_type not in ("SCORE_IMPROVEMENT",) and
            a.severity in ("CRITICAL", "HIGH")
            for a in anomalies
        )
        improvement = any(a.anomaly_type == "SCORE_IMPROVEMENT" for a in anomalies)

        return AnomalyResult(
            asset_hostname=hostname,
            anomalies_detected=anomalies,
            degradation_detected=degradation,
            improvement_detected=improvement,
            score_delta=delta,
            scan_date_compared=previous.get("scan_timestamp"),
            current_scan_date=current.get("scan_timestamp"),
        )
