"""
Q-Secure | ai/migration_planner.py
Phase 5 — Phased PQC Migration Roadmap Generator.

Analyzes scan data and generates a sequenced 5-phase migration plan.
Phases are always sequenced in the correct order:
  1. Trust chain (DNSSEC, HSTS, rogue certs)
  2. Critical vulns (legacy TLS, weak ciphers, PFS)
  3. Hybrid PQC transport (ML-KEM-768 / FIPS-203)
  4. Application layer (JWT, SSH, DNSKEY)
  5. Full PQC, remove classical fallbacks → ELITE_PQC
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class MigrationAction:
    action_id: str
    title: str
    current_state: str
    target_state: str
    nist_standard: str
    effort: str                         # Low / Medium / High / Very High
    technical_steps: list[str] = field(default_factory=list)
    verification_method: str = ""

    def to_dict(self) -> dict:
        return {
            "action_id": self.action_id,
            "title": self.title,
            "current_state": self.current_state,
            "target_state": self.target_state,
            "nist_standard": self.nist_standard,
            "effort": self.effort,
            "technical_steps": self.technical_steps,
            "verification_method": self.verification_method,
        }


@dataclass
class MigrationPhase:
    phase_number: int
    phase_name: str
    priority: str                       # IMMEDIATE / HIGH / MEDIUM / LOW / NONE
    timeframe: str                      # e.g. "0–2 weeks"
    actions: list[MigrationAction] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    risk_if_delayed: str = ""

    def to_dict(self) -> dict:
        return {
            "phase_number": self.phase_number,
            "phase_name": self.phase_name,
            "priority": self.priority,
            "timeframe": self.timeframe,
            "actions": [a.to_dict() for a in self.actions],
            "dependencies": self.dependencies,
            "risk_if_delayed": self.risk_if_delayed,
        }


@dataclass
class MigrationRoadmap:
    asset_hostname: str
    generated_at: str
    total_phases: int
    estimated_total_effort: str
    current_label: str
    phases: list[MigrationPhase] = field(default_factory=list)
    ai_enhanced: bool = False           # True if Groq added guidance on top

    def to_dict(self) -> dict:
        return {
            "asset_hostname": self.asset_hostname,
            "generated_at": self.generated_at,
            "total_phases": self.total_phases,
            "estimated_total_effort": self.estimated_total_effort,
            "current_label": self.current_label,
            "phases": [p.to_dict() for p in self.phases],
            "ai_enhanced": self.ai_enhanced,
        }


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------

class MigrationPlanner:

    def generate(self, scan: dict) -> MigrationRoadmap:
        hostname = scan.get("target", {}).get("hostname", "unknown")
        label    = (scan.get("quantum_score") or {}).get("label", "NOT_QUANTUM_SAFE")
        qs       = scan.get("quantum_score") or {}
        cert     = scan.get("certificate") or {}
        kex      = scan.get("key_exchange") or {}
        dnssec   = scan.get("dnssec_result") or {}
        headers  = scan.get("headers_result") or {}
        ssh      = scan.get("ssh_result") or {}
        jwt_r    = scan.get("jwt_result") or {}
        ct_log   = scan.get("ct_log_result") or {}
        versions = scan.get("tls_versions") or []

        phases: list[MigrationPhase] = []
        p1 = self._phase1_trust_chain(dnssec, headers, ct_log)
        p2 = self._phase2_critical_vulns(versions, scan.get("ciphers") or [], kex)
        p3 = self._phase3_hybrid_pqc_transport(kex, cert, label)
        p4 = self._phase4_application_layer(jwt_r, ssh, dnssec)
        p5 = self._phase5_full_pqc(label, kex, cert)

        for p in (p1, p2, p3, p4, p5):
            if p.actions:
                phases.append(p)

        if not phases:
            phases = [MigrationPhase(
                phase_number=1,
                phase_name="Maintain Quantum-Safe Posture",
                priority="NONE",
                timeframe="Ongoing",
                actions=[MigrationAction(
                    action_id="MA-000",
                    title="Continue monitoring for new PQC standards",
                    current_state="ELITE_PQC or QUANTUM_SAFE",
                    target_state="Stay current with NIST PQC updates",
                    nist_standard="FIPS-203/204/205",
                    effort="Low",
                    technical_steps=["Subscribe to NIST PQC announcements", "Review FIPS updates annually"],
                    verification_method="Annual cryptographic audit",
                )],
                dependencies=[],
                risk_if_delayed="Potential obsolescence as standards evolve",
            )]

        effort_map = {"IMMEDIATE": "Very High", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "NONE": "Minimal"}
        max_priority = phases[0].priority if phases else "NONE"
        estimated_effort = effort_map.get(max_priority, "Medium")

        return MigrationRoadmap(
            asset_hostname=hostname,
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_phases=len(phases),
            estimated_total_effort=estimated_effort,
            current_label=label,
            phases=phases,
        )

    # ------------------------------------------------------------------
    # Phase 1 — Fix Trust Chain
    # ------------------------------------------------------------------
    def _phase1_trust_chain(self, dnssec, headers, ct_log) -> MigrationPhase:
        actions = []
        seq = 1

        if not dnssec.get("enabled"):
            actions.append(MigrationAction(
                action_id=f"MA-1-{seq:02d}",
                title="Enable DNSSEC",
                current_state="DNSSEC disabled",
                target_state="DNSSEC enabled with chain validation",
                nist_standard="NIST SP 800-81r2",
                effort="Medium",
                technical_steps=[
                    "Generate DNSSEC signing keys (KSK + ZSK) at your DNS registrar/provider",
                    "Sign all zone records with ZSK; sign DNSKEY with KSK",
                    "Upload DS record to parent zone (registrar)",
                    "Enable automatic DNSSEC key rollover (RFC 5011)",
                    "Monitor RRSIG expiry — set alerts 30 days before expiry",
                ],
                verification_method="Use `dig +dnssec {hostname}` and verify RRSIG records are present and valid",
            ))
            seq += 1

        elif dnssec.get("enabled") and not dnssec.get("chain_valid"):
            actions.append(MigrationAction(
                action_id=f"MA-1-{seq:02d}",
                title="Fix DNSSEC Chain Validation",
                current_state="DNSSEC enabled but chain invalid",
                target_state="DNSSEC chain fully validated",
                nist_standard="NIST SP 800-81r2",
                effort="Low",
                technical_steps=[
                    "Check DS record in parent zone matches DNSKEY in child zone",
                    "Verify RRSIG expiry dates are valid",
                    "Re-sign zone if RRSIGs have expired",
                    "Test from external resolver: `dig +cd +dnssec @8.8.8.8`",
                ],
                verification_method="DNSSEC chain validation passes from multiple independent resolvers",
            ))
            seq += 1

        if ct_log.get("flagged") or ct_log.get("unexpected_cas"):
            actions.append(MigrationAction(
                action_id=f"MA-1-{seq:02d}",
                title="Investigate and Revoke Unexpected CT Log Entries",
                current_state="Unexpected CA or flagged CT log entry",
                target_state="Clean CT log with known CAs only",
                nist_standard="CAB Forum Baseline Requirements",
                effort="High",
                technical_steps=[
                    "Query crt.sh for all certificates matching your domain",
                    "Identify certificates from unexpected Certificate Authorities",
                    "Request revocation via your CA's CRL/OCSP mechanism",
                    "Implement CAA DNS records to restrict which CAs may issue",
                    "Set up CT log monitoring alerts (e.g., cert-spotter, certstream)",
                ],
                verification_method="No unexpected CA entries in crt.sh; CAA record validated",
            ))
            seq += 1

        if not headers.get("hsts_enabled"):
            actions.append(MigrationAction(
                action_id=f"MA-1-{seq:02d}",
                title="Enable HTTP Strict Transport Security (HSTS)",
                current_state="HSTS missing",
                target_state="HSTS with max-age ≥ 31536000, includeSubDomains, preload",
                nist_standard="NIST SP 800-52r2",
                effort="Low",
                technical_steps=[
                    "Add header: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`",
                    "Start with short max-age (300s) to test, then increase to 1 year",
                    "Submit domain to HSTS preload list at https://hstspreload.org",
                    "Ensure all subdomains also serve valid HTTPS before enabling includeSubDomains",
                ],
                verification_method="Response headers include HSTS with max-age ≥ 31536000",
            ))
            seq += 1

        return MigrationPhase(
            phase_number=1,
            phase_name="Fix Trust Chain",
            priority="IMMEDIATE" if actions else "NONE",
            timeframe="0–2 weeks",
            actions=actions,
            dependencies=[],
            risk_if_delayed="DNS poisoning or certificate misissuance attacks remain viable; HSTS bypass possible",
        )

    # ------------------------------------------------------------------
    # Phase 2 — Eliminate Critical Vulnerabilities
    # ------------------------------------------------------------------
    def _phase2_critical_vulns(self, versions, ciphers, kex) -> MigrationPhase:
        actions = []
        seq = 1

        insecure = [v["version"] for v in versions if v.get("is_insecure") and v.get("supported")]
        if insecure:
            actions.append(MigrationAction(
                action_id=f"MA-2-{seq:02d}",
                title=f"Disable Legacy TLS Versions: {', '.join(insecure)}",
                current_state=f"Insecure protocols enabled: {', '.join(insecure)}",
                target_state="Only TLS 1.2 and TLS 1.3 supported",
                nist_standard="NIST SP 800-52r2",
                effort="Low",
                technical_steps=[
                    "In Nginx: `ssl_protocols TLSv1.2 TLSv1.3;`",
                    "In Apache: `SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1`",
                    "In HAProxy: `ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11`",
                    "Test with: `nmap --script ssl-enum-ciphers -p 443 {hostname}`",
                    "Verify no client breakage via access logs",
                ],
                verification_method="SSL scan shows only TLSv1.2 and TLSv1.3 supported",
            ))
            seq += 1

        vuln_ciphers = [c for c in ciphers if c.get("is_quantum_vulnerable")]
        non_pfs = [c for c in ciphers if not c.get("is_forward_secret")]
        if vuln_ciphers or non_pfs:
            actions.append(MigrationAction(
                action_id=f"MA-2-{seq:02d}",
                title="Remove Quantum-Vulnerable and Non-PFS Cipher Suites",
                current_state=f"{len(vuln_ciphers)} quantum-vulnerable, {len(non_pfs)} non-PFS ciphers",
                target_state="Only ECDHE/DHE key exchange with AEAD encryption",
                nist_standard="NIST SP 800-52r2",
                effort="Medium",
                technical_steps=[
                    "Set cipher list to ECDHE+AESGCM:ECDHE+CHACHA20",
                    "Nginx: `ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:...'`",
                    "Disable static RSA key exchange (no PFS)",
                    "Disable DES, 3DES, RC4, and NULL ciphers",
                    "Enable only AEAD cipher modes (GCM, CCM, Poly1305)",
                ],
                verification_method="SSL Labs test shows A or A+; no quantum-vulnerable or non-PFS ciphers",
            ))
            seq += 1

        return MigrationPhase(
            phase_number=2,
            phase_name="Eliminate Critical Vulnerabilities",
            priority="IMMEDIATE" if actions else "NONE",
            timeframe="0–4 weeks",
            actions=actions,
            dependencies=["Phase 1"],
            risk_if_delayed="Ongoing exposure to downgrade attacks and cipher-level HNDL harvesting",
        )

    # ------------------------------------------------------------------
    # Phase 3 — Deploy Hybrid PQC on Transport Layer
    # ------------------------------------------------------------------
    def _phase3_hybrid_pqc_transport(self, kex, cert, label) -> MigrationPhase:
        actions = []
        seq = 1

        if not kex.get("is_post_quantum"):
            actions.append(MigrationAction(
                action_id=f"MA-3-{seq:02d}",
                title="Deploy Hybrid PQC Key Exchange (ML-KEM-768)",
                current_state=f"Classical key exchange: {kex.get('algorithm', 'unknown')}",
                target_state="X25519Kyber768 hybrid or ML-KEM-768 (FIPS-203)",
                nist_standard="FIPS-203 (ML-KEM)",
                effort="High",
                technical_steps=[
                    "Upgrade to OpenSSL 3.2+ or BoringSSL with ML-KEM support",
                    "Enable hybrid groups: X25519Kyber768Draft00 or X25519MLKEM768",
                    "Nginx (with OpenSSL 3.2+): `ssl_ecdh_curve X25519Kyber768Draft00:X25519:prime256v1`",
                    "Configure hybrid mode to maintain classical fallback during transition",
                    "Test with browsers that support KEMTLS (Chrome 131+, Firefox 132+)",
                    "Monitor TLS handshake sizes — PQC keys are larger",
                ],
                verification_method="TLS handshake inspection shows hybrid key exchange; client compatibility verified",
            ))
            seq += 1

        if not cert.get("is_quantum_safe_cert"):
            actions.append(MigrationAction(
                action_id=f"MA-3-{seq:02d}",
                title="Deploy ML-DSA Hybrid Certificate (FIPS-204)",
                current_state=f"Classical certificate: {cert.get('public_key_algorithm', 'unknown')} {cert.get('public_key_size', 0)}b",
                target_state="ML-DSA-65 or ML-DSA-87 certificate (FIPS-204)",
                nist_standard="FIPS-204 (ML-DSA)",
                effort="Very High",
                technical_steps=[
                    "Contact your CA to request a PQC or hybrid certificate",
                    "Generate ML-DSA key pair using liboqs or OpenSSL with OQS provider",
                    "Submit CSR with ML-DSA public key to a PQC-capable CA",
                    "Deploy as hybrid cert (classical + PQC) for backward compatibility",
                    "Let's Encrypt note: PQC certs not yet available; use a commercial CA",
                    "Alternatively deploy ML-DSA self-signed for internal services",
                ],
                verification_method="Certificate inspection shows ML-DSA or hybrid algorithm; chain validates",
            ))
            seq += 1

        return MigrationPhase(
            phase_number=3,
            phase_name="Deploy Hybrid PQC on Transport",
            priority="HIGH",
            timeframe="1–3 months",
            actions=actions,
            dependencies=["Phase 1", "Phase 2"],
            risk_if_delayed="HNDL window remains open; archived traffic retroactively decryptable",
        )

    # ------------------------------------------------------------------
    # Phase 4 — Secure Application Layer
    # ------------------------------------------------------------------
    def _phase4_application_layer(self, jwt_r, ssh, dnssec) -> MigrationPhase:
        actions = []
        seq = 1

        # JWT
        jwts = jwt_r.get("jwts_found") or []
        vuln_jwts = [j for j in jwts if j.get("algorithm") in ("RS256", "ES256", "RS384", "ES384", "HS256")]
        if vuln_jwts:
            algs = list({j["algorithm"] for j in vuln_jwts})
            actions.append(MigrationAction(
                action_id=f"MA-4-{seq:02d}",
                title=f"Migrate JWT Signing to Post-Quantum Algorithm",
                current_state=f"JWT signed with: {', '.join(algs)}",
                target_state="JWT signed with ML-DSA-65 (FIPS-204) or EdDSA as interim",
                nist_standard="FIPS-204 (ML-DSA)",
                effort="High",
                technical_steps=[
                    "Inventory all JWT issuers (auth servers, microservices)",
                    "Transition RS256/ES256 → EdDSA (Ed25519) as immediate step",
                    "Implement ML-DSA JWT signing using liboqs JOSE library",
                    "Update all JWT consumers to accept new algorithm",
                    "Rotate signing keys — revoke all old tokens",
                    "Monitor for algorithm downgrade in token headers",
                ],
                verification_method="JWT header `alg` field shows ML-DSA or EdDSA across all services",
            ))
            seq += 1

        # SSH
        hk_algos = ssh.get("host_key_algorithms") or []
        rsa_hk = [a for a in hk_algos if "rsa" in a.get("name", "").lower()]
        if rsa_hk:
            actions.append(MigrationAction(
                action_id=f"MA-4-{seq:02d}",
                title="Replace SSH RSA Host Keys with ML-DSA / Ed25519",
                current_state=f"RSA SSH host keys: {', '.join(a['name'] for a in rsa_hk[:3])}",
                target_state="Ed25519 host keys (interim) → ML-DSA host keys (PQC)",
                nist_standard="FIPS-204 (ML-DSA) / NIST SP 800-186",
                effort="Medium",
                technical_steps=[
                    "Generate Ed25519 host key: `ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key`",
                    "Add to sshd_config: `HostKey /etc/ssh/ssh_host_ed25519_key`",
                    "Disable RSA host keys from sshd_config",
                    "Distribute new host key fingerprint to all clients / known_hosts",
                    "For PQC: deploy OQS-SSH with ML-DSA host keys (experimental)",
                    "Restrict to Ed25519+ECDH for immediate improvement",
                ],
                verification_method="`ssh-keyscan -t ed25519 {hostname}` returns valid Ed25519 host key",
            ))
            seq += 1

        # DNSKEY algorithm if not quantum-safe
        if dnssec.get("enabled") and not dnssec.get("dnskey_algorithm_safe"):
            actions.append(MigrationAction(
                action_id=f"MA-4-{seq:02d}",
                title="Upgrade DNSKEY Algorithm to Quantum-Safe",
                current_state=f"DNSKEY algorithm: {dnssec.get('dnskey_algorithm', 'unknown')} (classical)",
                target_state="Ed448 or future PQC DNSKEY algorithm",
                nist_standard="NIST SP 800-81r2 / IETF DNSSEC-PQC (draft)",
                effort="High",
                technical_steps=[
                    "Perform DNSSEC algorithm rollover per RFC 6781",
                    "Introduce Ed448 signing keys alongside existing RSA keys",
                    "Double-sign zone with both algorithms during transition",
                    "Remove RSA DNSKEY once all resolvers have updated",
                    "Monitor for DNSSEC validation failures during rollover",
                ],
                verification_method="DNSKEY record shows Ed448 algorithm; chain validates from multiple resolvers",
            ))
            seq += 1

        return MigrationPhase(
            phase_number=4,
            phase_name="Secure Application Layer",
            priority="HIGH",
            timeframe="1–6 months",
            actions=actions,
            dependencies=["Phase 3"],
            risk_if_delayed="Application-layer tokens and management access remain quantum-vulnerable",
        )

    # ------------------------------------------------------------------
    # Phase 5 — Full PQC, Remove Classical Fallbacks
    # ------------------------------------------------------------------
    def _phase5_full_pqc(self, label, kex, cert) -> MigrationPhase:
        if label == "QUANTUM_SAFE":
            return MigrationPhase(
                phase_number=5,
                phase_name="Maintain ELITE_PQC Posture",
                priority="NONE",
                timeframe="Ongoing",
                actions=[],
                dependencies=[],
                risk_if_delayed="",
            )

        actions = [
            MigrationAction(
                action_id="MA-5-01",
                title="Remove Classical Algorithm Fallbacks",
                current_state="Hybrid mode: classical + PQC",
                target_state="PQC-only: ML-KEM + ML-DSA, no RSA/ECDH fallback",
                nist_standard="FIPS-203, FIPS-204",
                effort="High",
                technical_steps=[
                    "Remove X25519 and P-256 from TLS key exchange group list",
                    "Remove RSA cipher suites entirely",
                    "Enforce ML-KEM-768 as sole key exchange",
                    "Replace all hybrid certificates with pure ML-DSA certificates",
                    "Update all client libraries to support PQC-only negotiation",
                    "Run compatibility testing across all consumers/integrations",
                ],
                verification_method="TLS handshake shows only PQC algorithms; no classical fallback in cipher list",
            ),
            MigrationAction(
                action_id="MA-5-02",
                title="Achieve ELITE_PQC Tier Certification",
                current_state=f"Current tier: {label}",
                target_state="ELITE_PQC (score 90–100)",
                nist_standard="FIPS-203, FIPS-204, FIPS-205",
                effort="Medium",
                technical_steps=[
                    "Run Q-Secure full scan and verify all surfaces are PQC-compliant",
                    "Ensure SLH-DSA (FIPS-205) considered for code signing",
                    "Implement ML-DSA for all signing operations",
                    "Document PQC implementation for compliance audit trail",
                    "Submit to CMVP for FIPS 140-3 validation if required",
                ],
                verification_method="Q-Secure quantum score ≥ 90, label = QUANTUM_SAFE, tier = ELITE_PQC",
            ),
        ]

        return MigrationPhase(
            phase_number=5,
            phase_name="Full PQC — Eliminate Classical Fallbacks",
            priority="MEDIUM",
            timeframe="6–18 months",
            actions=actions,
            dependencies=["Phase 4"],
            risk_if_delayed="Cannot claim ELITE_PQC posture; hybrid mode still harvested by HNDL",
        )
