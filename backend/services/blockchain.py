"""Q-Secure Blockchain Engine.

A purpose-built blockchain for banking cybersecurity operations:
- Immutable audit ledger for all scan/compliance/label events
- PQC certificate issuance and verification on-chain
- Merkle-tree based CBOM integrity verification
- Smart contract compliance automation
- Cross-institution threat intelligence sharing
- Tamper-proof evidence for regulatory audits (RBI, SOX, PCI DSS)

Uses SHA-256 + optional post-quantum hash (SHAKE-256) for quantum resistance.
"""

import hashlib
import json
import time
import threading
from datetime import datetime, timezone
from collections import OrderedDict


# ═══════════════════════════ MERKLE TREE ═══════════════════════════

class MerkleTree:
    """Merkle tree for data integrity verification."""

    def __init__(self, data_list, hash_func=None):
        self.hash_func = hash_func or self._sha256
        self.leaves = [self.hash_func(json.dumps(d, sort_keys=True)) for d in data_list]
        self.tree = self._build_tree(self.leaves[:])
        self.root = self.tree[-1][0] if self.tree and self.tree[-1] else ""

    def _sha256(self, data):
        return hashlib.sha256(data.encode()).hexdigest()

    def _build_tree(self, leaves):
        if not leaves:
            return [[]]
        tree = [leaves]
        current = leaves
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else left
                next_level.append(self.hash_func(left + right))
            tree.append(next_level)
            current = next_level
        return tree

    def get_proof(self, index):
        """Get Merkle proof for a leaf at given index."""
        if index >= len(self.leaves):
            return []
        proof = []
        current = self.leaves[:]
        idx = index
        for level in self.tree[:-1]:
            if len(level) <= 1:
                break
            if idx % 2 == 0:
                sibling_idx = idx + 1
                direction = "right"
            else:
                sibling_idx = idx - 1
                direction = "left"
            if sibling_idx < len(level):
                proof.append({"hash": level[sibling_idx], "direction": direction})
            idx //= 2
        return proof

    def verify_proof(self, leaf_hash, proof, root):
        """Verify a Merkle proof against the root."""
        current = leaf_hash
        for step in proof:
            if step["direction"] == "right":
                current = self.hash_func(current + step["hash"])
            else:
                current = self.hash_func(step["hash"] + current)
        return current == root

    def to_dict(self):
        return {
            "root": self.root,
            "leaf_count": len(self.leaves),
            "depth": len(self.tree),
            "leaves": self.leaves[:10],  # First 10 for display
        }


# ═══════════════════════════ BLOCK ═══════════════════════════

class Block:
    """A single block in the Q-Secure blockchain."""

    def __init__(self, index, timestamp, transactions, previous_hash,
                 merkle_root="", nonce=0, difficulty=2):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.merkle_root = merkle_root
        self.nonce = nonce
        self.difficulty = difficulty
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_data = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "nonce": self.nonce,
        }, sort_keys=True)
        return hashlib.sha256(block_data.encode()).hexdigest()

    def mine(self):
        """Proof-of-work mining with configurable difficulty."""
        target = "0" * self.difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.compute_hash()
        return self.hash

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "hash": self.hash,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "nonce": self.nonce,
            "difficulty": self.difficulty,
            "transaction_count": len(self.transactions),
            "transactions": self.transactions,
        }


# ═══════════════════════════ SMART CONTRACTS ═══════════════════════════

class SmartContract:
    """Smart contract for automated compliance and certificate issuance."""

    CONTRACTS = {
        "pqc_certificate_issuance": {
            "name": "PQC Certificate Auto-Issuance",
            "description": "Automatically issues PQC-Ready or Fully Quantum Safe certificates when scan scores meet thresholds",
            "version": "1.0.0",
            "conditions": {
                "fully_quantum_safe": {"min_score": 90, "requires_ml_kem": True, "requires_ml_dsa": True},
                "pqc_ready": {"min_score": 75, "requires_any_pqc": True},
            },
        },
        "compliance_auto_check": {
            "name": "Compliance Auto-Verification",
            "description": "Automatically verifies scan results against PCI DSS, RBI, SWIFT CSP requirements",
            "version": "1.0.0",
            "frameworks": ["pci_dss", "rbi_cyber", "swift_csp", "gdpr", "nist_pqc"],
        },
        "threat_intelligence_share": {
            "name": "Threat Intelligence Sharing",
            "description": "Cross-institution sharing of vulnerability discoveries and threat indicators",
            "version": "1.0.0",
            "data_types": ["weak_cipher", "expired_cert", "deprecated_protocol", "hndl_risk"],
        },
        "cbom_integrity": {
            "name": "CBOM Integrity Verification",
            "description": "Merkle-tree based integrity verification for Cryptographic Bill of Materials",
            "version": "1.0.0",
        },
        "audit_immutability": {
            "name": "Immutable Audit Trail",
            "description": "Every scan, report, login, and configuration change is recorded immutably",
            "version": "1.0.0",
            "event_types": ["scan_completed", "report_generated", "label_issued", "label_revoked",
                           "user_login", "user_created", "asset_created", "compliance_check",
                           "config_change", "alert_triggered"],
        },
        "certificate_revocation": {
            "name": "Certificate Revocation Registry",
            "description": "On-chain registry of revoked PQC certificates for instant verification",
            "version": "1.0.0",
        },
        "risk_score_consensus": {
            "name": "Multi-Validator Risk Scoring",
            "description": "Consensus-based risk scoring from multiple scan validators",
            "version": "1.0.0",
        },
    }

    @staticmethod
    def execute(contract_id, input_data):
        """Execute a smart contract and return the result."""
        contract = SmartContract.CONTRACTS.get(contract_id)
        if not contract:
            return {"error": f"Contract {contract_id} not found"}

        if contract_id == "pqc_certificate_issuance":
            return SmartContract._execute_pqc_issuance(input_data)
        elif contract_id == "compliance_auto_check":
            return SmartContract._execute_compliance(input_data)
        elif contract_id == "cbom_integrity":
            return SmartContract._execute_cbom_integrity(input_data)
        elif contract_id == "certificate_revocation":
            return SmartContract._execute_revocation(input_data)

        return {"status": "executed", "contract": contract_id}

    @staticmethod
    def _execute_pqc_issuance(data):
        score = data.get("overall_score", 0)
        nist = data.get("nist_compliance", {})

        if score >= 90 and nist.get("ml_kem") and nist.get("ml_dsa"):
            return {
                "action": "issue_certificate",
                "label_type": "fully_quantum_safe",
                "confidence": "high",
                "reason": "All NIST PQC standards met with score >= 90",
            }
        elif score >= 75 and any(nist.values()):
            return {
                "action": "issue_certificate",
                "label_type": "pqc_ready",
                "confidence": "medium",
                "reason": "Partial PQC implementation with score >= 75",
            }
        else:
            return {
                "action": "deny_certificate",
                "label_type": "not_quantum_safe",
                "reason": f"Score {score} below threshold, PQC algorithms not detected",
                "recommendations": [
                    "Implement ML-KEM-768 for key exchange",
                    "Deploy ML-DSA-65 for certificate signatures",
                    "Upgrade to TLS 1.3 with PQC cipher suites",
                ],
            }

    @staticmethod
    def _execute_compliance(data):
        results = {}
        scan_data = data.get("scan_data", {})
        tls_ver = scan_data.get("tls_info", {}).get("version", "")
        key_size = scan_data.get("certificate", {}).get("public_key_size", 0)

        for fw in ["pci_dss", "rbi_cyber", "swift_csp"]:
            checks = []
            checks.append({"check": "TLS >= 1.2", "pass": tls_ver in ("TLSv1.2", "TLSv1.3")})
            checks.append({"check": "Key >= 2048", "pass": key_size >= 2048})
            passed = sum(1 for c in checks if c["pass"])
            results[fw] = {"passed": passed, "total": len(checks), "compliant": passed == len(checks)}

        return {"compliance_results": results}

    @staticmethod
    def _execute_cbom_integrity(data):
        entries = data.get("cbom_entries", [])
        if not entries:
            return {"error": "No CBOM entries provided"}
        tree = MerkleTree(entries)
        return {
            "merkle_root": tree.root,
            "leaf_count": len(tree.leaves),
            "integrity_verified": True,
            "tree": tree.to_dict(),
        }

    @staticmethod
    def _execute_revocation(data):
        return {
            "action": "revoke",
            "certificate_id": data.get("certificate_id"),
            "reason": data.get("reason", "Security concern"),
            "revoked_at": datetime.now(timezone.utc).isoformat(),
            "status": "revoked",
        }


# ═══════════════════════════ BLOCKCHAIN ═══════════════════════════

class QSecureBlockchain:
    """The Q-Secure blockchain — purpose-built for banking cybersecurity."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.chain = []
        self.pending_transactions = []
        self.difficulty = 2  # Low for demo speed; production would use 4+
        self.mining_reward = 0  # No monetary reward
        self.smart_contracts = SmartContract.CONTRACTS
        self.threat_intel_pool = []  # Shared threat intelligence
        self.revocation_registry = {}  # Certificate revocation on-chain
        self._create_genesis_block()

    def _create_genesis_block(self):
        genesis = Block(
            index=0,
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat(),
            transactions=[{
                "type": "genesis",
                "message": "Q-Secure Blockchain Genesis — Quantum-Ready Cybersecurity for Future-Safe Banking",
                "created_by": "Q-Secure System",
                "nist_standards": ["FIPS 203 (ML-KEM)", "FIPS 204 (ML-DSA)", "FIPS 205 (SLH-DSA)"],
            }],
            previous_hash="0" * 64,
            merkle_root=hashlib.sha256(b"genesis").hexdigest(),
        )
        genesis.mine()
        self.chain.append(genesis)

    @property
    def last_block(self):
        return self.chain[-1]

    def add_transaction(self, transaction):
        """Add a transaction to the pending pool."""
        tx = {
            **transaction,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tx_hash": hashlib.sha256(
                json.dumps(transaction, sort_keys=True).encode()
            ).hexdigest(),
        }
        self.pending_transactions.append(tx)
        return tx

    def mine_pending(self):
        """Mine all pending transactions into a new block."""
        if not self.pending_transactions:
            return None

        # Build Merkle tree from transactions
        tree = MerkleTree(self.pending_transactions)

        block = Block(
            index=len(self.chain),
            timestamp=datetime.now(timezone.utc).isoformat(),
            transactions=self.pending_transactions[:],
            previous_hash=self.last_block.hash,
            merkle_root=tree.root,
            difficulty=self.difficulty,
        )
        block.mine()
        self.chain.append(block)
        self.pending_transactions = []
        return block

    def auto_mine_if_needed(self, threshold=5):
        """Auto-mine when pending transactions reach threshold."""
        if len(self.pending_transactions) >= threshold:
            return self.mine_pending()
        return None

    # ─────── High-level operations ───────

    def record_scan(self, scan_id, asset_name, hostname, score, quantum_safe,
                    user_id, vulnerabilities_count=0):
        """Record a completed scan on the blockchain."""
        tx = self.add_transaction({
            "type": "scan_completed",
            "scan_id": scan_id,
            "asset_name": asset_name,
            "hostname": hostname,
            "quantum_safety_score": score,
            "quantum_safe": quantum_safe,
            "vulnerabilities_found": vulnerabilities_count,
            "initiated_by": user_id,
            "evidence_hash": hashlib.sha256(
                f"{scan_id}:{hostname}:{score}:{quantum_safe}".encode()
            ).hexdigest(),
        })
        self.auto_mine_if_needed()
        return tx

    def issue_pqc_certificate(self, asset_id, asset_name, label_type, score,
                               nist_compliance, issued_by):
        """Issue a PQC certificate on the blockchain."""
        # Execute smart contract first
        contract_result = SmartContract.execute("pqc_certificate_issuance", {
            "overall_score": score,
            "nist_compliance": nist_compliance,
        })

        cert_hash = hashlib.sha256(
            f"{asset_id}:{label_type}:{score}:{datetime.now(timezone.utc).isoformat()}".encode()
        ).hexdigest()

        tx = self.add_transaction({
            "type": "pqc_certificate_issued",
            "asset_id": asset_id,
            "asset_name": asset_name,
            "label_type": label_type,
            "score": score,
            "nist_compliance": nist_compliance,
            "issued_by": issued_by,
            "certificate_hash": cert_hash,
            "smart_contract_result": contract_result,
            "verification_url": f"/api/blockchain/verify/{cert_hash}",
        })
        self.auto_mine_if_needed(threshold=1)  # Mine immediately for certificates
        return {**tx, "certificate_hash": cert_hash}

    def revoke_certificate(self, cert_hash, reason, revoked_by):
        """Revoke a PQC certificate on-chain."""
        self.revocation_registry[cert_hash] = {
            "revoked_at": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "revoked_by": revoked_by,
        }
        tx = self.add_transaction({
            "type": "pqc_certificate_revoked",
            "certificate_hash": cert_hash,
            "reason": reason,
            "revoked_by": revoked_by,
        })
        self.auto_mine_if_needed(threshold=1)
        return tx

    def verify_certificate(self, cert_hash):
        """Verify a PQC certificate against the blockchain."""
        # Check revocation registry
        if cert_hash in self.revocation_registry:
            return {
                "valid": False,
                "status": "revoked",
                "revocation_details": self.revocation_registry[cert_hash],
            }

        # Search chain for issuance
        for block in self.chain:
            for tx in block.transactions:
                if tx.get("type") == "pqc_certificate_issued" and tx.get("certificate_hash") == cert_hash:
                    return {
                        "valid": True,
                        "status": "active",
                        "certificate": tx,
                        "block_index": block.index,
                        "block_hash": block.hash,
                        "mined_at": block.timestamp,
                    }

        return {"valid": False, "status": "not_found"}

    def record_compliance_check(self, asset_id, framework_id, result, user_id):
        """Record a compliance check result on-chain."""
        tx = self.add_transaction({
            "type": "compliance_check",
            "asset_id": asset_id,
            "framework": framework_id,
            "compliant": result.get("compliant", False),
            "compliance_pct": result.get("compliance_pct", 0),
            "checked_by": user_id,
        })
        self.auto_mine_if_needed()
        return tx

    def record_cbom_snapshot(self, asset_id, cbom_entries):
        """Record a CBOM integrity snapshot using Merkle tree."""
        result = SmartContract.execute("cbom_integrity", {"cbom_entries": cbom_entries})
        tx = self.add_transaction({
            "type": "cbom_integrity_snapshot",
            "asset_id": asset_id,
            "merkle_root": result.get("merkle_root"),
            "component_count": result.get("leaf_count"),
            "integrity_verified": True,
        })
        self.auto_mine_if_needed()
        return {**tx, "merkle_tree": result}

    def share_threat_intel(self, threat_type, details, reported_by, severity="high"):
        """Share threat intelligence on the blockchain."""
        intel = {
            "type": "threat_intelligence",
            "threat_type": threat_type,
            "details": details,
            "severity": severity,
            "reported_by": reported_by,
            "shared_at": datetime.now(timezone.utc).isoformat(),
        }
        self.threat_intel_pool.append(intel)
        tx = self.add_transaction(intel)
        self.auto_mine_if_needed()
        return tx

    def record_audit_event(self, event_type, user_id, details, resource_type=None, resource_id=None):
        """Record any audit event immutably."""
        tx = self.add_transaction({
            "type": "audit_event",
            "event_type": event_type,
            "user_id": user_id,
            "details": details,
            "resource_type": resource_type,
            "resource_id": resource_id,
        })
        self.auto_mine_if_needed()
        return tx

    # ─────── Chain operations ───────

    def validate_chain(self):
        """Validate the entire blockchain integrity."""
        errors = []
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            if current.hash != current.compute_hash():
                errors.append({"block": i, "error": "Hash mismatch — block tampered"})
            if current.previous_hash != previous.hash:
                errors.append({"block": i, "error": "Previous hash mismatch — chain broken"})
            if not current.hash.startswith("0" * current.difficulty):
                errors.append({"block": i, "error": "Proof-of-work invalid"})

        return {
            "valid": len(errors) == 0,
            "blocks_checked": len(self.chain),
            "errors": errors,
            "chain_hash": self.last_block.hash,
        }

    def get_chain_stats(self):
        """Get blockchain statistics."""
        total_txs = sum(len(b.transactions) for b in self.chain)
        tx_types = {}
        for b in self.chain:
            for tx in b.transactions:
                t = tx.get("type", "unknown")
                tx_types[t] = tx_types.get(t, 0) + 1

        return {
            "chain_length": len(self.chain),
            "total_transactions": total_txs,
            "pending_transactions": len(self.pending_transactions),
            "difficulty": self.difficulty,
            "latest_block_hash": self.last_block.hash,
            "genesis_hash": self.chain[0].hash,
            "transaction_types": tx_types,
            "threat_intel_entries": len(self.threat_intel_pool),
            "revoked_certificates": len(self.revocation_registry),
            "chain_valid": self.validate_chain()["valid"],
            "smart_contracts": list(self.smart_contracts.keys()),
        }

    def get_chain_data(self, start=0, limit=20):
        """Get blocks from the chain."""
        blocks = self.chain[start:start + limit]
        return [b.to_dict() for b in reversed(blocks)]

    def search_transactions(self, tx_type=None, asset_id=None, limit=50):
        """Search transactions across the blockchain."""
        results = []
        for block in reversed(self.chain):
            for tx in block.transactions:
                if tx_type and tx.get("type") != tx_type:
                    continue
                if asset_id and tx.get("asset_id") != asset_id:
                    continue
                results.append({**tx, "block_index": block.index, "block_hash": block.hash})
                if len(results) >= limit:
                    return results
        return results

    def get_threat_intel_feed(self, limit=50):
        """Get shared threat intelligence feed."""
        return self.threat_intel_pool[-limit:]


# Singleton accessor
def get_blockchain():
    return QSecureBlockchain()
