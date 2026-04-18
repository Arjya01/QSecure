"""Q-Secure | backend/routes/blockchain.py — Blockchain explorer, certificates, smart contracts, threat intel"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import get_jwt_identity
from middleware.rbac import require_read, require_write, require_admin
from middleware.audit import log_action
from services.blockchain import get_blockchain, SmartContract, MerkleTree

bp = Blueprint("blockchain", __name__, url_prefix="/api/blockchain")

def ok(data, code=200): return jsonify({"success": True, "data": data, "error": None}), code
def err(msg, code=400): return jsonify({"success": False, "data": None, "error": msg}), code

# ━━━ Chain Explorer ━━━
@bp.route("/stats", methods=["GET"])
@require_read
def chain_stats():
    return ok(get_blockchain().get_chain_stats())

@bp.route("/blocks", methods=["GET"])
@require_read
def list_blocks():
    bc = get_blockchain()
    start = request.args.get("start", 0, type=int)
    limit = min(request.args.get("limit", 20, type=int), 100)
    return ok({"blocks": bc.get_chain_data(start, limit), "total": len(bc.chain),
               "chain_valid": bc.validate_chain()["valid"]})

@bp.route("/blocks/<int:index>", methods=["GET"])
@require_read
def get_block(index):
    bc = get_blockchain()
    if index >= len(bc.chain): return err("Block not found", 404)
    return ok(bc.chain[index].to_dict())

@bp.route("/validate", methods=["GET"])
@require_read
def validate_chain():
    return ok(get_blockchain().validate_chain())

@bp.route("/transactions", methods=["GET"])
@require_read
def search_transactions():
    bc = get_blockchain()
    txs = bc.search_transactions(
        tx_type=request.args.get("type"),
        asset_id=request.args.get("asset_id"),
        limit=min(request.args.get("limit", 50, type=int), 200))
    return ok({"transactions": txs, "count": len(txs)})

@bp.route("/pending", methods=["GET"])
@require_read
def pending():
    bc = get_blockchain()
    return ok({"pending": bc.pending_transactions, "count": len(bc.pending_transactions)})

# ━━━ Mining ━━━
@bp.route("/mine", methods=["POST"])
@require_write
def mine_block():
    bc = get_blockchain()
    uid = get_jwt_identity()
    bc.record_audit_event("manual_mine", uid, "Manual block mining triggered")
    block = bc.mine_pending()
    if not block: return ok({"message": "No pending transactions to mine"})
    log_action("blockchain_mine", resource=f"block#{block.index}")
    return ok({"block": block.to_dict(), "message": f"Block #{block.index} mined"})

# ━━━ PQC Certificates ━━━
@bp.route("/certificates/issue", methods=["POST"])
@require_write
def issue_certificate():
    body = request.get_json(silent=True) or {}
    for r in ("asset_id", "asset_name", "label_type", "score"):
        if r not in body: return err(f"{r} required")
    uid = get_jwt_identity()
    result = get_blockchain().issue_pqc_certificate(
        asset_id=body["asset_id"], asset_name=body["asset_name"],
        label_type=body["label_type"], score=body["score"],
        nist_compliance=body.get("nist_compliance", {}), issued_by=uid)
    log_action("blockchain_cert_issue", resource=body["asset_name"])
    return ok(result, 201)

@bp.route("/certificates/verify/<cert_hash>", methods=["GET"])
def verify_certificate(cert_hash):
    """Public — no auth required."""
    return ok(get_blockchain().verify_certificate(cert_hash))

@bp.route("/certificates/revoke", methods=["POST"])
@require_admin
def revoke_certificate():
    body = request.get_json(silent=True) or {}
    cert_hash = body.get("certificate_hash")
    if not cert_hash: return err("certificate_hash required")
    uid = get_jwt_identity()
    result = get_blockchain().revoke_certificate(cert_hash, body.get("reason", "Administrative"), uid)
    log_action("blockchain_cert_revoke", resource=cert_hash[:16])
    return ok(result)

@bp.route("/certificates", methods=["GET"])
@require_read
def list_certificates():
    bc = get_blockchain()
    certs = bc.search_transactions(tx_type="pqc_certificate_issued")
    for c in certs:
        ch = c.get("certificate_hash", "")
        c["revoked"] = ch in bc.revocation_registry
        if c["revoked"]: c["revocation"] = bc.revocation_registry[ch]
    return ok({"certificates": certs, "count": len(certs)})

# ━━━ Smart Contracts ━━━
@bp.route("/contracts", methods=["GET"])
@require_read
def list_contracts():
    return ok({"contracts": [{"id": cid, **c} for cid, c in SmartContract.CONTRACTS.items()]})

@bp.route("/contracts/<contract_id>/execute", methods=["POST"])
@require_write
def execute_contract(contract_id):
    body = request.get_json(silent=True) or {}
    result = SmartContract.execute(contract_id, body)
    log_action("smart_contract_exec", resource=contract_id)
    return ok({"result": result, "contract_id": contract_id})

# ━━━ CBOM Integrity ━━━
@bp.route("/cbom/snapshot", methods=["POST"])
@require_write
def cbom_snapshot():
    body = request.get_json(silent=True) or {}
    if not body.get("asset_id") or not body.get("entries"): return err("asset_id and entries required")
    result = get_blockchain().record_cbom_snapshot(body["asset_id"], body["entries"])
    return ok(result, 201)

@bp.route("/cbom/verify", methods=["POST"])
@require_read
def verify_cbom():
    body = request.get_json(silent=True) or {}
    if not body.get("entries") or not body.get("merkle_root"): return err("entries and merkle_root required")
    tree = MerkleTree(body["entries"])
    return ok({"verified": tree.root == body["merkle_root"], "computed_root": tree.root,
               "expected_root": body["merkle_root"], "leaf_count": len(tree.leaves)})

# ━━━ Threat Intelligence ━━━
@bp.route("/threat-intel", methods=["GET"])
@require_read
def threat_intel_feed():
    limit = min(request.args.get("limit", 50, type=int), 200)
    feed = get_blockchain().get_threat_intel_feed(limit)
    return ok({"feed": feed, "count": len(feed)})

@bp.route("/threat-intel/share", methods=["POST"])
@require_write
def share_threat():
    body = request.get_json(silent=True) or {}
    if not body.get("threat_type") or not body.get("details"): return err("threat_type and details required")
    uid = get_jwt_identity()
    result = get_blockchain().share_threat_intel(body["threat_type"], body["details"], uid, body.get("severity", "high"))
    log_action("threat_intel_share", resource=body["threat_type"])
    return ok(result, 201)

# ━━━ Blockchain Audit ━━━
@bp.route("/audit", methods=["GET"])
@require_admin
def blockchain_audit():
    return ok({"events": get_blockchain().search_transactions(tx_type="audit_event", limit=100)})
