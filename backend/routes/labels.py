"""Q-Secure | backend/routes/labels.py"""
from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity
from datetime import datetime, timezone, timedelta
from extensions import db
from models.scan import PQCLabel
from middleware.rbac import require_read, require_write, require_admin
from middleware.audit import log_action

bp = Blueprint("labels", __name__, url_prefix="/api/labels")

def ok(data, code=200): return jsonify({"success": True, "data": data, "error": None}), code
def err(msg, code=400): return jsonify({"success": False, "data": None, "error": msg}), code

@bp.route("", methods=["GET"])
@require_read
def list_labels():
    labels = PQCLabel.query.filter_by(revoked=False).order_by(PQCLabel.issued_at.desc()).all()
    return ok([l.to_dict() for l in labels])

@bp.route("/issue", methods=["POST"])
@require_write
def issue_label():
    body = request.get_json(silent=True) or {}
    asset_id = body.get("asset_id")
    label    = body.get("label", "NOT_QUANTUM_SAFE")
    scan_id  = body.get("scan_id")
    uid      = get_jwt_identity()
    if not asset_id: return err("asset_id required")
    if label not in ("QUANTUM_SAFE","PQC_READY","NOT_QUANTUM_SAFE"):
        return err("Invalid label value")
    lbl = PQCLabel(
        asset_id=asset_id, scan_id=scan_id, label=label,
        issued_by=uid, expires_at=datetime.now(timezone.utc)+timedelta(days=90),
    )
    db.session.add(lbl); db.session.commit()
    log_action("label_issued", resource=f"asset:{asset_id} label:{label}")
    return ok(lbl.to_dict(), 201)

@bp.route("/revoke/<int:lid>", methods=["POST"])
@require_admin
def revoke_label(lid):
    lbl = PQCLabel.query.get_or_404(lid)
    body = request.get_json(silent=True) or {}
    lbl.revoked = True
    lbl.revoke_reason = body.get("reason", "Revoked by administrator")
    db.session.commit()
    log_action("label_revoked", resource=f"label:{lid}")
    return ok(lbl.to_dict())
