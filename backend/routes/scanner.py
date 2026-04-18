"""Q-Secure | backend/routes/scanner.py"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import get_jwt_identity
from extensions import db
from models.asset import Asset
from models.scan import ScanResult
from middleware.rbac import require_read, require_write
from middleware.audit import log_action
from services.scan_service import run_scan, run_batch_scan
from config import Config

bp = Blueprint("scanner", __name__, url_prefix="/api/scanner")

def ok(data, code=200): return jsonify({"success": True, "data": data, "error": None}), code
def err(msg, code=400): return jsonify({"success": False, "data": None, "error": msg}), code

def _paginate(q):
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(100, int(request.args.get("per_page", 25)))
    p = q.paginate(page=page, per_page=per_page, error_out=False)
    return p.items, {"page": page, "per_page": per_page, "total": p.total, "pages": p.pages}

@bp.route("/quick-scan", methods=["POST"])
@require_write
def quick_scan():
    body = request.get_json(silent=True) or {}
    hostname = (body.get("hostname") or "").strip()
    if not hostname: return err("hostname required")
    port = int(body.get("port", 443))
    mock = body.get("mock", Config.SCANNER_MOCK_MODE)
    uid  = get_jwt_identity()

    # Get or create ephemeral asset
    asset = Asset.query.filter_by(hostname=hostname, is_active=True).first()
    if not asset:
        asset = Asset(hostname=hostname, port=port, created_by=uid)
        db.session.add(asset); db.session.flush()

    scan = run_scan(asset, initiated_by=uid, mock=mock)
    log_action("quick_scan", resource=hostname)
    return ok(scan.to_dict(include_data=True), 201)

@bp.route("/scan/<int:asset_id>", methods=["POST"])
@require_write
def scan_asset(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    uid   = get_jwt_identity()
    mock  = request.get_json(silent=True, force=True).get("mock", Config.SCANNER_MOCK_MODE) if request.data else Config.SCANNER_MOCK_MODE
    scan  = run_scan(asset, initiated_by=uid, mock=mock)
    log_action("asset_scan", resource=asset.hostname)
    return ok(scan.to_dict(include_data=True), 201)

@bp.route("/batch-scan", methods=["POST"])
@require_write
def batch_scan():
    body     = request.get_json(silent=True) or {}
    asset_ids= body.get("asset_ids") or []
    mock     = body.get("mock", Config.SCANNER_MOCK_MODE)
    uid      = get_jwt_identity()
    assets   = Asset.query.filter(Asset.id.in_(asset_ids)).all()
    scans    = run_batch_scan(assets, initiated_by=uid, mock=mock)
    log_action("batch_scan", resource=f"{len(scans)} assets")
    return ok([s.to_dict() for s in scans], 201)

@bp.route("/results", methods=["GET"])
@require_read
def list_results():
    q = ScanResult.query
    if aid := request.args.get("asset_id"): q = q.filter_by(asset_id=int(aid))
    items, meta = _paginate(q.order_by(ScanResult.started_at.desc()))
    return ok({"items": [s.to_dict() for s in items], "meta": meta})

@bp.route("/results/<int:rid>", methods=["GET"])
@require_read
def get_result(rid):
    s = ScanResult.query.get_or_404(rid)
    return ok(s.to_dict(include_data=True))
