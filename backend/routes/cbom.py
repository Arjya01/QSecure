"""Q-Secure | backend/routes/cbom.py"""
import csv, io
from flask import Blueprint, jsonify, request, send_file
from middleware.rbac import require_read, require_export
from models.scan import CBOMEntry, ScanResult
from extensions import db
from sqlalchemy import func
from services.scope_service import get_asset_ids_for_scope

bp = Blueprint("cbom", __name__, url_prefix="/api/cbom")

def ok(data): return jsonify({"success": True, "data": data, "error": None})

def _paginate(q):
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(200, int(request.args.get("per_page", 50)))
    p = q.paginate(page=page, per_page=per_page, error_out=False)
    return p.items, {"page": page, "per_page": per_page, "total": p.total, "pages": p.pages}

@bp.route("", methods=["GET"])
@require_read
def list_cbom():
    q = CBOMEntry.query
    if risk := request.args.get("quantum_risk"): q = q.filter_by(quantum_risk=risk)
    if ct := request.args.get("component_type"): q = q.filter_by(component_type=ct)
    if aid := request.args.get("asset_id"):      q = q.filter_by(asset_id=int(aid))
    elif request.args.get("domain") or request.args.get("group_id"):
        asset_ids = get_asset_ids_for_scope(
            domain=request.args.get("domain"),
            group_id=request.args.get("group_id", type=int),
        )
        if not asset_ids:
            return ok({"items": [], "meta": {"page": 1, "per_page": 50, "total": 0, "pages": 0}})
        q = q.filter(CBOMEntry.asset_id.in_(asset_ids))
    items, meta = _paginate(q.order_by(CBOMEntry.quantum_risk))
    return ok({"items": [e.to_dict() for e in items], "meta": meta})

@bp.route("/<int:asset_id>", methods=["GET"])
@require_read
def cbom_for_asset(asset_id):
    # Latest scan CBOM
    latest = (db.session.query(func.max(ScanResult.id)).filter_by(asset_id=asset_id).scalar())
    entries = CBOMEntry.query.filter_by(asset_id=asset_id, scan_id=latest).all() if latest else []
    return ok([e.to_dict() for e in entries])

@bp.route("/stats", methods=["GET"])
@require_read
def cbom_stats():
    q = CBOMEntry.query
    if aid := request.args.get("asset_id"):
        q = q.filter_by(asset_id=int(aid))
    elif request.args.get("domain") or request.args.get("group_id"):
        asset_ids = get_asset_ids_for_scope(
            domain=request.args.get("domain"),
            group_id=request.args.get("group_id", type=int),
        )
        if not asset_ids:
            return ok({"total": 0, "by_risk": {}, "by_type": {}, "key_size_distribution": []})
        q = q.filter(CBOMEntry.asset_id.in_(asset_ids))

    total = q.count()
    by_risk = {}
    for risk in ("CRITICAL","HIGH","MEDIUM","LOW","NONE"):
        by_risk[risk] = q.filter_by(quantum_risk=risk).count()
    by_type = {}
    for ct in ("algorithm","key","certificate","protocol"):
        by_type[ct] = q.filter_by(component_type=ct).count()
    # Key size distribution
    key_sizes = q.with_entities(CBOMEntry.key_size, func.count()).group_by(CBOMEntry.key_size).all()
    return ok({"total": total, "by_risk": by_risk, "by_type": by_type,
               "key_size_distribution": [{"size": k, "count": c} for k, c in key_sizes]})

@bp.route("/export", methods=["GET"])
@require_export
def export_cbom():
    q = CBOMEntry.query
    if aid := request.args.get("asset_id"):
        q = q.filter_by(asset_id=int(aid))
    elif request.args.get("domain") or request.args.get("group_id"):
        asset_ids = get_asset_ids_for_scope(
            domain=request.args.get("domain"),
            group_id=request.args.get("group_id", type=int),
        )
        if asset_ids:
            q = q.filter(CBOMEntry.asset_id.in_(asset_ids))
        else:
            q = q.filter(db.text("1=0"))
    entries = q.all()
    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(["id","scan_id","asset_id","component_type","algorithm","key_size",
                "quantum_risk","migration_priority","replacement","nist_standard"])
    for e in entries:
        w.writerow([e.id, e.scan_id, e.asset_id, e.component_type, e.algorithm,
                    e.key_size, e.quantum_risk, e.migration_priority,
                    e.replacement, e.nist_standard])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype="text/csv",
                     as_attachment=True, download_name="qsecure_cbom.csv")
