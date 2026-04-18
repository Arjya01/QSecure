"""Q-Secure | backend/routes/assets.py"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import get_jwt_identity
from extensions import db
from models.asset import Asset
from middleware.rbac import require_read, require_write, require_delete
from middleware.audit import log_action
from services.scope_service import get_asset_ids_for_scope

bp = Blueprint("assets", __name__, url_prefix="/api/assets")

def ok(data, code=200): return jsonify({"success": True, "data": data, "error": None}), code
def err(msg, code=400): return jsonify({"success": False, "data": None, "error": msg}), code

def _paginate(q):
    page     = max(1, int(request.args.get("page", 1)))
    per_page = min(100, int(request.args.get("per_page", 25)))
    p = q.paginate(page=page, per_page=per_page, error_out=False)
    return p.items, {"page": page, "per_page": per_page, "total": p.total, "pages": p.pages}

@bp.route("", methods=["GET"])
@require_read
def list_assets():
    q = Asset.query.filter_by(is_active=True)
    if t := request.args.get("type"): q = q.filter_by(type=t)
    if c := request.args.get("criticality"): q = q.filter_by(criticality=c)

    asset_ids = get_asset_ids_for_scope(
        domain=request.args.get("domain"),
        group_id=request.args.get("group_id", type=int),
    )
    if request.args.get("domain") or request.args.get("group_id"):
        if not asset_ids:
            return ok({"items": [], "meta": {"page": 1, "per_page": 25, "total": 0, "pages": 0}})
        q = q.filter(Asset.id.in_(asset_ids))

    items, meta = _paginate(q.order_by(Asset.created_at.desc()))
    return ok({"items": [a.to_dict(include_last_scan=True) for a in items], "meta": meta})

@bp.route("/<int:aid>", methods=["GET"])
@require_read
def get_asset(aid):
    a = Asset.query.get_or_404(aid)
    return ok(a.to_dict(include_last_scan=True))

@bp.route("", methods=["POST"])
@require_write
def create_asset():
    body = request.get_json(silent=True) or {}
    if not body.get("hostname"):
        return err("hostname required")
    uid = get_jwt_identity()
    a = Asset(
        hostname=body["hostname"], ip=body.get("ip"),
        port=int(body.get("port", 443)), type=body.get("type","web_server"),
        environment=body.get("environment","production"),
        criticality=body.get("criticality","medium"),
        owner=body.get("owner"), department=body.get("department"),
        business_unit=body.get("business_unit"), notes=body.get("notes"),
        created_by=uid,
    )
    db.session.add(a); db.session.commit()
    log_action("asset_created", resource=a.hostname)
    return ok(a.to_dict(), 201)

@bp.route("/<int:aid>", methods=["PUT"])
@require_write
def update_asset(aid):
    a = Asset.query.get_or_404(aid)
    body = request.get_json(silent=True) or {}
    for f in ("hostname","ip","port","type","environment","criticality","owner","department","business_unit","notes"):
        if f in body: setattr(a, f, body[f])
    db.session.commit()
    log_action("asset_updated", resource=a.hostname)
    return ok(a.to_dict())

@bp.route("/<int:aid>", methods=["DELETE"])
@require_delete
def delete_asset(aid):
    a = Asset.query.get_or_404(aid)
    a.is_active = False
    db.session.commit()
    log_action("asset_deleted", resource=a.hostname)
    return ok({"deleted": aid})
