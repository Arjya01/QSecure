"""Q-Secure | backend/routes/banking.py — Banking templates, compliance frameworks, advanced scanners"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import get_jwt_identity
from extensions import db
from models.asset import Asset
from middleware.rbac import require_read, require_write
from middleware.audit import log_action
from services.banking_templates import (
    BANKING_CATEGORIES, BANKING_TEMPLATES, COMPLIANCE_FRAMEWORKS,
    get_templates_by_category, get_template_by_id, check_tls_compliance,
)
from services.advanced_scanners import scan_http_headers, scan_dns_security, scan_api_security, SECURITY_HEADERS

bp = Blueprint("banking", __name__, url_prefix="/api/banking")

def ok(data, code=200): return jsonify({"success": True, "data": data, "error": None}), code
def err(msg, code=400): return jsonify({"success": False, "data": None, "error": msg}), code

# ━━━ Banking Templates ━━━
@bp.route("/categories", methods=["GET"])
@require_read
def list_categories():
    return ok({"categories": BANKING_CATEGORIES})

@bp.route("/templates", methods=["GET"])
@require_read
def list_templates():
    cat = request.args.get("category")
    templates = get_templates_by_category(cat)
    return ok({"templates": templates, "total": len(templates), "categories": BANKING_CATEGORIES})

@bp.route("/templates/<template_id>", methods=["GET"])
@require_read
def get_template(template_id):
    t = get_template_by_id(template_id)
    if not t: return err("Template not found", 404)
    return ok({"template": t})

@bp.route("/templates/<template_id>/create-asset", methods=["POST"])
@require_write
def create_from_template(template_id):
    t = get_template_by_id(template_id)
    if not t: return err("Template not found", 404)
    body = request.get_json(silent=True) or {}
    hostname = (body.get("hostname") or "").strip()
    if not hostname: return err("hostname required")
    uid = get_jwt_identity()
    asset = Asset(
        hostname=hostname, port=body.get("port", t["default_port"]),
        asset_type=t.get("asset_type", "web_server"),
        criticality=t.get("criticality", "medium"),
        description=t.get("description", ""),
        owner=body.get("owner", ""), department=body.get("department", ""),
        business_unit=body.get("business_unit", ""),
        created_by=uid)
    db.session.add(asset); db.session.commit()
    log_action("asset_from_template", resource=f"{t['name']} -> {hostname}")
    return ok({"asset": asset.to_dict(), "template": t}, 201)

# ━━━ Compliance Frameworks ━━━
@bp.route("/compliance/frameworks", methods=["GET"])
@require_read
def list_frameworks():
    fws = []
    for fid, f in COMPLIANCE_FRAMEWORKS.items():
        fws.append({"id": fid, "name": f["name"], "full_name": f["full_name"],
                     "jurisdiction": f["jurisdiction"], "category": f["category"],
                     "checks_count": len(f.get("checks", []))})
    return ok({"frameworks": fws})

@bp.route("/compliance/frameworks/<fid>", methods=["GET"])
@require_read
def get_framework(fid):
    f = COMPLIANCE_FRAMEWORKS.get(fid)
    if not f: return err("Framework not found", 404)
    return ok({"framework": {**f, "id": fid}})

@bp.route("/compliance/check", methods=["POST"])
@require_write
def check_compliance():
    body = request.get_json(silent=True) or {}
    asset_id = body.get("asset_id")
    framework_id = body.get("framework_id")
    if not asset_id or not framework_id: return err("asset_id and framework_id required")
    from models.scan import ScanResult
    asset = Asset.query.get(asset_id)
    if not asset: return err("Asset not found", 404)
    latest = ScanResult.query.filter_by(asset_id=asset_id).order_by(ScanResult.id.desc()).first()
    scan_data = {}
    if latest and latest.raw_json:
        import json
        scan_data = json.loads(latest.raw_json) if isinstance(latest.raw_json, str) else latest.raw_json
    result = check_tls_compliance(scan_data, framework_id)
    log_action("compliance_check", resource=f"{framework_id} on asset#{asset_id}")
    # Record on blockchain
    try:
        from services.blockchain import get_blockchain
        get_blockchain().record_compliance_check(str(asset_id), framework_id, result, str(get_jwt_identity()))
    except Exception: pass
    return ok({"compliance": result})

# ━━━ HTTP Headers Scanner ━━━
@bp.route("/scan/headers", methods=["POST"])
@require_write
def scan_headers():
    body = request.get_json(silent=True) or {}
    hostname = (body.get("hostname") or "").strip()
    if not hostname: return err("hostname required")
    result = scan_http_headers(hostname, body.get("port", 443))
    log_action("headers_scan", resource=hostname)
    return ok({"headers_scan": result})

@bp.route("/scan/headers/reference", methods=["GET"])
@require_read
def headers_ref():
    return ok({"headers": SECURITY_HEADERS})

# ━━━ DNS Security Scanner ━━━
@bp.route("/scan/dns", methods=["POST"])
@require_write
def scan_dns():
    body = request.get_json(silent=True) or {}
    hostname = (body.get("hostname") or "").strip()
    if not hostname: return err("hostname required")
    result = scan_dns_security(hostname)
    log_action("dns_scan", resource=hostname)
    return ok({"dns_scan": result})

# ━━━ API Security Scanner ━━━
@bp.route("/scan/api", methods=["POST"])
@require_write
def scan_api():
    body = request.get_json(silent=True) or {}
    hostname = (body.get("hostname") or "").strip()
    if not hostname: return err("hostname required")
    result = scan_api_security(hostname, body.get("port", 443), body.get("base_path", "/api"))
    log_action("api_scan", resource=hostname)
    return ok({"api_scan": result})
