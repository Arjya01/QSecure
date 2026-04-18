"""Q-Secure | backend/routes/reports.py"""
import os
from flask import Blueprint, jsonify, request, send_file
from flask_jwt_extended import get_jwt_identity
from middleware.rbac import require_read, require_write
from middleware.audit import log_action
from models.report import Report
from services.report_service import generate_report

bp = Blueprint("reports", __name__, url_prefix="/api/reports")

def ok(data, code=200): return jsonify({"success": True, "data": data, "error": None}), code
def err(msg, code=400): return jsonify({"success": False, "data": None, "error": msg}), code

def _paginate(q):
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(50, int(request.args.get("per_page", 10)))
    p = q.paginate(page=page, per_page=per_page, error_out=False)
    return p.items, {"page": page, "per_page": per_page, "total": p.total, "pages": p.pages}

@bp.route("", methods=["GET"])
@require_read
def list_reports():
    items, meta = _paginate(Report.query.order_by(Report.created_at.desc()))
    return ok({"items": [r.to_dict() for r in items], "meta": meta})

@bp.route("/generate", methods=["POST"])
@require_write
def gen_report():
    body  = request.get_json(silent=True) or {}
    rtype = body.get("type", "executive")
    scope = body.get("scope", "all")
    fmt   = body.get("format", "pdf")
    title = body.get("title")
    uid   = get_jwt_identity()
    try:
        report = generate_report(rtype, scope, fmt, uid, title)
        log_action("report_generated", resource=report.title)
        return ok(report.to_dict(), 201)
    except Exception as e:
        return err(str(e), 500)

@bp.route("/<int:rid>/download", methods=["GET"])
@require_read
def download_report(rid):
    r = Report.query.get_or_404(rid)
    if not r.file_path or not os.path.exists(r.file_path):
        return err("File not found", 404)
    mimes = {"pdf": "application/pdf", "json": "application/json", "csv": "text/csv"}
    log_action("report_downloaded", resource=r.title)
    return send_file(r.file_path, mimetype=mimes.get(r.format, "application/octet-stream"),
                     as_attachment=False, download_name=os.path.basename(r.file_path))
