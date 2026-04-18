"""Q-Secure | backend/routes/admin.py"""
from flask import Blueprint, jsonify, request
from extensions import db, bcrypt
from models.user   import User
from models.report import AuditLog
from models.asset  import Asset
from models.scan   import ScanResult
from models.report import Report
from middleware.rbac import require_admin, require_audit
from middleware.audit import log_action

bp = Blueprint("admin", __name__, url_prefix="/api/admin")

def ok(data, code=200): return jsonify({"success": True, "data": data, "error": None}), code
def err(msg, code=400): return jsonify({"success": False, "data": None, "error": msg}), code

def _paginate(q):
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(100, int(request.args.get("per_page", 25)))
    p = q.paginate(page=page, per_page=per_page, error_out=False)
    return p.items, {"page": page, "per_page": per_page, "total": p.total, "pages": p.pages}

@bp.route("/users", methods=["GET"])
@require_admin
def list_users():
    items, meta = _paginate(User.query.order_by(User.created_at.desc()))
    return ok({"items": [u.to_dict() for u in items], "meta": meta})

@bp.route("/users/<int:uid>", methods=["PUT"])
@require_admin
def update_user(uid):
    u = User.query.get_or_404(uid)
    body = request.get_json(silent=True) or {}
    if "role" in body and body["role"] in ("admin","analyst","viewer","auditor"):
        u.role = body["role"]
    if "is_active" in body:
        u.is_active = bool(body["is_active"])
    if "password" in body and body["password"]:
        u.password_hash = bcrypt.generate_password_hash(body["password"]).decode()
    db.session.commit()
    log_action("user_updated", resource=u.email)
    return ok(u.to_dict())

@bp.route("/users/<int:uid>/unlock", methods=["POST"])
@require_admin
def unlock_user(uid):
    u = User.query.get_or_404(uid)
    u.locked_at = None
    u.failed_attempts = 0
    db.session.commit()
    log_action("user_unlocked", resource=u.email)
    return ok(u.to_dict())

@bp.route("/audit-log", methods=["GET"])
@require_audit
def audit_log():
    q = AuditLog.query
    if user := request.args.get("user"):   q = q.filter(AuditLog.user_email.ilike(f"%{user}%"))
    if action := request.args.get("action"): q = q.filter(AuditLog.action.ilike(f"%{action}%"))
    items, meta = _paginate(q.order_by(AuditLog.timestamp.desc()))
    return ok({"items": [a.to_dict() for a in items], "meta": meta})

@bp.route("/stats", methods=["GET"])
@require_admin
def stats():
    return ok({
        "users":   User.query.count(),
        "assets":  Asset.query.filter_by(is_active=True).count(),
        "scans":   ScanResult.query.count(),
        "reports": Report.query.count(),
        "audit_entries": AuditLog.query.count(),
    })

# ---------------------------------------------------------------------------
# Groq API Key Management
# ---------------------------------------------------------------------------

import json as _json
import os as _os

_AI_CONFIG_PATH = _os.path.join(_os.path.dirname(__file__), "..", "ai_config.json")

def _read_ai_config():
    try:
        with open(_AI_CONFIG_PATH, "r") as f:
            return _json.load(f)
    except Exception:
        return {"groq_api_key": ""}

def _write_ai_config(data):
    with open(_AI_CONFIG_PATH, "w") as f:
        _json.dump(data, f, indent=2)


@bp.route("/groq-key", methods=["GET"])
@require_admin
def get_groq_key():
    """Return masked Groq API key status."""
    from services.ai_service import _groq
    config = _read_ai_config()
    stored_key = config.get("groq_api_key", "")
    env_key = _os.environ.get("GROQ_API_KEY", "")
    active_key = stored_key or env_key
    return ok({
        "configured": bool(active_key),
        "source": "settings" if stored_key else ("env" if env_key else "none"),
        "masked_key": (active_key[:8] + "..." + active_key[-4:]) if len(active_key) > 12 else ("***" if active_key else ""),
        "groq_available": _groq.is_available(),
    })


@bp.route("/groq-key", methods=["POST"])
@require_admin
def set_groq_key():
    """Save a new Groq API key and hot-reload the AI client."""
    from services.ai_service import _groq
    body = request.get_json(silent=True) or {}
    api_key = (body.get("api_key") or "").strip()
    if not api_key:
        return err("api_key is required", 400)
    # Persist
    config = _read_ai_config()
    config["groq_api_key"] = api_key
    _write_ai_config(config)
    # Hot-reload
    success = _groq.reload(api_key)
    log_action("groq_key_updated", resource="ai_config")
    return ok({"saved": True, "groq_available": success})


@bp.route("/groq-key", methods=["DELETE"])
@require_admin
def delete_groq_key():
    """Remove the stored Groq API key."""
    from services.ai_service import _groq
    config = _read_ai_config()
    config["groq_api_key"] = ""
    _write_ai_config(config)
    _groq.reload("")
    log_action("groq_key_removed", resource="ai_config")
    return ok({"removed": True, "groq_available": False})

