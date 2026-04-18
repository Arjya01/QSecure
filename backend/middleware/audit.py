"""Q-Secure | backend/middleware/audit.py"""
from flask import request
from flask_jwt_extended import get_jwt_identity
from extensions import db
from models.report import AuditLog
from models.user import User

def log_action(action: str, resource: str = None, outcome: str = "success", details: str = None):
    try:
        uid = get_jwt_identity()
        email = None
        if uid:
            u = User.query.get(uid)
            email = u.email if u else None
        entry = AuditLog(
            user_id=uid, user_email=email,
            action=action, resource=resource,
            outcome=outcome, details=details,
            ip_address=request.remote_addr,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        pass  # Audit never crashes the main flow
