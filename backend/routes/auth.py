"""Q-Secure | backend/routes/auth.py"""
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
from extensions import db, bcrypt, limiter
from models.user import User
from models.report import AuditLog

bp = Blueprint("auth", __name__, url_prefix="/api/auth")

def ok(data):   return jsonify({"success": True,  "data": data,  "error": None})
def err(msg, code=400): return jsonify({"success": False, "data": None, "error": msg}), code

def _audit(action, outcome="success", details=None, resource=None):
    try:
        al = AuditLog(action=action, outcome=outcome, details=details, resource=resource,
                      ip_address=request.remote_addr)
        db.session.add(al); db.session.commit()
    except Exception: pass


@bp.route("/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    body = request.get_json(silent=True) or {}
    email    = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""

    if not email or not password:
        return err("Email and password required")

    user = User.query.filter_by(email=email).first()
    if not user or not user.is_active:
        _audit("login_failed", "failure", f"Unknown email: {email}")
        return err("Invalid credentials", 401)

    if user.is_locked():
        _audit("login_blocked", "failure", f"Locked account: {email}")
        return err("Account locked after too many failed attempts. Contact your administrator.", 403)

    if not bcrypt.check_password_hash(user.password_hash, password):
        user.failed_attempts += 1
        if user.failed_attempts >= 5:
            user.locked_at = datetime.now(timezone.utc)
        db.session.commit()
        _audit("login_failed", "failure", f"Wrong password for {email} (attempt {user.failed_attempts})")
        return err("Invalid credentials", 401)

    # Success
    user.failed_attempts = 0
    user.last_login = datetime.now(timezone.utc)
    db.session.commit()

    access  = create_access_token(identity=str(user.id))
    refresh = create_refresh_token(identity=str(user.id))
    _audit("login_success", details=email)
    return ok({"access_token": access, "refresh_token": refresh, "user": user.to_dict()})


@bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    uid = get_jwt_identity()
    user = User.query.get(uid)
    if not user or not user.is_active:
        return err("Invalid token", 401)
    token = create_access_token(identity=str(uid))
    return ok({"access_token": token})


@bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    _audit("logout")
    return ok({"message": "Logged out"})


@bp.route("/register", methods=["POST"])
@jwt_required()
def register():
    # Only admins exist now, any authenticated user can register a new admin
    uid = get_jwt_identity()
    caller = User.query.get(uid)
    if not caller:
        return err("User not found", 403)

    body  = request.get_json(silent=True) or {}
    email    = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""
    role     = "admin"

    if not email or not password:
        return err("Email and password required")
    if User.query.filter_by(email=email).first():
        return err("Email already exists")

    user = User(email=email, password_hash=bcrypt.generate_password_hash(password).decode(), role=role)
    db.session.add(user); db.session.commit()
    _audit("user_created", resource=email)
    return ok(user.to_dict(), 201)


@bp.route("/me", methods=["GET"])
@jwt_required()
def me():
    uid = get_jwt_identity()
    user = User.query.get(uid)
    if not user:
        return err("Not found", 404)
    return ok(user.to_dict())
