"""Q-Secure | backend/middleware/rbac.py"""
from functools import wraps
from flask import jsonify
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from models.user import User

def _resp(msg, code):
    return jsonify({"success": False, "data": None, "error": msg}), code

def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        uid = get_jwt_identity()
        user = User.query.get(uid)
        if not user or not user.is_active:
            return _resp("Account inactive", 401)
        if user.is_locked():
            return _resp("Account locked — contact administrator", 403)
        return fn(*args, **kwargs)
    return wrapper

# Alias all legacy granular roles to require_auth to avoid breaking imports
require_read   = require_auth
require_write  = require_auth
require_delete = require_auth
require_admin  = require_auth
require_export = require_auth
require_audit  = require_auth
