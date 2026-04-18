"""Q-Secure | backend/app.py — Flask application factory"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))  # reach scanner/

from flask import Flask, jsonify
from config import config_map, Config
from extensions import db, jwt, cors, limiter, bcrypt

def create_app(env: str = None) -> Flask:
    env = env or os.environ.get("FLASK_ENV", "development")
    cfg = config_map.get(env, Config)

    app = Flask(__name__)
    app.config.from_object(cfg)

    # Init extensions
    db.init_app(app)
    jwt.init_app(app)
    bcrypt.init_app(app)
    limiter.init_app(app)
    cors.init_app(app, origins=cfg.CORS_ORIGINS, supports_credentials=True,
                  allow_headers=["Content-Type","Authorization"],
                  methods=["GET","POST","PUT","DELETE","OPTIONS"])

    # Register blueprints
    from routes.auth     import bp as auth_bp
    from routes.assets   import bp as assets_bp
    from routes.scanner  import bp as scanner_bp
    from routes.cbom     import bp as cbom_bp
    from routes.dashboard import bp as dash_bp
    from routes.reports  import bp as reports_bp
    from routes.admin    import bp as admin_bp
    from routes.labels   import bp as labels_bp
    from routes.ai       import bp as ai_bp
    from routes.groups   import bp as groups_bp
    from routes.blockchain import bp as blockchain_bp
    from routes.banking  import bp as banking_bp

    for bp in (auth_bp, assets_bp, scanner_bp, cbom_bp, dash_bp, reports_bp, admin_bp, labels_bp, ai_bp, groups_bp, blockchain_bp, banking_bp):
        app.register_blueprint(bp)

    # Consistent error handlers
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"success": False, "data": None, "error": "Not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"success": False, "data": None, "error": "Method not allowed"}), 405

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({"success": False, "data": None, "error": "Internal server error"}), 500

    @jwt.expired_token_loader
    def expired(_jwt_header, _jwt_payload):
        return jsonify({"success": False, "data": None, "error": "Token expired"}), 401

    @jwt.invalid_token_loader
    def invalid(reason):
        return jsonify({"success": False, "data": None, "error": f"Invalid token: {reason}"}), 401

    @jwt.unauthorized_loader
    def unauthorized(reason):
        return jsonify({"success": False, "data": None, "error": "Authorization required"}), 401

    @app.route("/api/health")
    def health():
        return jsonify({"success": True, "data": {"status": "ok", "version": "3.0.0"}, "error": None})

    # Create tables
    with app.app_context():
        db.create_all()

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)
