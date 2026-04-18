"""
Q-Secure | backend/routes/ai.py
Phase 5 — AI Intelligence Layer API Routes.

POST /api/ai/analyze/:asset_id       → full AI analysis for single asset
POST /api/ai/analyze/enterprise      → enterprise analysis across all assets
GET  /api/ai/roadmap/:asset_id       → migration roadmap (optionally AI-enhanced)
GET  /api/ai/anomalies/:asset_id     → scan-over-scan anomaly detection
GET  /api/ai/hndl-ranking            → HNDL priority ranking for all assets
POST /api/ai/narrative/:asset_id     → AI narrative report generation
"""

from flask import Blueprint, jsonify, request
from models.asset import Asset
from services.ai_service import (
    analyze_asset,
    analyze_enterprise,
    get_roadmap,
    get_anomalies,
    get_hndl_ranking,
    generate_narrative,
)
from services.scope_service import get_asset_ids_for_scope

bp = Blueprint("ai", __name__, url_prefix="/api/ai")


def ok(data):
    return jsonify({"success": True, "data": data, "error": None})


def err(msg, code=400):
    return jsonify({"success": False, "data": None, "error": msg}), code


def _scoped_asset_ids(payload: dict | None = None) -> list[int]:
    body = payload or {}
    asset_ids = body.get("asset_ids")
    if asset_ids:
        return asset_ids
    return get_asset_ids_for_scope(
        asset_id=request.args.get("asset_id", type=int),
        domain=request.args.get("domain"),
        group_id=request.args.get("group_id", type=int),
    )


# ---------------------------------------------------------------------------
# Single asset analysis
# ---------------------------------------------------------------------------

@bp.route("/analyze/<int:asset_id>", methods=["POST"])
def analyze(asset_id: int):
    asset = Asset.query.get(asset_id)
    if not asset:
        return err("Asset not found", 404)
    try:
        result = analyze_asset(asset_id)
        if "error" in result:
            return err(result["error"], 404)
        return ok(result)
    except Exception as e:
        return err(str(e), 500)


# ---------------------------------------------------------------------------
# Enterprise analysis
# ---------------------------------------------------------------------------

@bp.route("/analyze/enterprise", methods=["POST"])
def enterprise_analysis():
    data = request.get_json(force=True, silent=True) or {}
    asset_ids = _scoped_asset_ids(data)

    if not asset_ids:
        # Use all assets if none specified
        assets = Asset.query.all()
        asset_ids = [a.id for a in assets]

    if not asset_ids:
        return err("No assets found", 404)

    try:
        result = analyze_enterprise(asset_ids)
        if "error" in result:
            return err(result["error"], 404)
        return ok(result)
    except Exception as e:
        return err(str(e), 500)


# ---------------------------------------------------------------------------
# Migration roadmap
# ---------------------------------------------------------------------------

@bp.route("/roadmap/<int:asset_id>", methods=["GET"])
def roadmap(asset_id: int):
    asset = Asset.query.get(asset_id)
    if not asset:
        return err("Asset not found", 404)

    ai_enhance = request.args.get("ai", "true").lower() == "true"
    try:
        result = get_roadmap(asset_id, ai_enhance=ai_enhance)
        if "error" in result:
            return err(result["error"], 404)
        return ok(result)
    except Exception as e:
        return err(str(e), 500)


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------

@bp.route("/anomalies/<int:asset_id>", methods=["GET"])
def anomalies(asset_id: int):
    asset = Asset.query.get(asset_id)
    if not asset:
        return err("Asset not found", 404)

    try:
        result = get_anomalies(asset_id)
        if "error" in result:
            return err(result["error"], 404)
        return ok(result)
    except Exception as e:
        return err(str(e), 500)


# ---------------------------------------------------------------------------
# HNDL ranking
# ---------------------------------------------------------------------------

@bp.route("/hndl-ranking", methods=["GET"])
def hndl_ranking():
    asset_ids = _scoped_asset_ids()

    if not asset_ids:
        return ok({"rankings": [], "total": 0})

    try:
        result = get_hndl_ranking(asset_ids)
        return ok(result)
    except Exception as e:
        return err(str(e), 500)


# ---------------------------------------------------------------------------
# Narrative generation
# ---------------------------------------------------------------------------

@bp.route("/narrative/<int:asset_id>", methods=["POST"])
def narrative(asset_id: int):
    asset = Asset.query.get(asset_id)
    if not asset:
        return err("Asset not found", 404)

    try:
        result = generate_narrative(asset_id)
        if "error" in result:
            return err(result["error"], 404)
        return ok(result)
    except Exception as e:
        return err(str(e), 500)
