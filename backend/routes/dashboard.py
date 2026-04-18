"""Q-Secure | backend/routes/dashboard.py"""
from flask import Blueprint, jsonify, request
from extensions import db
from models.scan import ScanResult
from models.asset import Asset
from middleware.rbac import require_read
from services.scoring_service import get_enterprise_stats
from services.scope_service import get_asset_ids_for_scope, get_assets_for_scope, get_latest_scans_for_scope, summarize_scans
from datetime import datetime, timezone, timedelta

bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")

def ok(data): return jsonify({"success": True, "data": data, "error": None})


def _scope_params():
    return {
        "asset_id": request.args.get("asset_id", type=int),
        "domain": request.args.get("domain"),
        "group_id": request.args.get("group_id", type=int),
    }

@bp.route("/summary", methods=["GET"])
@require_read
def summary():
    return ok(get_enterprise_stats(db, **_scope_params()))

@bp.route("/cyber-rating", methods=["GET"])
@require_read
def cyber_rating():
    stats = get_enterprise_stats(db, **_scope_params())
    # Trend: simulate 30-day history from existing data
    base = stats["enterprise_cyber_rating"]["score"]
    trend = []
    for i in range(29, -1, -1):
        day = (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")
        # small variance around base
        import random; random.seed(i)
        val = round(max(0, min(1000, base + random.uniform(-30, 30))), 1)
        trend.append({"date": day, "score": val})
    return ok({"current": stats["enterprise_cyber_rating"], "trend": trend})

@bp.route("/pqc-posture", methods=["GET"])
@require_read
def pqc_posture():
    params = _scope_params()
    stats = get_enterprise_stats(db, **params)
    # Per-asset data
    scans = get_latest_scans_for_scope(db, **params)
    assets_data = []
    for s in scans:
        a = Asset.query.get(s.asset_id)
        if a:
            assets_data.append({
                "asset_id": a.id, "hostname": a.hostname, "type": a.type,
                "root_domain": a.to_dict().get("root_domain"),
                "criticality": a.criticality, "quantum_score": s.quantum_score,
                "label": s.label, "tier": s.tier, "cyber_rating": s.cyber_rating,
                "attack_surface": s.attack_surface_rating,
            })
    tier_dist = {"ELITE_PQC": 0, "STANDARD": 0, "LEGACY": 0, "CRITICAL": 0}
    for d in assets_data:
        t = d.get("tier","CRITICAL")
        if t in tier_dist: tier_dist[t] += 1
    return ok({
        "label_distribution": stats["label_distribution"],
        "tier_distribution": tier_dist,
        "risk_distribution": stats["risk_distribution"],
        "assets": assets_data,
    })

@bp.route("/asset-discovery", methods=["GET"])
@require_read
def asset_discovery():
    params = _scope_params()
    # Pull subdomains from latest scans
    scans = get_latest_scans_for_scope(db, **params)
    domains, certs, ips = [], [], []
    for s in scans:
        data = s.get_scan_data()
        cert = data.get("certificate") or {}
        if cert.get("subject_cn"):
            certs.append({
                "common_name": cert["subject_cn"], "issuer": cert.get("issuer_cn",""),
                "not_before": cert.get("not_before"), "not_after": cert.get("not_after"),
                "is_expired": cert.get("is_expired", False),
                "quantum_risk": cert.get("quantum_risk","HIGH"),
                "asset_id": s.asset_id,
            })
        for sub in data.get("subdomains", []):
            domains.append(sub)
            if sub.get("ip_address"):
                ips.append({"address": sub["ip_address"], "subdomain": sub["subdomain"],
                            "is_live": sub.get("is_live", False)})
    return ok({"domains": domains[:50], "certificates": certs[:50], "ips": ips[:50]})

from services.ai_service import generate_enterprise_insight, generate_action_plan

@bp.route("/ai-insight", methods=["GET"])
@require_read
def ai_insight():
    stats = get_enterprise_stats(db, **_scope_params())
    insight = generate_enterprise_insight(stats)
    return ok(insight)

@bp.route("/ai-roadmap", methods=["GET"])
@require_read
def ai_roadmap():
    params = _scope_params()
    stats = get_enterprise_stats(db, **params)
    asset_ids = get_asset_ids_for_scope(**params)
    
    # Extract detailed CBOM/vulnerability findings from recent scans to ground the AI
    import json
    recent_scans = ScanResult.query.filter(ScanResult.scan_data != None)
    if asset_ids:
        recent_scans = recent_scans.filter(ScanResult.asset_id.in_(asset_ids))
    recent_scans = recent_scans.order_by(ScanResult.started_at.desc()).limit(10).all()
    
    details = {
        "ciphers": [],
        "cbom": [],
        "vulnerabilities": []
    }
    
    for s in recent_scans:
        try:
            data = json.loads(s.scan_data)
            if data.get("ciphers"): details["ciphers"].extend(data["ciphers"][:5])
            if data.get("cbom"): details["cbom"].extend(data["cbom"][:5])
            if data.get("vulnerabilities"): details["vulnerabilities"].extend(data["vulnerabilities"][:3])
        except:
            pass
            
    roadmap = generate_action_plan(stats, details)
    return ok(roadmap)

@bp.route("/recent-scans", methods=["GET"])
@require_read
def recent_scans():
    params = _scope_params()

    if params["asset_id"] or params["domain"] or params["group_id"]:
        # Get all assets in scope
        asset_ids = get_asset_ids_for_scope(**params)
        if not asset_ids:
            return ok([])
        # Return full scan history for those assets, not just the latest one
        scans = (
            ScanResult.query
            .filter(ScanResult.asset_id.in_(asset_ids))
            .order_by(ScanResult.started_at.desc())
            .limit(20)
            .all()
        )
        result = []
        for s in scans:
            a = Asset.query.get(s.asset_id)
            result.append({
                **s.to_dict(),
                "hostname": a.hostname if a else str(s.asset_id),
                "asset_type": a.type if a else "unknown",
            })
        return ok(result)

    scans = ScanResult.query.order_by(ScanResult.started_at.desc()).limit(20).all()
    result = []
    for s in scans:
        a = Asset.query.get(s.asset_id)
        result.append({
            **s.to_dict(),
            "hostname": a.hostname if a else str(s.asset_id),
            "asset_type": a.type if a else "unknown",
        })
    return ok(result)
