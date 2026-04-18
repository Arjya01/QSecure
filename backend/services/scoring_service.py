"""Q-Secure | backend/services/scoring_service.py"""
from models.scan import ScanResult
from models.asset import Asset
from services.scope_service import get_assets_for_scope, get_latest_scans_for_scope

def compute_enterprise_cyber_rating(asset_scores: list[float]) -> dict:
    if not asset_scores:
        return {"score": 0, "tier": "CRITICAL", "assets_evaluated": 0}
    avg = sum(asset_scores) / len(asset_scores)
    # Scale to 0-1000
    rating = round(avg * 10, 1)
    if rating >= 900:   tier = "ELITE_PQC"
    elif rating >= 600: tier = "STANDARD"
    elif rating >= 300: tier = "LEGACY"
    else:               tier = "CRITICAL"
    return {"score": rating, "tier": tier, "assets_evaluated": len(asset_scores)}


def get_enterprise_stats(db, asset_id: int | None = None, domain: str | None = None, group_id: int | None = None) -> dict:
    scoped_assets = get_assets_for_scope(asset_id=asset_id, domain=domain, group_id=group_id)
    total_assets = len(scoped_assets)
    asset_ids = [asset.id for asset in scoped_assets]
    total_scans = (
        ScanResult.query.filter(ScanResult.asset_id.in_(asset_ids)).count()
        if asset_ids else 0
    )
    latest_scans = get_latest_scans_for_scope(db, asset_id=asset_id, domain=domain, group_id=group_id)

    scores = [s.quantum_score for s in latest_scans if s.quantum_score is not None]
    cyber  = compute_enterprise_cyber_rating(scores)

    label_dist = {"QUANTUM_SAFE": 0, "PQC_READY": 0, "NOT_QUANTUM_SAFE": 0}
    risk_dist  = {"CRITICAL": 0, "LARGE": 0, "MODERATE": 0, "MINIMAL": 0}
    for s in latest_scans:
        if s.label in label_dist:   label_dist[s.label] += 1
        if s.attack_surface_rating in risk_dist: risk_dist[s.attack_surface_rating] += 1

    critical_assets = sum(1 for s in latest_scans if s.label == "NOT_QUANTUM_SAFE")

    return {
        "total_assets": total_assets,
        "assets_scanned": len(latest_scans),
        "total_scans": total_scans,
        "critical_risk_assets": critical_assets,
        "average_quantum_score": round(sum(scores)/len(scores), 1) if scores else 0,
        "enterprise_cyber_rating": cyber,
        "label_distribution": label_dist,
        "risk_distribution": risk_dist,
    }
