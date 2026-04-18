"""Scope helpers for domain-based aggregation and manual groups."""

from __future__ import annotations

from collections import defaultdict

from common.domain_utils import get_registered_domain
from models.asset import Asset
from models.asset_group import AssetGroup
from models.scan import ScanResult


def summarize_scans(scans: list[ScanResult]) -> dict | None:
    if not scans:
        return None

    quantum_scores = [s.quantum_score for s in scans if s.quantum_score is not None]
    cyber_scores = [s.cyber_rating for s in scans if s.cyber_rating is not None]
    labels = [s.label for s in scans if s.label]
    risk_ratings = [s.attack_surface_rating for s in scans if s.attack_surface_rating]

    label_order = {"NOT_QUANTUM_SAFE": 0, "PQC_READY": 1, "QUANTUM_SAFE": 2}
    risk_order = {"CRITICAL": 0, "LARGE": 1, "MODERATE": 2, "MINIMAL": 3}

    latest = max(scans, key=lambda scan: scan.started_at or scan.completed_at)

    return {
        "quantum_score": round(sum(quantum_scores) / len(quantum_scores), 1) if quantum_scores else 0,
        "cyber_rating": round(sum(cyber_scores) / len(cyber_scores), 1) if cyber_scores else 0,
        "label": min(labels, key=lambda label: label_order.get(label, 99)) if labels else "NOT_QUANTUM_SAFE",
        "attack_surface_rating": min(risk_ratings, key=lambda level: risk_order.get(level, 99)) if risk_ratings else "CRITICAL",
        "scan_count": len(scans),
        "started_at": latest.started_at.isoformat() if latest.started_at else None,
        "completed_at": latest.completed_at.isoformat() if latest.completed_at else None,
    }


def get_scope_domains(group_id: int | None = None) -> list[str]:
    if not group_id:
        return []
    group = AssetGroup.query.get(group_id)
    if not group:
        return []
    return [domain.domain for domain in group.domains]


def get_assets_for_scope(asset_id: int | None = None, domain: str | None = None, group_id: int | None = None) -> list[Asset]:
    active_assets = Asset.query.filter_by(is_active=True).order_by(Asset.hostname.asc()).all()

    if asset_id:
        return [asset for asset in active_assets if asset.id == int(asset_id)]

    if group_id:
        allowed_domains = set(get_scope_domains(group_id))
        return [asset for asset in active_assets if get_registered_domain(asset.hostname) in allowed_domains]

    if domain:
        return [asset for asset in active_assets if get_registered_domain(asset.hostname) == domain]

    return active_assets


def get_asset_ids_for_scope(asset_id: int | None = None, domain: str | None = None, group_id: int | None = None) -> list[int]:
    return [asset.id for asset in get_assets_for_scope(asset_id=asset_id, domain=domain, group_id=group_id)]


def get_latest_scans_for_scope(db, asset_id: int | None = None, domain: str | None = None, group_id: int | None = None) -> list[ScanResult]:
    asset_ids = get_asset_ids_for_scope(asset_id=asset_id, domain=domain, group_id=group_id)
    if not asset_ids:
        return []

    latest = (
        db.session.query(
            ScanResult.asset_id,
            db.func.max(ScanResult.id).label("max_id"),
        )
        .filter(ScanResult.asset_id.in_(asset_ids))
        .group_by(ScanResult.asset_id)
        .subquery()
    )
    return (
        ScanResult.query
        .join(latest, ScanResult.id == latest.c.max_id)
        .order_by(ScanResult.started_at.desc())
        .all()
    )


def build_scope_catalog(db) -> dict:
    assets = Asset.query.filter_by(is_active=True).order_by(Asset.hostname.asc()).all()
    grouped_assets: dict[str, list[Asset]] = defaultdict(list)
    for asset in assets:
        grouped_assets[get_registered_domain(asset.hostname)].append(asset)

    latest_scans = get_latest_scans_for_scope(db)
    latest_by_asset = {scan.asset_id: scan for scan in latest_scans}

    domain_scopes = []
    for domain, domain_assets in sorted(grouped_assets.items(), key=lambda item: item[0]):
        scans = [latest_by_asset[asset.id] for asset in domain_assets if asset.id in latest_by_asset]
        domain_scopes.append({
            "scope_key": f"domain:{domain}",
            "scope_type": "domain",
            "label": domain,
            "domain": domain,
            "domains": [domain],
            "asset_ids": [asset.id for asset in domain_assets],
            "asset_count": len(domain_assets),
            "hostnames": [asset.hostname for asset in domain_assets],
            "latest_scan": summarize_scans(scans),
        })

    manual_groups = []
    for group in AssetGroup.query.order_by(AssetGroup.name.asc()).all():
        domains = [item.domain for item in group.domains]
        group_assets = [asset for asset in assets if get_registered_domain(asset.hostname) in domains]
        scans = [latest_by_asset[asset.id] for asset in group_assets if asset.id in latest_by_asset]
        manual_groups.append({
            "scope_key": f"group:{group.id}",
            "scope_type": "group",
            "id": group.id,
            "label": group.name,
            "name": group.name,
            "description": group.description,
            "domains": domains,
            "asset_ids": [asset.id for asset in group_assets],
            "asset_count": len(group_assets),
            "hostnames": [asset.hostname for asset in group_assets],
            "latest_scan": summarize_scans(scans),
        })

    return {
        "all": {
            "scope_key": "all",
            "scope_type": "all",
            "label": "All Domains",
            "asset_ids": [asset.id for asset in assets],
            "asset_count": len(assets),
            "domain_count": len(domain_scopes),
            "latest_scan": summarize_scans(latest_scans),
        },
        "domains": domain_scopes,
        "groups": manual_groups,
    }
