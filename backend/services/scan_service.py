"""Q-Secure | backend/services/scan_service.py"""
import sys, os, json
from datetime import datetime, timezone

# Add scanner package to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from extensions import db
from models.scan import ScanResult, CBOMEntry, PQCLabel
from models.asset import Asset
import scanner as sc

def run_scan(asset: Asset, initiated_by: int = None, mock: bool = False) -> ScanResult:
    result_obj = sc.scan(asset.hostname, asset.port, mock=mock)
    data = result_obj.to_dict()

    qs = data.get("quantum_score") or {}
    scan = ScanResult(
        asset_id=asset.id,
        scan_data=json.dumps(data),
        quantum_score=qs.get("overall_score", 0),
        extended_risk_score=data.get("extended_risk_score", 0),
        label=qs.get("label", "NOT_QUANTUM_SAFE"),
        tier=qs.get("tier", "CRITICAL"),
        cyber_rating=qs.get("cyber_rating", 0),
        attack_surface_rating=data.get("attack_surface_rating", "CRITICAL"),
        scan_status=data.get("scan_status", "SUCCESS"),
        is_mock=data.get("is_mock", True),
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        initiated_by=initiated_by,
    )
    db.session.add(scan)
    db.session.flush()

    # Store CBOM entries
    for entry in data.get("cbom", []):
        cbom = CBOMEntry(
            scan_id=scan.id, asset_id=asset.id,
            entry_id=entry.get("entry_id",""),
            component_type=entry.get("component_type",""),
            algorithm=entry.get("name",""),
            key_size=entry.get("key_size",0),
            quantum_risk=entry.get("quantum_risk","HIGH"),
            migration_priority=entry.get("migration_priority","HIGH"),
            replacement=entry.get("recommended_replacement",""),
            nist_standard=entry.get("nist_fips_standard"),
            notes=entry.get("notes",""),
        )
        db.session.add(cbom)

    # Auto-issue PQC label
    label_val = qs.get("label", "NOT_QUANTUM_SAFE")
    lbl = PQCLabel(
        asset_id=asset.id, scan_id=scan.id,
        label=label_val, issued_by=initiated_by,
    )
    db.session.add(lbl)
    db.session.commit()

    # Record on blockchain (non-blocking)
    try:
        from services.blockchain import get_blockchain
        bc = get_blockchain()
        bc.record_scan(
            scan_id=str(scan.id), asset_name=asset.hostname,
            hostname=asset.hostname, score=qs.get("overall_score", 0),
            quantum_safe=label_val in ("PQC_READY", "QUANTUM_SAFE"),
            user_id=str(initiated_by) if initiated_by else "system",
            vulnerabilities_count=len(data.get("vulnerabilities", [])),
        )
        # Auto-issue PQC certificate on blockchain
        if label_val in ("PQC_READY", "QUANTUM_SAFE"):
            bc.issue_pqc_certificate(
                asset_id=str(asset.id), asset_name=asset.hostname,
                label_type=label_val.lower(), score=qs.get("overall_score", 0),
                nist_compliance=qs.get("nist_compliance", {}),
                issued_by=str(initiated_by) if initiated_by else "system",
            )
    except Exception:
        pass  # Blockchain is supplementary — never block scans

    return scan


def run_batch_scan(assets: list, initiated_by: int = None, mock: bool = False) -> list:
    return [run_scan(a, initiated_by, mock) for a in assets]
