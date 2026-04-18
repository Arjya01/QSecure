"""Q-Secure | backend/models/scan.py"""
import json
from datetime import datetime, timezone
from extensions import db

class ScanResult(db.Model):
    __tablename__ = "scan_results"

    id            = db.Column(db.Integer, primary_key=True)
    asset_id      = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False, index=True)
    scan_data     = db.Column(db.Text, nullable=True)   # JSON blob of full ScanResult.to_dict()
    quantum_score = db.Column(db.Float, default=0.0)
    extended_risk_score = db.Column(db.Float, default=0.0)
    label         = db.Column(db.String(64), default="NOT_QUANTUM_SAFE")
    tier          = db.Column(db.String(64), default="CRITICAL")
    cyber_rating  = db.Column(db.Float, default=0.0)
    attack_surface_rating = db.Column(db.String(32), default="CRITICAL")
    scan_status   = db.Column(db.String(32), default="SUCCESS")
    is_mock       = db.Column(db.Boolean, default=True)
    started_at    = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at  = db.Column(db.DateTime, nullable=True)
    initiated_by  = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    cbom_entries = db.relationship("CBOMEntry", backref="scan", lazy="dynamic")

    def get_scan_data(self):
        try:
            return json.loads(self.scan_data) if self.scan_data else {}
        except Exception:
            return {}

    def to_dict(self, include_data=False):
        d = {
            "id": self.id, "asset_id": self.asset_id,
            "quantum_score": self.quantum_score,
            "extended_risk_score": self.extended_risk_score,
            "label": self.label, "tier": self.tier,
            "cyber_rating": self.cyber_rating,
            "attack_surface_rating": self.attack_surface_rating,
            "scan_status": self.scan_status, "is_mock": self.is_mock,
            "started_at":  self.started_at.isoformat()  if self.started_at  else None,
            "completed_at":self.completed_at.isoformat() if self.completed_at else None,
            "initiated_by": self.initiated_by,
        }
        if include_data:
            d["scan_data"] = self.get_scan_data()
        return d


class CBOMEntry(db.Model):
    __tablename__ = "cbom_entries"

    id                  = db.Column(db.Integer, primary_key=True)
    scan_id             = db.Column(db.Integer, db.ForeignKey("scan_results.id"), nullable=False, index=True)
    asset_id            = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False, index=True)
    entry_id            = db.Column(db.String(32))
    component_type      = db.Column(db.String(64))
    algorithm           = db.Column(db.String(255))
    key_size            = db.Column(db.Integer, default=0)
    quantum_risk        = db.Column(db.String(32))
    migration_priority  = db.Column(db.String(32))
    replacement         = db.Column(db.String(255))
    nist_standard       = db.Column(db.String(64), nullable=True)
    notes               = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            "id": self.id, "scan_id": self.scan_id, "asset_id": self.asset_id,
            "entry_id": self.entry_id, "component_type": self.component_type,
            "algorithm": self.algorithm, "key_size": self.key_size,
            "quantum_risk": self.quantum_risk, "migration_priority": self.migration_priority,
            "replacement": self.replacement, "nist_standard": self.nist_standard,
            "notes": self.notes,
        }


class PQCLabel(db.Model):
    __tablename__ = "pqc_labels"

    id           = db.Column(db.Integer, primary_key=True)
    asset_id     = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False, index=True)
    scan_id      = db.Column(db.Integer, db.ForeignKey("scan_results.id"), nullable=True)
    label        = db.Column(db.String(64))  # QUANTUM_SAFE / PQC_READY / NOT_QUANTUM_SAFE
    issued_by    = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    issued_at    = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at   = db.Column(db.DateTime, nullable=True)
    revoked      = db.Column(db.Boolean, default=False)
    revoke_reason= db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            "id": self.id, "asset_id": self.asset_id, "scan_id": self.scan_id,
            "label": self.label, "issued_by": self.issued_by,
            "issued_at": self.issued_at.isoformat() if self.issued_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "revoked": self.revoked, "revoke_reason": self.revoke_reason,
        }
