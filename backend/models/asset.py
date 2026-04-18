"""Q-Secure | backend/models/asset.py"""
from datetime import datetime, timezone
from common.domain_utils import get_registered_domain
from extensions import db

class Asset(db.Model):
    __tablename__ = "assets"

    id            = db.Column(db.Integer, primary_key=True)
    hostname      = db.Column(db.String(255), nullable=False)
    ip            = db.Column(db.String(64), nullable=True)
    port          = db.Column(db.Integer, default=443)
    type          = db.Column(db.String(64), default="web_server")  # web_server/api/vpn/system
    environment   = db.Column(db.String(64), default="production")  # production/staging/dev
    criticality   = db.Column(db.String(32), default="medium")      # critical/high/medium/low
    owner         = db.Column(db.String(255), nullable=True)
    department    = db.Column(db.String(255), nullable=True)
    business_unit = db.Column(db.String(255), nullable=True)
    notes         = db.Column(db.Text, nullable=True)
    is_active     = db.Column(db.Boolean, default=True)
    created_by    = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at    = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    scans  = db.relationship("ScanResult", backref="asset", lazy="dynamic", order_by="ScanResult.started_at.desc()")
    labels = db.relationship("PQCLabel",   backref="asset", lazy="dynamic")

    def last_scan(self):
        return self.scans.first()

    def to_dict(self, include_last_scan=False):
        d = {
            "id": self.id, "hostname": self.hostname, "ip": self.ip,
            "root_domain": get_registered_domain(self.hostname),
            "port": self.port, "type": self.type, "environment": self.environment,
            "criticality": self.criticality, "owner": self.owner,
            "department": self.department, "business_unit": self.business_unit,
            "notes": self.notes, "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if include_last_scan:
            ls = self.last_scan()
            d["last_scan"] = {
                "id": ls.id, "quantum_score": ls.quantum_score,
                "label": ls.label, "cyber_rating": ls.cyber_rating,
                "completed_at": ls.completed_at.isoformat() if ls.completed_at else None,
                "scan_status": ls.scan_status,
            } if ls else None
        return d
