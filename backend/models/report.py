"""Q-Secure | backend/models/report.py"""
from datetime import datetime, timezone
from extensions import db

class Report(db.Model):
    __tablename__ = "reports"

    id         = db.Column(db.Integer, primary_key=True)
    title      = db.Column(db.String(255))
    type       = db.Column(db.String(64))    # executive/cbom/asset/full
    scope      = db.Column(db.String(255))   # all / asset_id list json
    format     = db.Column(db.String(16))    # pdf/json/csv
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    file_path  = db.Column(db.String(512), nullable=True)
    file_size  = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            "id": self.id, "title": self.title, "type": self.type,
            "scope": self.scope, "format": self.format,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "file_path": self.file_path, "file_size": self.file_size,
        }


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    user_email = db.Column(db.String(255), nullable=True)
    action     = db.Column(db.String(128))
    resource   = db.Column(db.String(255), nullable=True)
    outcome    = db.Column(db.String(32), default="success")  # success/failure
    details    = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    timestamp  = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def to_dict(self):
        return {
            "id": self.id, "user_id": self.user_id, "user_email": self.user_email,
            "action": self.action, "resource": self.resource,
            "outcome": self.outcome, "details": self.details,
            "ip_address": self.ip_address,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
