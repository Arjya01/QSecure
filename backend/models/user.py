"""Q-Secure | backend/models/user.py"""
from datetime import datetime, timezone
from extensions import db

class User(db.Model):
    __tablename__ = "users"

    id             = db.Column(db.Integer, primary_key=True)
    email          = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash  = db.Column(db.String(255), nullable=False)
    role           = db.Column(db.String(32), nullable=False, default="admin")
    is_active      = db.Column(db.Boolean, default=True)
    failed_attempts= db.Column(db.Integer, default=0)
    locked_at      = db.Column(db.DateTime, nullable=True)
    last_login     = db.Column(db.DateTime, nullable=True)
    created_at     = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def has_permission(self, perm: str) -> bool:
        return True

    def is_locked(self) -> bool:
        return self.locked_at is not None

    def to_dict(self):
        return {
            "id": self.id, "email": self.email, "role": self.role,
            "is_active": self.is_active, "failed_attempts": self.failed_attempts,
            "locked": self.is_locked(), "last_login": self.last_login.isoformat() if self.last_login else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
