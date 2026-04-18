"""Q-Secure | backend/models/asset_group.py"""

from datetime import datetime, timezone

from extensions import db


class AssetGroup(db.Model):
    __tablename__ = "asset_groups"

    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(255), nullable=False, unique=True, index=True)
    description = db.Column(db.Text, nullable=True)
    created_at  = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    domains = db.relationship(
        "AssetGroupDomain",
        backref="group",
        cascade="all, delete-orphan",
        lazy="joined",
        order_by="AssetGroupDomain.domain.asc()",
    )

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "domains": [d.domain for d in self.domains],
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AssetGroupDomain(db.Model):
    __tablename__ = "asset_group_domains"

    id       = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey("asset_groups.id", ondelete="CASCADE"), nullable=False, index=True)
    domain   = db.Column(db.String(255), nullable=False, index=True)

    __table_args__ = (
        db.UniqueConstraint("group_id", "domain", name="uq_asset_group_domain"),
    )
