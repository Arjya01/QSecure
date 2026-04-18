"""Q-Secure | backend/routes/groups.py"""

from flask import Blueprint, jsonify, request

from common.domain_utils import get_registered_domain
from extensions import db
from middleware.audit import log_action
from middleware.rbac import require_read, require_write
from models.asset_group import AssetGroup, AssetGroupDomain
from services.scope_service import build_scope_catalog

bp = Blueprint("groups", __name__, url_prefix="/api/groups")


def ok(data, code=200):
    return jsonify({"success": True, "data": data, "error": None}), code


def err(msg, code=400):
    return jsonify({"success": False, "data": None, "error": msg}), code


def _normalize_domains(domains: list[str]) -> list[str]:
    cleaned = []
    seen = set()
    for domain in domains or []:
        root = get_registered_domain(domain)
        if root and root not in seen:
            seen.add(root)
            cleaned.append(root)
    return cleaned


@bp.route("", methods=["GET"])
@require_read
def list_groups():
    groups = AssetGroup.query.order_by(AssetGroup.name.asc()).all()
    return ok([group.to_dict() for group in groups])


@bp.route("/scopes", methods=["GET"])
@require_read
def list_scopes():
    return ok(build_scope_catalog(db))


@bp.route("", methods=["POST"])
@require_write
def create_group():
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    description = (body.get("description") or "").strip() or None
    domains = _normalize_domains(body.get("domains") or [])

    if not name:
        return err("Group name is required")
    if len(domains) < 2:
        return err("Select at least two domains to create a group")
    if AssetGroup.query.filter_by(name=name).first():
        return err("Group name already exists")

    group = AssetGroup(name=name, description=description)
    db.session.add(group)
    db.session.flush()

    for domain in domains:
        db.session.add(AssetGroupDomain(group_id=group.id, domain=domain))

    db.session.commit()
    log_action("group_created", resource=name)
    return ok(group.to_dict(), 201)


@bp.route("/<int:gid>", methods=["PUT"])
@require_write
def update_group(gid):
    group = AssetGroup.query.get_or_404(gid)
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or group.name).strip()
    description = (body.get("description") or "").strip() or None
    domains = _normalize_domains(body.get("domains") or [domain.domain for domain in group.domains])

    if len(domains) < 2:
        return err("Select at least two domains to keep a group")

    existing = AssetGroup.query.filter(AssetGroup.name == name, AssetGroup.id != gid).first()
    if existing:
        return err("Group name already exists")

    group.name = name
    group.description = description
    group.domains = [AssetGroupDomain(domain=domain) for domain in domains]
    db.session.commit()
    log_action("group_updated", resource=group.name)
    return ok(group.to_dict())


@bp.route("/<int:gid>", methods=["DELETE"])
@require_write
def delete_group(gid):
    group = AssetGroup.query.get_or_404(gid)
    name = group.name
    db.session.delete(group)
    db.session.commit()
    log_action("group_deleted", resource=name)
    return ok({"deleted": gid})
