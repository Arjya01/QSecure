"""Test fixtures."""

import pytest

from app import create_app, db as _db, limiter
from app.models.user import Role, User


@pytest.fixture(scope="session")
def app():
    app = create_app("testing")
    # Disable rate limiting in tests
    limiter.enabled = False
    with app.app_context():
        yield app


@pytest.fixture(scope="function")
def db(app):
    with app.app_context():
        _db.create_all()

        # Seed roles if they don't exist
        for name, desc in [
            ("admin", "Full access"),
            ("analyst", "Run scans and generate reports"),
            ("viewer", "Read-only access"),
            ("auditor", "Read-only with export"),
        ]:
            if not Role.query.filter_by(name=name).first():
                _db.session.add(Role(name=name, description=desc))
        _db.session.commit()

        yield _db
        _db.session.rollback()
        _db.drop_all()


@pytest.fixture
def client(app, db):
    return app.test_client()


@pytest.fixture
def admin_token(client, db):
    """Create admin user and return JWT token."""
    role = Role.query.filter_by(name="admin").first()

    # Check if default admin already exists
    existing = User.query.filter_by(username="admin").first()
    if existing:
        # Use existing admin, just ensure we know the password
        existing.set_password("TestPass1!")
        db.session.commit()
    else:
        user = User(
            email="admin@test.com",
            username="testadmin",
            full_name="Test Admin",
            role=role,
            is_active=True,
        )
        user.set_password("TestPass1!")
        db.session.add(user)
        db.session.commit()

    email = existing.email if existing else "admin@test.com"
    res = client.post("/api/auth/login", json={
        "email": email,
        "password": "TestPass1!",
    })
    return res.get_json()["access_token"]


@pytest.fixture
def viewer_token(client, db):
    """Create viewer user and return JWT token."""
    role = Role.query.filter_by(name="viewer").first()

    user = User(
        email="viewer@test.com",
        username="viewer",
        full_name="Test Viewer",
        role=role,
        is_active=True,
    )
    user.set_password("TestPass1!")
    db.session.add(user)
    db.session.commit()

    res = client.post("/api/auth/login", json={
        "email": "viewer@test.com",
        "password": "TestPass1!",
    })
    return res.get_json()["access_token"]
