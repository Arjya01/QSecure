"""Authentication and RBAC tests."""


def test_login_success(client, admin_token):
    """Test successful login returns token."""
    assert admin_token is not None


def test_login_invalid_credentials(client, db):
    """Test login with wrong password."""
    from app.models.user import Role, User

    role = Role.query.filter_by(name="viewer").first()
    if not role:
        role = Role(name="viewer")
        db.session.add(role)
        db.session.commit()

    user = User(email="bad@test.com", username="bad", full_name="Bad", role=role, is_active=True)
    user.set_password("Correct1!")
    db.session.add(user)
    db.session.commit()

    res = client.post("/api/auth/login", json={"email": "bad@test.com", "password": "Wrong1!"})
    assert res.status_code == 401


def test_protected_endpoint_no_token(client, db):
    """Test accessing protected route without token."""
    res = client.get("/api/assets")
    assert res.status_code == 401


def test_rbac_viewer_cannot_create_asset(client, viewer_token):
    """Test that viewer role cannot create assets."""
    res = client.post(
        "/api/assets",
        json={"hostname": "test.com", "name": "Test"},
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert res.status_code == 403


def test_rbac_admin_can_create_asset(client, admin_token):
    """Test that admin role can create assets."""
    res = client.post(
        "/api/assets",
        json={"hostname": "test.com", "name": "Test Asset"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 201


def test_get_profile(client, admin_token):
    """Test getting user profile."""
    res = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    assert res.get_json()["user"]["email"] == "admin@test.com"


def test_register_user_admin_only(client, admin_token, viewer_token):
    """Test that only admin can register users."""
    # Admin can register
    res = client.post(
        "/api/auth/register",
        json={
            "email": "new@test.com",
            "username": "newuser",
            "full_name": "New User",
            "password": "NewPass1!",
            "role": "viewer",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 201

    # Viewer cannot register
    res = client.post(
        "/api/auth/register",
        json={
            "email": "another@test.com",
            "username": "another",
            "full_name": "Another User",
            "password": "AnotherPass1!",
            "role": "viewer",
        },
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert res.status_code == 403


def test_account_lockout(client, db):
    """Test account lockout after too many failed attempts."""
    from app.models.user import Role, User

    role = Role.query.filter_by(name="viewer").first()
    if not role:
        role = Role(name="viewer")
        db.session.add(role)
        db.session.commit()

    user = User(email="lockme@test.com", username="lockme", full_name="Lock Me", role=role, is_active=True)
    user.set_password("Correct1!")
    db.session.add(user)
    db.session.commit()

    # Fail 5 times
    for _ in range(5):
        client.post("/api/auth/login", json={"email": "lockme@test.com", "password": "Wrong1!"})

    # Now even correct password should fail
    res = client.post("/api/auth/login", json={"email": "lockme@test.com", "password": "Correct1!"})
    assert res.status_code == 403
    assert "locked" in res.get_json()["error"].lower()
