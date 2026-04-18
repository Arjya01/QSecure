"""Asset management tests."""


def test_create_asset(client, admin_token):
    """Test creating a new asset."""
    res = client.post(
        "/api/assets",
        json={
            "name": "Test Web Server",
            "hostname": "example.com",
            "port": 443,
            "asset_type": "web_server",
            "criticality": "high",
            "owner": "Security Team",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 201
    data = res.get_json()
    assert data["asset"]["hostname"] == "example.com"
    assert data["asset"]["quantum_safe_status"] == "unknown"


def test_list_assets(client, admin_token):
    """Test listing assets."""
    # Create asset first
    client.post(
        "/api/assets",
        json={"name": "Test", "hostname": "test.example.com"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    res = client.get(
        "/api/assets",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    assert res.get_json()["total"] >= 1


def test_duplicate_asset(client, admin_token):
    """Test creating duplicate asset fails."""
    data = {"name": "Dup", "hostname": "dup.example.com", "port": 443}
    client.post("/api/assets", json=data, headers={"Authorization": f"Bearer {admin_token}"})

    res = client.post("/api/assets", json=data, headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 409


def test_invalid_hostname(client, admin_token):
    """Test creating asset with invalid hostname."""
    res = client.post(
        "/api/assets",
        json={"name": "Bad", "hostname": "invalid hostname with spaces!!"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 400


def test_update_asset(client, admin_token):
    """Test updating an asset."""
    res = client.post(
        "/api/assets",
        json={"name": "Update Me", "hostname": "update.example.com"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    asset_id = res.get_json()["asset"]["id"]

    res = client.put(
        f"/api/assets/{asset_id}",
        json={"criticality": "critical", "owner": "New Owner"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    assert res.get_json()["asset"]["criticality"] == "critical"


def test_delete_asset_soft(client, admin_token):
    """Test soft deleting an asset."""
    res = client.post(
        "/api/assets",
        json={"name": "Delete Me", "hostname": "delete.example.com"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    asset_id = res.get_json()["asset"]["id"]

    res = client.delete(
        f"/api/assets/{asset_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200

    # Asset should not appear in list
    res = client.get("/api/assets", headers={"Authorization": f"Bearer {admin_token}"})
    asset_ids = [a["id"] for a in res.get_json()["assets"]]
    assert asset_id not in asset_ids
