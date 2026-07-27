from app.main import app
from app.auth.jwt_handler import create_token


def test_viewer_cannot_create_threat():
    client = app.test_client()

    token = create_token(
        1,
        "viewer_user",
        "viewer"
    )

    response = client.post(
        "/threats",
        headers={
            "Authorization": f"Bearer {token}"
        },
        json={
            "name": "Test Threat",
            "threat_type": "Cyber",
            "impact": "High",
            "solution": "Fix it",
            "location": "Internet",
            "status": "Open"
        }
    )

    assert response.status_code == 403


def test_admin_can_create_threat():
    client = app.test_client()

    token = create_token(
        2,
        "admin_user",
        "admin"
    )

    response = client.post(
        "/threats",
        headers={
            "Authorization": f"Bearer {token}"
        },
        json={
            "name": "Test Threat",
            "threat_type": "Cyber",
            "impact": "High",
            "solution": "Fix it",
            "location": "Internet",
            "status": "Open"
        }
    )

    assert response.status_code != 401
    assert response.status_code != 403
