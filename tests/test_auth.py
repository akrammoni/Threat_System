from app.main import app


def test_missing_token_returns_401():
    client = app.test_client()

    response = client.get("/threats")

    assert response.status_code == 401


def test_invalid_token_returns_401():
    client = app.test_client()

    response = client.get(
        "/threats",
        headers={
            "Authorization": "Bearer invalid.token.here"
        }
    )

    assert response.status_code == 401
