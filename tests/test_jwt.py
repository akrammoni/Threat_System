from app.auth.jwt_handler import create_token, verify_token


def test_jwt_token_creation():
    token = create_token(1, "testuser", "viewer")

    assert token is not None
    assert isinstance(token, str)


def test_jwt_token_verification():
    token = create_token(1, "testuser", "viewer")

    payload = verify_token(token)

    assert payload is not None
    assert payload["user_id"] == 1
    assert payload["username"] == "testuser"
    assert payload["role"] == "viewer"


def test_invalid_jwt_token_is_rejected():
    invalid_token = "this.is.not.a.valid.token"

    payload = verify_token(invalid_token)

    assert payload is None
