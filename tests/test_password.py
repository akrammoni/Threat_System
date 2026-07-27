from app.auth.password import hash_password, verify_password


def test_password_is_hashed():
    password = "password123"

    hashed_password = hash_password(password)

    assert hashed_password != password


def test_correct_password_is_verified():
    password = "password123"

    hashed_password = hash_password(password)

    assert verify_password(password, hashed_password) is True


def test_wrong_password_is_rejected():
    password = "password123"
    wrong_password = "wrongpassword"

    hashed_password = hash_password(password)

    assert verify_password(wrong_password, hashed_password) is False
