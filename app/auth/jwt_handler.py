import os
import jwt

from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv


load_dotenv()

SECRET_KEY = os.getenv(
    "JWT_SECRET_KEY",
    "development-secret-key"
)


def create_token(user_id, username, role):

    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "exp": datetime.now(timezone.utc)
        + timedelta(hours=1)
    }

    token = jwt.encode(
        payload,
        SECRET_KEY,
        algorithm="HS256"
    )

    return token


def verify_token(token):

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"]
        )

        return payload

    except jwt.ExpiredSignatureError:

        return None

    except jwt.InvalidTokenError:

        return None
