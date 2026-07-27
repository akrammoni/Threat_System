from functools import wraps

from flask import request, jsonify, g

from app.auth.jwt_handler import verify_token
from app.logging.logger import logger


def require_auth(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        auth_header = request.headers.get(
            "Authorization"
        )

        if not auth_header:

            logger.warning(
                "Unauthorized request: Authorization header missing"
            )

            return jsonify({
                "error": "Authorization header required"
            }), 401

        if not auth_header.startswith(
            "Bearer "
        ):

            logger.warning(
                "Unauthorized request: Invalid authorization format"
            )

            return jsonify({
                "error": "Invalid authorization format"
            }), 401

        token = auth_header.split(
            " ",
            1
        )[1]

        payload = verify_token(token)

        if payload is None:

            logger.warning(
                "Unauthorized request: Invalid or expired token"
            )

            return jsonify({
                "error": "Invalid or expired token"
            }), 401

        g.user = payload

        logger.info(
            f"Authentication successful: "
            f"user={payload.get('username')}, "
            f"role={payload.get('role')}"
        )

        return function(*args, **kwargs)

    return wrapper
