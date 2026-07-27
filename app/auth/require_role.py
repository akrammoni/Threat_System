from functools import wraps

from flask import jsonify, g

from app.logging.logger import logger


def require_role(*allowed_roles):

    def decorator(function):

        @wraps(function)
        def wrapper(*args, **kwargs):

            user_role = g.user.get(
                "role"
            )

            username = g.user.get(
                "username"
            )

            if user_role not in allowed_roles:

                logger.warning(
                    f"RBAC denied: "
                    f"user={username}, "
                    f"role={user_role}, "
                    f"required_roles={allowed_roles}"
                )

                return jsonify({
                    "error": "Forbidden"
                }), 403

            logger.info(
                f"RBAC allowed: "
                f"user={username}, "
                f"role={user_role}, "
                f"required_roles={allowed_roles}"
            )

            return function(
                *args,
                **kwargs
            )

        return wrapper

    return decorator
