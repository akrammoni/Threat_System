from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.auth.password import hash_password, verify_password
from app.auth.jwt_handler import create_token
from app.exceptions.validation_error import ValidationError
from app.logging.logger import logger


class AuthService:

    def __init__(self):
        self.repository = UserRepository()

    def register(self, username, password):

        if len(username) < 3:
            raise ValidationError(
                "Username too short"
            )

        if len(password) < 8:
            raise ValidationError(
                "Password must be at least 8 characters"
            )

        password_hash = hash_password(password)

        user = User(
            username=username,
            password_hash=password_hash,
            role="viewer"
        )

        self.repository.create(user)

        logger.info(
            f"User registered successfully: "
            f"username={username}, role=viewer"
        )

    def login(self, username, password):

        user = self.repository.find_by_username(
            username
        )

        if user is None:

            logger.warning(
                f"Failed login attempt: "
                f"username={username}, reason=user_not_found"
            )

            raise ValidationError(
                "Invalid username or password"
            )

        password_valid = verify_password(
            password,
            user[2]
        )

        if not password_valid:

            logger.warning(
                f"Failed login attempt: "
                f"username={username}, reason=invalid_password"
            )

            raise ValidationError(
                "Invalid username or password"
            )

        token = create_token(
            user_id=user[0],
            username=user[1],
            role=user[3]
        )

        logger.info(
            f"User login successful: "
            f"username={user[1]}, role={user[3]}"
        )

        return token
