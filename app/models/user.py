class User:

    def __init__(
        self,
        username,
        password_hash,
        role="viewer",
        user_id=None
    ):
        self.id = user_id
        self.username = username
        self.password_hash = password_hash
        self.role = role
