from app.database.connection import DatabaseConnection


class UserRepository:

    def __init__(self):
        self.db = DatabaseConnection()

    def create(self, user):

        connection = self.db.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO users
            (username, password_hash, role)
            VALUES (%s, %s, %s)
            """,
            (
                user.username,
                user.password_hash,
                user.role
            )
        )

        connection.commit()

        cursor.close()
        connection.close()

    def find_by_username(self, username):

        connection = self.db.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM users
            WHERE username = %s
            """,
            (username,)
        )

        user = cursor.fetchone()

        cursor.close()
        connection.close()

        return user
