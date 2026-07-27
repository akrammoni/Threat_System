from app.database.connection import DatabaseConnection


class ThreatRepository:

    def __init__(self):
        self.db = DatabaseConnection()


    def create(self, threat):

        connection = self.db.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO threats
            (name, threat_type, impact, solution, location, status)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                threat.name,
                threat.threat_type,
                threat.impact,
                threat.solution,
                threat.location,
                threat.status
            )
        )

        connection.commit()

        cursor.close()
        connection.close()


    def get_all(self):

        connection = self.db.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT * FROM threats
            """
        )

        threats = cursor.fetchall()

        cursor.close()
        connection.close()

        return threats


    def get_by_id(self, threat_id):

        connection = self.db.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT * FROM threats
            WHERE id = %s
            """,
            (threat_id,)
        )

        threat = cursor.fetchone()

        cursor.close()
        connection.close()

        return threat


    def update_status(self, threat_id, status):

        connection = self.db.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE threats
            SET status = %s
            WHERE id = %s
            """,
            (status, threat_id)
        )

        connection.commit()

        cursor.close()
        connection.close()


    def delete(self, threat_id):

        connection = self.db.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            DELETE FROM threats
            WHERE id = %s
            """,
            (threat_id,)
        )

        connection.commit()

        cursor.close()
        connection.close()
