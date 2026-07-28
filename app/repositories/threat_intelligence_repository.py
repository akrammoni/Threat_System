from app.database.connection import DatabaseConnection


class ThreatIntelligenceRepository:

    def __init__(self):
        self.db = DatabaseConnection()

    def create(self, intelligence):

        connection = self.db.get_connection()
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO threat_intelligence (
                indicator,
                indicator_type,
                threat_type,
                severity,
                source,
                description,
                first_seen,
                last_seen
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            intelligence.indicator,
            intelligence.indicator_type,
            intelligence.threat_type,
            intelligence.severity,
            intelligence.source,
            intelligence.description,
            intelligence.first_seen,
            intelligence.last_seen
        ))

        connection.commit()

        cursor.close()
        connection.close()

    def get_all(self):

        connection = self.db.get_connection()
        cursor = connection.cursor()

        cursor.execute("""
            SELECT
                id,
                indicator,
                indicator_type,
                threat_type,
                severity,
                source,
                description,
                first_seen,
                last_seen,
                created_at
            FROM threat_intelligence
            ORDER BY created_at DESC
        """)

        results = cursor.fetchall()

        cursor.close()
        connection.close()

        return results
