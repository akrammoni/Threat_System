from app.database.connection import DatabaseConnection


def create_tables():
    db = DatabaseConnection()
    connection = db.get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100),
            threat_type VARCHAR(50),
            impact TEXT,
            solution TEXT,
            location VARCHAR(100),
            status VARCHAR(50)
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role VARCHAR(50) DEFAULT 'viewer'
        );
    """)

    cursor.execute("""
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS role VARCHAR(50) DEFAULT 'viewer';
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_intelligence (
            id SERIAL PRIMARY KEY,
            indicator VARCHAR(255) NOT NULL,
            indicator_type VARCHAR(50),
            threat_type VARCHAR(100),
            severity VARCHAR(50),
            source VARCHAR(100),
            description TEXT,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    connection.commit()

    cursor.close()
    connection.close()

    print("Tables created successfully!")


if __name__ == "__main__":
    create_tables()
