import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()


class DatabaseConnection:

    def get_connection(self):

        return psycopg2.connect(
            os.getenv("DATABASE_URL")
        )
