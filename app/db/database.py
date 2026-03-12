import os
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

load_dotenv()

def get_db_connection():
    try:
        conn = psycopg2.connect(
            os.getenv("DATABASE_URL"),
            cursor_factory=RealDictCursor 
        )
        return conn
    except Exception as e:
        print(f"Eroare la conectarea la baza de date: {e}")
        raise e

def log_audit_event(user_id: int, action: str, resource: str = None, resource_id: str = None, ip_address: str = None):
    """
    Salvează un eveniment în tabelul audit_logs.
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address) 
            VALUES (%s, %s, %s, %s, %s)
            """,
            (user_id, action, resource, resource_id, ip_address)
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"⚠️ Eroare la scrierea in audit log: {e}")
