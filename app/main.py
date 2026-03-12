from fastapi import FastAPI
from app.routers import auth, passwords
from app.db.database import get_db_connection

app = FastAPI(title="Break the Login API - Secure Version")

# Înregistrăm rutele din celelalte fișiere
app.include_router(auth.router)
app.include_router(passwords.router)

@app.get("/")
def read_root():
    return {"message": "Salutare! Backend-ul ruleaza (v2)."}

@app.get("/test-db")
def test_db():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT version();")
        db_version = cur.fetchone()
        cur.close()
        conn.close()
        return {"status": "success", "db_version": db_version['version']}
    except Exception as e:
        return {"status": "error", "message": str(e)}
