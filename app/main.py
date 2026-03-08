from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from app.database import get_db_connection
import psycopg2

app = FastAPI(title="Break the Login API")

class UserRegister(BaseModel):
    email: str
    password: str

@app.get("/test-db")
def test_db():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT version();")
        db_version = cur.fetchone()
        
        cur.close()
        conn.close()
        
        return {
            "status": "success", 
            "message": "Conexiune reusita la baza de date!", 
            "db_version": db_version['version']
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Nu m-am putut conecta la baza de date.")

@app.post("/register")
def register_user(user: UserRegister):
    # VULNERABILITATE 4.1: Nu verificăm dacă parola are o lungime minimă sau caractere speciale.
    # Acceptăm direct "123" sau "admin".

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT id FROM users WHERE email = %s;", (user.email,))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Email deja folosit.")

        # VULNERABILITATE 4.2: Inserăm parola ÎN CLAR în coloana password_hash.
        cur.execute(
            """
            INSERT INTO users (email, password_hash, role) 
            VALUES (%s, %s, 'USER') 
            RETURNING id;
            """,
            (user.email, user.password)
        )
        
        new_user = cur.fetchone()
        conn.commit()
        
        cur.close()
        conn.close()
        
        return {
            "status": "success", 
            "message": "Cont creat cu succes!", 
            "user_id": new_user['id']
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
