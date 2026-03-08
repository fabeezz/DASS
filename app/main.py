from fastapi import FastAPI, HTTPException, Response, Cookie
from pydantic import BaseModel
from app.database import get_db_connection
from typing import Optional
import psycopg2

app = FastAPI(title="Break the Login API")

class UserRegister(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class ForgotPasswordRequest(BaseModel):
    email: str

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

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

@app.post("/login")
def login_user(user: UserLogin, response: Response):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT * FROM users WHERE email = %s;", (user.email,))
        db_user = cur.fetchone()
        
        # VULNERABILITATEA 4.4 (User Enumeration - partea 1):
        # Spunem explicit atacatorului că email-ul nu e în baza de date
        if not db_user:
            raise HTTPException(status_code=404, detail="User inexistent.")
            
        if db_user['password_hash'] != user.password:
            # VULNERABILITATEA 4.4 (User Enumeration - partea 2):
            # Spunem explicit că email-ul există, dar parola e greșită
            raise HTTPException(status_code=401, detail="Parolă greșită.")
            
        # VULNERABILITATEA 4.3 (Brute force): 
        # Lipseste logica de incrementare a încercărilor greșite sau de blocare a contului (locked = true).
        
        # VULNERABILITATEA 4.5 (Gestionare nesigură a sesiunilor):
        # Generăm un token predictibil (în loc de un UUID sau JWT semnat corect)
        insecure_token = f"session_user_{db_user['id']}" 
        
        # Setăm un cookie nesigur (fără HttpOnly, Secure, SameSite)
        response.set_cookie(
            key="auth_session",
            value=insecure_token
        )
        
        cur.close()
        conn.close()
        
        return {
            "status": "success", 
            "message": "Autentificare cu succes!", 
            "token": insecure_token
        }
        
    except HTTPException:
        # Re-aruncăm excepțiile noastre (404, 401) mai departe
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Endpoint PROTEJAT: Funcționează doar dacă ai cookie-ul de sesiune
@app.get("/me")
def get_current_user(auth_session: Optional[str] = Cookie(None)):
    # Verificăm dacă utilizatorul a trimis cookie-ul
    if not auth_session:
        raise HTTPException(status_code=401, detail="Neautentificat. Te rog să faci login.")
    
    # VULNERABILITATEA 4.5 (Gestionare nesigură a sesiunilor):
    # Avem încredere oarbă în valoarea din cookie! Nu o validăm criptografic.
    # Token-ul nostru arată așa: "session_user_1"
    try:
        # Extragem ID-ul din string-ul token-ului (foarte nesigur)
        user_id_str = auth_session.split("_")[-1]
        user_id = int(user_id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Format token invalid.")
        
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT id, email, role FROM users WHERE id = %s;", (user_id,))
        user = cur.fetchone()
        
        cur.close()
        conn.close()
        
        if not user:
            raise HTTPException(status_code=404, detail="Userul din sesiune nu mai există.")
            
        return {
            "status": "success",
            "message": "Ai accesat o resursă protejată!",
            "user": user
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Cerința 3.3: Logout
@app.post("/logout")
def logout_user(response: Response):
    # VULNERABILITATE: Doar ștergem cookie-ul din browser. 
    # Dacă un atacator a copiat deja valoarea "session_user_1", o poate folosi în continuare
    # pentru că noi nu ținem o listă cu token-uri invalidate (blacklist) pe server.
    response.delete_cookie(key="auth_session")
    return {"status": "success", "message": "Te-ai delogat cu succes."}

# Endpoint pentru a cere resetarea parolei
@app.post("/forgot-password")
def forgot_password(request: ForgotPasswordRequest):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT id FROM users WHERE email = %s;", (request.email,))
        user = cur.fetchone()
        
        cur.close()
        conn.close()
        
        if not user:
            # Păstrăm și aici vulnerabilitatea de User Enumeration (4.4)
            raise HTTPException(status_code=404, detail="Email-ul nu există în sistem.")
            
        # VULNERABILITATEA 4.6 (Resetare parolă nesigură):
        # Generăm un token extrem de predictibil și NU îl salvăm în DB pentru validare ulterioară
        insecure_reset_token = f"reset_token_{request.email}"
        
        # Într-o aplicație reală, am trimite un email. Aici îl returnăm direct în răspuns pentru testare.
        return {
            "status": "success", 
            "message": "Link de resetare trimis (simulat).", 
            "reset_token": insecure_reset_token
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Endpoint pentru a seta noua parolă
@app.post("/reset-password")
def reset_password(request: ResetPasswordRequest):
    # VULNERABILITATEA 4.6:
    # Ne bazăm exclusiv pe token-ul trimis de client, fără să verificăm dacă a expirat
    # sau dacă a mai fost folosit. Pur și simplu extragem email-ul din el.
    
    if not request.token.startswith("reset_token_"):
        raise HTTPException(status_code=400, detail="Token invalid.")
        
    # Extragem email-ul din token
    extracted_email = request.token.replace("reset_token_", "")
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # VULNERABILITATEA 4.2 & 4.1: Salvăm noua parolă tot în clar, fără să cerem complexitate
        cur.execute(
            "UPDATE users SET password_hash = %s WHERE email = %s RETURNING id;",
            (request.new_password, extracted_email)
        )
        updated_user = cur.fetchone()
        
        conn.commit()
        cur.close()
        conn.close()
        
        if not updated_user:
            raise HTTPException(status_code=404, detail="Userul din token nu există.")
            
        return {"status": "success", "message": "Parola a fost resetată cu succes!"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
