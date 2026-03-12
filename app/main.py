import re
import bcrypt
import secrets
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Response, Cookie
from pydantic import BaseModel
from app.database import get_db_connection
from typing import Optional
import psycopg2

app = FastAPI(title="Break the Login v2")

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

# Rate Limiting: Key = email, Value = {"attempts": int, "locked_until": datetime}
login_attempts = {}
MAX_ATTEMPTS = 3
LOCKOUT_MINUTES = 5

# Gestionarea sesiunilor securizate în memorie
# Key = session_token, Value = user_id
active_sessions = {}

# Gestionarea token-urilor de resetare parolă
# Key = reset_token, Value = {"email": str, "expires_at": datetime}
reset_tokens = {}
RESET_TOKEN_EXPIRE_MINUTES = 15

def get_password_hash(password: str) -> str:
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_bytes = bcrypt.hashpw(pwd_bytes, salt)
    return hashed_bytes.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    pwd_bytes = plain_password.encode('utf-8')
    hash_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(pwd_bytes, hash_bytes)

def validate_password_complexity(password: str):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    return True

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
    # FIX 4.1: Validăm politica de parole (Password Policy)
    if not validate_password_complexity(user.password):
        raise HTTPException(
            status_code=400, 
            detail="Parola trebuie să aibă minim 8 caractere, să conțină o literă mare, o literă mică și o cifră."
        )

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Verificăm dacă email-ul există deja
        cur.execute("SELECT id FROM users WHERE email = %s;", (user.email,))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Email deja folosit.")

        # FIX 4.2: Hash-uim parola înainte de a o salva!
        hashed_password = get_password_hash(user.password)

        cur.execute(
            """
            INSERT INTO users (email, password_hash, role) 
            VALUES (%s, %s, 'USER') 
            RETURNING id;
            """,
            (user.email, hashed_password) 
        )
        
        new_user = cur.fetchone()
        conn.commit() 
        cur.close()
        conn.close()
        
        return {"status": "success", "message": "Cont creat cu succes!", "user_id": new_user['id']}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Eroare internă: {e}") 
        raise HTTPException(status_code=500, detail="Eroare internă de server.")

@app.post("/login")
def login_user(user: UserLogin, response: Response):
    # FIX 4.3 (Rate Limiting): Verificăm dacă userul este deja blocat temporar
    attempt_info = login_attempts.get(user.email, {"attempts": 0, "locked_until": None})
    
    if attempt_info["locked_until"] and datetime.now() < attempt_info["locked_until"]:
        raise HTTPException(
            status_code=429, # 429 Too Many Requests
            detail=f"Cont blocat temporar. Încearcă din nou mai târziu."
        )

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT * FROM users WHERE email = %s;", (user.email,))
        db_user = cur.fetchone()
        
        # FIX 4.4 (User Enumeration): Mesaj GENERIC dacă userul nu există
        if not db_user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
            
        # Verificăm dacă administratorul l-a blocat definitiv din baza de date
        if db_user['locked']:
            raise HTTPException(status_code=403, detail="Contul este blocat permanent.")

        # FIX 4.2 & 4.3: Verificăm parola folosind BCRYPT
        if not verify_password(user.password, db_user['password_hash']):
            # Parola este greșită -> Înregistrăm încercarea eșuată
            attempt_info["attempts"] += 1
            
            if attempt_info["attempts"] >= MAX_ATTEMPTS:
                # Blocăm contul pentru 5 minute
                attempt_info["locked_until"] = datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)
                # Opțional: îl marcăm ca blocat și în DB (pentru audit)
                cur.execute("UPDATE users SET locked = TRUE WHERE id = %s;", (db_user['id'],))
                conn.commit()
            
            login_attempts[user.email] = attempt_info
            
            # Returnăm ACELAȘI mesaj generic ca la user inexistent
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Parola e corectă! Resetăm numărătorul de încercări eșuate
        if user.email in login_attempts:
            del login_attempts[user.email]
        
        # FIX 4.5: Generăm un token criptografic puternic și aleator
        secure_token = secrets.token_urlsafe(64)
        
        # Salvăm sesiunea pe server
        active_sessions[secure_token] = db_user['id']
        
        # FIX 4.5: Setăm cookie-ul cu toate flag-urile de securitate activate
        response.set_cookie(
            key="auth_session",
            value=secure_token,
            httponly=True,  # Protejează împotriva XSS (Cross-Site Scripting)
            secure=False,   # În producție se pune True (pentru HTTPS). Lăsăm False DOAR pt că testăm local pe HTTP.
            samesite="lax", # Protejează împotriva CSRF
            max_age=3600    # Expiră în o oră (Sesiune limitată)
        )
        
        cur.close()
        conn.close()
        
        return {"status": "success", "message": "Autentificare cu succes!"}

    except HTTPException:
        raise
    except Exception as e:
        print(f"Eroare internă: {e}")
        raise HTTPException(status_code=500, detail="Eroare internă.")

@app.get("/me")
def get_current_user(auth_session: Optional[str] = Cookie(None)):
    if not auth_session:
        raise HTTPException(status_code=401, detail="Neautentificat.")
    
    # FIX 4.5: Validăm că token-ul există pe server și nu a fost inventat de atacator
    user_id = active_sessions.get(auth_session)
    if not user_id:
        raise HTTPException(status_code=401, detail="Sesiune invalidă sau expirată.")
        
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, email, role FROM users WHERE id = %s;", (user_id,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        
        if not user:
            raise HTTPException(status_code=404, detail="Userul nu mai există.")
            
        return {"status": "success", "user": user}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Eroare internă.")

@app.post("/logout")
def logout_user(response: Response, auth_session: Optional[str] = Cookie(None)):
    # FIX 4.5: Invalidare reală a sesiunii pe server
    if auth_session in active_sessions:
        del active_sessions[auth_session]
        
    response.delete_cookie(key="auth_session")
    return {"status": "success", "message": "Te-ai delogat în siguranță."}

@app.post("/forgot-password")
def forgot_password(request: ForgotPasswordRequest):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT id FROM users WHERE email = %s;", (request.email,))
        user = cur.fetchone()
        
        cur.close()
        conn.close()
        
        # FIX 4.4 (User Enumeration): Chiar dacă userul nu există, returnăm același mesaj de succes!
        # Astfel, un atacator nu poate folosi acest formular pentru a afla ce email-uri sunt înregistrate.
        if not user:
            return {"status": "success", "message": "Dacă adresa există, vei primi un email cu pașii de resetare."}
            
        # FIX 4.6: Generăm un token criptografic puternic și aleator 
        secure_reset_token = secrets.token_urlsafe(32)
        
        # FIX 4.6: Setăm o expirare scurtă (15 minute) 
        expiration_time = datetime.now() + timedelta(minutes=RESET_TOKEN_EXPIRE_MINUTES)
        
        # Salvăm token-ul pe server
        reset_tokens[secure_reset_token] = {
            "email": request.email,
            "expires_at": expiration_time
        }
        
        # Simulăm trimiterea email-ului returnând token-ul (pentru testare)
        return {
            "status": "success", 
            "message": "Dacă adresa există, vei primi un email cu pașii de resetare.", 
            "reset_token": secure_reset_token
        }
    except Exception as e:
        print(f"Eroare internă: {e}")
        raise HTTPException(status_code=500, detail="Eroare internă.")


@app.post("/reset-password")
def reset_password(request: ResetPasswordRequest):
    # FIX 4.6: Căutăm token-ul în memorie
    token_data = reset_tokens.get(request.token)
    
    if not token_data:
        raise HTTPException(status_code=400, detail="Token invalid sau inexistent.")
        
    # FIX 4.6: Verificăm dacă token-ul a expirat 
    if datetime.now() > token_data["expires_at"]:
        # Curățăm token-ul expirat
        del reset_tokens[request.token]
        raise HTTPException(status_code=400, detail="Token-ul a expirat. Te rog să ceri altul.")
        
    # FIX 4.1: Validăm complexitatea noii parole
    if not validate_password_complexity(request.new_password):
        raise HTTPException(
            status_code=400, 
            detail="Parola trebuie să aibă minim 8 caractere, să conțină o literă mare, o literă mică și o cifră."
        )
        
    extracted_email = token_data["email"]
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # FIX 4.2: Hash-uim NOA parolă cu bcrypt înainte de a o salva
        hashed_password = get_password_hash(request.new_password)
        
        cur.execute(
            "UPDATE users SET password_hash = %s WHERE email = %s RETURNING id;",
            (hashed_password, extracted_email)
        )
        updated_user = cur.fetchone()
        
        conn.commit()
        cur.close()
        conn.close()
        
        if not updated_user:
            raise HTTPException(status_code=404, detail="Eroare la actualizarea contului.")
            
        # FIX 4.6 (CRITIC): Invalidăm (ștergem) token-ul după utilizare, ca să fie "one-time" 
        del reset_tokens[request.token]
            
        return {"status": "success", "message": "Parola a fost resetată cu succes!"}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Eroare internă: {e}")
        raise HTTPException(status_code=500, detail="Eroare internă.")
