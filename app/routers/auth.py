from fastapi import APIRouter, HTTPException, Response, Cookie
from typing import Optional
from datetime import datetime, timedelta
import secrets

from app.db.database import get_db_connection
from app.schemas import UserRegister, UserLogin
from app.security import get_password_hash, verify_password, validate_password_complexity

router = APIRouter(tags=["Authentication"])

# Rate Limiting & Sesiuni (în memorie)
login_attempts = {}
MAX_ATTEMPTS = 3
LOCKOUT_MINUTES = 5

active_sessions = {}

@router.post("/register")
def register_user(user: UserRegister):
    # VULNERABILITATE v1 (4.1): Orice parolă era acceptată (ex: "123").
    # FIX v2: Verificăm complexitatea parolei (Password Policy).
    if not validate_password_complexity(user.password):
        raise HTTPException(status_code=400, detail="Parola trebuie să aibă minim 8 caractere, literă mare, mică și cifră.")

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT id FROM users WHERE email = %s;", (user.email,))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Email deja folosit.")

        # VULNERABILITATE v1 (4.2): Parola era stocată în clar în baza de date.
        # FIX v2: Hash-uim parola folosind bcrypt (care include salt automat).
        hashed_password = get_password_hash(user.password)

        cur.execute(
            "INSERT INTO users (email, password_hash, role) VALUES (%s, %s, 'USER') RETURNING id;",
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

@router.post("/login")
def login_user(user: UserLogin, response: Response):
    # VULNERABILITATE v1 (4.3): Lipsă rate limiting (permitea atacuri Brute Force).
    # FIX v2: Verificăm dacă userul este blocat temporar din cauza încercărilor eșuate.
    attempt_info = login_attempts.get(user.email, {"attempts": 0, "locked_until": None})
    
    if attempt_info["locked_until"] and datetime.now() < attempt_info["locked_until"]:
        raise HTTPException(status_code=429, detail="Cont blocat temporar.")

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s;", (user.email,))
        db_user = cur.fetchone()
        
        # VULNERABILITATE v1 (4.4): User Enumeration (returnam "User inexistent").
        # FIX v2: Returnăm mesaj generic ("Invalid credentials") chiar dacă email-ul nu există.
        if not db_user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
            
        if db_user['locked']:
            raise HTTPException(status_code=403, detail="Contul este blocat permanent.")

        # VULNERABILITATE v1 (4.2): Comparam parolele în clar.
        # FIX v2: Verificăm parola folosind bcrypt.checkpw.
        if not verify_password(user.password, db_user['password_hash']):
            # FIX v2 (4.3) - Continuare Rate Limiting: Înregistrăm încercarea eșuată.
            attempt_info["attempts"] += 1
            if attempt_info["attempts"] >= MAX_ATTEMPTS:
                attempt_info["locked_until"] = datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)
                cur.execute("UPDATE users SET locked = TRUE WHERE id = %s;", (db_user['id'],))
                conn.commit()
            login_attempts[user.email] = attempt_info
            
            # FIX v2 (4.4): Același mesaj generic ca la user inexistent.
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Autentificare reușită -> Resetăm încercările
        if user.email in login_attempts:
            del login_attempts[user.email]
        
        # VULNERABILITATE v1 (4.5): Token predictibil (session_user_ID) și cookie nesigur.
        # FIX v2: Token criptografic aleatoriu stocat pe server și cookie cu flag-uri de securitate.
        secure_token = secrets.token_urlsafe(64)
        active_sessions[secure_token] = db_user['id']
        
        response.set_cookie(
            key="auth_session", 
            value=secure_token, 
            httponly=True, 
            secure=False, # True în producție (HTTPS)
            samesite="lax", 
            max_age=3600
        )
        
        cur.close()
        conn.close()
        return {"status": "success", "message": "Autentificare cu succes!"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Eroare internă: {e}")
        raise HTTPException(status_code=500, detail="Eroare internă.")

@router.get("/me")
def get_current_user(auth_session: Optional[str] = Cookie(None)):
    if not auth_session:
        raise HTTPException(status_code=401, detail="Neautentificat.")
    
    # FIX v2 (4.5): Validăm că token-ul extras din cookie-ul HttpOnly chiar există pe server.
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

@router.post("/logout")
def logout_user(response: Response, auth_session: Optional[str] = Cookie(None)):
    # VULNERABILITATE v1 (4.5): Doar ștergeam cookie-ul, sesiunea rămânea validă.
    # FIX v2: Invalidare reală pe server a sesiunii (token-ul devine inutilizabil).
    if auth_session in active_sessions:
        del active_sessions[auth_session]
        
    response.delete_cookie(key="auth_session")
    return {"status": "success", "message": "Te-ai delogat în siguranță."}