from fastapi import APIRouter, HTTPException, Response, Cookie, Request, Depends
from fastapi.security import APIKeyCookie
from typing import Optional
from datetime import datetime, timedelta

from app.db.database import get_db_connection, log_audit_event
from app.schemas import UserRegister, UserLogin
from app.security import get_password_hash, verify_password, validate_password_complexity, revoke_token, verify_jwt_token, create_access_token

router = APIRouter(tags=["Authentication"])

cookie_scheme = APIKeyCookie(name="auth_session", auto_error=False)

login_attempts = {}
MAX_ATTEMPTS = 3
LOCKOUT_MINUTES = 5

@router.post("/register")
def register_user(user: UserRegister, request: Request):
    # [VULNERABILITATE v1 (4.1)]: Password Policy inexistent (aplicația accepta parole de tipul "123").
    # [FIX v2]: Validare strictă a complexității parolei (minim 8 caractere, literă mare, mică și cifră).
    if not validate_password_complexity(user.password):
        raise HTTPException(status_code=400, detail="Parola trebuie să aibă minim 8 caractere, literă mare, mică și cifră.")

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT id FROM users WHERE email = %s;", (user.email,))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Email deja folosit.")

        # [VULNERABILITATE v1 (4.2)]: Parolele erau stocate în clar în baza de date.
        # [FIX v2]: Stocare sigură folosind bcrypt, care adaugă și un salt automat.
        hashed_password = get_password_hash(user.password)

        cur.execute(
            "INSERT INTO users (email, password_hash, role) VALUES (%s, %s, 'USER') RETURNING id;",
            (user.email, hashed_password)
        )
        new_user = cur.fetchone()
        conn.commit()
        
        log_audit_event(new_user['id'], "REGISTER", "auth", None, request.client.host) 
        
        cur.close()
        conn.close()
        
        return {"status": "success", "message": "Cont creat cu succes!", "user_id": new_user['id']}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Eroare internă: {e}") 
        raise HTTPException(status_code=500, detail="Eroare internă de server.")


@router.post("/login")
def login_user(user: UserLogin, response: Response, request: Request):
    # [VULNERABILITATE v1 (4.3)]: Lipsă Rate Limiting. Un atacator putea rula un dicționar de parole (Brute Force).
    # [FIX v2]: Implementarea Account Lockout. Verificăm blocajul temporar.
    attempt_info = login_attempts.get(user.email, {"attempts": 0, "locked_until": None})
    
    if attempt_info["locked_until"] and datetime.now() < attempt_info["locked_until"]:
        raise HTTPException(status_code=429, detail="Cont blocat temporar.")

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s;", (user.email,))
        db_user = cur.fetchone()
        
        # [VULNERABILITATE v1 (4.4)]: User Enumeration (returna "User inexistent").
        # [FIX v2]: Returnăm mesaj generic ("Invalid credentials") mereu.
        if not db_user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
            
        if db_user['locked']:
            log_audit_event(db_user['id'], "LOGIN_LOCKED_ACCOUNT", "auth", None, request.client.host)
            raise HTTPException(status_code=403, detail="Contul este blocat permanent.")

        # [VULNERABILITATE v1 (4.2)]: Comparam parolele în clar.
        # [FIX v2]: Verificăm parola folosind bcrypt.
        if not verify_password(user.password, db_user['password_hash']):
            # [FIX v2 (4.3) - Continuare]: Înregistrăm încercarea eșuată.
            attempt_info["attempts"] += 1
            if attempt_info["attempts"] >= MAX_ATTEMPTS:
                attempt_info["locked_until"] = datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)
                cur.execute("UPDATE users SET locked = TRUE WHERE id = %s;", (db_user['id'],))
                conn.commit()
                log_audit_event(db_user['id'], "ACCOUNT_TEMPORARILY_LOCKED", "auth", None, request.client.host)
            else:
                log_audit_event(db_user['id'], "LOGIN_FAILED", "auth", None, request.client.host)
                
            login_attempts[user.email] = attempt_info
            
            # [FIX v2 (4.4) - Continuare]: Același mesaj generic.
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Autentificare reușită -> Resetăm încercările
        if user.email in login_attempts:
            del login_attempts[user.email]
        
        # [VULNERABILITATE v1 (4.5)]: Token predictibil și cookie nesigur.
        # [FIX v2]: Generăm JWT și îl ascundem într-un Secure Cookie (HttpOnly, SameSite=lax).
        jwt_token = create_access_token(user_id=db_user['id'], email=db_user['email'])
        
        response.set_cookie(
            key="auth_session", 
            value=jwt_token, 
            httponly=True, 
            secure=False, # În producție (HTTPS) se setează True
            samesite="lax", 
            max_age=3600
        )
        
        cur.close()
        conn.close()

        log_audit_event(db_user['id'], "LOGIN_SUCCESS", "auth", None, request.client.host)

        return {"status": "success", "message": "Autentificare cu succes!"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Eroare internă: {e}")
        raise HTTPException(status_code=500, detail="Eroare internă.")


@router.get("/me")
def get_current_user(auth_session: str = Depends(cookie_scheme)): 
    if not auth_session:
        raise HTTPException(status_code=401, detail="Neautentificat.")
    
    # [FIX v2 (4.5)]: Validăm JWT-ul. Dacă a fost falsificat sau e expirat, decodarea va eșua.
    user_id = verify_jwt_token(auth_session)
    if not user_id:
        raise HTTPException(status_code=401, detail="Sesiune invalidă, falsificată sau expirată.")
        
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
def logout_user(response: Response, request: Request, auth_session: str = Depends(cookie_scheme)):
    if auth_session:
        user_id = verify_jwt_token(auth_session)
        if user_id:
            log_audit_event(user_id, "LOGOUT", "auth", None, request.client.host)
            
        # [VULNERABILITATE v1 (4.5)]: Sesiunile nu erau invalidate server-side (doar se ștergea cookie-ul).
        # [FIX v2]: Invalidăm JWT-ul efectiv trecându-l pe un blocklist.
        revoke_token(auth_session)
            
    response.delete_cookie(key="auth_session")
    return {"status": "success", "message": "Te-ai delogat în siguranță."}
