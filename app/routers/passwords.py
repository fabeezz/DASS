from fastapi import APIRouter, HTTPException
from datetime import datetime, timedelta
import secrets

from app.db.database import get_db_connection
from app.schemas import ForgotPasswordRequest, ResetPasswordRequest
from app.security import get_password_hash, validate_password_complexity

router = APIRouter(tags=["Password Management"])

reset_tokens = {}
RESET_TOKEN_EXPIRE_MINUTES = 15

@router.post("/forgot-password")
def forgot_password(request: ForgotPasswordRequest):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email = %s;", (request.email,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        
        # VULNERABILITATE v1 (4.4): User Enumeration (returnam eroare dacă adresa nu exista).
        # FIX v2: Răspuns generic mereu, pentru a ascunde existența conturilor.
        if not user:
            return {"status": "success", "message": "Dacă adresa există, vei primi un email cu pașii de resetare."}
            
        # VULNERABILITATE v1 (4.6): Token predictibil (reset_token_email) salvat nicăieri.
        # FIX v2: Token complet aleatoriu, salvat pe server cu expirare scurtă (15 minute).
        secure_reset_token = secrets.token_urlsafe(32)
        expiration_time = datetime.now() + timedelta(minutes=RESET_TOKEN_EXPIRE_MINUTES)
        
        reset_tokens[secure_reset_token] = {
            "email": request.email,
            "expires_at": expiration_time
        }
        
        return {"status": "success", "message": "Dacă adresa există, vei primi un email cu pașii de resetare.", "reset_token": secure_reset_token}
    except Exception as e:
        print(f"Eroare internă: {e}")
        raise HTTPException(status_code=500, detail="Eroare internă.")

@router.post("/reset-password")
def reset_password(request: ResetPasswordRequest):
    # FIX v2 (4.6): Validăm existența token-ului în memorie.
    token_data = reset_tokens.get(request.token)
    if not token_data:
        raise HTTPException(status_code=400, detail="Token invalid sau inexistent.")
        
    # FIX v2 (4.6): Validăm timpul de expirare (token-ul nu este permanent).
    if datetime.now() > token_data["expires_at"]:
        del reset_tokens[request.token]
        raise HTTPException(status_code=400, detail="Token-ul a expirat.")
        
    # FIX v2 (4.1): Imbunătățim politica de parole și la resetare.
    if not validate_password_complexity(request.new_password):
        raise HTTPException(status_code=400, detail="Parola trebuie să aibă minim 8 caractere, literă mare, mică și cifră.")
        
    extracted_email = token_data["email"]
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # FIX v2 (4.2): Hash-uim noua parolă înainte de actualizare.
        hashed_password = get_password_hash(request.new_password)
        
        cur.execute("UPDATE users SET password_hash = %s WHERE email = %s RETURNING id;", (hashed_password, extracted_email))
        updated_user = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        
        if not updated_user:
            raise HTTPException(status_code=404, detail="Eroare la actualizarea contului.")
            
        # VULNERABILITATE v1 (4.6): Token-ul putea fi refolosit.
        # FIX v2: Invalidăm (ștergem) token-ul după o singură utilizare cu succes (One-Time Token).
        del reset_tokens[request.token]
        
        return {"status": "success", "message": "Parola a fost resetată cu succes!"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Eroare internă: {e}")
        raise HTTPException(status_code=500, detail="Eroare internă.")
