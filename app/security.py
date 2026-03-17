import os
import jwt
import bcrypt
import re
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
JWT_EXPIRATION_MINUTES = int(os.getenv("JWT_EXPIRATION_MINUTES"))

# [VULNERABILITATE v1 (4.5)]: Sesiunile (sau token-urile) nu puteau fi invalidate real pe server la logout, permițând Session Hijacking dacă token-ul era furat.
# [FIX v2]: Implementarea unui Blacklist (revoked_tokens). La logout, token-ul este adăugat aici, fiind respins la cereri ulterioare.
revoked_tokens = set()

def create_access_token(user_id: int, email: str) -> str:
    expire = datetime.now() + timedelta(minutes=JWT_EXPIRATION_MINUTES)
    to_encode = {"sub": str(user_id), "email": email, "exp": expire}
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> int:
    # Verificăm dacă token-ul a fost revocat (Logout)
    if token in revoked_tokens:
        return None 

    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id_str: str = payload.get("sub")
        if user_id_str is None:
            return None
        return int(user_id_str)
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def revoke_token(token: str):
    """Adaugă token-ul pe lista neagră la logout."""
    revoked_tokens.add(token)

# [VULNERABILITATE v1 (4.2)]: Parolele erau stocate în clar în baza de date PostgreSQL, expunând total utilizatorii în cazul unei breșe.
# [FIX v2]: Stocare sigură folosind o funcție de derivare a cheilor puternică (bcrypt). 
# Bcrypt generează automat un salt unic pentru fiecare parolă, mitigând atacurile cu Rainbow Tables.
def get_password_hash(password: str) -> str:
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_bytes = bcrypt.hashpw(pwd_bytes, salt)
    return hashed_bytes.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    pwd_bytes = plain_password.encode('utf-8')
    hash_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(pwd_bytes, hash_bytes)

# [VULNERABILITATE v1 (4.1)]: Password Policy inexistent (aplicația accepta parole de tipul "123").
# [FIX v2]: Validare strictă a complexității parolei (minim 8 caractere, minim o literă mare, o literă mică și o cifră).
def validate_password_complexity(password: str) -> bool:
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    return True
