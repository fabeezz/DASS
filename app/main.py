from fastapi import FastAPI, HTTPException, Response, Cookie
from pydantic import BaseModel
from app.database import get_db_connection
from typing import Optional

app = FastAPI(title="Break the Login v1 - Vulnerable API")

# Modele Pydantic la comun (Bad Practice pentru proiecte mari)
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

class TicketCreate(BaseModel):
    title: str
    description: str
    severity: str = "LOW"

class TicketUpdate(BaseModel):
    title: str
    description: str
    severity: str


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
        # [VULNERABILITATE v1 (Error Handling)]: Expunem eroarea internă (Stack Trace) către client
        raise HTTPException(status_code=500, detail=f"Eroare DB: {str(e)}")


@app.post("/register")
def register_user(user: UserRegister):
    # [VULNERABILITATE v1 (4.1)]: Lipsă Password Policy. Acceptăm orice parolă (ex: "123").
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT id FROM users WHERE email = %s;", (user.email,))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Email deja folosit.")

        # [VULNERABILITATE v1 (4.2)]: Stocăm parola în CLAR în baza de date. Nu folosim hash.
        cur.execute(
            "INSERT INTO users (email, password_hash, role) VALUES (%s, %s, 'USER') RETURNING id;",
            (user.email, user.password)
        )
        new_user = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        
        return {"status": "success", "message": "Cont creat cu succes!", "user_id": new_user['id']}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/login")
def login_user(user: UserLogin, response: Response):
    # [VULNERABILITATE v1 (4.3)]: Lipsă Rate Limiting / Brute Force. Nu contorizăm încercările eșuate.
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s;", (user.email,))
        db_user = cur.fetchone()
        
        # [VULNERABILITATE v1 (4.4)]: User Enumeration. Mesaj distinct dacă user-ul nu există.
        if not db_user:
            raise HTTPException(status_code=404, detail="User inexistent.")
            
        # [VULNERABILITATE v1 (4.2)]: Comparăm parola primită cu parola în clar din baza de date.
        if db_user['password_hash'] != user.password:
            # [VULNERABILITATE v1 (4.4)]: User Enumeration. Mesaj distinct dacă parola este greșită.
            raise HTTPException(status_code=401, detail="Parolă greșită.")
            
        # [VULNERABILITATE v1 (4.5)]: Gestionare nesigură a sesiunilor. Token 100% predictibil.
        insecure_token = f"session_user_{db_user['id']}" 
        
        # [VULNERABILITATE v1 (4.5)]: Cookie nesigur (fără HttpOnly, SameSite sau Secure).
        response.set_cookie(key="auth_session", value=insecure_token)
        
        cur.close()
        conn.close()
        
        return {"status": "success", "message": "Autentificare cu succes!", "token": insecure_token}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/me")
def get_current_user(auth_session: Optional[str] = Cookie(None)):
    if not auth_session:
        raise HTTPException(status_code=401, detail="Neautentificat.")
    
    # [VULNERABILITATE v1 (4.5)]: Avem încredere totală în valoarea din cookie și o parsam direct.
    try:
        user_id = int(auth_session.split("_")[-1])
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
            
        return {"status": "success", "user": user}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/logout")
def logout_user(response: Response):
    # [VULNERABILITATE v1 (4.5)]: Invalidation eșuată. Doar ștergem cookie-ul din browser. Token-ul este încă valid teoretic.
    response.delete_cookie(key="auth_session")
    return {"status": "success", "message": "Te-ai delogat cu succes."}


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
            # [VULNERABILITATE v1 (4.4)]: User Enumeration la password reset.
            raise HTTPException(status_code=404, detail="Email-ul nu există în sistem.")
            
        # [VULNERABILITATE v1 (4.6)]: Resetare parolă nesigură. Generăm un token predictibil derivat din email. Nu are expirare.
        insecure_reset_token = f"reset_token_{request.email}"
        
        return {"status": "success", "message": "Link de resetare trimis.", "reset_token": insecure_reset_token}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/reset-password")
def reset_password(request: ResetPasswordRequest):
    if not request.token.startswith("reset_token_"):
        raise HTTPException(status_code=400, detail="Token invalid.")
        
    extracted_email = request.token.replace("reset_token_", "")
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # [VULNERABILITATE v1 (4.6)]: Nu verificăm dacă tokenul a expirat sau dacă a fost refolosit. 
        # [VULNERABILITATE v1 (4.1 & 4.2)]: Salvăm noua parolă în clar, acceptând orice complexitate.
        cur.execute("UPDATE users SET password_hash = %s WHERE email = %s RETURNING id;",(request.new_password, extracted_email))
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

@app.post("/tickets")
def create_ticket(ticket: TicketCreate, auth_session: Optional[str] = Cookie(None)):
    if not auth_session:
        raise HTTPException(status_code=401, detail="Neautentificat.")
    user_id = int(auth_session.split("_")[-1]) # Insecure token parsing
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO tickets (title, description, severity, owner_id) VALUES (%s, %s, %s, %s) RETURNING id;",
            (ticket.title, ticket.description, ticket.severity, user_id)
        )
        new_ticket = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return {"status": "success", "ticket_id": new_ticket['id']}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/tickets")
def get_my_tickets(auth_session: Optional[str] = Cookie(None)):
    if not auth_session:
        raise HTTPException(status_code=401, detail="Neautentificat.")
    user_id = int(auth_session.split("_")[-1])
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM tickets WHERE owner_id = %s;", (user_id,))
        tickets = cur.fetchall()
        cur.close()
        conn.close()
        return {"status": "success", "tickets": tickets}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/tickets/search")
def search_tickets(query: str, auth_session: Optional[str] = Cookie(None)):
    if not auth_session:
        raise HTTPException(status_code=401, detail="Neautentificat.")
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # [VULNERABILITATE v1]: Concatenare directă de string-uri (Risc de SQL Injection)
        # Nu folosim query parametrizat
        sql_query = f"SELECT * FROM tickets WHERE title LIKE '%{query}%' OR description LIKE '%{query}%';"
        cur.execute(sql_query)
        
        results = cur.fetchall()
        cur.close()
        conn.close()
        
        return {"status": "success", "results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/tickets/{ticket_id}")
def get_ticket_by_id(ticket_id: int, auth_session: Optional[str] = Cookie(None)):
    if not auth_session:
        raise HTTPException(status_code=401, detail="Neautentificat.")
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # [VULNERABILITATE v1]: Nu verificăm ownership-ul (Risc de IDOR)
        # Permitem vizualizarea oricărui tichet dacă ID-ul este cunoscut
        cur.execute("SELECT * FROM tickets WHERE id = %s;", (ticket_id,))
        ticket = cur.fetchone()
        
        cur.close()
        conn.close()
        
        if not ticket:
            raise HTTPException(status_code=404, detail="Tichetul nu a fost găsit.")
            
        return {"status": "success", "ticket": ticket}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Eroare internă de server.")

@app.put("/tickets/{ticket_id}")
def update_ticket(ticket_id: int, ticket: TicketUpdate, auth_session: Optional[str] = Cookie(None)):
    if not auth_session:
        raise HTTPException(status_code=401, detail="Neautentificat.")
        
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # [VULNERABILITATE v1 (Control acces server-side)]: IDOR.
        # Updatăm tichetul bazându-ne DOAR pe ticket_id, ignorând owner_id.
        # Orice utilizator logat poate modifica tichetele altor utilizatori!
        cur.execute(
            "UPDATE tickets SET title = %s, description = %s, severity = %s WHERE id = %s RETURNING id;",
            (ticket.title, ticket.description, ticket.severity, ticket_id)
        )
        updated = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        
        if not updated:
            raise HTTPException(status_code=404, detail="Tichet inexistent.")
        return {"status": "success", "message": "Tichet modificat cu succes!"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/tickets/{ticket_id}")
def delete_ticket(ticket_id: int, auth_session: Optional[str] = Cookie(None)):
    if not auth_session:
        raise HTTPException(status_code=401, detail="Neautentificat.")
        
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # [VULNERABILITATE v1 (Control acces server-side)]: IDOR.
        # Permitem ștergerea tichetului fără a verifica dacă aparține userului curent.
        cur.execute("DELETE FROM tickets WHERE id = %s RETURNING id;", (ticket_id,))
        deleted = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        
        if not deleted:
            raise HTTPException(status_code=404, detail="Tichet inexistent.")
        return {"status": "success", "message": "Tichet șters!"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
