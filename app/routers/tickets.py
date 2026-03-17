from fastapi import APIRouter, HTTPException, Cookie, Request, Depends
from fastapi.security import APIKeyCookie
from typing import Optional

from app.db.database import get_db_connection, log_audit_event
from app.schemas import TicketCreate, TicketUpdate
from app.security import verify_jwt_token

router = APIRouter(tags=["Business (Tickets)"], prefix="/tickets")
cookie_scheme = APIKeyCookie(name="auth_session", auto_error=False)

def get_current_user_id(auth_session: str = Depends(cookie_scheme)):
    if not auth_session:
        raise HTTPException(status_code=401, detail="Neautentificat.")
    
    user_id = verify_jwt_token(auth_session)
    if not user_id:
        raise HTTPException(status_code=401, detail="Sesiune invalidă sau expirată.")
    return user_id

# C: CREATE (Creare tichet)
@router.post("/")
def create_ticket(ticket: TicketCreate, request: Request, user_id: int = Depends(get_current_user_id)):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute(
            "INSERT INTO tickets (title, description, severity, owner_id) VALUES (%s, %s, %s, %s) RETURNING id;",
            (ticket.title, ticket.description, ticket.severity, user_id)
        )
        new_ticket = cur.fetchone()
        conn.commit()
        
        log_audit_event(user_id, "CREATE_TICKET", "tickets", str(new_ticket['id']), request.client.host)
        
        cur.close()
        conn.close()
        return {"status": "success", "message": "Ticket creat!", "ticket_id": new_ticket['id']}
    except Exception as e:
        print(f"Eroare DB: {e}")
        raise HTTPException(status_code=500, detail="Eroare internă.")

# R: READ (Vizualizare toate tichetele mele)
@router.get("/")
def get_my_tickets(request: Request, user_id: int = Depends(get_current_user_id)):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # [PREVENIRE IDOR]: Aducem doar tichetele unde owner_id = user_id
        cur.execute("SELECT * FROM tickets WHERE owner_id = %s ORDER BY created_at DESC;", (user_id,))
        tickets = cur.fetchall()
        
        log_audit_event(user_id, "VIEW_TICKETS", "tickets", None, request.client.host)
        
        cur.close()
        conn.close()
        return {"status": "success", "tickets": tickets}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Eroare internă.")

# U: UPDATE (Modificare tichet)
@router.put("/{ticket_id}")
def update_ticket(ticket_id: int, ticket: TicketUpdate, request: Request, user_id: int = Depends(get_current_user_id)):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # [VULNERABILITATE v1]: Aplicația nu verifica cui aparține tichetul la modificare.
        # [FIX v2 (Barem: Control acces server-side)]: Verificăm explicit ownership-ul (owner_id = user_id extras din JWT).
        cur.execute(
            """
            UPDATE tickets SET title = %s, description = %s, severity = %s 
            WHERE id = %s AND owner_id = %s RETURNING id;
            """,
            (ticket.title, ticket.description, ticket.severity, ticket_id, user_id)
        )
        updated = cur.fetchone()
        conn.commit()
        
        if not updated:
            raise HTTPException(status_code=404, detail="Tichetul nu există sau nu ai permisiunea de a-l modifica.")
            
        log_audit_event(user_id, "UPDATE_TICKET", "tickets", str(ticket_id), request.client.host)
        
        cur.close()
        conn.close()
        return {"status": "success", "message": "Tichet actualizat cu succes!"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Eroare DB: {e}")
        raise HTTPException(status_code=500, detail="Eroare internă.")

# D: DELETE (Ștergere tichet)
@router.delete("/{ticket_id}")
def delete_ticket(ticket_id: int, request: Request, user_id: int = Depends(get_current_user_id)):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # [PREVENIRE IDOR]: Ștergem DOAR dacă ticketul ne aparține
        cur.execute("DELETE FROM tickets WHERE id = %s AND owner_id = %s RETURNING id;", (ticket_id, user_id))
        deleted = cur.fetchone()
        conn.commit()
        
        if not deleted:
            raise HTTPException(status_code=404, detail="Tichetul nu există sau nu ai permisiunea de a-l șterge.")
            
        log_audit_event(user_id, "DELETE_TICKET", "tickets", str(ticket_id), request.client.host)
        
        cur.close()
        conn.close()
        return {"status": "success", "message": "Tichet șters cu succes!"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Eroare DB: {e}")
        raise HTTPException(status_code=500, detail="Eroare internă.")
