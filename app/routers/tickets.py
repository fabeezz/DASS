from fastapi import APIRouter, HTTPException, Cookie, Request
from typing import Optional

from app.db.database import get_db_connection, log_audit_event
from app.schemas import TicketCreate
from app.routers.auth import active_sessions # Importăm sesiunile active

router = APIRouter(tags=["Business (Tickets)"], prefix="/tickets")

def get_current_user_id(auth_session: str):
    """Funcție helper pentru a extrage user-ul din sesiune."""
    if not auth_session:
        raise HTTPException(status_code=401, detail="Neautentificat.")
    user_id = active_sessions.get(auth_session)
    if not user_id:
        raise HTTPException(status_code=401, detail="Sesiune invalidă sau expirată.")
    return user_id

@router.post("/")
def create_ticket(ticket: TicketCreate, request: Request, auth_session: Optional[str] = Cookie(None)):
    user_id = get_current_user_id(auth_session)
    client_ip = request.client.host
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # PREVENIRE IDOR: Setăm owner_id direct din sesiune (server-side), NU din request-ul clientului [cite: 29]
        cur.execute(
            "INSERT INTO tickets (title, description, severity, owner_id) VALUES (%s, %s, %s, %s) RETURNING id;",
            (ticket.title, ticket.description, ticket.severity, user_id)
        )
        new_ticket = cur.fetchone()
        conn.commit()
        
        # Salvăm acțiunea în Audit Log [cite: 37]
        log_audit_event(user_id, "CREATE_TICKET", "tickets", str(new_ticket['id']), client_ip)
        
        cur.close()
        conn.close()
        return {"status": "success", "message": "Ticket creat!", "ticket_id": new_ticket['id']}
    except Exception as e:
        print(f"Eroare DB: {e}")
        raise HTTPException(status_code=500, detail="Eroare internă.")

@router.get("/")
def get_my_tickets(request: Request, auth_session: Optional[str] = Cookie(None)):
    user_id = get_current_user_id(auth_session)
    client_ip = request.client.host
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # PREVENIRE IDOR: Filtrăm tichetele aducând DOAR pe cele unde owner_id = user_id [cite: 37]
        cur.execute("SELECT * FROM tickets WHERE owner_id = %s ORDER BY created_at DESC;", (user_id,))
        tickets = cur.fetchall()
        
        # Salvăm acțiunea de vizualizare în Audit Log
        log_audit_event(user_id, "VIEW_TICKETS", "tickets", None, client_ip)
        
        cur.close()
        conn.close()
        return {"status": "success", "tickets": tickets}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Eroare internă.")
