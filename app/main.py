from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from app.routers import auth, passwords, tickets
from app.db.database import get_db_connection

app = FastAPI(title="Break the Login API - Secure Version")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"], # Aici pui doar adresa frontend-ului tău Next.js!
    allow_credentials=True, # Obligatoriu pentru a putea trimite Secure Cookies
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    
    # Excludem rutele Swagger (/docs, /openapi.json) de la CSP-ul strict deoarece Swagger folosește CDN-uri externe și scripturi inline pentru a randa interfața.
    if not request.url.path.startswith(("/docs", "/openapi.json", "/redoc")):
        # [FIX v2]: Implementare CSP (Content Security Policy)
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none';"
    
    # Aceste headere sunt sigure și le aplicăm peste tot
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    return response

app.include_router(auth.router)
app.include_router(passwords.router)
app.include_router(tickets.router)

@app.get("/")
def read_root():
    return {"message": "Salutare! Backend-ul ruleaza (v2)."}

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
        return {"status": "error", "message": str(e)}
