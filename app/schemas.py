from pydantic import BaseModel

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
