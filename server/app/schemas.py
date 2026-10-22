from datetime import datetime
from typing import Optional
from pydantic import BaseModel

class RegisterIn(BaseModel):
    username: str
    password: str

class RegisterOut(BaseModel):
    user_id: str
    username: str

class LoginIn(BaseModel):
    username: str
    password: str

class LoginOut(BaseModel):
    token: str
    expires_at: datetime

class LogoutOut(BaseModel):
    success: bool

class ActivateIn(BaseModel):
    key: str
    hwid: str

class ActivateOut(BaseModel):
    valid: bool
    expires_at: Optional[datetime] = None
    days_remaining: int

class ValidateIn(BaseModel):
    key: str
    hwid: str

class ValidateOut(BaseModel):
    valid: bool
    days_remaining: Optional[int] = None
    message: str

class MyLicenseOut(BaseModel):
    key: str
    expires_at: Optional[datetime] = None
    days_remaining: int

class GenerateIn(BaseModel):
    count: int
    duration_days: int

class GenerateOut(BaseModel):
    keys: list[str]

class KeyInfo(BaseModel):
    key: str
    is_active: bool
    user_id: Optional[str] = None
    hwid: Optional[str] = None
    duration_days: int
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None

class RevokeOut(BaseModel):
    revoked: bool
