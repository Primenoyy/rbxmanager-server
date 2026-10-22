from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=6, max_length=128)


class LoginIn(BaseModel):
    username: str
    password: str


class RegisterOut(BaseModel):
    user_id: str
    username: str


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
    days_remaining: int = 0


class ValidateIn(BaseModel):
    key: str
    hwid: str


class ValidateOut(BaseModel):
    valid: bool
    days_remaining: int = 0
    message: str = ""


class MyLicenseOut(BaseModel):
    key: str
    expires_at: Optional[datetime] = None
    days_remaining: int = 0


class GenerateIn(BaseModel):
    count: int = Field(ge=1, le=500)
    duration_days: int = Field(ge=-1, le=3650)


class GenerateOut(BaseModel):
    keys: list[str]


class KeyInfo(BaseModel):
    key: str
    is_active: bool
    user_id: Optional[str] = None
    hwid: Optional[str] = None
    duration_days: int
    created_at: datetime
    expires_at: Optional[datetime] = None


class RevokeOut(BaseModel):
    revoked: bool
