import hmac
import math
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from .config import ADMIN_SECRET, SESSION_DAYS
from .db import Base, engine, get_db
from .models import License, Session, User, utcnow
from .schemas import (
    ActivateIn,
    ActivateOut,
    GenerateIn,
    GenerateOut,
    KeyInfo,
    LoginIn,
    LoginOut,
    LogoutOut,
    MyLicenseOut,
    RegisterIn,
    RegisterOut,
    RevokeOut,
    ValidateIn,
    ValidateOut,
)
from .security import generate_key, hash_password, new_session_token, verify_password


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="RBX Manager API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------------------------------------------------------------ helpers

def as_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def remaining_days(lic: License) -> int:
    if lic.duration_days == -1:
        return -1
    exp = as_utc(lic.expires_at)
    if exp is None:
        return lic.duration_days
    seconds = (exp - utcnow()).total_seconds()
    if seconds <= 0:
        return 0
    return int(math.ceil(seconds / 86400.0))


def license_expired(lic: License) -> bool:
    if lic.duration_days == -1:
        return False
    exp = as_utc(lic.expires_at)
    return exp is not None and exp <= utcnow()


def current_user(
    request: Request,
    db: DbSession = Depends(get_db),
) -> User:
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Token manquant")
    token = auth[7:].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Token manquant")

    sess = db.scalar(select(Session).where(Session.token == token))
    if sess is None:
        raise HTTPException(status_code=401, detail="Session invalide")
    if as_utc(sess.expires_at) <= utcnow():
        db.delete(sess)
        db.commit()
        raise HTTPException(status_code=401, detail="Session expirée")

    user = db.get(User, sess.user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="Utilisateur introuvable")
    return user


def require_admin(x_admin_secret: Optional[str] = Header(default=None)) -> None:
    if not x_admin_secret or not hmac.compare_digest(x_admin_secret, ADMIN_SECRET):
        raise HTTPException(status_code=403, detail="Admin secret invalide")


# ------------------------------------------------------------------ health

@app.get("/health")
def health():
    return {"status": "ok", "time": utcnow().isoformat()}


# ------------------------------------------------------------------ auth

@app.post("/auth/register", response_model=RegisterOut)
def register(body: RegisterIn, db: DbSession = Depends(get_db)):
    username = body.username.strip()
    if len(username) < 3 or len(username) > 32:
        raise HTTPException(status_code=422, detail="Username: 3 à 32 caractères")

    exists = db.scalar(select(User).where(User.username == username))
    if exists is not None:
        raise HTTPException(status_code=409, detail="Ce nom d'utilisateur est déjà pris")

    user = User(username=username, password_hash=hash_password(body.password))
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Ce nom d'utilisateur est déjà pris")

    return RegisterOut(user_id=str(user.id), username=user.username)


@app.get("/auth/check-username")
def check_username(username: str, db: DbSession = Depends(get_db)):
    name = username.strip()
    if len(name) < 3 or len(name) > 32:
        return {"available": False, "message": "3 à 32 caractères"}
    taken = db.scalar(select(User).where(User.username == name))
    return {"available": taken is None, "message": "déjà pris" if taken else "disponible"}


@app.post("/auth/login", response_model=LoginOut)
def login(body: LoginIn, db: DbSession = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == body.username.strip()))
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Identifiants invalides")

    expires = utcnow() + timedelta(days=SESSION_DAYS)
    sess = Session(user_id=user.id, token=new_session_token(), expires_at=expires)
    db.add(sess)
    db.commit()

    return LoginOut(token=sess.token, expires_at=expires)


@app.post("/auth/logout", response_model=LogoutOut)
def logout(request: Request, db: DbSession = Depends(get_db)):
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        sess = db.scalar(select(Session).where(Session.token == token))
        if sess is not None:
            db.delete(sess)
            db.commit()
    return LogoutOut(success=True)


# ------------------------------------------------------------------ license

@app.post("/license/activate", response_model=ActivateOut)
def activate(body: ActivateIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
    lic = db.scalar(select(License).where(License.key == body.key.strip().upper()))
    if lic is None:
        raise HTTPException(status_code=404, detail="Clé inconnue")
    if not lic.is_active:
        raise HTTPException(status_code=403, detail="Clé révoquée")
    if license_expired(lic):
        raise HTTPException(status_code=403, detail="Clé expirée")

    hwid = body.hwid.strip()
    if not hwid:
        raise HTTPException(status_code=422, detail="HWID manquant")

    if lic.hwid is None:
        lic.hwid = hwid
    elif lic.hwid != hwid:
        raise HTTPException(status_code=403, detail="HWID mismatch — licence liée à une autre machine")

    if lic.user_id is not None and lic.user_id != user.id:
        raise HTTPException(status_code=409, detail="Clé déjà liée à un autre compte")

    lic.user_id = user.id

    if lic.duration_days != -1 and lic.expires_at is None:
        lic.expires_at = utcnow() + timedelta(days=lic.duration_days)

    db.commit()
    return ActivateOut(valid=True, expires_at=as_utc(lic.expires_at), days_remaining=remaining_days(lic))


@app.post("/license/validate", response_model=ValidateOut)
def validate(body: ValidateIn, db: DbSession = Depends(get_db)):
    lic = db.scalar(select(License).where(License.key == body.key.strip().upper()))
    if lic is None:
        return ValidateOut(valid=False, message="Clé inconnue")
    if not lic.is_active:
        return ValidateOut(valid=False, message="Clé révoquée")
    if license_expired(lic):
        return ValidateOut(valid=False, message="Clé expirée")
    if lic.hwid is None:
        return ValidateOut(valid=False, message="Licence non activée")
    if lic.hwid != body.hwid.strip():
        return ValidateOut(valid=False, message="HWID mismatch")

    return ValidateOut(valid=True, days_remaining=remaining_days(lic), message="OK")


@app.get("/license/mine", response_model=MyLicenseOut)
def my_license(user: User = Depends(current_user), db: DbSession = Depends(get_db)):
    lic = db.scalar(
        select(License)
        .where(License.user_id == user.id, License.is_active.is_(True))
        .order_by(License.created_at.desc())
    )
    if lic is None or license_expired(lic):
        raise HTTPException(status_code=404, detail="Aucune licence active sur ce compte")
    return MyLicenseOut(key=lic.key, expires_at=as_utc(lic.expires_at), days_remaining=remaining_days(lic))


# ------------------------------------------------------------------ admin

@app.post("/admin/generate-keys", response_model=GenerateOut, dependencies=[Depends(require_admin)])
def admin_generate(body: GenerateIn, db: DbSession = Depends(get_db)):
    keys: list[str] = []
    while len(keys) < body.count:
        key = generate_key()
        if db.scalar(select(License).where(License.key == key)) is not None:
            continue
        db.add(License(key=key, duration_days=body.duration_days, is_active=True))
        keys.append(key)
    db.commit()
    return GenerateOut(keys=keys)


@app.get("/admin/keys", response_model=list[KeyInfo], dependencies=[Depends(require_admin)])
def admin_keys(db: DbSession = Depends(get_db)):
    rows = db.scalars(select(License).order_by(License.created_at.desc())).all()
    return [
        KeyInfo(
            key=r.key,
            is_active=r.is_active,
            user_id=str(r.user_id) if r.user_id else None,
            hwid=r.hwid,
            duration_days=r.duration_days,
            created_at=as_utc(r.created_at),
            expires_at=as_utc(r.expires_at),
        )
        for r in rows
    ]


@app.delete("/admin/revoke/{key}", response_model=RevokeOut, dependencies=[Depends(require_admin)])
def admin_revoke(key: str, db: DbSession = Depends(get_db)):
    lic = db.scalar(select(License).where(License.key == key.strip().upper()))
    if lic is None:
        raise HTTPException(status_code=404, detail="Clé inconnue")
    lic.is_active = False
    db.commit()
    return RevokeOut(revoked=True)
