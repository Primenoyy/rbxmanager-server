import secrets
import bcrypt

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def new_session_token() -> str:
    return secrets.token_urlsafe(32)

def generate_key() -> str:
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    def seg():
        return ''.join(secrets.choice(chars) for _ in range(4))
    return f"RXBM-{seg()}-{seg()}-{seg()}"
