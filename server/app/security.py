import secrets
import string

import bcrypt

KEY_CHARS = string.ascii_uppercase + string.digits


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def _segment() -> str:
    return "".join(secrets.choice(KEY_CHARS) for _ in range(4))


def generate_key() -> str:
    return f"RXBM-{_segment()}-{_segment()}-{_segment()}"
