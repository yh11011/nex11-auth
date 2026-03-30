"""
Shared JWT utility — copy this file to each consuming service.
Each service needs JWT_SECRET_KEY in its environment.
"""
import os
from jose import jwt, JWTError
from datetime import datetime, timezone

JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")
JWT_ALGORITHM = "HS256"


def encode_token(user: dict, expire_minutes: int = 10080) -> str:
    """Issue a signed JWT for the given user dict."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user["id"]),
        "username": user.get("username"),
        "email": user.get("email"),
        "display_name": user.get("display_name"),
        "iat": int(now.timestamp()),
        "exp": int(now.timestamp()) + expire_minutes * 60,
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and verify a JWT. Raises JWTError on failure."""
    if not JWT_SECRET_KEY:
        raise JWTError("JWT_SECRET_KEY not configured")
    return jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])


def get_user_id(token: str) -> int:
    """Convenience: decode token and return user ID as int."""
    return int(decode_token(token)["sub"])
