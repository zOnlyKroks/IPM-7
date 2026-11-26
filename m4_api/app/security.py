"""Passwort-Hashing (argon2) und JWT. Keine Datenbankzugriffe, damit sich das ohne DB testen laesst."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from . import config

_hasher = PasswordHasher()
# Fuer unbekannte Benutzer wird trotzdem ein Hash geprueft, damit die Antwortzeit nichts verraet.
_DUMMY_HASH = _hasher.hash("argos-timing-dummy")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def create_token(user: dict, now: datetime | None = None) -> tuple[str, datetime]:
    now = now or datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=config.JWT_TTL_MINUTES)
    payload = {
        "sub": str(user["id"]),
        "role": user["role"],
        "ver": user["token_version"],
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM), expires_at


def decode_token(token: str) -> dict:
    """Wirft jwt.PyJWTError bei ungueltiger Signatur, Ablauf oder fehlenden Feldern."""
    return jwt.decode(token, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM],
                      options={"require": ["sub", "ver", "exp"]})
