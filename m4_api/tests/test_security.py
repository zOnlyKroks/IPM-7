"""Passwort-Hashing und JWT, ohne Datenbank."""
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from app import security

USER = {"id": 7, "role": "analyst", "token_version": 3}


def test_password_hash_roundtrip():
    h = security.hash_password("richtig-langes-passwort")
    assert h.startswith("$argon2")
    assert security.verify_password(h, "richtig-langes-passwort")
    assert not security.verify_password(h, "falsch")


def test_unknown_user_never_verifies():
    assert not security.verify_password(None, "argos-timing-dummy")
    assert not security.verify_password("kein-hash", "egal")


def test_token_roundtrip():
    token, _ = security.create_token(USER)
    payload = security.decode_token(token)
    assert payload["sub"] == "7" and payload["ver"] == 3 and payload["role"] == "analyst"


def test_expired_token_rejected():
    token, _ = security.create_token(USER, now=datetime.now(timezone.utc) - timedelta(days=2))
    with pytest.raises(jwt.ExpiredSignatureError):
        security.decode_token(token)


def test_foreign_signature_rejected():
    forged = jwt.encode({"sub": "7", "ver": 3, "exp": 9999999999}, "ein-ganz-anderer-schluessel-mit-32-bytes", algorithm="HS256")
    with pytest.raises(jwt.InvalidSignatureError):
        security.decode_token(forged)


def test_unsigned_token_rejected():
    forged = jwt.encode({"sub": "7", "ver": 3, "exp": 9999999999}, None, algorithm="none")
    with pytest.raises(jwt.PyJWTError):
        security.decode_token(forged)
