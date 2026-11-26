"""Abhaengigkeiten fuer Anmeldung und Rollen.

Rollen sind gestuft: viewer < analyst < admin. require_role("analyst") laesst also auch Admins zu.
"""
from __future__ import annotations

import hmac

import jwt
import psycopg
from fastapi import Depends, Header, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import config, security
from .db import get_conn

ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}

_bearer = HTTPBearer(auto_error=False)


def _unauthorized(detail: str = "Nicht angemeldet oder Sitzung abgelaufen") -> HTTPException:
    return HTTPException(status_code=401, detail=detail, headers={"WWW-Authenticate": "Bearer"})


def current_user(creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
                 conn: psycopg.Connection = Depends(get_conn)) -> dict:
    if creds is None:
        raise _unauthorized()
    try:
        payload = security.decode_token(creds.credentials)
        user_id = int(payload["sub"])
    except (jwt.PyJWTError, ValueError):
        raise _unauthorized()
    user = conn.execute(
        "SELECT id, username, role, is_active, token_version FROM m4.users WHERE id = %s", (user_id,)
    ).fetchone()
    # Deaktivierung, Passwort- oder Rollenwechsel erhoehen token_version: alte Tokens gelten dann nicht mehr.
    if not user or not user["is_active"] or user["token_version"] != payload["ver"]:
        raise _unauthorized()
    return user


def require_role(minimum: str):
    def check(user: dict = Depends(current_user)) -> dict:
        if ROLE_RANK[user["role"]] < ROLE_RANK[minimum]:
            raise HTTPException(status_code=403, detail="Keine Berechtigung fuer diese Aktion")
        return user
    return check


def require_internal_key(x_api_key: str | None = Header(default=None)) -> None:
    """Fuer interne Aufrufer (n8n). Gleiches Verfahren wie M2 und M3."""
    expected = config.INTERNAL_API_KEY
    if not expected or not x_api_key or not hmac.compare_digest(x_api_key.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="X-API-Key fehlt oder ist falsch")
