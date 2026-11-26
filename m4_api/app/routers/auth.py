"""Anmeldung, Abmeldung, eigenes Passwort."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .. import audit, config, security
from ..db import get_conn
from ..deps import current_user

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Bewusst dieselbe Meldung fuer unbekannte Benutzer, falsche Passwoerter, gesperrte und deaktivierte Konten.
LOGIN_FAILED = "Benutzername oder Passwort falsch, oder Konto voruebergehend gesperrt"


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=config.MIN_PASSWORD_LENGTH, max_length=256)


def _token_response(user: dict) -> dict:
    token, expires_at = security.create_token(user)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires_at,
        "user": {"id": user["id"], "username": user["username"], "role": user["role"]},
    }


@router.post("/login")
def login(body: LoginRequest, request: Request, conn: psycopg.Connection = Depends(get_conn)) -> dict:
    now = datetime.now(timezone.utc)
    with conn.transaction():
        user = conn.execute(
            """SELECT id, username, password_hash, role, is_active, token_version, failed_login_count, locked_until
                 FROM m4.users WHERE lower(username) = lower(%s) FOR UPDATE""",
            (body.username,),
        ).fetchone()
        password_ok = security.verify_password(user["password_hash"] if user else None, body.password)

        if user is None:
            audit.write(conn, request, None, "login_failed", "user", details={"reason": "unknown_user"},
                        username=body.username[:64])
            failed = True
        elif not user["is_active"]:
            audit.write(conn, request, user, "login_failed", "user", user["id"], {"reason": "inactive"})
            failed = True
        elif user["locked_until"] and user["locked_until"] > now:
            audit.write(conn, request, user, "login_failed", "user", user["id"], {"reason": "locked"})
            failed = True
        elif not password_ok:
            count = user["failed_login_count"] + 1
            locked_until = now + timedelta(minutes=config.LOGIN_LOCK_MINUTES) if count >= config.LOGIN_MAX_FAILURES else None
            conn.execute("UPDATE m4.users SET failed_login_count = %s, locked_until = %s WHERE id = %s",
                         (0 if locked_until else count, locked_until, user["id"]))
            audit.write(conn, request, user, "login_failed", "user", user["id"],
                        {"reason": "wrong_password", "locked": locked_until is not None})
            failed = True
        else:
            new_hash = security.hash_password(body.password) if security.needs_rehash(user["password_hash"]) else user["password_hash"]
            conn.execute(
                """UPDATE m4.users SET failed_login_count = 0, locked_until = NULL, last_login_at = %s, password_hash = %s
                    WHERE id = %s""",
                (now, new_hash, user["id"]),
            )
            audit.write(conn, request, user, "login", "user", user["id"])
            failed = False
    # Erst nach dem Commit abbrechen, damit Fehlversuch und Audit-Eintrag gespeichert sind.
    if failed:
        raise HTTPException(status_code=401, detail=LOGIN_FAILED)
    return _token_response(user)


@router.get("/me")
def me(user: dict = Depends(current_user)) -> dict:
    return {"id": user["id"], "username": user["username"], "role": user["role"]}


@router.post("/logout", status_code=204)
def logout(request: Request, user: dict = Depends(current_user), conn: psycopg.Connection = Depends(get_conn)) -> None:
    """Macht alle Tokens des Benutzers ungueltig (auch auf anderen Geraeten)."""
    with conn.transaction():
        conn.execute("UPDATE m4.users SET token_version = token_version + 1 WHERE id = %s", (user["id"],))
        audit.write(conn, request, user, "logout", "user", user["id"])


@router.post("/password")
def change_password(body: PasswordChange, request: Request, user: dict = Depends(current_user),
                    conn: psycopg.Connection = Depends(get_conn)) -> dict:
    row = conn.execute("SELECT password_hash FROM m4.users WHERE id = %s", (user["id"],)).fetchone()
    if not security.verify_password(row["password_hash"], body.current_password):
        raise HTTPException(status_code=400, detail="Aktuelles Passwort ist falsch")
    with conn.transaction():
        updated = conn.execute(
            """UPDATE m4.users SET password_hash = %s, token_version = token_version + 1
                WHERE id = %s RETURNING id, username, role, token_version""",
            (security.hash_password(body.new_password), user["id"]),
        ).fetchone()
        audit.write(conn, request, user, "password_change", "user", user["id"])
    # Neues Token, damit die aktuelle Sitzung weiterlaeuft; alle anderen sind abgemeldet.
    return _token_response(updated)
