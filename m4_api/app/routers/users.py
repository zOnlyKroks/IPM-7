"""Benutzerverwaltung (nur Admin). Benutzer werden nie geloescht, nur deaktiviert."""
from __future__ import annotations

from typing import Literal

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .. import audit, config, security
from ..db import get_conn
from ..deps import require_role

router = APIRouter(prefix="/api/users", tags=["users"])

Role = Literal["admin", "analyst", "viewer"]
USER_COLUMNS = "id, username, role, is_active, last_login_at, locked_until, created_at, updated_at"


class UserCreate(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9._-]{3,64}$")
    password: str = Field(min_length=config.MIN_PASSWORD_LENGTH, max_length=256)
    role: Role = "viewer"


class UserUpdate(BaseModel):
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=config.MIN_PASSWORD_LENGTH, max_length=256)


@router.get("")
def list_users(_: dict = Depends(require_role("admin")), conn: psycopg.Connection = Depends(get_conn)) -> list[dict]:
    return conn.execute(f"SELECT {USER_COLUMNS} FROM m4.users ORDER BY lower(username)").fetchall()


@router.post("", status_code=201)
def create_user(body: UserCreate, request: Request, admin: dict = Depends(require_role("admin")),
                conn: psycopg.Connection = Depends(get_conn)) -> dict:
    try:
        with conn.transaction():
            row = conn.execute(
                f"INSERT INTO m4.users (username, password_hash, role) VALUES (%s, %s, %s) RETURNING {USER_COLUMNS}",
                (body.username, security.hash_password(body.password), body.role),
            ).fetchone()
            audit.write(conn, request, admin, "create", "user", row["id"],
                        {"username": row["username"], "role": row["role"]})
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Benutzername ist schon vergeben")
    return row


@router.patch("/{user_id}")
def update_user(user_id: int, body: UserUpdate, request: Request, admin: dict = Depends(require_role("admin")),
                conn: psycopg.Connection = Depends(get_conn)) -> dict:
    changes = body.model_dump(exclude_unset=True, exclude_none=True)
    with conn.transaction():
        old = conn.execute(f"SELECT {USER_COLUMNS} FROM m4.users WHERE id = %s FOR UPDATE", (user_id,)).fetchone()
        if old is None:
            raise HTTPException(status_code=404, detail="Benutzer nicht gefunden")

        loses_admin = old["role"] == "admin" and old["is_active"] and (
            changes.get("role", "admin") != "admin" or changes.get("is_active", True) is False)
        if loses_admin:
            # Sperre auf alle Admins, damit zwei gleichzeitige Aenderungen nicht beide durchgehen.
            others = conn.execute(
                "SELECT count(*) AS n FROM (SELECT 1 FROM m4.users WHERE role = 'admin' AND is_active AND id <> %s FOR UPDATE) a",
                (user_id,)).fetchone()["n"]
            if others == 0:
                raise HTTPException(status_code=409, detail="Der letzte aktive Admin kann nicht herabgestuft oder deaktiviert werden")

        details = audit.diff(old, {k: v for k, v in changes.items() if k != "password"})
        password_hash = security.hash_password(changes["password"]) if "password" in changes else None
        if password_hash:
            details["password_reset"] = True
        if not details:
            return old

        # Jede Aenderung an Rolle, Status oder Passwort meldet den Benutzer ab (token_version + 1).
        row = conn.execute(
            f"""UPDATE m4.users
                   SET role = COALESCE(%s, role),
                       is_active = COALESCE(%s, is_active),
                       password_hash = COALESCE(%s, password_hash),
                       failed_login_count = CASE WHEN %s THEN 0 ELSE failed_login_count END,
                       locked_until = CASE WHEN %s THEN NULL ELSE locked_until END,
                       token_version = token_version + 1
                 WHERE id = %s RETURNING {USER_COLUMNS}""",
            (changes.get("role"), changes.get("is_active"), password_hash,
             password_hash is not None, password_hash is not None, user_id),
        ).fetchone()
        audit.write(conn, request, admin, "update", "user", user_id, details)
    return row
