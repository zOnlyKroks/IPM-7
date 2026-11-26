"""M4 Zentrale API und Benachrichtigung.

Routen fuer die Weboberflaeche liegen unter /api (nginx reicht /api/ unveraendert durch) und brauchen ein JWT.
Interne Routen (/health, spaeter /notify fuer n8n) liegen ohne Praefix. Details: m4_api/README.md.
"""
from __future__ import annotations

import logging
import os
import secrets
import threading
import time
from contextlib import asynccontextmanager

import psycopg
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from . import audit, config, db, security
from .routers import auth, sources, users

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("m4")


def ensure_admin(conn: psycopg.Connection) -> None:
    """Legt den ersten Admin aus der .env an, solange es keinen aktiven Admin gibt."""
    with conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(42004004)")   # mehrere Starts gleichzeitig: nur einer legt an
        if conn.execute("SELECT 1 FROM m4.users WHERE role = 'admin' AND is_active").fetchone():
            return
        password = config.ADMIN_PASSWORD
        if not password:
            password = secrets.token_urlsafe(16)
            log.warning("ADMIN_PASSWORD ist nicht gesetzt. Einmaliges Startpasswort fuer '%s': %s",
                        config.ADMIN_USERNAME, password)
        row = conn.execute(
            """INSERT INTO m4.users (username, password_hash, role) VALUES (%s, %s, 'admin')
               ON CONFLICT ((lower(username))) DO NOTHING RETURNING id""",
            (config.ADMIN_USERNAME, security.hash_password(password)),
        ).fetchone()
        if row is None:
            log.warning("Kein aktiver Admin, aber Benutzer '%s' existiert schon (inaktiv oder andere Rolle). "
                        "Bitte manuell pruefen.", config.ADMIN_USERNAME)
            return
        audit.write(conn, None, None, "create", "user", row["id"],
                    {"username": config.ADMIN_USERNAME, "role": "admin", "bootstrap": True}, username="system")
        log.info("Start-Admin '%s' angelegt", config.ADMIN_USERNAME)


# ---------------------------------------------------------------- Bereitschaft
# Fehlt das Schema m4 (Datenbank-Volume aelter als m4_initial.sql) oder ist die Datenbank nicht erreichbar,
# startet M4 trotzdem: /health bleibt erreichbar (sonst warten n8n und web endlos und es laufen keine
# Zeitplaene), die /api-Routen antworten mit 503 und einem Hinweis. Ist das Problem behoben, prueft die
# naechste Anfrage erneut, ein Neustart ist nicht noetig.

SCHEMA_MISSING = ("Datenbankschema m4 fehlt: die Datenbank wurde vor m4_initial.sql angelegt. "
                  "Nachladen siehe m4_api/README.md, Abschnitt 'Bestehende Datenbank'.")
DB_UNREACHABLE = "Datenbank nicht erreichbar"

_state = {"problem": "noch nicht geprueft"}
_state_lock = threading.Lock()


def prepare() -> str | None:
    """Prueft Schema und legt den Start-Admin an. None = bereit, sonst der Grund."""
    try:
        with db.connect() as conn:
            if conn.execute("SELECT to_regclass('m4.users') AS t").fetchone()["t"] is None:
                return SCHEMA_MISSING
            ensure_admin(conn)
    except psycopg.OperationalError:
        return DB_UNREACHABLE
    return None


def require_ready() -> None:
    if _state["problem"] is None:
        return
    with _state_lock:
        if _state["problem"] is not None:
            _state["problem"] = prepare()
    if _state["problem"] is not None:
        raise HTTPException(status_code=503, detail=_state["problem"])


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Unsichere, ausdruecklich gesetzte Werte -> ConfigError, M4 startet nicht.
    for warning in config.resolve_secrets():
        log.warning(warning)
    for _attempt in range(10):
        _state["problem"] = prepare()
        if _state["problem"] != DB_UNREACHABLE:
            break
        log.info("Datenbank noch nicht erreichbar, neuer Versuch in 2 s")
        time.sleep(2)
    if _state["problem"]:
        log.error("M4 laeuft eingeschraenkt, /api antwortet mit 503: %s", _state["problem"])
    yield


app = FastAPI(title="M4 Zentrale API und Benachrichtigung", lifespan=lifespan)
for router in (auth.router, users.router, sources.router):
    app.include_router(router, dependencies=[Depends(require_ready)])


@app.exception_handler(psycopg.errors.UndefinedTable)
async def schema_missing(request: Request, exc: psycopg.errors.UndefinedTable) -> JSONResponse:
    # Schema waehrend des Betriebs entfernt: wieder in den eingeschraenkten Zustand wechseln.
    _state["problem"] = SCHEMA_MISSING
    log.error("M4: Tabelle fehlt bei %s %s: %s", request.method, request.url.path, exc)
    return JSONResponse(status_code=503, content={"detail": SCHEMA_MISSING})


@app.exception_handler(Exception)
async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    log.exception("M4: unerwarteter Fehler bei %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Interner Fehler in M4, Details im Log"})


@app.get("/health")
def health() -> dict:
    """Immer 200, damit n8n und web nicht auf M4 warten. Probleme stehen in status und detail."""
    problem = _state["problem"]
    return {"status": "degraded" if problem else "ok", "module": "m4_api", "detail": problem}
