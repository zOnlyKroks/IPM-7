"""Quellenverwaltung. Die Tabelle public.sources liegt in m1_initial.sql, schreiben darf nur M4.

Quellen werden nie geloescht (raw_items und fetch_runs verweisen darauf), nur deaktiviert oder gesperrt.
Die erlaubten Werte entsprechen den CHECK-Constraints in m1_initial.sql.
"""
from __future__ import annotations

import re
from typing import Literal

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field, field_validator

from .. import audit
from ..db import get_conn
from ..deps import current_user, require_role

router = APIRouter(prefix="/api/sources", tags=["sources"])

Connector = Literal["rss", "cisa_kev", "nvd", "epss", "osv"]
SourceType = Literal["authority", "vendor", "press", "social"]
Status = Literal["active", "disabled", "blocked"]

# Zugangsdaten gehoeren in die .env, nie in sources.config (M1 liest die Tabelle ohne Schutz).
SECRET_KEY_PATTERN = re.compile(r"pass|secret|token|api[_-]?key|credential|auth", re.IGNORECASE)

SOURCE_COLUMNS = """s.id, s.name, s.url, s.connector, s.source_type, s.language, s.trust_weight,
                    s.is_primary_source, s.is_priority, s.status, s.fetch_interval_minutes, s.config,
                    s.created_at, s.updated_at"""
EDITABLE = ("name", "url", "connector", "source_type", "language", "trust_weight", "is_primary_source",
            "is_priority", "status", "fetch_interval_minutes", "config")

# Letzter Abruf je Quelle (juengste Zeile in fetch_runs nach started_at, siehe m1_initial.sql)
SELECT_SOURCES = f"""
    SELECT {SOURCE_COLUMNS},
           CASE WHEN fr.id IS NULL THEN NULL ELSE jsonb_build_object(
               'status', fr.status, 'started_at', fr.started_at, 'finished_at', fr.finished_at,
               'http_status', fr.http_status, 'items_new', fr.items_new, 'items_failed', fr.items_failed,
               'error_message', fr.error_message) END AS last_fetch
      FROM public.sources s
      LEFT JOIN LATERAL (
          SELECT * FROM public.fetch_runs f WHERE f.source_id = s.id ORDER BY f.started_at DESC LIMIT 1
      ) fr ON true
"""


def _check_config(value: dict | None) -> dict | None:
    if value is None:
        return value

    def walk(obj: object) -> None:
        if isinstance(obj, dict):
            for key, inner in obj.items():
                if SECRET_KEY_PATTERN.search(str(key)):
                    raise ValueError(f"config darf keine Zugangsdaten enthalten (Schluessel '{key}'), diese gehoeren in die .env")
                walk(inner)
        elif isinstance(obj, list):
            for inner in obj:
                walk(inner)
    walk(value)
    return value


class SourceBase(BaseModel):
    @field_validator("url", check_fields=False)
    @classmethod
    def _url(cls, v: str | None) -> str | None:
        if v is not None and not re.match(r"^https?://[^\s]+$", v):
            raise ValueError("URL muss mit http:// oder https:// beginnen")
        return v

    @field_validator("config", check_fields=False)
    @classmethod
    def _config(cls, v: dict | None) -> dict | None:
        return _check_config(v)


class SourceCreate(SourceBase):
    name: str = Field(min_length=1, max_length=200)
    url: str = Field(max_length=2000)
    connector: Connector
    source_type: SourceType
    language: str | None = Field(default=None, pattern=r"^[a-z]{2}(-[a-z]{2})?$")
    trust_weight: float = Field(default=0.5, ge=0, le=1)
    is_primary_source: bool = False
    is_priority: bool = False
    status: Status = "active"
    fetch_interval_minutes: int = Field(default=30, gt=0)
    config: dict = Field(default_factory=dict)


class SourceUpdate(SourceBase):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    url: str | None = Field(default=None, max_length=2000)
    connector: Connector | None = None
    source_type: SourceType | None = None
    language: str | None = Field(default=None, pattern=r"^[a-z]{2}(-[a-z]{2})?$")
    trust_weight: float | None = Field(default=None, ge=0, le=1)
    is_primary_source: bool | None = None
    is_priority: bool | None = None
    status: Status | None = None
    fetch_interval_minutes: int | None = Field(default=None, gt=0)
    config: dict | None = None


def _get(conn: psycopg.Connection, source_id: int) -> dict:
    row = conn.execute(SELECT_SOURCES + " WHERE s.id = %s", (source_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Quelle nicht gefunden")
    return row


def _jsonable(values: dict) -> dict:
    """trust_weight kommt als Decimal aus der DB; fuer Vergleich und Audit-Log einheitlich als float."""
    return {k: float(v) if k == "trust_weight" and v is not None else v for k, v in values.items()}


@router.get("")
def list_sources(status: Status | None = Query(default=None), _: dict = Depends(current_user),
                 conn: psycopg.Connection = Depends(get_conn)) -> list[dict]:
    if status:
        return conn.execute(SELECT_SOURCES + " WHERE s.status = %s ORDER BY s.name", (status,)).fetchall()
    return conn.execute(SELECT_SOURCES + " ORDER BY s.name").fetchall()


@router.get("/{source_id}")
def get_source(source_id: int, _: dict = Depends(current_user), conn: psycopg.Connection = Depends(get_conn)) -> dict:
    return _get(conn, source_id)


@router.post("", status_code=201)
def create_source(body: SourceCreate, request: Request, admin: dict = Depends(require_role("admin")),
                  conn: psycopg.Connection = Depends(get_conn)) -> dict:
    values = body.model_dump()
    try:
        with conn.transaction():
            source_id = conn.execute(
                f"""INSERT INTO public.sources ({", ".join(EDITABLE)})
                    VALUES ({", ".join(["%s"] * len(EDITABLE))}) RETURNING id""",
                [Jsonb(values[c]) if c == "config" else values[c] for c in EDITABLE],
            ).fetchone()["id"]
            audit.write(conn, request, admin, "create", "source", source_id, values)
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Eine Quelle mit diesem Namen gibt es schon")
    return _get(conn, source_id)


@router.patch("/{source_id}")
def update_source(source_id: int, body: SourceUpdate, request: Request, admin: dict = Depends(require_role("admin")),
                  conn: psycopg.Connection = Depends(get_conn)) -> dict:
    changes = body.model_dump(exclude_unset=True)
    # Pflichtfelder lassen sich nicht leeren; language darf bewusst auf null gesetzt werden.
    changes = {k: v for k, v in changes.items() if v is not None or k == "language"}
    try:
        with conn.transaction():
            old = conn.execute(f"SELECT {SOURCE_COLUMNS} FROM public.sources s WHERE s.id = %s FOR UPDATE",
                               (source_id,)).fetchone()
            if old is None:
                raise HTTPException(status_code=404, detail="Quelle nicht gefunden")
            details = audit.diff(_jsonable(old), _jsonable(changes))
            if details:
                columns = list(details)
                conn.execute(
                    f"UPDATE public.sources SET {', '.join(f'{c} = %s' for c in columns)} WHERE id = %s",
                    [Jsonb(changes[c]) if c == "config" else changes[c] for c in columns] + [source_id],
                )
                audit.write(conn, request, admin, "update", "source", source_id, details)
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Eine Quelle mit diesem Namen gibt es schon")
    return _get(conn, source_id)
