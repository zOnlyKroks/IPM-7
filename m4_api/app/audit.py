"""Eintraege ins Audit-Log (m4.audit_log, nur anhaengen).

In details stehen alter und neuer Wert, niemals Passwoerter, Hashes, Tokens oder Webhook-URLs.
"""
from __future__ import annotations

import ipaddress

import psycopg
from fastapi import Request
from psycopg.types.json import Jsonb


def client_ip(request: Request) -> str | None:
    """IP des Aufrufers. nginx setzt X-Forwarded-For auf die echte Adresse (web/nginx.conf)."""
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    candidate = forwarded or (request.client.host if request.client else "")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def write(conn: psycopg.Connection, request: Request | None, user: dict | None, action: str, entity: str,
          entity_id: object = None, details: dict | None = None, username: str | None = None) -> None:
    conn.execute(
        """INSERT INTO m4.audit_log (user_id, username, action, entity, entity_id, details, ip_address)
           VALUES (%s, %s, %s, %s, %s, %s, %s)""",
        (user["id"] if user else None,
         user["username"] if user else username,
         action, entity,
         None if entity_id is None else str(entity_id),
         Jsonb(details or {}),
         client_ip(request) if request else None),
    )


def diff(old: dict, new: dict) -> dict:
    """Nur geaenderte Felder: {"feld": {"old": ..., "new": ...}}."""
    return {k: {"old": old.get(k), "new": v} for k, v in new.items() if old.get(k) != v}
