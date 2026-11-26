"""Datenbankzugriff. Eine Verbindung je Anfrage, autocommit; mehrere Schreibvorgaenge laufen in conn.transaction()."""
from __future__ import annotations

from typing import Iterator

import psycopg
from psycopg.rows import dict_row

from . import config


def connect() -> psycopg.Connection:
    return psycopg.connect(config.DATABASE_URL, row_factory=dict_row, autocommit=True)


def get_conn() -> Iterator[psycopg.Connection]:
    """FastAPI-Abhaengigkeit."""
    with connect() as conn:
        yield conn
