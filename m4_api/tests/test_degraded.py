"""M4 auf einer Datenbank ohne Schema m4 (Volume aelter als m4_initial.sql).

Legt eine leere Wegwerf-Datenbank m4_empty_* an und loescht sie am Ende wieder.
Ohne M4_TEST_DATABASE_URL wird dieser Test uebersprungen.
"""
from __future__ import annotations

import os
import uuid
from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient

DB_URL = os.getenv("M4_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL, reason="M4_TEST_DATABASE_URL nicht gesetzt")

INIT_DIR = Path(__file__).resolve().parents[2] / "db" / "init"


@pytest.fixture
def empty_db(monkeypatch):
    name = f"m4_empty_{uuid.uuid4().hex[:8]}"
    with psycopg.connect(DB_URL, autocommit=True) as admin:
        admin.execute(f"CREATE DATABASE {name}")
    url = DB_URL.rsplit("/", 1)[0] + "/" + name
    from app import config
    monkeypatch.setattr(config, "DATABASE_URL", url)
    yield url
    monkeypatch.undo()
    with psycopg.connect(DB_URL, autocommit=True) as admin:
        admin.execute(f"DROP DATABASE {name} WITH (FORCE)")


def test_missing_schema_keeps_health_and_explains(empty_db):
    from app.main import app
    with TestClient(app) as client:                 # Start darf nicht abbrechen
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["status"] == "degraded" and "m4_initial.sql" in health.json()["detail"]
        r = client.post("/api/auth/login", json={"username": "admin", "password": "admin-test-password"})
        assert r.status_code == 503 and "m4_initial.sql" in r.json()["detail"]


@pytest.mark.skipif(not (INIT_DIR / "m4_initial.sql").exists(), reason="db/init nicht eingebunden")
def test_loading_schema_later_recovers_without_restart(empty_db):
    from app.main import app
    with TestClient(app) as client:
        assert client.get("/health").json()["status"] == "degraded"
        # Wie in der README beschrieben: M1-Tabellen sind Voraussetzung, dann m4_initial.sql nachladen
        with psycopg.connect(empty_db, autocommit=True) as conn:
            for file in ("m1_initial.sql", "m4_initial.sql"):
                conn.execute((INIT_DIR / file).read_text(encoding="utf-8"))
        r = client.post("/api/auth/login", json={"username": "admin", "password": "admin-test-password"})
        assert r.status_code == 200, r.text
        assert client.get("/health").json()["status"] == "ok"
