"""Durchlauf gegen eine echte Datenbank mit synthetischen Daten (example.invalid).

NUR gegen eine Wegwerf-Datenbank laufen lassen: der Test leert m4.users und m4.audit_log
und legt Quellen mit dem Namen m4-test-* an (werden am Ende wieder geloescht).
Start, wenn `docker compose up -d postgres` laeuft (im Ordner m4_api):

    M4_TEST_DATABASE_URL=postgresql://argos:argos@localhost:5432/argos python -m pytest tests

Ohne M4_TEST_DATABASE_URL wird dieser Test uebersprungen.
"""
from __future__ import annotations

import os
import uuid

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.rows import dict_row

DB_URL = os.getenv("M4_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL, reason="M4_TEST_DATABASE_URL nicht gesetzt")

ADMIN_PW = "admin-test-password"
SUFFIX = uuid.uuid4().hex[:8]


@pytest.fixture(scope="module")
def db():
    conn = psycopg.connect(DB_URL, row_factory=dict_row, autocommit=True)
    # TRUNCATE loest die Zeilen-Trigger des Audit-Logs nicht aus
    conn.execute("TRUNCATE m4.audit_log, m4.item_status, m4.users RESTART IDENTITY CASCADE")
    yield conn
    conn.execute("DELETE FROM public.sources WHERE name LIKE 'm4-test-%'")
    conn.close()


@pytest.fixture(scope="module")
def client(db):
    from app.main import app
    with TestClient(app) as c:          # startet lifespan -> Start-Admin wird angelegt
        yield c


def login(client, username, password):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def admin_token(client):
    r = login(client, "admin", ADMIN_PW)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def make_user(client, admin_token, username, role, password="viewer-password-123"):
    r = client.post("/api/users", headers=auth(admin_token),
                    json={"username": username, "password": password, "role": role})
    assert r.status_code == 201, r.text
    return r.json()


def last_audit(db, action=None):
    q = "SELECT * FROM m4.audit_log" + (" WHERE action = %s" if action else "") + " ORDER BY id DESC LIMIT 1"
    return db.execute(q, (action,) if action else ()).fetchone()


# ---------------------------------------------------------------- Anmeldung

def test_bootstrap_admin_and_me(client, admin_token, db):
    r = client.get("/api/auth/me", headers=auth(admin_token))
    assert r.json()["role"] == "admin"
    assert db.execute("SELECT count(*) AS n FROM m4.audit_log WHERE details->>'bootstrap' = 'true'").fetchone()["n"] == 1


def test_bootstrap_is_idempotent(client, db):
    from app.main import ensure_admin
    from app import db as appdb
    with appdb.connect() as conn:
        ensure_admin(conn)
    assert db.execute("SELECT count(*) AS n FROM m4.users WHERE role = 'admin'").fetchone()["n"] == 1


def test_password_hash_not_plaintext(db):
    h = db.execute("SELECT password_hash FROM m4.users WHERE username = 'admin'").fetchone()["password_hash"]
    assert h.startswith("$argon2") and ADMIN_PW not in h


def test_requests_without_token_rejected(client):
    assert client.get("/api/sources").status_code == 401
    assert client.get("/api/sources", headers=auth("kein.gueltiges.token")).status_code == 401


def test_unknown_user_same_answer_and_audited(client, db):
    r = login(client, "gibt-es-nicht", "egal-egal-egal")
    assert r.status_code == 401
    entry = last_audit(db, "login_failed")
    assert entry["user_id"] is None and entry["username"] == "gibt-es-nicht"
    assert entry["details"]["reason"] == "unknown_user"


def test_lockout_after_failures(client, admin_token, db):
    make_user(client, admin_token, "lockme", "viewer", "lockme-password-1")
    for _ in range(3):                                   # M4_LOGIN_MAX_FAILURES=3 (conftest)
        assert login(client, "lockme", "falsch").status_code == 401
    # Jetzt gesperrt: auch das richtige Passwort wird abgelehnt
    assert login(client, "lockme", "lockme-password-1").status_code == 401
    assert last_audit(db, "login_failed")["details"]["reason"] == "locked"
    # Admin setzt Passwort zurueck -> Sperre aufgehoben
    uid = db.execute("SELECT id FROM m4.users WHERE username = 'lockme'").fetchone()["id"]
    r = client.patch(f"/api/users/{uid}", headers=auth(admin_token), json={"password": "lockme-password-2"})
    assert r.status_code == 200
    assert login(client, "lockme", "lockme-password-2").status_code == 200


def test_logout_invalidates_token(client, admin_token):
    make_user(client, admin_token, "logoutuser", "viewer")
    token = login(client, "logoutuser", "viewer-password-123").json()["access_token"]
    assert client.post("/api/auth/logout", headers=auth(token)).status_code == 204
    assert client.get("/api/auth/me", headers=auth(token)).status_code == 401


def test_password_change(client, admin_token, db):
    make_user(client, admin_token, "pwuser", "viewer")
    old = login(client, "pwuser", "viewer-password-123").json()["access_token"]
    r = client.post("/api/auth/password", headers=auth(old),
                    json={"current_password": "falsch", "new_password": "neues-passwort-123"})
    assert r.status_code == 400
    r = client.post("/api/auth/password", headers=auth(old),
                    json={"current_password": "viewer-password-123", "new_password": "neues-passwort-123"})
    assert r.status_code == 200
    assert client.get("/api/auth/me", headers=auth(old)).status_code == 401
    assert client.get("/api/auth/me", headers=auth(r.json()["access_token"])).status_code == 200
    entry = last_audit(db, "password_change")
    assert "neues-passwort" not in str(entry["details"])


# ---------------------------------------------------------------- Benutzer

def test_viewer_cannot_manage_users(client, admin_token):
    make_user(client, admin_token, "nurlesen", "viewer")
    token = login(client, "nurlesen", "viewer-password-123").json()["access_token"]
    assert client.get("/api/users", headers=auth(token)).status_code == 403


def test_duplicate_username_case_insensitive(client, admin_token):
    r = client.post("/api/users", headers=auth(admin_token),
                    json={"username": "ADMIN", "password": "irgendwas-langes", "role": "viewer"})
    assert r.status_code == 409


def test_last_admin_protected(client, admin_token, db):
    admin_id = db.execute("SELECT id FROM m4.users WHERE username = 'admin'").fetchone()["id"]
    r = client.patch(f"/api/users/{admin_id}", headers=auth(admin_token), json={"is_active": False})
    assert r.status_code == 409
    r = client.patch(f"/api/users/{admin_id}", headers=auth(admin_token), json={"role": "viewer"})
    assert r.status_code == 409


def test_role_change_logs_user_out(client, admin_token, db):
    user = make_user(client, admin_token, "rollenwechsel", "viewer")
    token = login(client, "rollenwechsel", "viewer-password-123").json()["access_token"]
    r = client.patch(f"/api/users/{user['id']}", headers=auth(admin_token), json={"role": "analyst"})
    assert r.json()["role"] == "analyst"
    assert client.get("/api/auth/me", headers=auth(token)).status_code == 401
    entry = last_audit(db, "update")
    assert entry["details"] == {"role": {"old": "viewer", "new": "analyst"}}


# ---------------------------------------------------------------- Quellen

def new_source(name_part="rss"):
    return {"name": f"m4-test-{name_part}-{SUFFIX}", "url": "https://example.invalid/feed.xml",
            "connector": "rss", "source_type": "authority", "language": "de", "trust_weight": 0.9}


def test_source_create_list_and_audit(client, admin_token, db):
    r = client.post("/api/sources", headers=auth(admin_token), json=new_source("a"))
    assert r.status_code == 201, r.text
    src = r.json()
    assert src["status"] == "active" and src["last_fetch"] is None
    entry = last_audit(db, "create")
    assert entry["entity"] == "source" and entry["entity_id"] == str(src["id"])

    names = [s["name"] for s in client.get("/api/sources", headers=auth(admin_token)).json()]
    assert src["name"] in names


def test_source_last_fetch_status(client, admin_token, db):
    src = client.post("/api/sources", headers=auth(admin_token), json=new_source("fetch")).json()
    db.execute("""INSERT INTO public.fetch_runs (source_id, scope, status, started_at, finished_at, error_message)
                  VALUES (%s, 'regular', 'success', now() - interval '2 hours', now() - interval '2 hours', NULL),
                         (%s, 'regular', 'failed',  now() - interval '5 minutes', now(), 'Timeout')""",
               (src["id"], src["id"]))
    r = client.get(f"/api/sources/{src['id']}", headers=auth(admin_token)).json()
    assert r["last_fetch"]["status"] == "failed" and r["last_fetch"]["error_message"] == "Timeout"
    db.execute("DELETE FROM public.fetch_runs WHERE source_id = %s", (src["id"],))


def test_source_update_block_and_audit_diff(client, admin_token, db):
    src = client.post("/api/sources", headers=auth(admin_token), json=new_source("b")).json()
    r = client.patch(f"/api/sources/{src['id']}", headers=auth(admin_token),
                     json={"status": "blocked", "trust_weight": 0.2})
    assert r.status_code == 200 and r.json()["status"] == "blocked"
    entry = last_audit(db, "update")
    assert entry["details"] == {"status": {"old": "active", "new": "blocked"},
                                "trust_weight": {"old": 0.9, "new": 0.2}}
    # Unveraenderte Werte erzeugen keinen Audit-Eintrag
    before = last_audit(db)["id"]
    client.patch(f"/api/sources/{src['id']}", headers=auth(admin_token), json={"status": "blocked"})
    assert last_audit(db)["id"] == before


def test_source_validation(client, admin_token):
    bad_config = {**new_source("c"), "config": {"headers": {"X-Api-Key": "geheim"}}}
    assert client.post("/api/sources", headers=auth(admin_token), json=bad_config).status_code == 422
    bad_url = {**new_source("d"), "url": "ftp://example.invalid"}
    assert client.post("/api/sources", headers=auth(admin_token), json=bad_url).status_code == 422
    bad_connector = {**new_source("e"), "connector": "twitter"}
    assert client.post("/api/sources", headers=auth(admin_token), json=bad_connector).status_code == 422


def test_source_duplicate_name(client, admin_token):
    body = new_source("dup")
    assert client.post("/api/sources", headers=auth(admin_token), json=body).status_code == 201
    assert client.post("/api/sources", headers=auth(admin_token), json=body).status_code == 409


def test_viewer_can_read_but_not_write_sources(client, admin_token):
    make_user(client, admin_token, "quellenleser", "viewer")
    token = login(client, "quellenleser", "viewer-password-123").json()["access_token"]
    assert client.get("/api/sources", headers=auth(token)).status_code == 200
    assert client.post("/api/sources", headers=auth(token), json=new_source("f")).status_code == 403


def test_audit_log_never_contains_secrets(db):
    rows = db.execute("SELECT details::text AS d FROM m4.audit_log").fetchall()
    for row in rows:
        assert "password-" not in row["d"] and "$argon2" not in row["d"]
