"""Durchlauf gegen eine echte Datenbank mit synthetischen Daten (CVE-2099-*, example.invalid).

NUR gegen eine Wegwerf-Datenbank laufen lassen: der Test leert alle Tabellen im Schema m3.
Start, wenn `docker compose up -d postgres` laeuft (im Ordner m3_risk):

    M3_TEST_DATABASE_URL=postgresql://argos:argos@localhost:5432/argos python -m pytest tests

Ohne M3_TEST_DATABASE_URL wird dieser Test uebersprungen.
"""
from __future__ import annotations

import os
import uuid

import psycopg
import pytest
from psycopg.rows import dict_row

DB_URL = os.getenv("M3_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL, reason="M3_TEST_DATABASE_URL nicht gesetzt")

KEY = "test-key"
H = {"X-API-Key": KEY}
CVE_FW = "CVE-2099-0001"        # FortiOS, Bereich 7.2.0 bis < 7.2.7
CVE_LIB = "CVE-2099-0002"       # Tomcat, Version im Inventar nicht vergleichbar
CVE_INV = "CVE-2099-0003"       # FortiOS, Bereich 7.2.0 bis < 7.2.5, von keiner Meldung genannt

HEADER = "asset_key,name,asset_type,criticality,internet_exposed,vendor,product,version,component_type,vendor_country\n"
CSV_V1 = (HEADER
          + "fw-01,Firewall Zentrale,firewall,5,true,Fortinet,FortiOS,7.2.4,firmware,US\n"
          + "fw-02,Firewall Lager,firewall,2,false,Fortinet,FortiOS,7.4.1,firmware,US\n"
          + "web-01,Webserver,web_application,3,true,Apache Software Foundation,Tomcat,9.x-custom,application,US\n"
          + "ai-01,KI-Server,server,3,false,Alibaba,qwen2.5,7b,ai_model,CN\n")


@pytest.fixture(scope="module")
def db():
    conn = psycopg.connect(DB_URL, row_factory=dict_row, autocommit=True)
    conn.execute("""TRUNCATE m3.evidence, m3.recommendations, m3.risk_assessments, m3.suppressions,
                    m3.matches, m3.processing, m3.sbom_components, m3.assets RESTART IDENTITY CASCADE""")
    suffix = uuid.uuid4().hex[:8]
    src = conn.execute("""INSERT INTO public.sources (name, url, connector, source_type)
                          VALUES (%s, 'https://example.invalid', 'rss', 'authority') RETURNING id""",
                       (f"m3-test-{suffix}",)).fetchone()["id"]
    ids = {}
    for key, title, cves, category in [
        ("fw", "Kritische Luecke in FortiOS", [CVE_FW], "VULNERABILITY"),
        ("lib", "Luecke in Apache Tomcat", [CVE_LIB], "VULNERABILITY"),
        ("reg", "Neue Vorgaben fuer KI-Anbieter", [], "REGULATION"),
    ]:
        ids[key] = conn.execute("""
            INSERT INTO public.raw_items (source_id, external_id, url, title, body, title_de, body_de,
                                          translation_status, cve_ids, content_hash)
            VALUES (%s,%s,%s,%s,'',%s,'','not_needed',%s,%s) RETURNING id""",
            (src, f"{key}-{suffix}", f"https://example.invalid/{key}", title, title, cves,
             uuid.uuid4().hex + uuid.uuid4().hex)).fetchone()["id"]
        conn.execute("""INSERT INTO m2.summaries (raw_item_id, summary_text, category, model_name)
                        VALUES (%s, %s, %s, 'test')""", (ids[key], title, category))
        conn.execute("""INSERT INTO m2.trust_scores (raw_item_id, trust_score, trust_label, source_type_score,
                            corroboration_score, primary_source_score, recency_score, contradiction_score,
                            score_breakdown, reasoning, scoring_version)
                        VALUES (%s, 0.8, 'CONFIRMED', 1, 1, 1, 1, 0, '{}', 'test', 'test')""", (ids[key],))
    conn.execute("""INSERT INTO public.cve_facts (cve_id, cvss_score, cvss_version, kev_listed, epss_score)
                    VALUES (%s, 9.8, '3.1', false, 0.2), (%s, 7.5, '3.1', false, 0.05)""", (CVE_FW, CVE_LIB))
    conn.execute("""INSERT INTO public.cve_affected (cve_id, data_source, cpe, vendor, product,
                        version_start_including, version_end_excluding)
                    VALUES (%s,'nvd','cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*','fortinet','fortios','7.2.0','7.2.7'),
                           (%s,'nvd','cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*','apache','tomcat','9.0.0','9.0.90')""",
                 (CVE_FW, CVE_LIB))
    yield conn, ids
    # Aufraeumen der Testdaten ausserhalb von m3
    conn.execute("""TRUNCATE m3.evidence, m3.recommendations, m3.risk_assessments, m3.suppressions,
                    m3.matches, m3.processing, m3.sbom_components, m3.assets RESTART IDENTITY CASCADE""")
    conn.execute("DELETE FROM m2.entities WHERE raw_item_id = ANY(%s)", (list(ids.values()),))
    conn.execute("DELETE FROM m2.trust_scores WHERE raw_item_id = ANY(%s)", (list(ids.values()),))
    conn.execute("DELETE FROM m2.summaries WHERE raw_item_id = ANY(%s)", (list(ids.values()),))
    conn.execute("DELETE FROM public.cve_facts WHERE cve_id = ANY(%s)", ([CVE_FW, CVE_LIB, CVE_INV],))
    conn.execute("DELETE FROM public.raw_items WHERE source_id = %s", (src,))
    conn.execute("DELETE FROM public.sources WHERE id = %s", (src,))
    conn.close()


@pytest.fixture(scope="module")
def client(db):
    from app import config
    config.DATABASE_URL = DB_URL
    config.INTERNAL_API_KEY = KEY
    config.LLM_ENABLED = False             # kein Ollama im Test; LLM-Teil siehe test_recommend.py
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


def upload(client, text: str):
    return client.post("/import/assets", headers=H, files={"file": ("inventar.csv", text.encode(), "text/csv")})


def findings(conn, view="findings_current"):
    return {r["asset_key"]: r for r in conn.execute(f"SELECT * FROM m3.{view} ORDER BY match_id").fetchall()}


def test_auth_required(client):
    assert client.post("/run").status_code == 401
    assert client.post("/run", headers={"X-API-Key": "falsch"}).status_code == 401
    assert client.get("/health").status_code == 200


def test_csv_errors_return_422_and_store_nothing(client, db):
    conn, _ = db
    r = upload(client, HEADER + "fw-01,Firewall,router,9,true,Fortinet,FortiOS,7.2.4,,\n")
    assert r.status_code == 422
    assert {e["field"] for e in r.json()["errors"]} >= {"asset_type", "criticality"}
    assert conn.execute("SELECT count(*) AS n FROM m3.assets").fetchone()["n"] == 0


def test_import_and_first_run(client, db):
    conn, ids = db
    r = upload(client, CSV_V1)
    assert r.status_code == 200, r.text
    assert r.json()["assets_created"] == 4 and r.json()["components_created"] == 4

    r = client.post("/run", headers=H)
    assert r.status_code == 200, r.text
    assert r.json() == {"processed": 3, "matched": 2, "no_match": 0, "skipped": 1, "failed": 0, "inventory": 1,
                        "llm_passed": 0, "llm_fallback": 0, "llm_unavailable": 0}

    f = findings(conn)
    assert set(f) == {"fw-01", "web-01"}                     # fw-02 hat 7.4.1 -> nicht betroffen
    fw = f["fw-01"]
    assert (fw["match_method"], fw["version_status"], fw["cve_id"]) == ("cpe_version", "affected", CVE_FW)
    assert fw["risk_level"] in ("critical", "high")
    assert fw["dependency_path_names"] == ["FortiOS"]
    assert {e["claim_key"] for e in fw["evidence"]} >= {"report", "affected_version", "asset", "cvss", "trust"}
    web = f["web-01"]
    assert (web["match_method"], web["version_status"]) == ("cpe_product_only", "unknown")

    status = {r["raw_item_id"]: r["status"] for r in conn.execute("SELECT * FROM m3.processing").fetchall()}
    assert status[ids["reg"]] == "skipped"


def test_second_run_is_idempotent(client, db):
    r = client.post("/run", headers=H)
    assert r.json()["processed"] == 0


def test_kev_change_creates_new_assessment(client, db):
    conn, _ = db
    before = findings(conn)["fw-01"]
    conn.execute("UPDATE public.cve_facts SET kev_listed = true, kev_due_date = '2099-01-31' WHERE cve_id = %s", (CVE_FW,))
    r = client.post("/run", headers=H)
    assert r.json()["processed"] == 1
    after = findings(conn)["fw-01"]
    assert after["risk_assessment_id"] != before["risk_assessment_id"]      # neue ID -> M4 benachrichtigt erneut
    assert after["risk_score"] > before["risk_score"]
    assert any(e["claim_key"] == "kev_listed" for e in after["evidence"])
    n = conn.execute("SELECT count(*) AS n FROM m3.risk_assessments WHERE match_id = %s",
                     (after["match_id"],)).fetchone()["n"]
    assert n == 2                                                            # Historie bleibt


def test_upgrade_resolves_match(client, db):
    conn, _ = db
    r = upload(client, CSV_V1.replace("FortiOS,7.2.4", "FortiOS,7.2.7"))
    assert r.json()["components_updated"] == 1
    client.post("/run", headers=H)
    assert "fw-01" not in findings(conn)
    hist = findings(conn, "findings_history")["fw-01"]
    assert (hist["status"], hist["resolved_reason"]) == ("resolved", "version_not_affected")


def test_downgrade_reopens_with_new_assessment(client, db):
    conn, _ = db
    old = findings(conn, "findings_history")["fw-01"]["risk_assessment_id"]
    upload(client, CSV_V1)
    client.post("/run", headers=H)
    fw = findings(conn)["fw-01"]
    assert fw["status"] == "open" and fw["risk_assessment_id"] != old


def test_new_m2_entity_or_osv_row_triggers_rematch_without_new_assessment(client, db):
    conn, ids = db
    before = findings(conn)["fw-01"]["risk_assessment_id"]
    conn.execute("""INSERT INTO m2.entities (raw_item_id, entity_type, name, normalized_name, extraction_method)
                    VALUES (%s, 'PRODUCT', 'FortiOS', 'fortios', 'LLM')""", (ids["fw"],))
    assert client.post("/run", headers=H).json()["processed"] == 1          # Eingabe geaendert -> neu abgleichen
    conn.execute("""INSERT INTO public.cve_affected (cve_id, data_source, ecosystem, package_name, version_end_excluding)
                    VALUES (%s, 'osv', 'npm', 'beispiel-paket', '2.0.0')""", (CVE_FW,))
    assert client.post("/run", headers=H).json()["processed"] == 1
    assert findings(conn)["fw-01"]["risk_assessment_id"] == before          # Ergebnis gleich -> keine neue Bewertung
    assert client.post("/run", headers=H).json()["processed"] == 0


def test_asset_swap_with_same_count_triggers_rematch(client, db):
    """Ein Asset wird deaktiviert, ein anderes aktiviert: Anzahl gleich, Komponenten unveraendert
    (wie bei einem Asset, das nur SBOM-Komponenten hat). Der Treffer muss trotzdem geschlossen werden."""
    conn, _ = db
    conn.execute("""INSERT INTO m3.assets (asset_key, name, asset_type, criticality)
                    VALUES ('tmp-01', 'Platzhalter', 'other', 1)""")
    client.post("/run", headers=H)
    assert "web-01" in findings(conn)
    conn.execute("UPDATE m3.assets SET is_active = false WHERE asset_key = 'web-01'")
    conn.execute("UPDATE m3.assets SET is_active = true WHERE asset_key = 'tmp-01'")
    conn.execute("UPDATE m3.assets SET is_active = false WHERE asset_key = 'tmp-01'")
    conn.execute("INSERT INTO m3.assets (asset_key, name, asset_type, criticality) VALUES ('tmp-02', 'Platzhalter 2', 'other', 1)")
    client.post("/run", headers=H)
    assert findings(conn, "findings_history")["web-01"]["resolved_reason"] == "asset_deactivated"
    # Ausgangszustand wiederherstellen
    conn.execute("UPDATE m3.assets SET is_active = true WHERE asset_key = 'web-01'")
    conn.execute("UPDATE m3.assets SET is_active = false WHERE asset_key = 'tmp-02'")
    client.post("/run", headers=H)
    assert findings(conn)["web-01"]["status"] == "open"


def test_removed_asset_resolves_match(client, db):
    conn, _ = db
    without_web = "\n".join(l for l in CSV_V1.splitlines() if not l.startswith("web-01")) + "\n"
    r = upload(client, without_web)
    assert r.json()["assets_deactivated"] == 1
    client.post("/run", headers=H)
    assert "web-01" not in findings(conn)
    assert findings(conn, "findings_history")["web-01"]["resolved_reason"] == "asset_deactivated"
    overview = {r["asset_key"]: r for r in conn.execute("SELECT * FROM m3.assets_overview").fetchall()}
    assert overview["web-01"]["is_active"] is False
    assert overview["web-01"]["active_component_count"] == 0                 # Software des Assets mit deaktiviert
    assert overview["fw-01"]["open_finding_count"] == 1
    comp = conn.execute("""SELECT c.is_active FROM m3.sbom_components c JOIN m3.assets a ON a.id = c.asset_id
                           WHERE a.asset_key = 'web-01'""").fetchone()
    assert comp["is_active"] is False


def test_criticality_change_rescores_same_match(client, db):
    conn, _ = db
    before = findings(conn)["fw-01"]
    conn.execute("UPDATE m3.assets SET criticality = 1 WHERE asset_key = 'fw-01'")
    assert client.post("/run", headers=H).json()["processed"] == 3
    after = findings(conn)["fw-01"]
    assert after["match_id"] == before["match_id"]
    assert after["risk_assessment_id"] != before["risk_assessment_id"]
    assert after["risk_score"] < before["risk_score"]


# ---------------------------------------------------------------- Inventarfunde ohne Meldung

def _by_cve(conn, cve, view="findings_current"):
    return conn.execute(f"SELECT * FROM m3.{view} WHERE cve_id = %s ORDER BY match_id", (cve,)).fetchall()


def test_inventory_scan_finds_known_cve_without_report(client, db):
    conn, _ = db
    upload(client, CSV_V1)                                   # Ausgangszustand: alle Assets aktiv, FortiOS 7.2.4
    conn.execute("INSERT INTO public.cve_facts (cve_id, cvss_score, cvss_version, kev_listed, epss_score) "
                 "VALUES (%s, 8.8, '3.1', true, 0.5)", (CVE_INV,))
    conn.execute("""INSERT INTO public.cve_affected (cve_id, data_source, cpe, vendor, product,
                        version_start_including, version_end_excluding)
                    VALUES (%s,'nvd','cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*','fortinet','fortios','7.2.0','7.2.5')""",
                 (CVE_INV,))
    r = client.post("/run", headers=H)
    assert r.status_code == 200, r.text
    rows = _by_cve(conn, CVE_INV)
    assert [x["asset_key"] for x in rows] == ["fw-01"]                     # fw-02 hat 7.4.1 -> nicht betroffen
    f = rows[0]
    assert f["raw_item_id"] is None and f["title"].startswith("Bekannte Schwachstelle")
    assert f["url"] == f"https://nvd.nist.gov/vuln/detail/{CVE_INV}"
    assert f["risk_level"] in ("critical", "high")                         # KEV + Internet + sicher betroffen
    assert "trust" in f["factor_breakdown"]["missing"]                     # ohne Meldung kein Trust-Score aus M2
    assert {e["claim_key"] for e in f["evidence"]} >= {"affected_version", "asset", "cvss", "kev_listed"}


def test_inventory_finding_hidden_when_report_names_same_cve(client, db):
    conn, _ = db
    hist = [x for x in _by_cve(conn, CVE_FW, "findings_history") if x["asset_key"] == "fw-01" and x["status"] == "open"]
    assert sorted(x["raw_item_id"] is None for x in hist) == [False, True]  # Meldung + Inventarfund
    cur = [x for x in _by_cve(conn, CVE_FW) if x["asset_key"] == "fw-01"]
    assert len(cur) == 1 and cur[0]["raw_item_id"] is not None            # nur einmal angezeigt


def test_inventory_scan_ignores_unclear_versions(client, db):
    conn, _ = db
    rows = [x for x in _by_cve(conn, CVE_LIB, "findings_history") if x["raw_item_id"] is None]
    assert rows == []                                                       # Tomcat "9.x-custom": kein Inventarfund


def test_inventory_finding_resolved_after_update(client, db):
    conn, _ = db
    upload(client, CSV_V1.replace("FortiOS,7.2.4", "FortiOS,7.2.7"))
    client.post("/run", headers=H)
    assert _by_cve(conn, CVE_INV) == []
    hist = _by_cve(conn, CVE_INV, "findings_history")
    assert [(x["status"], x["resolved_reason"]) for x in hist] == [("resolved", "version_not_affected")]
    upload(client, CSV_V1)                                                  # wieder zurueck fuer folgende Tests
    client.post("/run", headers=H)


def test_parallel_run_returns_409(client):
    from app import main
    assert main.RUN_MUTEX.acquire(blocking=False)
    try:
        assert client.post("/run", headers=H).status_code == 409
    finally:
        main.RUN_MUTEX.release()


def test_naming_warnings_on_import(client, db):
    r = upload(client, CSV_V1)
    assert r.status_code == 200
    warned = {w["asset_key"] for w in r.json()["warnings"]}
    assert warned == {"ai-01"}            # qwen2.5 gibt es in NVD nicht; FortiOS und Tomcat (Alias apache) schon


def test_suppression_closes_and_reopens(client, db):
    conn, _ = db
    client.post("/run", headers=H)
    fw = [x for x in _by_cve(conn, CVE_FW) if x["asset_key"] == "fw-01"][0]
    body = {"component_id": fw["component_id"], "match_key": CVE_FW, "reason": "Funktion nicht aktiv",
            "created_by": "analyst@test"}
    r = client.post("/suppressions", headers=H, json=body)
    assert r.status_code == 200, r.text
    assert r.json()["created"] is True and r.json()["matches_resolved"] == 2   # Meldung + Inventarfund
    assert client.post("/suppressions", headers=H, json=body).json()["created"] is False
    assert [x for x in _by_cve(conn, CVE_FW) if x["asset_key"] == "fw-01"] == []
    client.post("/run", headers=H)                                           # bleibt geschlossen
    hist = [x for x in _by_cve(conn, CVE_FW, "findings_history") if x["asset_key"] == "fw-01"]
    assert {x["resolved_reason"] for x in hist} == {"suppressed"}
    listed = client.get("/suppressions", headers=H).json()
    assert [s["match_key"] for s in listed] == [CVE_FW]

    sid = r.json()["suppression_id"]
    assert client.delete(f"/suppressions/{sid}", headers=H).status_code == 200
    assert client.delete(f"/suppressions/{sid}", headers=H).status_code == 404
    client.post("/run", headers=H)
    reopened = [x for x in _by_cve(conn, CVE_FW) if x["asset_key"] == "fw-01"]
    assert len(reopened) == 1 and reopened[0]["risk_assessment_id"] != fw["risk_assessment_id"]


def test_suppression_unknown_component_404(client):
    body = {"component_id": 999999, "match_key": CVE_FW, "reason": "x", "created_by": "y"}
    assert client.post("/suppressions", headers=H, json=body).status_code == 404
    assert client.post("/suppressions", json=body).status_code == 401
