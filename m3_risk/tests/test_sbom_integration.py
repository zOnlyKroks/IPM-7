"""SBOM-Import und Abgleich ueber purl/OSV gegen eine echte Datenbank (synthetische Daten).

NUR gegen eine Wegwerf-Datenbank laufen lassen: der Test leert alle Tabellen im Schema m3.
Start wie test_integration.py:  M3_TEST_DATABASE_URL=... python -m pytest tests
"""
from __future__ import annotations

import os
import uuid
from pathlib import Path

import psycopg
import pytest
from psycopg.rows import dict_row

DB_URL = os.getenv("M3_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL, reason="M3_TEST_DATABASE_URL nicht gesetzt")

KEY = "test-key"
H = {"X-API-Key": KEY}
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "sbom_small.cdx.json"
CVE_NPM = "CVE-2099-1001"     # axios < 1.6.5 (OSV npm), von einer Meldung genannt
CVE_PYPI = "CVE-2099-1002"    # Django >= 4.0 < 4.2.7 (OSV PyPI), von keiner Meldung genannt
CVE_DEB = "CVE-2099-1003"     # openssl (OSV Debian): Betriebssystempaket, wird nicht abgeglichen
CSV = ("asset_key,name,asset_type,criticality,internet_exposed,product\n"
       "host-01,Container-Host,container_host,4,true,Docker Engine\n")
TRUNCATE = """TRUNCATE m3.evidence, m3.recommendations, m3.risk_assessments, m3.suppressions,
              m3.matches, m3.processing, m3.sbom_components, m3.assets RESTART IDENTITY CASCADE"""


@pytest.fixture(scope="module")
def db():
    conn = psycopg.connect(DB_URL, row_factory=dict_row, autocommit=True)
    conn.execute(TRUNCATE)
    suffix = uuid.uuid4().hex[:8]
    src = conn.execute("""INSERT INTO public.sources (name, url, connector, source_type)
                          VALUES (%s, 'https://example.invalid', 'rss', 'authority') RETURNING id""",
                       (f"m3-sbom-test-{suffix}",)).fetchone()["id"]
    raw = conn.execute("""
        INSERT INTO public.raw_items (source_id, external_id, url, title, body, title_de, body_de,
                                      translation_status, cve_ids, content_hash)
        VALUES (%s,%s,'https://example.invalid/axios','Luecke in axios','', 'Luecke in axios','',
                'not_needed',%s,%s) RETURNING id""",
        (src, f"axios-{suffix}", [CVE_NPM], uuid.uuid4().hex * 2)).fetchone()["id"]
    conn.execute("INSERT INTO m2.summaries (raw_item_id, summary_text, category, model_name) "
                 "VALUES (%s, 'axios', 'VULNERABILITY', 'test')", (raw,))
    conn.execute("""INSERT INTO public.cve_facts (cve_id, cvss_score, cvss_version, kev_listed, epss_score)
                    VALUES (%s, 7.5, '3.1', false, 0.3), (%s, 9.1, '3.1', false, 0.1), (%s, 7.0, '3.1', false, 0.1)""",
                 (CVE_NPM, CVE_PYPI, CVE_DEB))
    conn.execute("""INSERT INTO public.cve_affected (cve_id, data_source, ecosystem, package_name,
                        version_start_including, version_end_excluding)
                    VALUES (%s,'osv','npm','axios',NULL,'1.6.5'),
                           (%s,'osv','PyPI','Django','4.0','4.2.7'),
                           (%s,'osv','Debian:12','openssl',NULL,'3.0.13-1')""",
                 (CVE_NPM, CVE_PYPI, CVE_DEB))
    yield conn, raw
    conn.execute(TRUNCATE)
    conn.execute("DELETE FROM m2.summaries WHERE raw_item_id = %s", (raw,))
    conn.execute("DELETE FROM public.cve_facts WHERE cve_id = ANY(%s)", ([CVE_NPM, CVE_PYPI, CVE_DEB],))
    conn.execute("DELETE FROM public.raw_items WHERE source_id = %s", (src,))
    conn.execute("DELETE FROM public.sources WHERE id = %s", (src,))
    conn.close()


@pytest.fixture(scope="module")
def client(db):
    from app import config
    config.DATABASE_URL = DB_URL
    config.INTERNAL_API_KEY = KEY
    from fastapi.testclient import TestClient
    from app.main import app
    c = TestClient(app)
    assert c.post("/import/assets", headers=H,
                  files={"file": ("inventar.csv", CSV.encode(), "text/csv")}).status_code == 200
    return c


def sbom_upload(client, data: bytes, asset_key="host-01", name="sbom.json"):
    return client.post(f"/import/sbom?asset_key={asset_key}", headers=H,
                       files={"file": (name, data, "application/json")})


def by_cve(conn, cve, view="findings_current"):
    return conn.execute(f"SELECT * FROM m3.{view} WHERE cve_id = %s ORDER BY match_id", (cve,)).fetchall()


def test_sbom_errors(client):
    assert sbom_upload(client, FIXTURE.read_bytes(), asset_key="gibt-es-nicht").status_code == 404
    assert sbom_upload(client, b'{"bomFormat": "SPDX"}').status_code == 422
    assert sbom_upload(client, b"x", name="sbom.txt").status_code in (415, 422)


def test_sbom_import(client, db):
    conn, _ = db
    r = sbom_upload(client, FIXTURE.read_bytes())
    assert r.status_code == 200, r.text
    s = r.json()
    assert s["image_ref"] == "example/webapp:1.0" and s["unchanged"] is False
    assert s["packages"] == 6 and s["packages_matchable"] == 4 and s["files_skipped"] == 1
    img = conn.execute("SELECT * FROM m3.sbom_components WHERE component_type = 'container_image'").fetchone()
    kids = conn.execute("SELECT count(*) AS n FROM m3.sbom_components WHERE parent_component_id = %s",
                        (img["id"],)).fetchone()["n"]
    assert kids == 6
    assert sbom_upload(client, FIXTURE.read_bytes()).json()["unchanged"] is True   # gleiche Datei


def test_osv_match_from_report_and_inventory(client, db):
    conn, raw = db
    r = client.post("/run", headers=H)
    assert r.status_code == 200, r.text
    npm = by_cve(conn, CVE_NPM)
    assert len(npm) == 1 and npm[0]["raw_item_id"] == raw                     # Meldung; Inventarfund ausgeblendet
    f = npm[0]
    assert (f["match_method"], f["version_status"], f["is_direct"]) == ("purl_version", "affected", False)
    assert f["dependency_path_names"] == ["example/webapp:1.0", "axios"]
    ev = next(e for e in f["evidence"] if e["claim_key"] == "affected_version")
    assert "laut OSV" in ev["claim_text"] and "example/webapp:1.0" in ev["claim_text"]
    assert ev["source_url"] == f"https://osv.dev/vulnerability/{CVE_NPM}"

    django = by_cve(conn, CVE_PYPI)                                          # PyPI-Name normalisiert
    assert len(django) == 1 and django[0]["raw_item_id"] is None
    assert by_cve(conn, CVE_DEB, "findings_history") == []                   # deb wird nicht abgeglichen


def test_new_sbom_version_closes_old_package(client, db):
    conn, _ = db
    newer = FIXTURE.read_text(encoding="utf-8").replace("axios@1.6.0", "axios@1.6.8").replace('"1.6.0"', '"1.6.8"')
    s = sbom_upload(client, newer.encode()).json()
    assert s["components_deactivated"] == 1 and s["components_created"] == 1
    client.post("/run", headers=H)
    assert by_cve(conn, CVE_NPM) == []
    reasons = {x["resolved_reason"] for x in by_cve(conn, CVE_NPM, "findings_history")}
    assert reasons == {"component_removed"}
