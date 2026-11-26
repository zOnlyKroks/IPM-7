"""M3 Unternehmensabgleich, Lieferkette und Risiko: HTTP-Schnittstelle.

Aufrufer sind nur n8n (/run) und M4 (Import, Fehlalarme). Alle Endpunkte ausser /health
brauchen den Header X-API-Key. Details: m3_risk/README.md.
"""
from __future__ import annotations

import hmac
import logging
import os
import threading
from contextlib import contextmanager
from typing import Iterator

import psycopg
from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from psycopg.rows import dict_row

from . import config, pipeline
import hashlib

from .inventory import CsvValidationError, apply_inventory, naming_warnings, parse_csv
from .sbom import SbomError, apply_sbom, default_image_ref, parse_cyclonedx
from .risk import load_policy

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("m3")

app = FastAPI(title="M3 Unternehmensabgleich, Lieferkette und Risiko")

POLICY = load_policy(config.RISK_POLICY_PATH)     # ungueltige Regeln -> Start schlaegt sofort fehl
RUN_MUTEX = threading.Lock()

JSON_TYPES = {"application/json", "application/vnd.cyclonedx+json", "text/plain", "application/octet-stream"}
CSV_TYPES = {"text/csv", "application/csv", "application/vnd.ms-excel", "text/plain", "application/octet-stream"}


def authorize(x_api_key: str | None = Header(default=None)) -> None:
    expected = config.INTERNAL_API_KEY
    if not expected or not x_api_key or not hmac.compare_digest(x_api_key.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="X-API-Key fehlt oder ist falsch")


@contextmanager
def exclusive_db() -> Iterator[psycopg.Connection]:
    """Verbindung mit exklusivem Zugriff fuer /run und Importe (Thread-Lock + PostgreSQL-Advisory-Lock)."""
    if not RUN_MUTEX.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="M3 verarbeitet gerade, bitte spaeter erneut versuchen")
    try:
        with psycopg.connect(config.DATABASE_URL, row_factory=dict_row, autocommit=True) as conn:
            if not conn.execute("SELECT pg_try_advisory_lock(%s) AS ok", (config.ADVISORY_LOCK_ID,)).fetchone()["ok"]:
                raise HTTPException(status_code=409, detail="M3 verarbeitet gerade (Datenbank-Sperre), bitte spaeter erneut versuchen")
            try:
                yield conn
            finally:
                conn.execute("SELECT pg_advisory_unlock(%s)", (config.ADVISORY_LOCK_ID,))
    finally:
        RUN_MUTEX.release()


@app.exception_handler(Exception)
async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    # Details nur ins Log, nie Inventardaten in die Antwort
    log.exception("M3: unerwarteter Fehler bei %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Interner Fehler in M3, Details im Log"})


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "module": "m3_risk", "policy_version": POLICY.version}


@app.post("/run", dependencies=[Depends(authorize)])
def run() -> dict:
    with exclusive_db() as conn:
        return pipeline.run(conn, POLICY)


@app.post("/import/assets", dependencies=[Depends(authorize)])
async def import_assets(file: UploadFile = File(...)):
    name = (file.filename or "").lower()
    if not name.endswith(".csv") and (file.content_type or "").split(";")[0] not in CSV_TYPES:
        raise HTTPException(status_code=415, detail="CSV-Datei erwartet")
    data = await file.read(config.MAX_UPLOAD_BYTES + 1)
    if len(data) > config.MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"Datei groesser als {config.MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
    try:
        inventory = parse_csv(data)
    except CsvValidationError as exc:
        return JSONResponse(status_code=422, content={"detail": exc.message, "errors": exc.errors})
    with exclusive_db() as conn:
        with conn.transaction():
            result = apply_inventory(conn, inventory)
            result["warnings"] = naming_warnings(conn, inventory)
            return result


@app.post("/import/sbom", dependencies=[Depends(authorize)])
async def import_sbom(asset_key: str, image_ref: str | None = None, file: UploadFile = File(...)):
    name = (file.filename or "").lower()
    ctype = (file.content_type or "").split(";")[0]
    if not name.endswith(".json") and ctype not in JSON_TYPES:
        raise HTTPException(status_code=415, detail="CycloneDX-JSON erwartet")
    data = await file.read(config.MAX_SBOM_BYTES + 1)
    if len(data) > config.MAX_SBOM_BYTES:
        raise HTTPException(status_code=413, detail=f"Datei groesser als {config.MAX_SBOM_BYTES // (1024 * 1024)} MB")
    try:
        parsed = parse_cyclonedx(data)
    except SbomError as exc:
        return JSONResponse(status_code=422, content={"detail": str(exc)})
    ref = (image_ref or default_image_ref(parsed) or "").strip()
    if not ref:
        return JSONResponse(status_code=422, content={"detail": "image_ref fehlt und steht nicht in der SBOM"})
    with exclusive_db() as conn:
        with conn.transaction():
            asset = conn.execute("SELECT id, is_active FROM m3.assets WHERE asset_key = %s", (asset_key,)).fetchone()
            if asset is None:
                raise HTTPException(status_code=404, detail=f"Asset '{asset_key}' existiert nicht")
            if not asset["is_active"]:
                raise HTTPException(status_code=409, detail=f"Asset '{asset_key}' ist deaktiviert")
            return apply_sbom(conn, asset["id"], ref, parsed, hashlib.sha256(data).hexdigest())


class SuppressionIn(BaseModel):
    component_id: int
    match_key: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=1000)
    created_by: str = Field(min_length=1, max_length=200)


@app.get("/suppressions", dependencies=[Depends(authorize)])
def list_suppressions() -> list[dict]:
    with psycopg.connect(config.DATABASE_URL, row_factory=dict_row) as conn:
        return conn.execute("""SELECT s.id, s.component_id, c.name AS component_name, a.asset_key, s.match_key,
                                      s.reason, s.created_by, s.created_at
                                 FROM m3.suppressions s
                                 JOIN m3.sbom_components c ON c.id = s.component_id
                                 JOIN m3.assets a ON a.id = c.asset_id
                                WHERE s.is_active ORDER BY s.id""").fetchall()


@app.post("/suppressions", dependencies=[Depends(authorize)])
def create_suppression(body: SuppressionIn) -> dict:
    """Markiert (Komponente, match_key) als Fehlalarm und schliesst offene Treffer sofort."""
    with exclusive_db() as conn:
        with conn.transaction():
            if conn.execute("SELECT 1 FROM m3.sbom_components WHERE id = %s", (body.component_id,)).fetchone() is None:
                raise HTTPException(status_code=404, detail=f"Komponente {body.component_id} existiert nicht")
            existing = conn.execute("SELECT id FROM m3.suppressions WHERE component_id = %s AND match_key = %s "
                                    "AND is_active", (body.component_id, body.match_key)).fetchone()
            if existing:
                sid, created = existing["id"], False
            else:
                sid = conn.execute("INSERT INTO m3.suppressions (component_id, match_key, reason, created_by) "
                                   "VALUES (%s,%s,%s,%s) RETURNING id",
                                   (body.component_id, body.match_key, body.reason, body.created_by)).fetchone()["id"]
                created = True
            closed = conn.execute("""UPDATE m3.matches SET status = 'resolved', resolved_at = now(),
                                            resolved_reason = 'suppressed'
                                      WHERE component_id = %s AND match_key = %s AND status = 'open'""",
                                  (body.component_id, body.match_key)).rowcount
            return {"suppression_id": sid, "created": created, "matches_resolved": closed}


@app.delete("/suppressions/{suppression_id}", dependencies=[Depends(authorize)])
def delete_suppression(suppression_id: int) -> dict:
    """Hebt die Markierung auf (nur deaktiviert). Der naechste /run gleicht wieder ab."""
    with exclusive_db() as conn:
        with conn.transaction():
            n = conn.execute("UPDATE m3.suppressions SET is_active = false WHERE id = %s AND is_active",
                             (suppression_id,)).rowcount
            if n == 0:
                raise HTTPException(status_code=404, detail=f"Aktive Markierung {suppression_id} existiert nicht")
            return {"suppression_id": suppression_id, "lifted": True}
