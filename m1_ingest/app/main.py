import asyncio
import logging
import secrets
import threading
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException

from . import ingest, nvd_mirror, translate
from .config import settings
from .db import close_pool, get_pool

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Zeitplaene liegen in n8n (n8n/workflows), M1 laeuft nur auf Aufruf.
    # Nach einem Neustart gibt es keine laufenden Abrufe mehr.
    try:
        n = await asyncio.to_thread(ingest.recover_stale_runs)
        if n:
            logging.getLogger("m1").warning("%d haengende Abrufe als fehlgeschlagen markiert", n)
    except Exception:
        logging.getLogger("m1").exception("Aufraeumen haengender Abrufe fehlgeschlagen")
    # Einmalige Erstbefuellung (kein Zeitplan): kompletter NVD-Bestand, im Hintergrund
    if settings().nvd_mirror_on_start:
        threading.Thread(target=nvd_mirror.run_until_complete, name="nvd-mirror", daemon=True).start()
    yield
    close_pool()


app = FastAPI(title="M1 Datenerfassung und Plattform", lifespan=lifespan)


def require_key(x_api_key: str = Header(default="")) -> None:
    """Schuetzt die Steuer-Endpunkte, sobald INTERNAL_API_KEY gesetzt ist."""
    key = settings().internal_api_key
    if key and not secrets.compare_digest(x_api_key, key):
        raise HTTPException(401, "X-API-Key fehlt oder ist falsch")


def _query(sql: str, params: tuple = ()) -> list[dict]:
    with get_pool().connection() as conn:
        return conn.execute(sql, params).fetchall()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "module": "m1_ingest"}


@app.get("/health/db", dependencies=[Depends(require_key)])
def health_db() -> dict:
    _query("SELECT 1")
    return {"status": "ok", "db": True}


# ------------------------------------------------------------------ Steuerung

# Die Abrufe laufen synchron und liefern pro Quelle das Ergebnis (n8n zeigt es in der Ausfuehrung).
# Dauert ein Abruf lange (z. B. NVD), wartet der Aufrufer; ein zweiter Aufruf ueberspringt
# Quellen, die noch laufen, statt doppelt abzurufen.

@app.post("/fetch/due", dependencies=[Depends(require_key)])
def fetch_due() -> dict:
    """Alle faelligen Quellen abrufen."""
    return ingest.summarize(ingest.run_due())


@app.post("/fetch/priority", dependencies=[Depends(require_key)])
def fetch_priority() -> dict:
    """Eilmeldungs-Lauf: alle aktiven Prioritaetsquellen sofort abrufen."""
    return ingest.summarize(ingest.run_priority())


@app.post("/fetch/{source_id}", dependencies=[Depends(require_key)])
def fetch_source(source_id: int) -> dict:
    run = ingest.run_one(source_id)
    if run is None:
        raise HTTPException(404, "Quelle nicht gefunden oder nicht aktiv")
    return ingest.summarize([run])


@app.post("/translate", dependencies=[Depends(require_key)])
def run_translation(limit: int | None = None) -> dict:
    return translate.translate_pending(limit)


# ------------------------------------------------------------------ Lesen

@app.get("/runs", dependencies=[Depends(require_key)])
def runs(source_id: int | None = None, limit: int = 50) -> list[dict]:
    return _query(
        "SELECT * FROM fetch_runs WHERE (%s::bigint IS NULL OR source_id = %s) "
        "ORDER BY started_at DESC LIMIT %s",
        (source_id, source_id, min(max(limit, 1), 500)))


@app.get("/items/{item_id}", dependencies=[Depends(require_key)])
def item(item_id: int) -> dict:
    rows = _query("SELECT * FROM raw_items WHERE id = %s", (item_id,))
    if not rows:
        raise HTTPException(404, "Meldung nicht gefunden")
    return rows[0]


@app.get("/cves/{cve_id}", dependencies=[Depends(require_key)])
def cve(cve_id: str) -> dict:
    cve_id = cve_id.upper()
    rows = _query("SELECT * FROM cve_facts WHERE cve_id = %s", (cve_id,))
    if not rows:
        raise HTTPException(404, "CVE unbekannt")
    return {**rows[0], "affected": _query(
        "SELECT * FROM cve_affected WHERE cve_id = %s ORDER BY data_source, id", (cve_id,))}
