"""Einmaliger Vollimport aller NVD-CVEs (rund 430 000) nach cve_facts und cve_affected.

    docker compose exec m1 python -m app.nvd_mirror

Danach haelt der normale NVD-Abruf den Bestand aktuell. Der Lauf steht in fetch_runs (Quelle mit
Connector 'nvd'), jede Seite wird sofort gespeichert. Nach einem Abbruch setzt derselbe Befehl an der
letzten gespeicherten Seite fort. Mit NVD_API_KEY deutlich schneller.
"""
from __future__ import annotations

import argparse
import logging
import sys
import time
from datetime import datetime, timezone

from psycopg.types.json import Jsonb

from . import facts
from .connectors import nvd
from .db import close_pool, get_pool
from .httpclient import FetchError, Http

log = logging.getLogger("m1.mirror")
PAGE_SIZE = 2000          # Maximum der NVD-API
PAGE_RETRIES = 5          # zusaetzlich zu den Wiederholungen je Request
RETRY_WAIT = 30
MIRROR_LOCK_ID = 41001002   # nur ein Vollimport gleichzeitig (Start von M1 und Handaufruf)


def resume_point(last_state: dict | None) -> tuple[int, str | None]:
    """(startIndex, Startzeitpunkt) aus dem letzten Vollimport; (0, None) = neu beginnen."""
    if last_state and "mirror_index" in last_state:
        return int(last_state["mirror_index"]), last_state.get("mirror_started")
    return 0, None


def _get_page(get, index: int) -> dict:
    for attempt in range(1, PAGE_RETRIES + 1):
        try:
            return get(f"resultsPerPage={PAGE_SIZE}&startIndex={index}")
        except (FetchError, ValueError) as exc:      # ValueError: abgeschnittene JSON-Antwort
            if attempt == PAGE_RETRIES:
                raise
            log.warning("Seite ab %s fehlgeschlagen (%s), neuer Versuch in %s s", index, exc, RETRY_WAIT)
            time.sleep(RETRY_WAIT)


def _wait_for_facts_lock(conn) -> None:
    while not facts.try_lock(conn):
        time.sleep(5)


def mirror(conn, source: dict, get, max_pages: int | None = None) -> bool:
    """True, wenn der Bestand vollstaendig ist."""
    row = conn.execute(
        "SELECT fetch_state FROM fetch_runs WHERE source_id = %s "
        "AND (fetch_state->>'mirror_index' IS NOT NULL OR fetch_state->>'mirror' IS NOT NULL) "
        "ORDER BY started_at DESC LIMIT 1", (source["id"],)).fetchone()
    index, started = resume_point(row["fetch_state"] if row else None)
    started = started or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    state = {"mirror_index": index, "mirror_started": started}
    run_id = conn.execute(
        "INSERT INTO fetch_runs (source_id, scope, fetch_state) VALUES (%s, 'manual', %s) RETURNING id",
        (source["id"], Jsonb(state))).fetchone()["id"]
    conn.commit()
    if index:
        log.info("Setze Vollimport bei %s fort", index)

    pages = stored = 0
    began = time.monotonic()
    try:
        total = None
        while total is None or index < total:
            if max_pages is not None and pages >= max_pages:
                raise KeyboardInterrupt(f"nach {pages} Seiten angehalten")
            data = _get_page(get, index)
            total = int(data["totalResults"])
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break
            _wait_for_facts_lock(conn)                  # nur beim Speichern, andere Faktenquellen laufen dazwischen
            try:
                stored += nvd._store(conn, vulns)       # speichert die Seite (commit)
            finally:
                facts.unlock(conn)
            index += len(vulns)
            pages += 1
            conn.execute(
                "UPDATE fetch_runs SET items_seen = %s, items_new = %s, fetch_state = %s WHERE id = %s",
                (stored, stored, Jsonb({"mirror_index": index, "mirror_started": started}), run_id))
            conn.commit()
            log.info("%s / %s CVEs (%.0f %%), %.0f s", index, total, 100 * index / max(total, 1),
                     time.monotonic() - began)
    except BaseException as exc:                        # auch Strg+C: Fortschritt bleibt erhalten
        conn.rollback()
        conn.execute(
            "UPDATE fetch_runs SET status = 'failed', finished_at = now(), error_message = %s WHERE id = %s",
            (f"Vollimport unterbrochen: {type(exc).__name__}: {exc}"[:1000], run_id))
        conn.commit()
        log.warning("Unterbrochen bei %s: %s. Derselbe Befehl setzt dort fort.", index, exc)
        return False

    # Ab dem Startzeitpunkt uebernimmt der inkrementelle Abruf
    conn.execute(
        "UPDATE fetch_runs SET status = 'success', finished_at = now(), fetch_state = %s WHERE id = %s",
        (Jsonb({"last_modified": started, "mirror": True}), run_id))
    conn.commit()
    log.info("Vollimport fertig: %s CVEs in diesem Lauf", stored)
    return True


def run_once(max_pages: int | None = None) -> int:
    """Ein Importversuch. 0 = vollstaendig, 1 = unterbrochen, 2 = keine NVD-Quelle, 3 = Import laeuft schon."""
    http = Http()
    http.client.timeout = 180                           # volle Seiten sind gross
    try:
        with get_pool().connection() as conn:
            source = conn.execute(
                "SELECT * FROM sources WHERE connector = 'nvd' AND status = 'active' ORDER BY id LIMIT 1"
            ).fetchone()
            conn.commit()
            if source is None:
                log.error("Keine aktive Quelle mit Connector 'nvd' vorhanden")
                return 2
            if not conn.execute("SELECT pg_try_advisory_lock(%s) AS ok", (MIRROR_LOCK_ID,)).fetchone()["ok"]:
                log.warning("Ein Vollimport laeuft bereits")
                return 3
            conn.commit()
            try:
                return 0 if mirror(conn, source, nvd._client(source, http), max_pages) else 1
            finally:
                conn.rollback()
                conn.execute("SELECT pg_advisory_unlock(%s)", (MIRROR_LOCK_ID,))
                conn.commit()
    finally:
        http.close()


def is_complete() -> bool:
    with get_pool().connection() as conn:
        return conn.execute(
            "SELECT 1 FROM fetch_runs WHERE status = 'success' AND fetch_state->>'mirror' IS NOT NULL LIMIT 1"
        ).fetchone() is not None


def run_until_complete(retry_seconds: int = 300) -> None:
    """Fuer den Start von M1: laeuft nur, solange noch kein Vollimport abgeschlossen ist,
    und setzt nach Fehlern oder Neustarts an der letzten Seite fort."""
    while True:
        try:
            if is_complete() or run_once() == 0:
                return
        except Exception:
            log.exception("NVD-Vollimport fehlgeschlagen")
        log.warning("NVD-Vollimport wird in %s s erneut versucht", retry_seconds)
        time.sleep(retry_seconds)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Vollimport aller NVD-CVEs")
    parser.add_argument("--max-pages", type=int, help="nach so vielen Seiten anhalten (zum Testen)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    try:
        return run_once(args.max_pages)
    finally:
        close_pool()


if __name__ == "__main__":
    sys.exit(main())
