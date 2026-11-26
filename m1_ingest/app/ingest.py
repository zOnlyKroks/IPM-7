"""Abruf einer Quelle: fetch_runs protokollieren, Meldungen normalisieren und in raw_items speichern."""
import logging
import threading

from psycopg.types.json import Jsonb

from . import facts, nvd_mirror
from .config import settings
from .connectors import CONNECTORS
from .db import get_pool
from .httpclient import FetchError, Http
from .models import FetchResult, RawItem
from .textutil import content_hash, detect_language, extract_cve_ids

log = logging.getLogger("m1.ingest")

MAX_LISTED = 50   # so viele neue Meldungen je Quelle stehen in der Antwort
_active: set[int] = set()
# Diese Connectors schreiben dieselben Zeilen in cve_facts: nie gleichzeitig (sonst Deadlocks)
FACT_CONNECTORS = {"cisa_kev", "nvd", "epss", "osv"}
_facts_lock = threading.Lock()
_active_lock = threading.Lock()

INSERT_ITEM = """
INSERT INTO raw_items (source_id, fetch_run_id, external_id, url, title, body, lang,
                       title_de, body_de, translation_status, cve_ids, published_at,
                       content_hash, raw_payload)
VALUES (%(source_id)s, %(run_id)s, %(external_id)s, %(url)s, %(title)s, %(body)s, %(lang)s,
        %(title_de)s, %(body_de)s, %(status)s, %(cve_ids)s, %(published_at)s,
        %(hash)s, %(payload)s)
ON CONFLICT DO NOTHING
RETURNING id
"""


def recover_stale_runs() -> int:
    """Nach einem Neustart gibt es keine laufenden Abrufe mehr."""
    with get_pool().connection() as conn:
        cur = conn.execute(
            "UPDATE fetch_runs SET status = 'failed', finished_at = now(), "
            "error_message = 'Abbruch durch Neustart' WHERE status = 'running'")
        return cur.rowcount


def store_items(conn, source: dict, run_id: int,
                items: list[RawItem]) -> tuple[int, int, int, list[dict]]:
    """Speichert Meldungen. Rueckgabe: (neu, doppelt, fehlerhaft, neue Meldungen).
    Doppelt = (Quelle, external_id) oder (Quelle, Inhalt) gibt es schon."""
    new = dup = failed = 0
    created: list[dict] = []
    for it in items:
        title = (it.title or "").strip()
        if not title or not it.external_id:
            failed += 1
            continue
        body = it.body or ""
        lang = it.lang or detect_language(title, body, source.get("language"))
        german = lang == "de"
        cves = extract_cve_ids(title, body)
        try:
            with conn.transaction():   # Savepoint: ein kaputter Eintrag stoppt nicht den Lauf
                row = conn.execute(INSERT_ITEM, {
                    "source_id": source["id"], "run_id": run_id, "external_id": it.external_id,
                    "url": it.url, "title": title, "body": body, "lang": lang,
                    "title_de": title if german else None, "body_de": body if german else None,
                    "status": "not_needed" if german else "pending", "cve_ids": cves,
                    "published_at": it.published_at, "hash": content_hash(title, body),
                    "payload": Jsonb(it.raw_payload) if it.raw_payload is not None else None,
                }).fetchone()
                if row:
                    facts.ensure_stub(conn, cves)
        except Exception:
            log.exception("Meldung %r aus Quelle %s nicht speicherbar", it.external_id, source["id"])
            failed += 1
            continue
        if row:
            new += 1
            created.append({"id": row["id"], "title": title, "url": it.url, "lang": lang,
                            "translation_status": "not_needed" if german else "pending",
                            "cve_ids": cves})
        else:
            dup += 1
    return new, dup, failed, created


def _entry(source: dict, status: str, **values) -> dict:
    """Ergebnis eines Abrufs. Immer dieselben Felder, sonst zeigt n8n in der Tabelle 'undefined'."""
    return {"source_id": source["id"], "source": source["name"], "status": status, "run_id": None,
            "seen": 0, "new": 0, "duplicate": 0, "failed": 0, "facts_changed": 0, "new_items": [],
            "error": "", "reason": "", **values}


def run_source(source: dict, scope: str = "regular") -> dict:
    """Ein kompletter Abruf. Gibt die Zaehler des Laufs zurueck (oder {'skipped': ...})."""
    sid = source["id"]
    if source["connector"] == "nvd" and settings().nvd_mirror_on_start and not nvd_mirror.is_complete():
        return _entry(source, "skipped", reason="NVD-Vollimport laeuft noch")
    with _active_lock:
        if sid in _active:
            return _entry(source, "skipped", reason="laeuft bereits")
        _active.add(sid)
    facts_source = source["connector"] in FACT_CONNECTORS
    if facts_source and not _facts_lock.acquire(blocking=False):
        # Ohne fetch_runs-Zeile bleibt die Quelle faellig und kommt beim naechsten Aufruf dran
        with _active_lock:
            _active.discard(sid)
        return _entry(source, "skipped", reason="andere Faktenquelle laeuft")
    http = Http()
    try:
        with get_pool().connection() as conn:
            # Zusaetzlich zur Sperre im Prozess: der NVD-Vollimport laeuft als eigener Prozess
            if facts_source and not facts.try_lock(conn):
                return _entry(source, "skipped", reason="andere Faktenquelle laeuft")
            try:
                return _fetch_and_store(conn, source, scope, http)
            finally:
                if facts_source:
                    facts.unlock(conn)
    finally:
        http.close()
        if facts_source:
            _facts_lock.release()
        with _active_lock:
            _active.discard(sid)


def _fetch_and_store(conn, source: dict, scope: str, http: Http) -> dict:
    sid = source["id"]
    run_id = conn.execute(
        "INSERT INTO fetch_runs (source_id, scope) VALUES (%s, %s) RETURNING id",
        (sid, scope)).fetchone()["id"]
    conn.commit()
    prev = conn.execute(
        "SELECT fetch_state FROM fetch_runs WHERE source_id = %s AND status = 'success' "
        "ORDER BY started_at DESC LIMIT 1", (sid,)).fetchone()
    conn.commit()
    state = prev["fetch_state"] if prev else None
    try:
        fetch = CONNECTORS.get(source["connector"])
        if fetch is None:
            raise ValueError(f"unbekannter Connector {source['connector']!r}")
        result: FetchResult = fetch(source, state, http, conn)
        new, dup, failed, created = store_items(conn, source, run_id, result.items)
        seen = result.seen if result.seen is not None else len(result.items)
        conn.execute(
            "UPDATE fetch_runs SET status = 'success', finished_at = now(), attempts = %s, "
            "http_status = %s, items_seen = %s, items_new = %s, items_duplicate = %s, "
            "items_failed = %s, fetch_state = %s WHERE id = %s",
            (http.attempts, http.status, seen, new + result.changed, dup, failed,
             Jsonb(result.state if result.state is not None else (state or {})), run_id))
        conn.commit()
        counts = {"seen": seen, "new": new + result.changed, "duplicate": dup, "failed": failed}
        log.info("Quelle %s (%s): %s", sid, source["name"], counts)
        return _entry(source, "success", run_id=run_id, **counts,
                      facts_changed=result.changed, new_items=created[:MAX_LISTED])
    except Exception as exc:
        conn.rollback()
        status = exc.status if isinstance(exc, FetchError) else http.status
        conn.execute(
            "UPDATE fetch_runs SET status = 'failed', finished_at = now(), attempts = %s, "
            "http_status = %s, error_message = %s WHERE id = %s",
            (http.attempts, status, f"{type(exc).__name__}: {exc}"[:1000], run_id))
        conn.commit()
        log.warning("Quelle %s (%s) fehlgeschlagen: %s", sid, source["name"], exc)
        return _entry(source, "failed", run_id=run_id, error=str(exc))


def _sources(where: str, params: tuple = ()) -> list[dict]:
    with get_pool().connection() as conn:
        return conn.execute(f"SELECT * FROM sources WHERE status = 'active' {where} ORDER BY id",
                            params).fetchall()


def run_due() -> list[dict]:
    """Regulaerer Lauf: aktive Quellen, deren letzter Abruf laenger als ihr Intervall her ist."""
    due = _sources("""AND NOT EXISTS (
        SELECT 1 FROM fetch_runs r WHERE r.source_id = sources.id
          AND r.started_at > now() - make_interval(mins => sources.fetch_interval_minutes))""")
    return [run_source(s, "regular") for s in due]


def run_priority() -> list[dict]:
    """Eilmeldungs-Lauf: alle aktiven Prioritaetsquellen sofort."""
    return [run_source(s, "priority") for s in _sources("AND is_priority")]


def run_one(source_id: int) -> dict | None:
    rows = _sources("AND id = %s", (source_id,))
    return run_source(rows[0], "manual") if rows else None


def summarize(runs: list[dict]) -> dict:
    """Antwort fuer n8n: Kennzahlen plus ein Eintrag je Quelle (auch wenn nichts faellig war)."""
    return {
        "sources": len(runs),
        "success": sum(r.get("status") == "success" for r in runs),
        "failed": sum(r.get("status") == "failed" for r in runs),
        "skipped": sum(r.get("status") == "skipped" for r in runs),
        "new_items": sum(len(r.get("new_items", ())) for r in runs),
        "runs": runs,
    }
