"""M2 v1.3 review regressions. Run: python -m pytest tests/test_v13.py -q"""
from __future__ import annotations

import ast
import importlib.util
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN_PATH = ROOT / "m2_analysis" / "main.py"
SOURCE = MAIN_PATH.read_text(encoding="utf-8")


def load_main():
    """Use lightweight psycopg stubs if the DB client is unavailable in CI."""
    try:
        import psycopg  # noqa: F401
    except ImportError:
        pg = types.ModuleType("psycopg")
        pg.Connection = object
        rows = types.ModuleType("psycopg.rows")
        rows.dict_row = object()
        jsonmod = types.ModuleType("psycopg.types.json")
        jsonmod.Jsonb = lambda obj: obj
        sys.modules["psycopg"] = pg
        sys.modules["psycopg.rows"] = rows
        sys.modules["psycopg.types"] = types.ModuleType("psycopg.types")
        sys.modules["psycopg.types.json"] = jsonmod
    spec = importlib.util.spec_from_file_location("m2_review_v13", MAIN_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ConnStub:
    def __init__(self, rows=None):
        self.calls = []
        self.rows = rows or []

    def execute(self, query, params=()):
        self.calls.append((query, params))
        return self

    def fetchall(self):
        return self.rows


def test_source_is_valid_python():
    ast.parse(SOURCE)


def test_queue_excludes_delayed_and_quarantined_items():
    main = load_main()
    conn = ConnStub()
    main.load_unprocessed(conn, 4)
    sql, params = conn.calls[0]
    assert "m2.processing_failures" in sql
    assert "f.attempts < %s" in sql
    assert "f.next_retry_at <= now()" in sql
    assert params == (main.MAX_RETRIES, 4)


def test_backoff_is_persisted_after_rollback():
    main = load_main()
    conn = ConnStub()
    main.record_processing_failure(conn, 7, ValueError("bad JSON"))
    sql, params = conn.calls[0]
    assert "ON CONFLICT (raw_item_id) DO UPDATE" in sql
    assert "power(2.0" in sql
    assert params[0] == 7
    assert "ValueError" in params[1]


def test_related_events_ranks_similarity_globally():
    segment = SOURCE.split("def link_related_events(", 1)[1].split("def claim_value_text(", 1)[0]
    assert "ROW_NUMBER() OVER" in segment
    assert "PARTITION BY ev.id" in segment
    assert "ORDER BY similarity DESC, id" in segment
    assert "ORDER BY ev.id, similarity DESC LIMIT 20" not in segment


def test_processing_refreshes_old_scores():
    segment = SOURCE.split("def process_item(", 1)[1].split('@app.get("/health")', 1)[0]
    assert "refresh_related_trust(" in segment
    assert "rescored_reports" in segment
    refresh = SOURCE.split("def refresh_related_trust(", 1)[1].split("def process_item(", 1)[0]
    assert "JOIN m2.trust_scores" in refresh
    assert "find_relations_and_score(" in refresh
    assert "save_trust(" in refresh


def test_dependencies_include_http_and_postgresql_drivers():
    req = (ROOT / "m2_analysis" / "requirements.txt").read_text()
    assert "httpx" in req
    assert "psycopg[binary]" in req


def test_sql_migration_is_idempotent():
    migration = (ROOT / "db" / "migrations" / "m2_processing_failures.sql").read_text()
    assert "CREATE TABLE IF NOT EXISTS m2.processing_failures" in migration
    assert "REFERENCES public.raw_items(id)" in migration
    assert "DROP TABLE" not in migration
