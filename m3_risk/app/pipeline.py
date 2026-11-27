"""Verarbeitungslauf (POST /run): offene Meldungen finden, abgleichen, bewerten, Belege schreiben.

Offen ist eine Meldung, wenn sie in m2.summaries steht und
  - noch keine Zeile in m3.processing hat, oder
  - sich ein Fingerabdruck geaendert hat (Werte statt Zeitstempel, siehe README Abschnitt 9), oder
  - der letzte Versuch fehlgeschlagen ist (hoechstens MAX_ATTEMPTS Versuche).
Jede Meldung laeuft in einer eigenen Transaktion. Ein Fehler stoppt den Lauf nicht.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any

from psycopg.types.json import Jsonb

from . import config
from .matching import Candidate, match_cves
from .risk import Policy, RiskInput, score

log = logging.getLogger("m3.pipeline")

CVE_CATEGORIES = {"VULNERABILITY", "ATTACK"}
NVD_URL = "https://nvd.nist.gov/vuln/detail/{}"
KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
EPSS_URL = "https://www.first.org/epss/"


# ---------------------------------------------------------------- Hilfen

def _jsonable(value: Any) -> Any:
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def fingerprint(payload: Any) -> str:
    text = json.dumps(_jsonable(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _f(value: Any) -> float | None:
    return None if value is None else float(value)


# ---------------------------------------------------------------- Eingaben laden

def inventory_state(conn) -> dict[str, Any]:
    """Stand fuer den Abgleich. Kritikalitaet und Internet-Exposition gehoeren in den Risiko-Fingerabdruck,
    nicht hier: sonst wuerde eine reine Bewertungsaenderung den Abgleich wiederholen.
    active_assets aendert sich bei jeder Aktivierung/Deaktivierung, auch wenn die Anzahl gleich bleibt
    und keine manuelle Komponente betroffen ist (z. B. Asset nur mit SBOM-Komponenten).
    """
    return conn.execute("""
        SELECT (SELECT count(*) FROM m3.assets WHERE is_active)          AS assets,
               (SELECT md5(coalesce(string_agg(asset_key, ',' ORDER BY asset_key), ''))
                  FROM m3.assets WHERE is_active)                         AS active_assets,
               (SELECT count(*) FROM m3.sbom_components WHERE is_active) AS components,
               (SELECT max(updated_at) FROM m3.sbom_components)           AS components_changed,
               (SELECT count(*) FROM m3.suppressions WHERE is_active)    AS suppressions,
               (SELECT max(updated_at) FROM m3.suppressions)              AS suppressions_changed
    """).fetchone()


def load_asset_attributes(conn) -> list[list[Any]]:
    """Kritikalitaet und Internet-Exposition aller aktiven Assets. Vor dem Abgleich ist noch nicht
    bekannt, welches Asset eine Meldung trifft, deshalb gehen alle aktiven Assets in den Risiko-Fingerabdruck.
    """
    return [[r["asset_key"], r["criticality"], r["internet_exposed"]] for r in conn.execute("""
        SELECT asset_key, criticality, internet_exposed FROM m3.assets WHERE is_active ORDER BY asset_key
    """).fetchall()]


def load_items(conn) -> list[dict[str, Any]]:
    return conn.execute("""
        SELECT r.id, r.cve_ids, coalesce(r.title_de, r.title) AS title, r.url,
               s.category, t.trust_score, t.trust_label,
               p.status AS p_status, p.attempts AS p_attempts,
               p.match_fingerprint AS p_match_fp, p.risk_fingerprint AS p_risk_fp
          FROM m2.summaries s
          JOIN public.raw_items r ON r.id = s.raw_item_id
          LEFT JOIN m2.trust_scores t ON t.raw_item_id = r.id
          LEFT JOIN m3.processing p ON p.raw_item_id = r.id
         ORDER BY r.id
    """).fetchall()


def load_cve_data(conn, cve_ids: list[str]) -> tuple[dict[str, dict], dict[str, list]]:
    facts = {r["cve_id"]: r for r in conn.execute("""
        SELECT cve_id, cvss_score, cvss_version, kev_listed, kev_due_date, epss_score
          FROM public.cve_facts WHERE cve_id = ANY(%s)
    """, (cve_ids,)).fetchall()}
    # NVD- und OSV-Zeilen stehen im Fingerabdruck, auch solange ein Weg sie noch nicht nutzt.
    # Ein neuer Codepfad aendert den Hash nicht von selbst: dabei MATCH_LOGIC_VERSION anheben.
    affected: dict[str, list] = {}
    for r in conn.execute("""
        SELECT cve_id, data_source, cpe, vendor, product, ecosystem, package_name, version_exact,
               version_start_including, version_start_excluding, version_end_including, version_end_excluding
          FROM public.cve_affected WHERE cve_id = ANY(%s)
    """, (cve_ids,)).fetchall():
        affected.setdefault(r["cve_id"], []).append([r[k] for k in r if k != "cve_id"])
    for rows in affected.values():
        rows.sort(key=lambda row: [("" if v is None else str(v)) for v in row])
    return facts, affected


def load_entities(conn) -> dict[int, list[list]]:
    """Hersteller- und Produktentitaeten aus M2 je Meldung, inklusive version_text (heute meist leer)."""
    out: dict[int, list[list]] = {}
    for r in conn.execute("""
        SELECT raw_item_id, entity_type,
               lower(btrim(coalesce(normalized_name, name))) AS name,
               nullif(lower(btrim(version_text)), '') AS version_text
          FROM m2.entities WHERE entity_type IN ('VENDOR', 'PRODUCT')
         ORDER BY raw_item_id, entity_type, 3, 4
    """).fetchall():
        out.setdefault(r["raw_item_id"], []).append([r["entity_type"], r["name"], r["version_text"]])
    return out


def item_fingerprints(item, facts, affected, entities, inv_state, asset_attributes, policy: Policy) -> tuple[str, str]:
    cves = sorted(item["cve_ids"] or [])
    match_fp = fingerprint({
        "logic": config.MATCH_LOGIC_VERSION, "cves": cves, "category": item["category"],
        "affected": [affected.get(c, []) for c in cves], "entities": entities.get(item["id"], []),
        "inventory": inv_state,
    })
    risk_fp = fingerprint({
        "logic": config.MATCH_LOGIC_VERSION, "policy": policy.version, "category": item["category"],
        "trust": [item["trust_score"], item["trust_label"]],
        "facts": [facts.get(c) for c in cves],
        "assets": asset_attributes,
    })
    return match_fp, risk_fp


def needs_rematch(item, match_fp: str) -> bool:
    """Nur neu abgleichen, wenn sich die Abgleichseingaben geaendert haben oder der letzte Lauf scheiterte.
    Aendert sich nur der Risiko-Fingerabdruck, werden offene Treffer neu bewertet.
    """
    return item["p_status"] in (None, "failed") or item["p_match_fp"] != match_fp


def is_open(item, match_fp: str, risk_fp: str) -> bool:
    if item["p_status"] is None:
        return True
    changed = item["p_match_fp"] != match_fp or item["p_risk_fp"] != risk_fp
    if item["p_status"] == "failed":
        return changed or item["p_attempts"] < config.MAX_ATTEMPTS
    return changed


# ---------------------------------------------------------------- Treffer abgleichen

def _active_suppressions(conn) -> set[tuple[int, str]]:
    return {(r["component_id"], r["match_key"]) for r in conn.execute(
        "SELECT component_id, match_key FROM m3.suppressions WHERE is_active").fetchall()}


def _resolve_reason(conn, row, not_affected: set, suppressed: set) -> str:
    key = (row["component_id"], row["match_key"])
    if key in suppressed:
        return "suppressed"
    state = conn.execute("""
        SELECT c.is_active AS component_active, a.is_active AS asset_active
          FROM m3.sbom_components c JOIN m3.assets a ON a.id = c.asset_id WHERE c.id = %s
    """, (row["component_id"],)).fetchone()
    if not state["asset_active"]:
        return "asset_deactivated"
    if not state["component_active"]:
        return "component_removed"
    if key in not_affected:
        return "version_not_affected"
    return "advisory_changed"


def _of_item(column: str, raw_item_id: int | None) -> tuple[str, tuple]:
    """WHERE-Teil fuer die Treffer einer Meldung bzw. (None) die Inventarfunde ohne Meldung."""
    return (f"{column} IS NULL", ()) if raw_item_id is None else (f"{column} = %s", (raw_item_id,))


def reconcile_matches(conn, raw_item_id: int | None, candidates: dict[tuple[int, str], Candidate],
                      not_affected: set) -> set[int]:
    """Gleicht Treffer ab und gibt die IDs wieder geoeffneter Treffer zurueck."""
    suppressed = _active_suppressions(conn)
    reopened: set[int] = set()
    wanted = {k: c for k, c in candidates.items() if k not in suppressed}
    where, params = _of_item("raw_item_id", raw_item_id)
    existing = {(r["component_id"], r["match_key"]): r for r in conn.execute(
        f"SELECT * FROM m3.matches WHERE {where} FOR UPDATE", params).fetchall()}

    for key, row in existing.items():
        if key not in wanted and row["status"] == "open":
            conn.execute("""UPDATE m3.matches SET status='resolved', resolved_at=now(), resolved_reason=%s
                             WHERE id=%s""", (_resolve_reason(conn, row, not_affected, suppressed), row["id"]))

    for key, c in wanted.items():
        values = (c.cve_id, c.match_method, c.confidence, c.version_status, len(c.dependency_path) == 1,
                  c.dependency_path, Jsonb(c.match_details))
        if key in existing:
            if existing[key]["status"] == "resolved":
                reopened.add(existing[key]["id"])
            conn.execute("""
                UPDATE m3.matches
                   SET cve_id=%s, match_method=%s, confidence=%s, version_status=%s, is_direct=%s,
                       dependency_path=%s, match_details=%s,
                       status='open', resolved_at=NULL, resolved_reason=NULL
                 WHERE id=%s""", values + (existing[key]["id"],))
        else:
            conn.execute("""
                INSERT INTO m3.matches (cve_id, match_method, confidence, version_status, is_direct,
                                        dependency_path, match_details, raw_item_id, component_id, match_key)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                values + (raw_item_id, c.component_id, c.match_key))
    return reopened


# ---------------------------------------------------------------- Bewerten und belegen

def _evidence(conn, assessment_id: int, item, m, fact) -> None:
    rows = []
    if item["id"] is not None:
        rows.append(("report", f"Meldung: {item['title']}", "raw_item", item["id"], item["url"], None))
    rule = (m["match_details"].get("rules") or [{}])[0]
    bounds = ", ".join(f"{k.replace('version_', '')}={v}" for k, v in rule.items() if k.startswith("version_"))
    version = m["match_details"].get("component_version") or "unbekannt"
    if m["version_status"] == "affected":
        text = f"{m['component_name']} {version} liegt im betroffenen Bereich von {m['cve_id']}" + (f" ({bounds})" if bounds else " (alle Versionen)")
    else:
        text = f"{m['component_name']} ist laut NVD betroffen, Version {version} ist nicht sicher vergleichbar"
    rows.append(("affected_version", text, "cve_affected", None, NVD_URL.format(m["cve_id"]), rule))
    rows.append(("asset", f"System {m['asset_key']} ({m['asset_name']}), Kritikalität {m['criticality']}, "
                 f"aus dem Internet erreichbar: {'ja' if m['internet_exposed'] else 'nein'}", "inventory", None, None,
                 {"asset_id": m["asset_id"], "component_id": m["component_id"]}))
    if fact:
        if fact["cvss_score"] is not None:
            rows.append(("cvss", f"CVSS {fact['cvss_score']} (Version {fact['cvss_version']})", "cve_fact", None,
                         NVD_URL.format(m["cve_id"]), {"field": "cvss_score"}))
        if fact["kev_listed"]:
            due = f", Frist {fact['kev_due_date']}" if fact["kev_due_date"] else ""
            rows.append(("kev_listed", f"In CISA KEV gelistet (aktiv ausgenutzt{due})", "cve_fact", None, KEV_URL,
                         {"field": "kev_listed"}))
        if fact["epss_score"] is not None:
            rows.append(("epss", f"EPSS {float(fact['epss_score']):.3f} (Wahrscheinlichkeit einer Ausnutzung in 30 Tagen)",
                         "cve_fact", None, EPSS_URL, {"field": "epss_score"}))
    if item["trust_label"]:
        rows.append(("trust", f"Glaubwürdigkeit der Meldung laut M2: {item['trust_label']} ({float(item['trust_score']):.2f})",
                     "m2_analysis", item["id"], None, {"table": "m2.trust_scores"}))
    for claim_key, claim_text, kind, raw_id, url, ref in rows:
        conn.execute("""INSERT INTO m3.evidence (risk_assessment_id, claim_key, claim_text, source_kind,
                                                  raw_item_id, source_url, ref_detail)
                        VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                     (assessment_id, claim_key, claim_text, kind, raw_id, url, Jsonb(ref) if ref else None))


def assess_matches(conn, item, facts: dict, policy: Policy, now: datetime, force: set[int] = frozenset()) -> int:
    """Bewertet alle offenen Treffer der Meldung. Neue Zeile nur, wenn sich Eingaben geaendert haben
    oder der Treffer wieder geoeffnet wurde (neue ID -> M4 benachrichtigt erneut)."""
    created = 0
    where, params = _of_item("m.raw_item_id", item["id"])
    matches = conn.execute(f"""
        SELECT m.*, c.name AS component_name, a.id AS asset_id, a.asset_key, a.name AS asset_name,
               a.criticality, a.internet_exposed,
               ra.id AS current_id, ra.risk_fingerprint AS current_fp
          FROM m3.matches m
          JOIN m3.sbom_components c ON c.id = m.component_id
          JOIN m3.assets a ON a.id = c.asset_id
          LEFT JOIN m3.risk_assessments ra ON ra.match_id = m.id AND ra.is_current
         WHERE {where} AND m.status = 'open'
    """, params).fetchall()
    for m in matches:
        fact = facts.get(m["cve_id"])
        inp = RiskInput(
            cvss_score=_f(fact["cvss_score"]) if fact else None,
            kev_listed=fact["kev_listed"] if fact else None,
            kev_due_date=fact["kev_due_date"] if fact else None,
            epss_score=_f(fact["epss_score"]) if fact else None,
            asset_criticality=m["criticality"],
            internet_exposed=m["internet_exposed"],
            trust_score=_f(item["trust_score"]),
            match_confidence=float(m["confidence"]),
            version_status=m["version_status"],
        )
        fp = fingerprint({"logic": config.MATCH_LOGIC_VERSION, "policy": policy.version, "input": inp.__dict__,
                          "method": m["match_method"], "category": item["category"],
                          "trust_label": item["trust_label"]})
        if fp == m["current_fp"] and m["id"] not in force:
            continue
        r = score(inp, policy, now)
        if m["current_id"]:
            conn.execute("UPDATE m3.risk_assessments SET is_current=false WHERE id=%s", (m["current_id"],))
        new_id = conn.execute("""
            INSERT INTO m3.risk_assessments
              (match_id, scoring_branch, score, risk_level, action_code, deadline_at, policy_version,
               cvss_score, cvss_version, kev_listed, kev_due_date, epss_score, asset_criticality,
               internet_exposed, match_confidence, trust_score, trust_label, category, factor_breakdown,
               risk_fingerprint, assessed_at)
            VALUES (%s,'cve',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
            (m["id"], r.score, r.risk_level, r.action_code, r.deadline_at, policy.version,
             inp.cvss_score, fact["cvss_version"] if fact else None, inp.kev_listed, inp.kev_due_date,
             inp.epss_score, inp.asset_criticality, inp.internet_exposed, inp.match_confidence,
             inp.trust_score, item["trust_label"], item["category"], Jsonb(_jsonable(r.factor_breakdown)),
             fp, now)).fetchone()["id"]
        _evidence(conn, new_id, item, m, fact)
        created += 1
    return created


# ---------------------------------------------------------------- Lauf

def process_item(conn, item, facts, policy: Policy, match_fp: str, risk_fp: str, now: datetime,
                 rematch: bool) -> str:
    cves = list(item["cve_ids"] or [])
    status_if_empty = "no_match" if cves or item["category"] in CVE_CATEGORIES else "skipped"
    reopened: set[int] = set()
    if rematch:
        result = match_cves(conn, cves)                 # Wege ohne CVE (Name, Hersteller) folgen in PR 3
        reopened = reconcile_matches(conn, item["id"], result.candidates, result.not_affected)
    assess_matches(conn, item, facts, policy, now, force=reopened)
    has_open = conn.execute("SELECT 1 FROM m3.matches WHERE raw_item_id=%s AND status='open' LIMIT 1",
                            (item["id"],)).fetchone() is not None
    status = "done" if has_open else status_if_empty
    conn.execute("""
        INSERT INTO m3.processing (raw_item_id, status, category, match_fingerprint, risk_fingerprint,
                                   attempts, last_error, processed_at)
        VALUES (%s,%s,%s,%s,%s,0,NULL,now())
        ON CONFLICT (raw_item_id) DO UPDATE SET status=EXCLUDED.status, category=EXCLUDED.category,
            match_fingerprint=EXCLUDED.match_fingerprint, risk_fingerprint=EXCLUDED.risk_fingerprint,
            attempts=0, last_error=NULL, processed_at=now()""",
        (item["id"], status, item["category"], match_fp, risk_fp))
    return status


INVENTORY_ITEM = {"id": None, "title": None, "url": None, "category": "VULNERABILITY",
                  "trust_score": None, "trust_label": None}


def scan_inventory(conn, policy: Policy, now: datetime) -> int:
    """Bekannte Schwachstellen der Inventar-Software, auch ohne Meldung. Nur sicher betroffene
    Versionen: bei unklarer Version waere sonst jede CVE eines Produkts ein Fund.
    Rueckgabe: Anzahl offener Inventarfunde."""
    cves = [r["cve_id"] for r in conn.execute("""
        SELECT DISTINCT ca.cve_id
          FROM public.cve_affected ca
          JOIN m3.sbom_components c ON c.vendor_norm = ca.vendor AND c.product_norm = ca.product AND c.is_active
          JOIN m3.assets a ON a.id = c.asset_id AND a.is_active
         WHERE ca.data_source = 'nvd'
    """).fetchall()]
    result = match_cves(conn, cves)
    affected = {k: c for k, c in result.candidates.items() if c.version_status == "affected"}
    reopened = reconcile_matches(conn, None, affected, result.not_affected)
    facts, _ = load_cve_data(conn, sorted({c.cve_id for c in affected.values()}))
    assess_matches(conn, INVENTORY_ITEM, facts, policy, now, force=reopened)
    return conn.execute(
        "SELECT count(*) AS n FROM m3.matches WHERE raw_item_id IS NULL AND status = 'open'").fetchone()["n"]


def run(conn, policy: Policy) -> dict[str, int]:
    """conn muss autocommit=True sein; jede Meldung bekommt ihre eigene Transaktion."""
    stats = {"processed": 0, "matched": 0, "no_match": 0, "skipped": 0, "failed": 0}
    inv_state = inventory_state(conn)
    items = load_items(conn)
    all_cves = sorted({c for it in items for c in (it["cve_ids"] or [])})
    facts, affected = load_cve_data(conn, all_cves)
    entities = load_entities(conn)
    asset_attributes = load_asset_attributes(conn)
    now = datetime.now(timezone.utc)

    todo = []
    for it in items:
        mfp, rfp = item_fingerprints(it, facts, affected, entities, inv_state, asset_attributes, policy)
        if is_open(it, mfp, rfp):
            todo.append((it, mfp, rfp, needs_rematch(it, mfp)))
    for it, mfp, rfp, rematch in todo[:config.RUN_LIMIT]:
        stats["processed"] += 1
        try:
            with conn.transaction():
                status = process_item(conn, it, facts, policy, mfp, rfp, now, rematch)
            stats["matched" if status == "done" else status] += 1
        except Exception as exc:  # eine fehlerhafte Meldung darf den Lauf nicht stoppen
            log.exception("M3: Meldung %s fehlgeschlagen", it["id"])
            stats["failed"] += 1
            with conn.transaction():
                conn.execute("""
                    INSERT INTO m3.processing (raw_item_id, status, category, match_fingerprint, risk_fingerprint,
                                               attempts, last_error, processed_at)
                    VALUES (%s,'failed',%s,%s,%s,1,%s,now())
                    ON CONFLICT (raw_item_id) DO UPDATE SET status='failed', category=EXCLUDED.category,
                        match_fingerprint=EXCLUDED.match_fingerprint, risk_fingerprint=EXCLUDED.risk_fingerprint,
                        attempts=CASE WHEN m3.processing.status = 'failed'
                                      THEN m3.processing.attempts + 1 ELSE 1 END,
                        last_error=EXCLUDED.last_error, processed_at=now()""",
                    (it["id"], it["category"], mfp, rfp, f"{type(exc).__name__}: {exc}"[:500]))
    with conn.transaction():
        stats["inventory"] = scan_inventory(conn, policy, now)
    return stats
