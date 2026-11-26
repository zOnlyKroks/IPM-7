"""Schreibzugriffe auf cve_facts und cve_affected."""
from datetime import date, datetime, timezone

import psycopg


FACTS_LOCK_ID = 41001001   # Advisory-Lock: nur ein Prozess schreibt Fakten (Dienst oder Vollimport)


def try_lock(conn: psycopg.Connection) -> bool:
    ok = conn.execute("SELECT pg_try_advisory_lock(%s) AS ok", (FACTS_LOCK_ID,)).fetchone()["ok"]
    conn.commit()
    return ok


def unlock(conn: psycopg.Connection) -> None:
    conn.rollback()
    conn.execute("SELECT pg_advisory_unlock(%s)", (FACTS_LOCK_ID,))
    conn.commit()


def parse_ts(value: str | None) -> datetime | None:
    """ISO-Zeitstempel; ohne Zeitzone gilt UTC (so liefert NVD)."""
    if not value:
        return None
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def ensure_stub(conn: psycopg.Connection, cve_ids: list[str]) -> None:
    """Legt leere Faktenzeilen an, damit Joins und Fremdschluessel greifen."""
    if cve_ids:
        conn.execute(
            "INSERT INTO cve_facts (cve_id) SELECT unnest(%s::text[]) ON CONFLICT DO NOTHING",
            (cve_ids,),
        )


def upsert_kev(conn: psycopg.Connection, rows: list[dict]) -> int:
    """KEV-Eintraege schreiben; CVEs, die nicht mehr im Katalog stehen, werden entlistet."""
    changed = 0
    for r in rows:
        cur = conn.execute(
            """
            INSERT INTO cve_facts (cve_id, kev_listed, kev_date_added, kev_due_date,
                                   kev_required_action, kev_ransomware_use)
            VALUES (%(cve_id)s, true, %(date_added)s, %(due_date)s, %(action)s, %(ransomware)s)
            ON CONFLICT (cve_id) DO UPDATE SET
                kev_listed = true,
                kev_date_added = EXCLUDED.kev_date_added,
                kev_due_date = EXCLUDED.kev_due_date,
                kev_required_action = EXCLUDED.kev_required_action,
                kev_ransomware_use = EXCLUDED.kev_ransomware_use
            WHERE (cve_facts.kev_listed, cve_facts.kev_date_added, cve_facts.kev_due_date,
                   cve_facts.kev_required_action, cve_facts.kev_ransomware_use)
                  IS DISTINCT FROM (true, EXCLUDED.kev_date_added, EXCLUDED.kev_due_date,
                                    EXCLUDED.kev_required_action, EXCLUDED.kev_ransomware_use)
            """,
            r,
        )
        changed += cur.rowcount
    cur = conn.execute(
        """
        UPDATE cve_facts SET kev_listed = false, kev_date_added = NULL, kev_due_date = NULL,
               kev_required_action = NULL, kev_ransomware_use = NULL
        WHERE kev_listed AND cve_id <> ALL(%s::text[])
        """,
        ([r["cve_id"] for r in rows],),
    )
    return changed + cur.rowcount


def upsert_nvd(conn: psycopg.Connection, rec: dict) -> None:
    """NVD-Felder einer CVE schreiben, KEV- und EPSS-Felder bleiben unberuehrt."""
    conn.execute(
        """
        INSERT INTO cve_facts (cve_id, description, nvd_status, published_at, nvd_modified_at,
                               nvd_checked_at, cvss_score, cvss_vector, cvss_version,
                               cvss_severity, cwe_ids)
        VALUES (%(cve_id)s, %(description)s, %(nvd_status)s, %(published_at)s, %(nvd_modified_at)s,
                now(), %(cvss_score)s, %(cvss_vector)s, %(cvss_version)s, %(cvss_severity)s,
                %(cwe_ids)s)
        ON CONFLICT (cve_id) DO UPDATE SET
            description = EXCLUDED.description, nvd_status = EXCLUDED.nvd_status,
            published_at = EXCLUDED.published_at, nvd_modified_at = EXCLUDED.nvd_modified_at,
            nvd_checked_at = now(), cvss_score = EXCLUDED.cvss_score,
            cvss_vector = EXCLUDED.cvss_vector, cvss_version = EXCLUDED.cvss_version,
            cvss_severity = EXCLUDED.cvss_severity, cwe_ids = EXCLUDED.cwe_ids
        """,
        rec,
    )


AFFECTED_COLS = ("cpe", "vendor", "product", "ecosystem", "package_name", "version_exact",
                 "version_start_including", "version_start_excluding",
                 "version_end_including", "version_end_excluding")


def replace_affected(conn: psycopg.Connection, cve_id: str, data_source: str,
                     rows: list[dict]) -> bool:
    """Ersetzt alle Zeilen (cve_id, data_source). True, wenn sich der Inhalt geaendert hat;
    nur dann wird cve_facts.updated_at angehoben (M3 rechnet dann neu)."""
    cols = ", ".join(AFFECTED_COLS)
    old = conn.execute(
        f"SELECT {cols} FROM cve_affected WHERE cve_id = %s AND data_source = %s",
        (cve_id, data_source),
    ).fetchall()
    unique = {tuple(r.get(c) for c in AFFECTED_COLS): r for r in rows}
    if {tuple(o[c] for c in AFFECTED_COLS) for o in old} == set(unique):
        return False
    conn.execute("DELETE FROM cve_affected WHERE cve_id = %s AND data_source = %s",
                 (cve_id, data_source))
    if unique:
        # executemany buendelt die Zeilen (eine CVE hat oft Hunderte Produktzeilen)
        conn.cursor().executemany(
            f"INSERT INTO cve_affected (cve_id, data_source, {cols}) "
            f"VALUES (%s, %s, {', '.join(['%s'] * len(AFFECTED_COLS))})",
            [(cve_id, data_source, *key) for key in unique],
        )
    conn.execute("UPDATE cve_facts SET updated_at = now() WHERE cve_id = %s", (cve_id,))
    return True


def update_epss(conn: psycopg.Connection, rows: list[tuple[str, float, float]],
                score_date: date | None) -> int:
    """EPSS nur fuer bereits bekannte CVEs eintragen. Geschrieben wird nur, was sich merklich aendert
    (Score, oder Perzentil um mindestens 0.01): bei voller NVD-Spiegelung sonst ~400 000 Zeilen je Tag.
    epss_date ist damit der Stichtag des gespeicherten Werts."""
    n = 0
    for i in range(0, len(rows), 5000):
        chunk = rows[i:i + 5000]
        cur = conn.execute(
            """
            UPDATE cve_facts f SET epss_score = v.s, epss_percentile = v.p, epss_date = %s
            FROM unnest(%s::text[], %s::numeric[], %s::numeric[]) AS v(id, s, p)
            WHERE f.cve_id = v.id
              AND (f.epss_score IS DISTINCT FROM v.s OR f.epss_percentile IS NULL
                   OR abs(f.epss_percentile - v.p) >= 0.01)
            """,
            (score_date, [r[0] for r in chunk], [r[1] for r in chunk], [r[2] for r in chunk]),
        )
        n += cur.rowcount
    return n
