"""NVD CVE API 2.0 -> cve_facts (NVD-Felder) und cve_affected (data_source 'nvd').
Je Lauf: (1) Aenderungen seit dem letzten Lauf, (2) CVEs aus Meldungen ohne NVD-Daten, (3) KEV-CVEs.
fetch_state: last_modified (Ende des zuletzt abgefragten Fensters).
source.config: initial_days (7), page_size (2000), lookup_batch (20, mit NVD_API_KEY 100)."""
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from .. import facts
from ..config import settings
from ..httpclient import FetchError
from ..models import FetchResult

log = logging.getLogger("m1.nvd")
DEFAULT_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_WINDOW = timedelta(days=120)   # NVD erlaubt hoechstens 120 Tage je Abfrage
_SEVERITIES = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
_CVSS_KEYS = (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
              ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0"))
_CPE_SPLIT = re.compile(r"(?<!\\):")


def _cvss(metrics: dict) -> dict:
    for key, default_version in _CVSS_KEYS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData") or {}
        if data.get("baseScore") is None:
            continue
        severity = (data.get("baseSeverity") or entry.get("baseSeverity") or "").upper()
        return {"cvss_score": data["baseScore"], "cvss_vector": data.get("vectorString"),
                "cvss_version": data.get("version") or default_version,
                "cvss_severity": severity if severity in _SEVERITIES else None}
    return {"cvss_score": None, "cvss_vector": None, "cvss_version": None, "cvss_severity": None}


def _affected(configurations: list[dict]) -> list[dict]:
    rows = []

    def walk(nodes):
        for node in nodes:
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                parts = _CPE_SPLIT.split(m.get("criteria", ""))
                if len(parts) < 6:
                    continue
                version = parts[5]
                rows.append({
                    "cpe": m["criteria"],
                    "vendor": parts[3].lower(),
                    "product": parts[4].lower(),
                    "version_exact": None if version in ("*", "-") else version,
                    "version_start_including": m.get("versionStartIncluding"),
                    "version_start_excluding": m.get("versionStartExcluding"),
                    "version_end_including": m.get("versionEndIncluding"),
                    "version_end_excluding": m.get("versionEndExcluding"),
                })
            walk(node.get("children", []))

    for conf in configurations:
        walk(conf.get("nodes", []))
    return rows


def parse_cve(vuln: dict) -> tuple[dict, list[dict]]:
    """Eine Eintragung der API -> (cve_facts-Felder, cve_affected-Zeilen)."""
    cve = vuln["cve"]
    descriptions = cve.get("descriptions") or []
    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"),
                descriptions[0]["value"] if descriptions else None)
    cwes = sorted({d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
                   if re.fullmatch(r"CWE-\d+", d.get("value", ""))})
    rec = {
        "cve_id": cve["id"].upper(),
        "description": desc,
        "nvd_status": cve.get("vulnStatus"),
        "published_at": facts.parse_ts(cve.get("published")),
        "nvd_modified_at": facts.parse_ts(cve.get("lastModified")),
        "cwe_ids": cwes,
        **_cvss(cve.get("metrics") or {}),
    }
    return rec, _affected(cve.get("configurations") or [])


def _fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def _store(conn, vulns: list[dict]) -> int:
    for v in vulns:
        rec, affected = parse_cve(v)
        facts.upsert_nvd(conn, rec)
        facts.replace_affected(conn, rec["cve_id"], "nvd", affected)
    # Seitenweise speichern: kurze Sperren (RSS legt parallel cve_facts-Zeilen an),
    # und ein spaeterer Fehler verwirft nicht alles
    conn.commit()
    return len(vulns)


def _client(source: dict, http):
    """Liefert get(query) mit API-Schluessel und Pause zwischen den Anfragen (Rate-Limit)."""
    key = settings().nvd_api_key
    headers = {"apiKey": key} if key else {}
    pause = 0.7 if key else 6.5   # NVD: 50 Anfragen/30 s mit, 5/30 s ohne Schluessel
    base = source["url"] or DEFAULT_URL
    sent = False

    def get(query: str) -> dict:
        nonlocal sent
        if sent:
            time.sleep(pause)
        sent = True
        # Query als Text: hasKev ist ein Parameter ohne Wert
        return http.get(f"{base}?{query}", headers=headers).json()
    return get


def _paged(get, query: str, page_size: int):
    index, total = 0, None
    while total is None or index < total:
        data = get(f"{query}&resultsPerPage={page_size}&startIndex={index}")
        total = int(data.get("totalResults", 0))
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break
        yield vulns
        index += len(vulns)


def _missing_article_cves(conn, limit: int) -> list[str]:
    """CVEs aus Meldungen ohne NVD-Daten, neueste Meldung zuerst. Unbekannte erst nach einem Tag erneut."""
    rows = conn.execute(
        """
        SELECT f.cve_id
        FROM cve_facts f
        JOIN (SELECT unnest(cve_ids) AS cve, max(fetched_at) AS seen FROM raw_items GROUP BY 1) r
          ON r.cve = f.cve_id
        WHERE f.nvd_checked_at IS NULL
           OR (f.nvd_status IS NULL AND f.nvd_checked_at < now() - interval '1 day')
        ORDER BY r.seen DESC, f.cve_id LIMIT %s
        """,
        (limit,),
    ).fetchall()
    return [r["cve_id"] for r in rows]


def _lookup(conn, get, cve_ids: list[str]) -> int:
    found = 0
    for cve_id in cve_ids:
        vulns = get(f"cveId={cve_id}").get("vulnerabilities", [])
        if vulns:
            found += _store(conn, vulns)
        else:
            conn.execute("UPDATE cve_facts SET nvd_checked_at = now() WHERE cve_id = %s", (cve_id,))
    return found


def _backfill_kev(conn, get, page_size: int) -> int:
    """Alle KEV-CVEs auf einmal laden, sobald eine davon noch nie bei NVD nachgeschlagen wurde."""
    if not conn.execute("SELECT 1 FROM cve_facts WHERE kev_listed AND nvd_checked_at IS NULL LIMIT 1").fetchone():
        return 0
    n = sum(_store(conn, vulns) for vulns in _paged(get, "hasKev", page_size))
    # Was NVD (noch) nicht als KEV fuehrt, soll nicht bei jedem Lauf alles neu laden
    conn.execute("UPDATE cve_facts SET nvd_checked_at = now() WHERE kev_listed AND nvd_checked_at IS NULL")
    return n


def fetch(source: dict, state: dict | None, http, conn) -> FetchResult:
    cfg = source.get("config") or {}
    end = datetime.now(timezone.utc)
    last = facts.parse_ts((state or {}).get("last_modified"))
    start = last or end - timedelta(days=int(cfg.get("initial_days", 7)))
    start = max(start, end - MAX_WINDOW)
    page_size = int(cfg.get("page_size", 2000))
    batch = int(cfg.get("lookup_batch", 100 if settings().nvd_api_key else 20))
    get = _client(source, http)

    # 1. Aenderungen seit dem letzten Lauf
    window = urlencode({"lastModStartDate": _fmt(start), "lastModEndDate": _fmt(end)})
    changed = sum(_store(conn, vulns) for vulns in _paged(get, window, page_size))

    # 2. Gezielt nachladen, was M3 braucht. Ein HTTP-Fehler hier verwirft die Ergebnisse oben nicht,
    #    der naechste Lauf holt den Rest nach.
    try:
        changed += _lookup(conn, get, _missing_article_cves(conn, batch))
        changed += _backfill_kev(conn, get, page_size)
    except FetchError as exc:
        log.warning("NVD-Nachladen abgebrochen: %s", exc)
    return FetchResult(state={"last_modified": _fmt(end)}, seen=changed, changed=changed)
