# M1 Datenerfassung und Plattform

Quellenabruf, Normalisierung, Spracherkennung, Uebersetzung (LibreTranslate), Faktentabelle.
Schema: `db/init/m1_initial.sql`. M1 schreibt `raw_items`, `fetch_runs`, `cve_facts`, `cve_affected`;
`sources` gehoert M4 (M1 liest nur).

## Ablauf

1. M1 hat keinen eigenen Zeitplan. n8n ruft die Endpunkte auf (Workflows in `n8n/workflows/`):
   jede Minute `POST /fetch/due` (ruft jede aktive Quelle ab, deren letzter Abruf laenger als ihr
   `fetch_interval_minutes` her ist), alle 5 Minuten `POST /fetch/priority`, alle 2 Minuten
   `POST /translate`. Intervalle je Quelle stehen in `sources`, die Taktung der Aufrufe im Workflow.
2. Jeder Abruf schreibt eine Zeile in `fetch_runs` (Status, Zaehler, Fehlertext, `fetch_state`).
   Netzwerkfehler, 429 und 5xx werden bis zu `M1_HTTP_RETRIES`-mal wiederholt. `fetch_state` des
   letzten erfolgreichen Laufs ist der Startpunkt des naechsten (ETag, Last-Modified, Zeitstempel).
3. Meldungen werden bereinigt (HTML, Entities), bekommen Sprache, CVE-IDs und `content_hash` und
   landen in `raw_items`. Doppelte (gleiche Quelle + `external_id` oder gleicher Inhalt) zaehlen als
   `items_duplicate`. Deutsche Meldungen sind sofort `not_needed`, alle anderen `pending`.
4. Der Uebersetzer setzt `title_de`/`body_de` und `translation_status = 'done'`. Nach
   `M1_TRANSLATE_MAX_ATTEMPTS` Versuchen (oder bei nicht unterstuetzter Sprache) wird er `failed`.

## Connectors (`sources.connector`)

| Connector | Quelle | Ergebnis | `sources.config` |
|---|---|---|---|
| `rss` | RSS/Atom-Feed | `raw_items` | `max_items` (200) |
| `cisa_kev` | KEV-JSON-Katalog | `cve_facts.kev_*` | |
| `nvd` | NVD API 2.0: Aenderungen per `lastModified`, dazu gezielt CVEs aus Meldungen und KEV | `cve_facts`, `cve_affected` | `initial_days` (7), `page_size` (2000), `lookup_batch` (20, mit Key 100) |
| `epss` | EPSS-CSV (gzip) | `cve_facts.epss_*`, nur bekannte CVEs | |
| `osv` | OSV je neu aufgetauchter CVE, Pakete aus den Alias-Eintraegen (GHSA u. a.) | `cve_affected` (`osv`) | `batch` (200) |

`sources.url` ist die Abruf-URL (bei `nvd`, `cisa_kev`, `epss`, `osv` die jeweilige API-/Datei-URL;
die Standardwerte stehen in den Connectors und gelten nur bei leerem String).
CVEs aus Meldungen bekommen sofort eine leere Zeile in `cve_facts`, die NVD/KEV/EPSS spaeter fuellen.

## Endpunkte

`GET /health` ist offen. Alle anderen verlangen den Header `X-API-Key: $INTERNAL_API_KEY`, sobald
die Variable gesetzt ist.

| Endpunkt | Zweck |
|---|---|
| `POST /fetch/due` | faellige Quellen abrufen (Hintergrund, 202) |
| `POST /fetch/priority` | Eilmeldungs-Lauf, alle aktiven Quellen mit `is_priority` |
| `POST /fetch/{source_id}` | eine Quelle sofort abrufen (`scope = manual`) |
| `POST /translate?limit=n` | Uebersetzung sofort anstossen |
| `GET /runs`, `/items/{id}`, `/cves/{cve_id}` | Lesezugriff zum Pruefen |

## Umgebung

`DATABASE_URL`, `LIBRETRANSLATE_URL` (kommen aus docker-compose), `INTERNAL_API_KEY`,
optional `NVD_API_KEY` (ohne Schluessel drosselt M1 auf ~5 Anfragen/30 s), `M1_HTTP_RETRIES`, `M1_HTTP_TIMEOUT`, `M1_TRANSLATE_BATCH`.

## Tests

```
pip install -r requirements-dev.txt
python -m pytest
```

Die Tests decken Parser, Normalisierung, Retry und Textaufteilung ab, nicht die Datenbankzugriffe.

## Voller NVD-Bestand

Der normale Abruf kennt nur kuerzlich geaenderte, KEV- und in Meldungen genannte CVEs. Alle rund 430 000
laedt einmalig `docker compose exec m1 python -m app.nvd_mirror` (1-2 GB Datenbank, fortsetzbar).
M1 startet diesen Import beim Start selbst, solange er noch nie fertig wurde (`M1_NVD_MIRROR=0` schaltet
das ab); bis dahin pausiert der normale NVD-Abruf.

## Social-Media-Quellen

Ueber den `rss`-Connector mit `source_type = 'social'` und niedrigem `trust_weight`, z. B. Mastodon-Hashtags:
`https://mastodon.social/tags/cve.rss`. Reddit blockt anonyme Abrufe (braucht eine registrierte API-App),
X hat keine kostenlose API; beide sind nicht angebunden.
