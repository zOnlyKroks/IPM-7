# M4 Zentrale API und Benachrichtigung

REST-API fuer die Weboberflaeche, Konfiguration, Benachrichtigungen, Berichte.

> **Stand:** Anmeldung (JWT), Rollen, Benutzerverwaltung, Audit-Log und Quellenverwaltung sind umgesetzt.
> **Folgt:** Meldungen (Liste, Detail), Inventar-Upload an M3, Empfaenger und Regeln, `/run-now`, `/notify`, Oberflaeche, Berichte.

## Endpunkte

Routen fuer die Oberflaeche liegen unter `/api` (nginx reicht `/api/` unveraendert an M4 durch) und brauchen
den Header `Authorization: Bearer <token>`. Interne Routen liegen ohne Praefix.

| Methode | Pfad | Rolle | Zweck |
|---|---|---|---|
| GET | `/health` | - | Lebenszeichen |
| POST | `/api/auth/login` | - | `{"username", "password"}` -> `access_token`, `expires_at`, `user` |
| GET | `/api/auth/me` | viewer | Eigener Benutzer |
| POST | `/api/auth/logout` | viewer | Meldet ab, macht alle Tokens des Benutzers ungueltig |
| POST | `/api/auth/password` | viewer | `{"current_password", "new_password"}` -> neues Token, andere Sitzungen abgemeldet |
| GET, POST | `/api/users` | admin | Benutzer auflisten, anlegen |
| PATCH | `/api/users/{id}` | admin | Rolle, `is_active`, Passwort zuruecksetzen. Kein Loeschen |
| GET | `/api/sources?status=` | viewer | Quellen mit letztem Abruf (`last_fetch` aus `fetch_runs`) |
| GET | `/api/sources/{id}` | viewer | Eine Quelle |
| POST | `/api/sources` | admin | Quelle anlegen |
| PATCH | `/api/sources/{id}` | admin | Aendern, aktivieren, sperren (`status`). Kein Loeschen |

Rollen sind gestuft: `viewer` < `analyst` < `admin`. Eine Route fuer `analyst` erlaubt also auch Admins.

**Anmeldung**
- Passwoerter mit argon2, mindestens 10 Zeichen.
- Nach `M4_LOGIN_MAX_FAILURES` (Standard 5) Fehlversuchen ist das Konto `M4_LOGIN_LOCK_MINUTES` (15) gesperrt.
  Unbekannter Benutzer, falsches Passwort, Sperre und deaktiviertes Konto geben dieselbe Antwort.
- Tokens gelten `M4_JWT_TTL_MINUTES` (480). Abmelden, Passwort-, Rollenwechsel oder Deaktivierung erhoehen
  `users.token_version`, alte Tokens sind danach sofort ungueltig.
- Erster Admin aus `ADMIN_USERNAME` und `ADMIN_PASSWORD` (`.env`), nur solange es keinen aktiven Admin gibt.
  Ohne `ADMIN_PASSWORD` steht ein einmaliges Zufallspasswort im Log: `docker compose logs m4 | grep Startpasswort`.
- Der letzte aktive Admin kann nicht herabgestuft oder deaktiviert werden (409).

**Geheimnisse beim Start**

| Wert | fehlt oder Platzhalter aus dem Repo | gesetzt, aber zu kurz |
|---|---|---|
| `JWT_SECRET` (mind. 32 Byte) | Zufallsschluessel fuer diesen Start, Warnung im Log. Anmeldungen gelten nur bis zum Neustart | M4 startet nicht |
| `ADMIN_PASSWORD` (mind. 10 Zeichen) | Einmaliges Zufallspasswort im Log | M4 startet nicht |

Oeffentlich bekannte Werte (z. B. die alten Platzhalter aus `.env.example`) stehen in `app/config.py` und gelten als nicht gesetzt,
damit sich niemand mit ihnen ein Admin-Token bauen kann.
**Audit-Log:** Anmeldungen (auch fehlgeschlagene), Abmeldungen, Passwortwechsel und jede Aenderung an Benutzern
und Quellen. Bei Aenderungen stehen nur die geaenderten Felder mit altem und neuem Wert drin, nie Passwoerter.

**Quellen:** `config` darf keine Zugangsdaten enthalten (Schluessel wie `password`, `token`, `api_key` -> 422),
die gehoeren in die `.env`.

## Datenbank

Schema `m4` in [db/init/m4_initial.sql](../db/init/m4_initial.sql). M4 schreibt nur dort und in `public.sources`.
M3 wird ausschliesslich ueber die Views `m3.findings_current`, `m3.findings_history` und `m3.assets_overview` gelesen.

| Tabelle | Zweck |
|---|---|
| `users` | Anmeldung, Rollen `admin`, `analyst`, `viewer` |
| `recipient_groups`, `recipients` | Empfaenger je Zielgruppe (`it_security`, `management`, `executive`) |
| `notification_rules` | Risikostufe -> Gruppe, Kanal, sofort/taeglich/woechentlich |
| `notification_log` | Versandprotokoll (im Arbeitspaket `notifications`) |
| `item_status` | Bearbeitungsstatus je Meldung (im Arbeitspaket `alert_status`) |
| `audit_log` | Aenderungsprotokoll, nur anhaengen |

**Genau einmal benachrichtigen:** M3 legt bei jeder Aenderung der Eingangswerte (z. B. neuer EPSS-Wert)
eine neue `risk_assessment_id` an. Gemeldet wird deshalb je Treffer (`match_id`), Empfaenger und Kanal nur
beim ersten Mal und wenn die Risikostufe hoeher ist als die zuletzt gemeldete.

**Rauchtest** (Testdaten werden zurueckgerollt):
```sh
docker compose down -v
docker compose up -d postgres
docker compose exec -T postgres psql -U argos -d argos -v ON_ERROR_STOP=1 < m4_api/tests/m4_schema_smoke.sql
```
Erwartet: `NOTICE:  M4 smoke test OK`.

### Bestehende Datenbank: m4_initial.sql nachladen

Die Dateien in `db/init/` laufen nur beim allerersten Start auf einem leeren Volume. Wurde die Datenbank vorher
angelegt, fehlt das Schema `m4`. M4 startet dann trotzdem, damit n8n und die anderen Module weiterlaufen:
`/health` meldet `"status": "degraded"`, alle `/api`-Routen antworten mit 503 und diesem Hinweis.

Nachladen, ohne andere Daten zu verlieren (im Hauptordner des Repositorys):
```sh
docker compose exec -T postgres psql -U argos -d argos -v ON_ERROR_STOP=1 < db/init/m4_initial.sql
```
PowerShell:
```powershell
Get-Content -Raw db\init\m4_initial.sql | docker compose exec -T postgres psql -U argos -d argos -v ON_ERROR_STOP=1
```
Ein Neustart von M4 ist nicht noetig, die naechste Anfrage prueft erneut und legt den Start-Admin an.
Die Datei laeuft in einer Transaktion: bricht sie ab (z. B. weil Teile des Schemas schon existieren), wird nichts geaendert.
Alternativ alles neu aufsetzen mit `docker compose down -v` (loescht **alle** Daten).

## Tests

Im Ordner `m4_api`, Python 3.12:
```sh
pip install -r requirements-dev.txt
python -m pytest                                   # Unit-Tests, ohne Datenbank
M4_TEST_DATABASE_URL=postgresql://argos:argos@localhost:5432/argos python -m pytest   # zusaetzlich mit DB
```
Ohne lokales Python 3.12 im Container:
```sh
# im Hauptordner des Repositorys (der Test fuer das Nachladen braucht db/init)
docker run --rm --network argos_default -v "$PWD:/repo" -w /repo/m4_api \
  -e M4_TEST_DATABASE_URL=postgresql://argos:argos@postgres:5432/argos \
  python:3.12-slim sh -c "pip install -q -r requirements-dev.txt && python -m pytest"
```
Der Durchlauf mit DB **leert `m4.users` und `m4.audit_log`** und legt kurz eine Wegwerf-Datenbank `m4_empty_*` an:
nur gegen die lokale Entwicklungsdatenbank laufen lassen.
