# n8n

Orchestrierung. Alle Zeitplaene liegen hier, die Module (M1 bis M4) haben keinen eigenen Scheduler und
laufen nur auf Aufruf. Workflows als JSON in `workflows/` ablegen (Export aus der n8n-Oberflaeche), damit
sie im Repository liegen.

Beim Start importiert `init.sh` alle `workflows/*.json` und veroeffentlicht sie (`n8n publish:workflow`),
damit ihre Zeitplaene laufen. Das passiert bei jedem Start und ueberschreibt den Stand in n8n mit dem
aus dem Repository: Aenderungen in der Oberflaeche also exportieren und einchecken. Jede Datei braucht
eine feste `id` in der obersten Ebene (zwei Leerzeichen eingerueckt, `  "id": "..."`), daran
veroeffentlicht `init.sh` den Workflow.

| Workflow | Takt | Aufruf |
|---|---|---|
| `m1_fetch_due.json` | jede Minute | `POST m1:8000/fetch/due`: faellige Quellen abrufen (Intervall je Quelle: `sources.fetch_interval_minutes`) |
| `m1_fetch_priority.json` | alle 5 Minuten | `POST m1:8000/fetch/priority`: Eilmeldungs-Lauf aller Quellen mit `is_priority` |
| `m1_translate.json` | alle 2 Minuten | `POST m1:8000/translate`: ausstehende Meldungen uebersetzen |
| `m2_analyze.json` | alle 5 Minuten | `POST m2:8000/run`: bis zu `M2_BATCH_SIZE` (Standard 5) uebersetzte Meldungen analysieren |
| `m3_assess.json` | alle 5 Minuten | `POST m3:8000/run`: neue oder geaenderte Meldungen mit dem Inventar abgleichen und bewerten |

Die Aufrufe senden `X-API-Key: $INTERNAL_API_KEY` (die Variable kennt n8n aus `docker-compose.yml`).
Laeuft ein Aufruf noch, wenn der naechste kommt, ueberspringt M1 die betroffene Quelle bzw. den
Uebersetzer, es entstehen keine doppelten Laeufe.

Ausfuehrungen und Fehler: n8n-Oberflaeche (http://localhost:5678), Reiter "Executions". Manuell ausloesen:
Workflow oeffnen, "Execute workflow". Ein Workflow laesst sich dort auch deaktivieren, bis zum naechsten
Start (dann wird er wieder veroeffentlicht); dauerhaft: Datei aus `workflows/` entfernen.
