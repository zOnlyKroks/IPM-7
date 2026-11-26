# M2 KI-Analyse und Quellenbewertung — v1.3

M2 liest die normalisierten Meldungen aus `public.raw_items` (M1), nutzt Ollama
(`qwen2.5:7b`, `bge-m3`) und schreibt Ergebnisse ausschließlich in `m2.*`.

## Voraussetzungen

- M1-Schema (`public.raw_items`, `public.sources`) ist vorhanden.
- M2-Schema v1.2 ist bereits installiert (`db/init/m2_initial.sql`).
- **Zusätzlich v1.3:** `m2.processing_failures` aus
  `db/migrations/m2_processing_failures.sql` anlegen; bei komplett neuer
  Datenbank wird `db/init/m2_z_processing_failures.sql` automatisch nach dem
  M2-Initialschema ausgeführt.
- `requirements.txt` enthält `fastapi`, `uvicorn`, `httpx` und `psycopg[binary]`.

## Start und Prüfung

Im Repository-Hauptverzeichnis:

```sh
docker compose up --build -d
curl http://localhost:8002/health
curl -X POST http://localhost:8002/run -H "X-API-Key: dev-internal-key"
python -m pytest tests/test_v13.py -q
```

Den API-Key bei eigener `.env` entsprechend ersetzen. Die `/health`-Antwort
bestätigt lediglich, dass der HTTP-Dienst antwortet, nicht die Modellbereitschaft.

## Änderungen in v1.3

1. Fehlende Python-Abhängigkeiten hinzugefügt.
2. Fehlerhafte Meldungen werden mit einem persistenten Fehlerdatensatz,
   exponentieller Wartezeit und `M2_MAX_RETRIES` isoliert; Folgeeinträge
   bleiben verarbeitbar. Standard: 5 Versuche, 60 s bis 3600 s Pause.
3. Nach erfolgreicher Analyse werden bereits bewertete Meldungen aus den
   betroffenen Clustern erneut bewertet (Trust-Score). Die Neubewertung wird
   zusammen mit der neuen Meldung in einer Transaktion gespeichert.
4. Related Events werden über alle geeigneten Ereignisse hinweg nach
   Ähnlichkeit absteigend sortiert; Ereignis-ID dient nur als Tie-Breaker.
5. Regressionstests und dieses README aktualisiert.

## Fehlgeschlagene Meldungen

```sql
SELECT raw_item_id, attempts, last_error, next_retry_at
FROM m2.processing_failures ORDER BY last_failed_at DESC;
```

Eine Meldung nach Fehlerbehebung erneut freigeben:

```sql
DELETE FROM m2.processing_failures WHERE raw_item_id = 123;
```

Nur für eine konkrete, bereits geprüfte ID verwenden. Der Datensatz
`public.raw_items` bleibt erhalten.

## Einschränkungen

- Ältere Bewertungen werden durch **neue Meldungen in denselben Clustern**
  aktualisiert, nicht automatisch bei jeder Änderung von `sources` oder bei
  Änderungen alter Texte.
- Die Neubewertung kann bei sehr großen Clustern teuer werden. Für größere
  Datensätze wäre eine separate Neubewertungs-Queue geeigneter.
- Nach fünf Fehlversuchen ist eine Meldung bis zum manuellen Zurücksetzen
  isoliert. Bei zentralem Ollama-Ausfall können mehrere Meldungen in diesen
  Zustand geraten; deshalb Monitoring der Fehlerliste einplanen.
- Die Trust-Score-Formel ist eine Heuristik und keine kalibrierte
  Wahrscheinlichkeit.
- Ohne erfolgreiche PostgreSQL-/Ollama-Integrationstests ist die Version
  noch nicht produktionsreif.
