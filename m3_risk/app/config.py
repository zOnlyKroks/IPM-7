"""Konfiguration von M3. Alle Werte kommen aus Umgebungsvariablen (.env), nie aus dem Code."""
from __future__ import annotations

import os
from pathlib import Path

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://argos:argos@postgres:5432/argos")

# Gleicher Entwicklungs-Standard wie M2 und n8n (docker-compose reicht den Key nicht an die Module durch).
# Wird der Key ausdruecklich leer gesetzt, lehnt M3 jede Anfrage ab.
INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY", "dev-internal-key")

RISK_POLICY_PATH = Path(os.getenv("M3_RISK_POLICY", Path(__file__).resolve().parent / "risk_policy.yaml"))

# Grenzen fuer Uploads und Laeufe
MAX_UPLOAD_BYTES = int(os.getenv("M3_MAX_UPLOAD_BYTES", str(5 * 1024 * 1024)))
MAX_SBOM_BYTES = int(os.getenv("M3_MAX_SBOM_BYTES", str(20 * 1024 * 1024)))   # Syft-SBOMs grosser Images: mehrere MB
MAX_ATTEMPTS = max(1, int(os.getenv("M3_MAX_ATTEMPTS", "5")))      # fehlgeschlagene Meldungen nicht endlos wiederholen
RUN_LIMIT = max(1, int(os.getenv("M3_RUN_LIMIT", "500")))          # hoechstens so viele Meldungen je /run

# Handlungsempfehlungen (README Abschnitt 8). Nur lokales Ollama; ohne Ollama bleiben die Mustertexte.
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434").rstrip("/")
LLM_MODEL = os.getenv("LLM_MODEL", "qwen2.5:7b")
LLM_ENABLED = os.getenv("M3_LLM_ENABLED", "true").strip().lower() not in ("0", "false", "no")
LLM_TIMEOUT = float(os.getenv("M3_LLM_TIMEOUT", "60"))                     # Sekunden je Aufruf
LLM_LIMIT = max(1, int(os.getenv("M3_LLM_LIMIT", "10")))                   # hoechstens so viele LLM-Aufrufe je /run
LLM_LEVELS = tuple(x.strip() for x in os.getenv("M3_LLM_LEVELS", "critical,high,medium").split(",") if x.strip())

# PostgreSQL-Advisory-Lock fuer /run (M2 nutzt 42002002)
ADVISORY_LOCK_ID = 42003003

# Aendert sich die Abgleichs- oder Bewertungslogik, aendert sich diese Version.
# Sie geht in die Fingerabdruecke ein, dadurch wird beim naechsten /run alles neu bewertet.
# Auch noetig, wenn ein bisher ungenutzter Eingabewert (OSV, Entitaeten) erstmals verwendet wird:
# der Wert steht dann schon im Hash, der Codepfad allein loest keine Neubewertung aus.
MATCH_LOGIC_VERSION = "match-v1"
