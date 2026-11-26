"""Konfiguration von M4. Alle Werte kommen aus Umgebungsvariablen (.env), nie aus dem Code."""
from __future__ import annotations

import os
import secrets

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://argos:argos@postgres:5432/argos")

# Gleicher Entwicklungs-Standard wie M2, M3 und n8n. Leer gesetzt = jede interne Anfrage wird abgelehnt.
INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY", "dev-internal-key")

# JWT fuer die Weboberflaeche. Kein Standardwert im Code: wer den Schluessel kennt, kann sich Admin-Tokens bauen.
# Fehlt er oder ist er ein oeffentlich bekannter Platzhalter, erzeugt resolve_secrets() beim Start einen Zufallswert.
JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
JWT_TTL_MINUTES = max(5, int(os.getenv("M4_JWT_TTL_MINUTES", "480")))
MIN_JWT_SECRET_BYTES = 32

# Erster Admin. Ohne ADMIN_PASSWORD wird beim ersten Start ein Zufallspasswort erzeugt und einmal ins Log geschrieben.
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

# Brute-Force-Schutz: nach so vielen Fehlversuchen wird das Konto kurz gesperrt.
LOGIN_MAX_FAILURES = max(1, int(os.getenv("M4_LOGIN_MAX_FAILURES", "5")))
LOGIN_LOCK_MINUTES = max(1, int(os.getenv("M4_LOGIN_LOCK_MINUTES", "15")))

MIN_PASSWORD_LENGTH = 10

# Werte, die im Repository stehen oder standen und deshalb oeffentlich sind. Sie gelten als "nicht gesetzt".
PLACEHOLDER_JWT_SECRETS = frozenset({
    "change-me-jwt",
    "change-me-jwt-at-least-32-characters-long",
    "dev-jwt-secret",
    "dev-jwt-secret-only-for-local-development",
})
PLACEHOLDER_ADMIN_PASSWORDS = frozenset({"change-me-admin"})


class ConfigError(RuntimeError):
    """Ein ausdruecklich gesetzter Wert ist unsicher. M4 startet dann nicht."""


def resolve_secrets() -> list[str]:
    """Prueft die Geheimnisse beim Start und gibt Warnungen fuers Log zurueck.

    Fehlt ein Wert oder ist er ein Platzhalter, wird er ersetzt (JWT: Zufallswert, Admin-Passwort: leer,
    dann erzeugt ensure_admin ein Zufallspasswort). Ist ein Wert ausdruecklich gesetzt, aber zu kurz,
    bricht der Start mit ConfigError ab, damit der Fehler nicht unbemerkt bleibt.
    """
    global JWT_SECRET, ADMIN_PASSWORD
    warnings = []
    if not JWT_SECRET or JWT_SECRET in PLACEHOLDER_JWT_SECRETS:
        JWT_SECRET = secrets.token_urlsafe(48)
        warnings.append("JWT_SECRET fehlt oder ist ein oeffentlicher Platzhalter. Fuer diesen Start gilt ein "
                        "Zufallsschluessel, Anmeldungen gelten nur bis zum naechsten Neustart. Bitte in der .env setzen.")
    elif len(JWT_SECRET.encode()) < MIN_JWT_SECRET_BYTES:
        raise ConfigError(f"JWT_SECRET ist kuerzer als {MIN_JWT_SECRET_BYTES} Byte. Neuen Wert erzeugen mit: "
                          "python -c \"import secrets; print(secrets.token_urlsafe(48))\"")

    if ADMIN_PASSWORD in PLACEHOLDER_ADMIN_PASSWORDS:
        ADMIN_PASSWORD = ""
        warnings.append("ADMIN_PASSWORD ist ein oeffentlicher Platzhalter und wird ignoriert.")
    elif ADMIN_PASSWORD and len(ADMIN_PASSWORD) < MIN_PASSWORD_LENGTH:
        raise ConfigError(f"ADMIN_PASSWORD ist kuerzer als {MIN_PASSWORD_LENGTH} Zeichen.")
    return warnings
