"""Konfiguration aus Umgebungsvariablen (siehe .env.example und docker-compose.yml)."""
import os
from dataclasses import dataclass
from functools import lru_cache


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    database_url: str
    libretranslate_url: str
    internal_api_key: str
    nvd_api_key: str
    http_timeout: float
    http_retries: int
    translate_batch: int
    translate_max_attempts: int
    user_agent: str
    nvd_mirror_on_start: bool


@lru_cache
def settings() -> Settings:
    return Settings(
        database_url=os.environ.get("DATABASE_URL", "postgresql://argos:argos@localhost:5432/argos"),
        libretranslate_url=os.environ.get("LIBRETRANSLATE_URL", "http://libretranslate:5000").rstrip("/"),
        internal_api_key=os.environ.get("INTERNAL_API_KEY", ""),
        nvd_api_key=os.environ.get("NVD_API_KEY", ""),
        http_timeout=float(os.environ.get("M1_HTTP_TIMEOUT", "30")),
        http_retries=_int("M1_HTTP_RETRIES", 3),
        translate_batch=_int("M1_TRANSLATE_BATCH", 20),
        translate_max_attempts=_int("M1_TRANSLATE_MAX_ATTEMPTS", 3),
        user_agent=os.environ.get("M1_USER_AGENT", "ArgosAI-M1/1.0"),
        nvd_mirror_on_start=os.environ.get("M1_NVD_MIRROR", "1").lower() not in ("0", "false", "no"),
    )
